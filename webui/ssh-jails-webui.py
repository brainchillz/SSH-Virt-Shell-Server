#!/usr/bin/env python3
"""SSH-Virt-Shell-Server web UI (optional addon).

Zero-dependency HTTPS admin panel for provisioning jail users. All
provisioning goes through the same /opt/ssh-router/bin scripts the CLI
uses; this process never talks to Incus directly.

Runtime files (created by install-webui.sh, all in this directory):
  webui.json  - {"bind": ..., "port": ...}
  auth.json   - admin credential (PBKDF2-SHA256)
  cert.pem / key.pem - self-signed TLS material
"""

import base64
import hashlib
import hmac
import html
import http.server
import ipaddress
import json
import os
import re
import secrets
import ssl
import struct
import subprocess
import time
import urllib.parse

APP_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = "/opt/ssh-router/bin"

with open(os.path.join(APP_DIR, "webui.json")) as f:
    CFG = json.load(f)
with open(os.path.join(APP_DIR, "auth.json")) as f:
    AUTH = json.load(f)

# Optional admin-IP allowlist (config "allow": ["ip/cidr", ...]). Empty =
# open to all (the default). When set, any client not in the list gets 403
# before authentication even runs. NOTE: this checks the direct socket peer;
# behind a reverse proxy you'd instead trust an X-Forwarded-For header.
ALLOW_NETS = []
for _entry in CFG.get("allow", []) or []:
    try:
        ALLOW_NETS.append(ipaddress.ip_network(_entry, strict=False))
    except ValueError:
        print(f"webui: ignoring invalid allow entry: {_entry}", flush=True)

USERNAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,29}$")
PASSWORD_LINE_RE = re.compile(r"[Pp]assword\s*:\s*(\S+)")
SNAPSHOT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SIZE_RE = re.compile(r"^[0-9]+([KMGT]i?B)?$")
CPU_RE = re.compile(r"^[0-9]+$")
IP_RE = re.compile(
    r"^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$|^[0-9a-fA-F:]+(/[0-9]{1,3})?$")
ADMIN_USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,31}$")

SESSION_TTL = 3600
SESSIONS = {}  # token -> {"exp": epoch, "csrf": token}
# Per-IP login throttling: a wrong guess only counts against the guessing
# IP, so an attacker can't lock the real admin out. LOGIN_MAX failures ->
# that IP is blocked for LOGIN_BAN seconds.
FAILS = {}  # ip -> {"count": int, "until": epoch}
LOGIN_MAX = 5
LOGIN_BAN = 60


def check_password(pw):
    """Verify a password against the stored hash (used for re-auth of an
    already-logged-in admin)."""
    digest = hashlib.pbkdf2_hmac(
        "sha256", pw.encode(), bytes.fromhex(AUTH["salt"]), AUTH["iterations"]
    )
    return secrets.compare_digest(digest.hex(), AUTH["hash"])


def check_credentials(user, pw):
    """Verify username AND password for login. Both are compared in constant
    time and combined without short-circuiting, so a wrong username and a
    wrong password are indistinguishable (the login page returns one generic
    error either way, and the username can't be enumerated)."""
    user_ok = secrets.compare_digest(user, AUTH.get("user", "admin"))
    pw_ok = check_password(pw)
    return user_ok and pw_ok


def save_auth():
    """Atomically persist the AUTH dict to auth.json (mode 600)."""
    tmp = os.path.join(APP_DIR, "auth.json.tmp")
    with open(tmp, "w") as f:
        json.dump(AUTH, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, os.path.join(APP_DIR, "auth.json"))


def set_admin_account(user=None, pw=None):
    """Update the admin username and/or password (either may be None)."""
    if user:
        AUTH["user"] = user
    if pw:
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 600000)
        AUTH.update({"salt": salt, "hash": digest.hex(), "iterations": 600000})
    save_auth()


# --- TOTP (RFC 6238, SHA1/30s/6-digit) — stdlib only, no dependency -------
def gen_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode()


def totp_at(secret, t):
    key = base64.b32decode(secret)
    msg = struct.pack(">Q", int(t // 30))
    h = hmac.new(key, msg, hashlib.sha1).digest()
    off = h[-1] & 0x0F
    code = (struct.unpack(">I", h[off:off + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


def totp_verify(secret, code, t=None, window=1):
    """Verify a code, allowing +/- one 30s step for clock skew."""
    if not secret or not code or not code.strip().isdigit():
        return False
    code = code.strip()
    now = t if t is not None else time.time()
    return any(secrets.compare_digest(totp_at(secret, now + w * 30), code)
               for w in range(-window, window + 1))


def totp_uri(secret, account):
    issuer = "SSH-Virt-Shell-Server"
    q = urllib.parse.urlencode({"secret": secret, "issuer": issuer})
    return f"otpauth://totp/{issuer}:{account}?{q}"


def run_tool(tool, *args, timeout=300, input=None):
    proc = subprocess.run(
        [os.path.join(BIN_DIR, tool), *args],
        capture_output=True, text=True, timeout=timeout, input=input,
    )
    return proc.returncode, proc.stdout, proc.stderr


def list_users():
    rc, out, _ = run_tool("jail-user-list", timeout=60)
    users = []
    if rc == 0:
        for line in out.splitlines()[1:]:
            parts = line.split()
            if parts:
                users.append({
                    "user": parts[0],
                    "container": parts[1] if len(parts) > 1 else "",
                    "state": parts[2] if len(parts) > 2 else "",
                    "ip": parts[3] if len(parts) > 3 else "",
                    "sudo": parts[4] if len(parts) > 4 else "no",
                    "keys": parts[5] if len(parts) > 5 else "0",
                    "auth": parts[6] if len(parts) > 6 else "password",
                })
    return users


def f2b_info():
    """(available, banned_ips, whitelist) from the jail-fail2ban tool."""
    rc, out, _ = run_tool("jail-fail2ban", "status", timeout=60)
    banned = []
    if rc == 0:
        m = re.search(r"Banned IP list:\s*(.*)", out)
        if m:
            banned = m.group(1).split()
    rc2, out2, _ = run_tool("jail-fail2ban", "whitelist", timeout=60)
    whitelist = [l.strip() for l in out2.splitlines()[1:] if l.strip()] if rc2 == 0 else []
    return rc == 0, banned, whitelist


def user_detail(name):
    """Collect limits, keys and snapshots for the per-user page."""
    d = {"limits": {}, "keys": [], "keyonly": False, "snapshots": []}
    rc, out, _ = run_tool("jail-user-limits", name, timeout=60)
    if rc == 0:
        for label in ("CPU", "Memory", "Disk"):
            m = re.search(label + r"\s*:\s*(.*)", out)
            d["limits"][label.lower()] = m.group(1).strip() if m else "?"
    rc, out, _ = run_tool("jail-user-key", "list", name, timeout=60)
    if rc == 0:
        for line in out.splitlines()[1:]:
            line = line.strip()
            if line.startswith("Auth:"):
                d["keyonly"] = "key-only" in line
            elif line and not line.startswith("(no keys"):
                d["keys"].append(line)
    rc, out, _ = run_tool("jail-user-backup", name, "list", "--csv", timeout=60)
    if rc == 0:
        for line in out.splitlines():
            cols = line.split(",")
            if cols and cols[0].strip():
                d["snapshots"].append({"name": cols[0].strip(),
                                       "taken": cols[1].strip() if len(cols) > 1 else ""})
    return d


# Inline stylesheet — no external assets, keeping the single-file,
# zero-dependency design. Visual language: NexusDashboard-Modular (dark-first
# sidebar + card grid, warm rust accent); light is the prefers-color-scheme
# variant. Palette pinned in docs/roadmap.md.
STYLE = """
:root{--bg:#1c1e22;--sidebar-bg:#24262b;--card-bg:#2a2d33;--border:#7a4a22;
--border-soft:#3a3d43;--text:#d6d8dc;--muted:#9aa0a8;--primary:#c1550f;
--primary-hover:#d96a1e;--green:#22c55e;--yellow:#eab308;--red:#ef4444;--radius:8px}
@media (prefers-color-scheme:light){:root{--bg:#f2f1ef;--sidebar-bg:#fff;
--card-bg:#fff;--border:#c98a5b;--border-soft:#ddd8d2;--text:#26221e;
--muted:#6b655e;--primary:#b34d0c;--primary-hover:#983f08;--green:#16a34a;
--yellow:#ca8a04;--red:#dc2626}}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:var(--bg);color:var(--text);margin:0;min-height:100vh;display:flex}
a{color:var(--primary);text-decoration:none}
/* Page (body) is the scroll container so #section links work reliably;
   the sidebar sticks to the top while content scrolls. */
.sidebar{width:240px;background:var(--sidebar-bg);border-right:1px solid var(--border);
display:flex;flex-direction:column;flex-shrink:0;position:sticky;top:0;
align-self:flex-start;height:100vh}
.sidebar-header{padding:22px 20px 16px;border-bottom:1px solid var(--border)}
.sidebar-header h1{font-size:17px;font-weight:700;margin:0;letter-spacing:.3px}
.sidebar-header .sub{font-size:12px;color:var(--muted);margin-top:3px}
.nav{list-style:none;padding:10px 0;margin:0;flex:1}
.nav a{display:flex;align-items:center;gap:10px;padding:9px 20px;color:var(--muted);
border-left:3px solid transparent;font-size:14px}
.nav a:hover{color:var(--text);background:rgba(255,255,255,.04)}
.nav a.active{color:var(--primary);background:rgba(193,85,15,.12);border-left-color:var(--primary)}
.nav .icon{width:18px;text-align:center;font-size:15px}
.sidebar-footer{padding:14px 20px;border-top:1px solid var(--border-soft);
display:flex;align-items:center;justify-content:space-between;gap:8px}
.dot{width:9px;height:9px;border-radius:50%;background:var(--green);
box-shadow:0 0 6px var(--green);flex-shrink:0}
.content{flex:1;min-width:0;padding:26px 34px}
.content .inner{max-width:62rem}
h1.page{font-size:19px;margin:0 0 4px}
h2{font-size:14px;font-weight:600;margin:26px 0 12px;color:var(--text);
text-transform:uppercase;letter-spacing:.6px;scroll-margin-top:18px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin:16px 0 6px}
.card{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);
padding:18px;text-align:center}
.card .v{font-size:26px;font-weight:700}
.card .l{font-size:12px;color:var(--muted);margin-top:2px}
table{border-collapse:collapse;width:100%;background:var(--card-bg);
border:1px solid var(--border-soft);border-radius:var(--radius);overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--border-soft);
font-size:14px;vertical-align:middle}
th{background:rgba(255,255,255,.03);color:var(--muted);font-weight:600;
text-transform:uppercase;font-size:11px;letter-spacing:.5px}
tr:last-child td{border-bottom:none}
form.inline{display:inline}
input,textarea,select{background:var(--bg);border:1px solid var(--border-soft);
border-radius:6px;color:var(--text);padding:8px 11px;font-size:14px;font-family:inherit}
input:focus,textarea:focus{outline:none;border-color:var(--primary)}
input[type=checkbox]{vertical-align:middle}
label{font-size:14px;color:var(--muted)}
button{display:inline-flex;align-items:center;gap:6px;padding:8px 15px;
background:var(--primary);color:#fff;border:none;border-radius:6px;font-size:13px;
cursor:pointer;font-family:inherit;white-space:nowrap}
button:hover{background:var(--primary-hover)}
button.danger{background:transparent;color:var(--red);border:1px solid var(--red)}
button.danger:hover{background:rgba(239,68,68,.12)}
button.ghost{background:transparent;color:var(--muted);border:1px solid var(--border-soft)}
button.ghost:hover{color:var(--text)}
.msg{background:rgba(34,197,94,.12);border:1px solid var(--green);padding:11px 14px;
border-radius:var(--radius);margin:14px 0}
.err{background:rgba(239,68,68,.12);border:1px solid var(--red);padding:11px 14px;
border-radius:var(--radius);margin:14px 0}
code{background:var(--bg);border:1px solid var(--border-soft);border-radius:4px;
padding:1px 5px;font-size:13px}
code.pw{font-size:1.05rem;border-style:dashed;border-color:var(--primary);padding:3px 8px}
pre{white-space:pre-wrap;background:var(--bg);border:1px solid var(--border-soft);
border-radius:6px;padding:10px;font-size:12px;margin:6px 0 0}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:10px 0}
small{color:var(--muted)}
ul.plain{list-style:none;padding:0;margin:8px 0}
ul.plain li{display:flex;align-items:center;gap:10px;padding:5px 0}
body.login{align-items:center;justify-content:center}
.login-box{background:var(--card-bg);border:1px solid var(--border);
border-radius:var(--radius);padding:30px 28px;width:330px;max-width:90vw}
.login-box h1{font-size:18px;margin:0 0 2px}
.login-box .sub{font-size:12px;color:var(--muted);margin-bottom:18px}
.login-box input{width:100%;margin-bottom:10px}
.login-box button{width:100%;justify-content:center;padding:10px}
"""

_HEAD = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
         '<meta name="viewport" content="width=device-width, initial-scale=1">'
         '<title>SSH-Virt-Shell-Server</title><style>' + STYLE + '</style></head>')

NAV_ITEMS = [("/", "◉", "Users", "users"),
             ("/fail2ban", "⛨", "fail2ban", "fail2ban"),
             ("/account", "⚙", "Account", "account")]


def render(body, logged_in=False, csrf="", active="", login=False):
    """Wrap page body in the chrome. login=True -> centered login box;
    logged_in=True -> sidebar layout (the logout form needs the session CSRF
    token, like any mutating POST); otherwise a bare content shell."""
    if login:
        return (_HEAD + '<body class="login">' + body + "</body></html>").encode()
    if not logged_in:
        return (_HEAD + '<body><main class="content"><div class="inner">'
                + body + "</div></main></body></html>").encode()
    nav = ""
    for href, icon, label, key in NAV_ITEMS:
        cls = ' class="active"' if key == active else ""
        nav += (f'<li><a href="{href}"{cls}><span class="icon">{icon}</span>'
                f"{label}</a></li>")
    logout = ""
    if csrf:
        logout = ('<form method="post" action="/logout">'
                  f'<input type="hidden" name="csrf" value="{csrf}">'
                  '<button class="ghost">Log out</button></form>')
    sidebar = ('<aside class="sidebar"><div class="sidebar-header">'
               '<h1>SSH-Virt-Shell</h1><div class="sub">admin panel</div></div>'
               f'<ul class="nav">{nav}</ul>'
               f'<div class="sidebar-footer"><span class="dot" title="online"></span>'
               f"{logout}</div></aside>")
    return (_HEAD + "<body>" + sidebar + '<main class="content"><div class="inner">'
            + body + "</div></main></body></html>").encode()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SSHJailsWebUI"

    # --- plumbing ---------------------------------------------------------
    def _send(self, code, body, extra_headers=()):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location, cookie=None):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _session(self):
        cookies = self.headers.get("Cookie", "")
        for part in cookies.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "session":
                sess = SESSIONS.get(value)
                if sess and sess["exp"] > time.time():
                    sess["exp"] = time.time() + SESSION_TTL
                    return value, sess
                SESSIONS.pop(value, None)
        return None, None

    def _form(self):
        try:
            length = min(int(self.headers.get("Content-Length", 0)), 65536)
        except ValueError:
            return {}
        raw = self.rfile.read(length).decode("utf-8", "replace")
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def log_message(self, fmt, *args):  # journald via stderr, without noise
        print("%s %s" % (self.address_string(), fmt % args), flush=True)

    def _client_ip(self):
        return self.client_address[0]

    def _ip_allowed(self):
        if not ALLOW_NETS:
            return True
        try:
            ip = ipaddress.ip_address(self._client_ip())
        except ValueError:
            return False
        return any(ip in net for net in ALLOW_NETS)

    # --- pages ------------------------------------------------------------
    def page_login(self, error=""):
        err = f'<div class="err">{html.escape(error)}</div>' if error else ""
        code_field = ""
        if AUTH.get("totp"):
            code_field = ('<input type="text" name="code" placeholder="6-digit code" '
                          'inputmode="numeric" autocomplete="one-time-code" maxlength="6">')
        return render(f"""<div class="login-box">
<h1>SSH-Virt-Shell-Server</h1>
<div class="sub">Administrator sign in</div>
{err}
<form method="post" action="/login">
 <input type="text" name="username" placeholder="Username" autofocus autocomplete="username">
 <input type="password" name="password" placeholder="Password" autocomplete="current-password">
 {code_field}
 <button>Sign in</button>
</form>
</div>""", login=True)

    def page_users(self, sess, msg="", err=""):
        users = list_users()
        rows = ""
        for u in users:
            name = html.escape(u["user"])
            has_sudo = u["sudo"] == "yes"
            sudo_action = "off" if has_sudo else "on"
            auth = ("key-only" if u["auth"] == "key-only" else "password") + \
                   (f" +{html.escape(u['keys'])}k" if u["keys"] not in ("", "0") else "")
            rows += (f"<tr><td>{name}</td><td>{html.escape(u['container'])}</td>"
                     f"<td>{html.escape(u['state'])}</td><td>{html.escape(u['ip'])}</td>"
                     f"<td>{'yes' if has_sudo else 'no'}</td><td>{auth}</td><td>"
                     f'<a href="/user?u={name}"><button>Manage…</button></a> '
                     f'<form class="inline" method="post" action="/sudo">'
                     f'<input type="hidden" name="csrf" value="{sess["csrf"]}">'
                     f'<input type="hidden" name="username" value="{name}">'
                     f'<input type="hidden" name="mode" value="{sudo_action}">'
                     f"<button>Sudo {sudo_action}</button></form> "
                     f'<form class="inline" method="post" action="/passwd">'
                     f'<input type="hidden" name="csrf" value="{sess["csrf"]}">'
                     f'<input type="hidden" name="username" value="{name}">'
                     f"<button>Reset password</button></form> "
                     f'<a href="/delete?u={name}"><button class="danger">Delete…</button></a>'
                     f"</td></tr>")
        if not rows:
            rows = '<tr><td colspan="7"><em>No users provisioned yet.</em></td></tr>'
        n_sudo = sum(1 for u in users if u["sudo"] == "yes")
        n_keyonly = sum(1 for u in users if u["auth"] == "key-only")
        cards = (f'<div class="card"><div class="v">{len(users)}</div><div class="l">Jail users</div></div>'
                 f'<div class="card"><div class="v">{n_sudo}</div><div class="l">With sudo</div></div>'
                 f'<div class="card"><div class="v">{n_keyonly}</div><div class="l">Key-only</div></div>')
        msg_html = f'<div class="msg">{msg}</div>' if msg else ""
        err_html = f'<div class="err">{err}</div>' if err else ""
        return render(f"""<h1 class="page">Users</h1>{msg_html}{err_html}
<div class="cards">{cards}</div>
<h2>Jail users</h2>
<table><tr><th>User</th><th>Container</th><th>State</th><th>IP</th><th>Sudo</th><th>Auth</th><th></th></tr>{rows}</table>
<h2>Add user</h2>
<form method="post" action="/add">
 <input type="hidden" name="csrf" value="{sess['csrf']}">
 <p><input type="text" name="username" placeholder="username" required
           pattern="[a-z][a-z0-9-]{{1,29}}">
    <input type="password" name="password" placeholder="password (blank = generate)">
    <label><input type="checkbox" name="sudo" value="1"> sudo in own jail</label>
    <button>Create</button></p>
 <p><small>Provisioning launches a container and takes ~30&ndash;60 seconds.</small></p>
</form>""", logged_in=True, csrf=sess["csrf"], active="users")

    def page_fail2ban(self, sess, msg="", err=""):
        f2b_ok, banned, whitelist = f2b_info()
        if not f2b_ok:
            body = "<p><em>fail2ban is not available (re-run install.sh).</em></p>"
            cards = '<div class="card"><div class="v">&mdash;</div><div class="l">unavailable</div></div>'
        else:
            banned_html = ""
            for ip in banned:
                s = html.escape(ip)
                banned_html += (f'<li><code>{s}</code> '
                                f'<form class="inline" method="post" action="/f2b-unban">'
                                f'<input type="hidden" name="csrf" value="{sess["csrf"]}">'
                                f'<input type="hidden" name="ip" value="{s}">'
                                f"<button>Unban</button></form></li>")
            wl_html = ""
            for ip in whitelist:
                s = html.escape(ip)
                wl_html += (f'<li><code>{s}</code> '
                            f'<form class="inline" method="post" action="/f2b-wl-del">'
                            f'<input type="hidden" name="csrf" value="{sess["csrf"]}">'
                            f'<input type="hidden" name="ip" value="{s}">'
                            f"<button>Remove</button></form></li>")
            body = f"""
<h2>Banned right now</h2>
<ul class="plain">{banned_html or "<li><em>nobody</em></li>"}</ul>
<h2>Whitelist (never banned)</h2>
<ul class="plain">{wl_html or "<li><em>empty</em></li>"}</ul>
<form method="post" action="/f2b-wl-add">
 <input type="hidden" name="csrf" value="{sess['csrf']}">
 <div class="row"><input type="text" name="ip" placeholder="IP or CIDR, e.g. 203.0.113.5 or 10.0.0.0/8" size="34" required>
 <button>Add to whitelist</button></div>
</form>"""
            cards = (f'<div class="card"><div class="v">{len(banned)}</div><div class="l">Banned now</div></div>'
                     f'<div class="card"><div class="v">{len(whitelist)}</div><div class="l">Whitelisted</div></div>')
        msg_html = f'<div class="msg">{msg}</div>' if msg else ""
        err_html = f'<div class="err">{err}</div>' if err else ""
        return render(f"""<h1 class="page">fail2ban</h1>{msg_html}{err_html}
<div class="cards">{cards}</div>{body}""", logged_in=True, csrf=sess["csrf"], active="fail2ban")

    def page_account(self, sess, msg="", err=""):
        msg_html = f'<div class="msg">{msg}</div>' if msg else ""
        err_html = f'<div class="err">{err}</div>' if err else ""
        csrf = f'<input type="hidden" name="csrf" value="{sess["csrf"]}">'
        if AUTH.get("totp"):
            twofa = (f"<p>Two-factor authentication is <b>enabled</b>.</p>"
                     f'<form method="post" action="/totp-disable">{csrf}'
                     f'<div class="row"><input type="password" name="current" '
                     f'placeholder="current password" required>'
                     f'<button class="danger">Disable 2FA</button></div></form>')
        elif sess.get("totp_pending"):
            secret = sess["totp_pending"]
            uri = html.escape(totp_uri(secret, AUTH.get("user", "admin")))
            twofa = (f"<p>Add this secret to your authenticator app "
                     f"(Google Authenticator, Aegis, 1Password, …), then enter a "
                     f"code to confirm:</p>"
                     f'<p>Secret key: <code class="pw">{secret}</code></p>'
                     f'<p><small>Or use this setup URI:<br><code>{uri}</code></small></p>'
                     f'<form method="post" action="/totp-enable">{csrf}'
                     f'<div class="row"><input type="text" name="code" placeholder="6-digit code" '
                     f'inputmode="numeric" maxlength="6" required>'
                     f'<button>Confirm &amp; enable</button></div></form>')
        else:
            twofa = (f"<p>Two-factor authentication is <b>off</b>. Enabling it adds a "
                     f"time-based one-time code to every login.</p>"
                     f'<form method="post" action="/totp-setup">{csrf}'
                     f"<button>Set up 2FA</button></form>")
        return render(f"""<h1 class="page">Admin account</h1>{msg_html}{err_html}
<h2>Credentials</h2>
<p><small>Signed in as <b>{html.escape(AUTH.get('user', 'admin'))}</b>. Current password is required for any change.</small></p>
<form method="post" action="/account">
 {csrf}
 <div class="row"><input type="password" name="current" placeholder="current password" required></div>
 <div class="row"><input type="text" name="new_user" placeholder="new username (blank = unchanged)"
        pattern="[A-Za-z0-9][A-Za-z0-9_.-]{{1,31}}"></div>
 <div class="row"><input type="password" name="new1" placeholder="new password (min 8, blank = unchanged)">
    <input type="password" name="new2" placeholder="repeat new password"></div>
 <div class="row"><button>Update account</button></div>
</form>
<h2>Two-factor authentication</h2>
{twofa}""", logged_in=True, csrf=sess["csrf"], active="account")

    def page_user(self, sess, name, msg="", err=""):
        safe = html.escape(name)
        d = user_detail(name)
        lim = d["limits"]
        hidden = (f'<input type="hidden" name="csrf" value="{sess["csrf"]}">'
                  f'<input type="hidden" name="username" value="{safe}">')
        keys_rows = ""
        for i, k in enumerate(d["keys"], 1):
            keys_rows += (f"<tr><td><code>{html.escape(k)}</code></td><td>"
                          f'<form class="inline" method="post" action="/key-del">{hidden}'
                          f'<input type="hidden" name="index" value="{i}">'
                          f'<button class="danger">Remove</button></form></td></tr>')
        if not keys_rows:
            keys_rows = '<tr><td colspan="2"><em>No keys installed.</em></td></tr>'
        if d["keyonly"]:
            keyonly_html = (f'<p>Password auth is <b>disabled</b> (key-only). '
                            f'<form class="inline" method="post" action="/key-only">{hidden}'
                            f'<input type="hidden" name="mode" value="off">'
                            f"<button>Re-enable password auth</button></form></p>")
        else:
            keyonly_html = (f'<p>Password auth is <b>enabled</b>. '
                            f'<form class="inline" method="post" action="/key-only">{hidden}'
                            f'<input type="hidden" name="mode" value="on">'
                            f"<button>Switch to key-only</button></form>"
                            f" <small>(requires at least one key)</small></p>")
        snap_rows = ""
        for s in d["snapshots"]:
            sn = html.escape(s["name"])
            snap_rows += (f"<tr><td>{sn}</td><td>{html.escape(s['taken'])}</td><td>"
                          f'<a href="/restore?u={safe}&s={sn}"><button>Restore…</button></a> '
                          f'<form class="inline" method="post" action="/snap-del">{hidden}'
                          f'<input type="hidden" name="snapshot" value="{sn}">'
                          f'<button class="danger">Delete</button></form></td></tr>')
        if not snap_rows:
            snap_rows = '<tr><td colspan="3"><em>No snapshots.</em></td></tr>'
        msg_html = f'<div class="msg">{msg}</div>' if msg else ""
        err_html = f'<div class="err">{err}</div>' if err else ""
        return render(f"""<h1 class="page">{safe}</h1>
<p><a href="/">&larr; All users</a></p>{msg_html}{err_html}
<h2>{safe} — resource limits</h2>
<form method="post" action="/limits">{hidden}
 <p>CPU <input type="text" name="cpu" size="4" placeholder="{html.escape(lim.get('cpu', ''))}">
    Memory <input type="text" name="memory" size="8" placeholder="{html.escape(lim.get('memory', ''))}">
    Disk <input type="text" name="disk" size="8" placeholder="{html.escape(lim.get('disk', ''))}">
    <button>Apply</button></p>
</form>
<form method="post" action="/limits">{hidden}
 <input type="hidden" name="reset" value="1">
 <p><button>Reset to profile defaults</button>
 <small>Blank fields above are left unchanged; sizes like 512MiB, 2GiB.</small></p>
</form>
<h2>{safe} — login keys</h2>
{keyonly_html}
<table><tr><th>Key</th><th></th></tr>{keys_rows}</table>
<form method="post" action="/key-add">{hidden}
 <p><textarea name="pubkey" rows="3" cols="70"
     placeholder="ssh-ed25519 AAAA... comment (one key per line)" required></textarea></p>
 <p><button>Add key(s)</button></p>
</form>
<h2>{safe} — backups</h2>
<table><tr><th>Snapshot</th><th>Taken</th><th></th></tr>{snap_rows}</table>
<form class="inline" method="post" action="/snap-create">{hidden}
 <p><input type="text" name="snapshot" placeholder="name (blank = timestamp)">
 <button>Snapshot now</button></p>
</form>
<form class="inline" method="post" action="/export">{hidden}
 <p><button>Export to tarball</button>
 <small>written on the host; restore via CLI: jail-user-backup {safe} import &lt;file&gt;</small></p>
</form>""", logged_in=True, csrf=sess["csrf"])

    # --- GET --------------------------------------------------------------
    def do_GET(self):
        if not self._ip_allowed():
            self._send(403, b"Forbidden")
            return
        path = urllib.parse.urlparse(self.path).path
        token, sess = self._session()
        if path == "/login":
            self._send(200, self.page_login())
        elif not sess:
            self._redirect("/login")
        elif path == "/":
            self._send(200, self.page_users(sess))
        elif path == "/fail2ban":
            self._send(200, self.page_fail2ban(sess))
        elif path == "/account":
            self._send(200, self.page_account(sess))
        elif path == "/user":
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            name = query.get("u", [""])[0]
            if not USERNAME_RE.match(name):
                self._redirect("/")
                return
            self._send(200, self.page_user(sess, name))
        elif path == "/restore":
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            name = query.get("u", [""])[0]
            snap = query.get("s", [""])[0]
            if not USERNAME_RE.match(name) or not SNAPSHOT_RE.match(snap):
                self._redirect("/")
                return
            safe, ssnap = html.escape(name), html.escape(snap)
            self._send(200, render(f"""
<h2>Restore '{safe}' to snapshot '{ssnap}'?</h2>
<div class="err">Everything changed in <b>jail-{safe}</b> since the snapshot will be <b>lost</b>.</div>
<form method="post" action="/snap-restore">
 <input type="hidden" name="csrf" value="{sess['csrf']}">
 <input type="hidden" name="username" value="{safe}">
 <input type="hidden" name="snapshot" value="{ssnap}">
 <p><button class="danger">Yes, restore</button> <a href="/user?u={safe}">Cancel</a></p>
</form>""", logged_in=True, csrf=sess["csrf"]))
        elif path == "/delete":
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            name = query.get("u", [""])[0]
            if not USERNAME_RE.match(name):
                self._redirect("/")
                return
            safe = html.escape(name)
            self._send(200, render(f"""
<h2>Delete user '{safe}'?</h2>
<div class="err">This destroys container <b>jail-{safe}</b> and <b>all of its data</b>.</div>
<form method="post" action="/del">
 <input type="hidden" name="csrf" value="{sess['csrf']}">
 <input type="hidden" name="username" value="{safe}">
 <p><button class="danger">Yes, delete everything</button> <a href="/">Cancel</a></p>
</form>""", logged_in=True, csrf=sess["csrf"]))
        else:
            self._send(404, render("<p>Not found.</p>"))

    # --- POST -------------------------------------------------------------
    def do_POST(self):
        if not self._ip_allowed():
            self._send(403, b"Forbidden")
            return
        path = urllib.parse.urlparse(self.path).path
        form = self._form()
        token, sess = self._session()

        if path == "/login":
            now = time.time()
            ip = self._client_ip()
            rec = FAILS.get(ip, {"count": 0, "until": 0.0})
            if now < rec["until"]:
                self._send(429, self.page_login("Too many attempts - try again shortly."))
                return
            creds_ok = check_credentials(form.get("username", ""), form.get("password", ""))
            totp_secret = AUTH.get("totp")
            totp_ok = (not totp_secret) or totp_verify(totp_secret, form.get("code", ""))
            if creds_ok and totp_ok:
                FAILS.pop(ip, None)
                new_token = secrets.token_urlsafe(32)
                SESSIONS[new_token] = {"exp": now + SESSION_TTL,
                                       "csrf": secrets.token_urlsafe(32)}
                cookie = (f"session={new_token}; Path=/; HttpOnly; Secure; "
                          f"SameSite=Strict; Max-Age={SESSION_TTL}")
                self._redirect("/", cookie=cookie)
            else:
                rec["count"] += 1
                if rec["count"] >= LOGIN_MAX:
                    rec["until"] = now + LOGIN_BAN
                    rec["count"] = 0
                FAILS[ip] = rec
                # One generic message for wrong username OR password, so the
                # username can't be enumerated.
                self._send(403, self.page_login("Invalid username or password."))
            return

        if not sess:
            self._redirect("/login")
            return
        if not secrets.compare_digest(form.get("csrf", ""), sess["csrf"]):
            self._send(403, render("<p>Invalid CSRF token. <a href='/'>Back</a></p>", True, sess["csrf"]))
            return

        if path == "/logout":
            SESSIONS.pop(token, None)
            self._redirect("/login", cookie="session=; Path=/; Max-Age=0")
            return

        if path == "/account":
            cur = form.get("current", "")
            new_user = form.get("new_user", "").strip()
            new1, new2 = form.get("new1", ""), form.get("new2", "")
            if not check_password(cur):
                self._send(403, self.page_account(sess, err="Current password is wrong."))
            elif new_user and not ADMIN_USER_RE.match(new_user):
                self._send(400, self.page_account(
                    sess, err="Invalid username (2-32 chars: letters, digits, . _ -)."))
            elif (new1 or new2) and new1 != new2:
                self._send(400, self.page_account(sess, err="New passwords do not match."))
            elif new1 and len(new1) < 8:
                self._send(400, self.page_account(
                    sess, err="New password must be at least 8 characters."))
            elif not new_user and not new1:
                self._send(400, self.page_account(sess, err="Nothing to change."))
            else:
                set_admin_account(user=new_user or None, pw=new1 or None)
                changed = ", ".join(
                    p for p in (("username" if new_user else ""),
                                ("password" if new1 else "")) if p)
                self._send(200, self.page_account(sess, msg=f"Admin {changed} updated."))
            return

        if path == "/totp-setup":
            # Hold the candidate secret in the session until confirmed.
            sess["totp_pending"] = gen_totp_secret()
            self._send(200, self.page_account(
                sess, msg="Scan or enter the secret, then confirm with a code."))
            return

        if path == "/totp-enable":
            pending = sess.get("totp_pending")
            if not pending:
                self._send(400, self.page_account(sess, err="No pending 2FA setup."))
            elif not totp_verify(pending, form.get("code", "")):
                self._send(400, self.page_account(sess, err="Code did not match - try again."))
            else:
                AUTH["totp"] = pending
                save_auth()
                sess.pop("totp_pending", None)
                self._send(200, self.page_account(sess, msg="Two-factor authentication enabled."))
            return

        if path == "/totp-disable":
            if not check_password(form.get("current", "")):
                self._send(403, self.page_account(sess, err="Current password is wrong."))
            else:
                AUTH.pop("totp", None)
                save_auth()
                sess.pop("totp_pending", None)
                self._send(200, self.page_account(sess, msg="Two-factor authentication disabled."))
            return

        if path in ("/f2b-unban", "/f2b-wl-add", "/f2b-wl-del"):
            ip = form.get("ip", "").strip()
            if not IP_RE.match(ip):
                self._send(400, self.page_fail2ban(sess, err="Invalid IP address."))
                return
            action = {"/f2b-unban": ("unban", ip),
                      "/f2b-wl-add": ("whitelist", "add", ip),
                      "/f2b-wl-del": ("whitelist", "remove", ip)}[path]
            rc, out, errout = run_tool("jail-fail2ban", *action, timeout=60)
            if rc == 0:
                self._send(200, self.page_fail2ban(
                    sess, msg=f"fail2ban: <code>{html.escape(ip)}</code> done."))
            else:
                self._send(500, self.page_fail2ban(
                    sess, err=f"fail2ban action failed:<pre>{html.escape((errout or out)[-500:])}</pre>"))
            return

        name = form.get("username", "")
        if not USERNAME_RE.match(name):
            self._send(400, self.page_users(sess, err="Invalid username."))
            return
        safe = html.escape(name)

        if path == "/add":
            args = ["jail-user-add", name]
            if form.get("password"):
                args += ["--password", form["password"]]
            if form.get("sudo"):
                args += ["--sudo"]
            rc, out, errout = run_tool(*args)
            if rc == 0:
                match = PASSWORD_LINE_RE.search(out)
                pw = html.escape(match.group(1)) if match else "(as chosen)"
                self._send(200, self.page_users(
                    sess, msg=f"User <b>{safe}</b> created. Password (shown once): "
                              f'<code class="pw">{pw}</code>'))
            else:
                detail = html.escape((errout or out).strip()[-500:])
                self._send(500, self.page_users(
                    sess, err=f"Failed to create <b>{safe}</b>:<pre>{detail}</pre>"))
        elif path == "/sudo":
            mode = form.get("mode", "")
            if mode not in ("on", "off"):
                self._send(400, self.page_users(sess, err="Invalid sudo mode."))
                return
            rc, out, errout = run_tool("jail-user-sudo", name, mode, timeout=120)
            if rc == 0:
                self._send(200, self.page_users(
                    sess, msg=f"Sudo turned <b>{mode}</b> for <b>{safe}</b>."))
            else:
                self._send(500, self.page_users(
                    sess, err=f"Sudo change failed:<pre>{html.escape(errout[-500:])}</pre>"))
        elif path == "/passwd":
            rc, out, errout = run_tool("jail-user-passwd", name, timeout=60)
            if rc == 0:
                match = PASSWORD_LINE_RE.search(out)
                pw = html.escape(match.group(1)) if match else "(unknown)"
                self._send(200, self.page_users(
                    sess, msg=f"New password for <b>{safe}</b> (shown once): "
                              f'<code class="pw">{pw}</code>'))
            else:
                self._send(500, self.page_users(
                    sess, err=f"Password reset failed:<pre>{html.escape(errout[-500:])}</pre>"))
        elif path == "/del":
            rc, out, errout = run_tool("jail-user-del", name, "--yes", timeout=120)
            if rc == 0:
                self._send(200, self.page_users(
                    sess, msg=f"User <b>{safe}</b> and their container were deleted."))
            else:
                self._send(500, self.page_users(
                    sess, err=f"Deletion failed:<pre>{html.escape(errout[-500:])}</pre>"))
        elif path == "/limits":
            if form.get("reset"):
                args = ["--reset"]
            else:
                args = []
                cpu = form.get("cpu", "").strip()
                memory = form.get("memory", "").strip()
                disk = form.get("disk", "").strip()
                if cpu:
                    if not CPU_RE.match(cpu):
                        self._send(400, self.page_user(sess, name, err="CPU must be a whole number."))
                        return
                    args += ["--cpu", cpu]
                for label, val in (("--memory", memory), ("--disk", disk)):
                    if val:
                        if not SIZE_RE.match(val):
                            self._send(400, self.page_user(
                                sess, name, err=f"Bad size '{html.escape(val)}' (e.g. 512MiB, 2GiB)."))
                            return
                        args += [label, val]
                if not args:
                    self._send(400, self.page_user(sess, name, err="Nothing to change."))
                    return
            rc, out, errout = run_tool("jail-user-limits", name, *args, timeout=120)
            if rc == 0:
                self._send(200, self.page_user(sess, name, msg="Limits updated."))
            else:
                self._send(500, self.page_user(
                    sess, name, err=f"Limit change failed:<pre>{html.escape((errout or out)[-500:])}</pre>"))
        elif path == "/key-add":
            pubkey = form.get("pubkey", "").strip()
            if not pubkey:
                self._send(400, self.page_user(sess, name, err="No key given."))
                return
            rc, out, errout = run_tool("jail-user-key", "add", name, timeout=60,
                                       input=pubkey + "\n")
            if rc == 0:
                self._send(200, self.page_user(sess, name, msg="Key(s) added."))
            else:
                self._send(500, self.page_user(
                    sess, name, err=f"Key add failed:<pre>{html.escape((errout or out)[-500:])}</pre>"))
        elif path == "/key-del":
            index = form.get("index", "")
            if not index.isdigit():
                self._send(400, self.page_user(sess, name, err="Bad key index."))
                return
            rc, out, errout = run_tool("jail-user-key", "remove", name, index, timeout=60)
            if rc == 0:
                self._send(200, self.page_user(sess, name, msg="Key removed."))
            else:
                self._send(500, self.page_user(
                    sess, name, err=f"Key removal failed:<pre>{html.escape((errout or out)[-500:])}</pre>"))
        elif path == "/key-only":
            mode = form.get("mode", "")
            if mode not in ("on", "off"):
                self._send(400, self.page_user(sess, name, err="Invalid mode."))
                return
            rc, out, errout = run_tool("jail-user-key", "key-only", name, mode, timeout=60)
            if rc == 0:
                what = "disabled (key-only)" if mode == "on" else "re-enabled"
                self._send(200, self.page_user(sess, name, msg=f"Password auth {what}."))
            else:
                self._send(500, self.page_user(
                    sess, name, err=f"Change failed:<pre>{html.escape((errout or out)[-500:])}</pre>"))
        elif path in ("/snap-create", "/snap-del", "/snap-restore"):
            snap = form.get("snapshot", "").strip()
            if path == "/snap-create" and not snap:
                args = ["snapshot"]
            elif SNAPSHOT_RE.match(snap):
                sub = {"/snap-create": "snapshot", "/snap-del": "delete",
                       "/snap-restore": "restore"}[path]
                args = [sub, snap]
                if sub == "restore":
                    args.append("--yes")
            else:
                self._send(400, self.page_user(sess, name, err="Invalid snapshot name."))
                return
            rc, out, errout = run_tool("jail-user-backup", name, *args, timeout=300)
            if rc == 0:
                self._send(200, self.page_user(sess, name, msg="Backup operation done."))
            else:
                self._send(500, self.page_user(
                    sess, name, err=f"Backup operation failed:<pre>{html.escape((errout or out)[-500:])}</pre>"))
        elif path == "/export":
            rc, out, errout = run_tool("jail-user-backup", name, "export", timeout=600)
            if rc == 0:
                m = re.search(r"Export complete: (\S+) (\S+)", out)
                where = (f"<code>{html.escape(m.group(2))}</code> ({html.escape(m.group(1))})"
                         if m else "done")
                self._send(200, self.page_user(sess, name, msg=f"Exported to {where}."))
            else:
                self._send(500, self.page_user(
                    sess, name, err=f"Export failed:<pre>{html.escape((errout or out)[-500:])}</pre>"))
        else:
            self._send(404, render("<p>Not found.</p>", True, sess["csrf"]))


def main():
    addr = (CFG.get("bind", "0.0.0.0"), int(CFG.get("port", 8443)))
    httpd = http.server.ThreadingHTTPServer(addr, Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CFG.get("cert") or os.path.join(APP_DIR, "cert.pem"),
                        CFG.get("key") or os.path.join(APP_DIR, "key.pem"))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"ssh-jails-webui listening on https://{addr[0]}:{addr[1]}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
