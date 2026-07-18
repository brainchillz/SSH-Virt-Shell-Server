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

import hashlib
import html
import http.server
import json
import os
import re
import secrets
import ssl
import subprocess
import time
import urllib.parse

APP_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = "/opt/ssh-router/bin"

with open(os.path.join(APP_DIR, "webui.json")) as f:
    CFG = json.load(f)
with open(os.path.join(APP_DIR, "auth.json")) as f:
    AUTH = json.load(f)

USERNAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,29}$")
PASSWORD_LINE_RE = re.compile(r"[Pp]assword\s*:\s*(\S+)")
SNAPSHOT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SIZE_RE = re.compile(r"^[0-9]+([KMGT]i?B)?$")
CPU_RE = re.compile(r"^[0-9]+$")
IP_RE = re.compile(
    r"^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$|^[0-9a-fA-F:]+(/[0-9]{1,3})?$")

SESSION_TTL = 3600
SESSIONS = {}  # token -> {"exp": epoch, "csrf": token}
LOGIN_FAILS = {"count": 0, "locked_until": 0.0}


def check_password(pw):
    digest = hashlib.pbkdf2_hmac(
        "sha256", pw.encode(), bytes.fromhex(AUTH["salt"]), AUTH["iterations"]
    )
    return secrets.compare_digest(digest.hex(), AUTH["hash"])


def set_admin_password(pw):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 600000)
    AUTH.update({"salt": salt, "hash": digest.hex(), "iterations": 600000})
    tmp = os.path.join(APP_DIR, "auth.json.tmp")
    with open(tmp, "w") as f:
        json.dump(AUTH, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, os.path.join(APP_DIR, "auth.json"))


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


PAGE = """<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSH-Virt-Shell-Server</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 46rem;
        padding: 0 1rem; color: #222; background: #fafafa; }}
 h1 {{ font-size: 1.3rem; }} h2 {{ font-size: 1.05rem; margin-top: 2rem; }}
 table {{ border-collapse: collapse; width: 100%; }}
 th, td {{ text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #ddd; }}
 th {{ background: #f0f0f0; }}
 form.inline {{ display: inline; }}
 input[type=text], input[type=password] {{ padding: .35rem; }}
 button {{ padding: .35rem .8rem; cursor: pointer; }}
 button.danger {{ color: #a00; }}
 .msg {{ background: #eef6ee; border: 1px solid #9c9; padding: .8rem; margin: 1rem 0; }}
 .err {{ background: #fdeaea; border: 1px solid #d99; padding: .8rem; margin: 1rem 0; }}
 code.pw {{ font-size: 1.1rem; background: #fff; border: 1px dashed #999; padding: .2rem .5rem; }}
 .topbar {{ display: flex; justify-content: space-between; align-items: baseline; }}
 pre {{ white-space: pre-wrap; }}
</style></head><body>
<div class="topbar"><h1>SSH-Virt-Shell-Server</h1>{topbar}</div>
{body}
</body></html>"""


def render(body, logged_in=False, csrf=""):
    # The logout form is a POST like any other mutating action, so it must
    # carry the session's CSRF token or do_POST rejects it.
    topbar = ""
    if logged_in:
        token = f'<input type="hidden" name="csrf" value="{csrf}">' if csrf else ""
        topbar = (f'<form class="inline" method="post" action="/logout">{token}'
                  "<button>Log out</button></form>")
    return PAGE.format(topbar=topbar, body=body).encode()


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

    # --- pages ------------------------------------------------------------
    def page_login(self, error=""):
        err = f'<div class="err">{html.escape(error)}</div>' if error else ""
        return render(f"""{err}
<h2>Administrator login</h2>
<form method="post" action="/login">
 <p><input type="password" name="password" placeholder="Admin password" autofocus>
 <button>Log in</button></p>
</form>""")

    def page_dashboard(self, sess, msg="", err=""):
        rows = ""
        for u in list_users():
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
        f2b_ok, banned, whitelist = f2b_info()
        if not f2b_ok:
            f2b_html = "<p><em>fail2ban is not available (re-run install.sh).</em></p>"
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
            f2b_html = f"""
<p>Banned right now: {"<ul>" + banned_html + "</ul>" if banned_html else "<em>nobody</em>"}</p>
<p>Whitelist (never banned):</p><ul>{wl_html or "<li><em>empty</em></li>"}</ul>
<form method="post" action="/f2b-wl-add">
 <input type="hidden" name="csrf" value="{sess['csrf']}">
 <p><input type="text" name="ip" placeholder="IP or CIDR, e.g. 203.0.113.5 or 10.0.0.0/8" size="34" required>
 <button>Add to whitelist</button></p>
</form>"""
        msg_html = f'<div class="msg">{msg}</div>' if msg else ""
        err_html = f'<div class="err">{err}</div>' if err else ""
        return render(f"""{msg_html}{err_html}
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
</form>
<h2>fail2ban</h2>
{f2b_html}
<h2>Admin password</h2>
<form method="post" action="/chpasswd">
 <input type="hidden" name="csrf" value="{sess['csrf']}">
 <p><input type="password" name="current" placeholder="current password" required>
    <input type="password" name="new1" placeholder="new password (min 8)" required>
    <input type="password" name="new2" placeholder="repeat new password" required>
    <button>Change</button></p>
</form>""", logged_in=True, csrf=sess["csrf"])

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
        return render(f"""{msg_html}{err_html}
<p><a href="/">&larr; All users</a></p>
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
        path = urllib.parse.urlparse(self.path).path
        token, sess = self._session()
        if path == "/login":
            self._send(200, self.page_login())
        elif not sess:
            self._redirect("/login")
        elif path == "/":
            self._send(200, self.page_dashboard(sess))
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
        path = urllib.parse.urlparse(self.path).path
        form = self._form()
        token, sess = self._session()

        if path == "/login":
            now = time.time()
            if now < LOGIN_FAILS["locked_until"]:
                self._send(429, self.page_login("Too many attempts - try again shortly."))
                return
            if check_password(form.get("password", "")):
                LOGIN_FAILS["count"] = 0
                new_token = secrets.token_urlsafe(32)
                SESSIONS[new_token] = {"exp": now + SESSION_TTL,
                                       "csrf": secrets.token_urlsafe(32)}
                cookie = (f"session={new_token}; Path=/; HttpOnly; Secure; "
                          f"SameSite=Strict; Max-Age={SESSION_TTL}")
                self._redirect("/", cookie=cookie)
            else:
                LOGIN_FAILS["count"] += 1
                if LOGIN_FAILS["count"] >= 5:
                    LOGIN_FAILS["locked_until"] = now + 60
                    LOGIN_FAILS["count"] = 0
                self._send(403, self.page_login("Wrong password."))
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

        if path == "/chpasswd":
            cur = form.get("current", "")
            new1, new2 = form.get("new1", ""), form.get("new2", "")
            if not check_password(cur):
                self._send(403, self.page_dashboard(sess, err="Current password is wrong."))
            elif new1 != new2:
                self._send(400, self.page_dashboard(sess, err="New passwords do not match."))
            elif len(new1) < 8:
                self._send(400, self.page_dashboard(
                    sess, err="New password must be at least 8 characters."))
            else:
                set_admin_password(new1)
                self._send(200, self.page_dashboard(sess, msg="Admin password changed."))
            return

        if path in ("/f2b-unban", "/f2b-wl-add", "/f2b-wl-del"):
            ip = form.get("ip", "").strip()
            if not IP_RE.match(ip):
                self._send(400, self.page_dashboard(sess, err="Invalid IP address."))
                return
            action = {"/f2b-unban": ("unban", ip),
                      "/f2b-wl-add": ("whitelist", "add", ip),
                      "/f2b-wl-del": ("whitelist", "remove", ip)}[path]
            rc, out, errout = run_tool("jail-fail2ban", *action, timeout=60)
            if rc == 0:
                self._send(200, self.page_dashboard(
                    sess, msg=f"fail2ban: <code>{html.escape(ip)}</code> done."))
            else:
                self._send(500, self.page_dashboard(
                    sess, err=f"fail2ban action failed:<pre>{html.escape((errout or out)[-500:])}</pre>"))
            return

        name = form.get("username", "")
        if not USERNAME_RE.match(name):
            self._send(400, self.page_dashboard(sess, err="Invalid username."))
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
                self._send(200, self.page_dashboard(
                    sess, msg=f"User <b>{safe}</b> created. Password (shown once): "
                              f'<code class="pw">{pw}</code>'))
            else:
                detail = html.escape((errout or out).strip()[-500:])
                self._send(500, self.page_dashboard(
                    sess, err=f"Failed to create <b>{safe}</b>:<pre>{detail}</pre>"))
        elif path == "/sudo":
            mode = form.get("mode", "")
            if mode not in ("on", "off"):
                self._send(400, self.page_dashboard(sess, err="Invalid sudo mode."))
                return
            rc, out, errout = run_tool("jail-user-sudo", name, mode, timeout=120)
            if rc == 0:
                self._send(200, self.page_dashboard(
                    sess, msg=f"Sudo turned <b>{mode}</b> for <b>{safe}</b>."))
            else:
                self._send(500, self.page_dashboard(
                    sess, err=f"Sudo change failed:<pre>{html.escape(errout[-500:])}</pre>"))
        elif path == "/passwd":
            rc, out, errout = run_tool("jail-user-passwd", name, timeout=60)
            if rc == 0:
                match = PASSWORD_LINE_RE.search(out)
                pw = html.escape(match.group(1)) if match else "(unknown)"
                self._send(200, self.page_dashboard(
                    sess, msg=f"New password for <b>{safe}</b> (shown once): "
                              f'<code class="pw">{pw}</code>'))
            else:
                self._send(500, self.page_dashboard(
                    sess, err=f"Password reset failed:<pre>{html.escape(errout[-500:])}</pre>"))
        elif path == "/del":
            rc, out, errout = run_tool("jail-user-del", name, "--yes", timeout=120)
            if rc == 0:
                self._send(200, self.page_dashboard(
                    sess, msg=f"User <b>{safe}</b> and their container were deleted."))
            else:
                self._send(500, self.page_dashboard(
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
