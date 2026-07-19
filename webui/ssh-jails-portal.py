#!/usr/bin/env python3
"""SSH-Virt-Shell-Server self-service portal (optional addon).

End users sign in with the SAME username + password they SSH with and can
change their own password and manage their own login keys. Unlike the admin
panel, this process runs UNPRIVILEGED: it authenticates users against their
own jail (via `sudo jail-user-auth`) and performs the two self-service
operations through a narrowly-scoped sudo rule (jail-user-passwd,
jail-user-key). Every action targets the SESSION's user, never a value from
the request, so a user can only ever touch their own account.

Runtime files (created by install-webui.sh --portal, all in this directory):
  portal.json - {"bind": ..., "port": ..., "cert": ..., "key": ...}
  cert.pem / key.pem - TLS material (shared with the admin panel by default)
"""

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

with open(os.path.join(APP_DIR, "portal.json")) as f:
    CFG = json.load(f)

USERNAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,29}$")

SESSION_TTL = 3600
SESSIONS = {}  # token -> {"exp", "csrf", "user"}
FAILS = {}     # ip -> {"count", "until"}
LOGIN_MAX = 5
LOGIN_BAN = 60


def run_priv(tool, *args, input=None, timeout=120):
    """Run a privileged helper through the narrow sudo rule."""
    proc = subprocess.run(
        ["sudo", "-n", os.path.join(BIN_DIR, tool), *args],
        capture_output=True, text=True, input=input, timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def authenticate(user, pw):
    if not USERNAME_RE.match(user) or not pw:
        return False
    rc, _, _ = run_priv("jail-user-auth", user, input=pw, timeout=25)
    return rc == 0


def user_state(user):
    """Return {'keys': [fp,...], 'keyonly': bool} for the session user."""
    d = {"keys": [], "keyonly": False}
    rc, out, _ = run_priv("jail-user-key", "list", user, timeout=60)
    if rc == 0:
        for line in out.splitlines()[1:]:
            line = line.strip()
            if line.startswith("Auth:"):
                d["keyonly"] = "key-only" in line
            elif line and not line.startswith("(no keys"):
                d["keys"].append(line)
    return d


# Same visual language as the admin panel (NexusDashboard-Modular), inlined
# to keep this a zero-dependency single file.
STYLE = """
:root{--bg:#1c1e22;--sidebar-bg:#24262b;--card-bg:#2a2d33;--border:#7a4a22;
--border-soft:#3a3d43;--text:#d6d8dc;--muted:#9aa0a8;--primary:#c1550f;
--primary-hover:#d96a1e;--green:#22c55e;--red:#ef4444;--radius:8px}
@media (prefers-color-scheme:light){:root{--bg:#f2f1ef;--sidebar-bg:#fff;
--card-bg:#fff;--border:#c98a5b;--border-soft:#ddd8d2;--text:#26221e;
--muted:#6b655e;--primary:#b34d0c;--primary-hover:#983f08;--green:#16a34a;--red:#dc2626}}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:var(--bg);color:var(--text);margin:0;min-height:100vh;display:flex}
a{color:var(--primary);text-decoration:none}
.sidebar{width:240px;background:var(--sidebar-bg);border-right:1px solid var(--border);
display:flex;flex-direction:column;flex-shrink:0;position:sticky;top:0;align-self:flex-start;height:100vh}
.sidebar-header{padding:22px 20px 16px;border-bottom:1px solid var(--border)}
.sidebar-header h1{font-size:17px;font-weight:700;margin:0;letter-spacing:.3px}
.sidebar-header .sub{font-size:12px;color:var(--muted);margin-top:3px}
.nav{list-style:none;padding:10px 0;margin:0;flex:1}
.nav a{display:flex;align-items:center;gap:10px;padding:9px 20px;color:var(--primary);
border-left:3px solid var(--primary);background:rgba(193,85,15,.12);font-size:14px}
.sidebar-footer{padding:14px 20px;border-top:1px solid var(--border-soft);
display:flex;align-items:center;justify-content:space-between;gap:8px}
.who{font-size:13px;color:var(--muted);overflow:hidden;text-overflow:ellipsis}
.content{flex:1;min-width:0;padding:26px 34px}.content .inner{max-width:56rem}
h1.page{font-size:19px;margin:0 0 4px}
h2{font-size:14px;font-weight:600;margin:26px 0 12px;text-transform:uppercase;letter-spacing:.6px}
table{border-collapse:collapse;width:100%;background:var(--card-bg);border:1px solid var(--border-soft);border-radius:var(--radius);overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--border-soft);font-size:14px}
th{background:rgba(255,255,255,.03);color:var(--muted);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.5px}
tr:last-child td{border-bottom:none}
form.inline{display:inline}
input,textarea{background:var(--bg);border:1px solid var(--border-soft);border-radius:6px;color:var(--text);padding:8px 11px;font-size:14px;font-family:inherit}
input:focus,textarea:focus{outline:none;border-color:var(--primary)}
button{display:inline-flex;align-items:center;gap:6px;padding:8px 15px;background:var(--primary);color:#fff;border:none;border-radius:6px;font-size:13px;cursor:pointer;font-family:inherit}
button:hover{background:var(--primary-hover)}
button.danger{background:transparent;color:var(--red);border:1px solid var(--red)}
button.danger:hover{background:rgba(239,68,68,.12)}
button.ghost{background:transparent;color:var(--muted);border:1px solid var(--border-soft)}
.msg{background:rgba(34,197,94,.12);border:1px solid var(--green);padding:11px 14px;border-radius:var(--radius);margin:14px 0}
.err{background:rgba(239,68,68,.12);border:1px solid var(--red);padding:11px 14px;border-radius:var(--radius);margin:14px 0}
code{background:var(--bg);border:1px solid var(--border-soft);border-radius:4px;padding:1px 5px;font-size:13px}
pre{white-space:pre-wrap;background:var(--bg);border:1px solid var(--border-soft);border-radius:6px;padding:10px;font-size:12px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:10px 0}
small{color:var(--muted)}
body.login{align-items:center;justify-content:center}
.login-box{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:30px 28px;width:330px;max-width:90vw}
.login-box h1{font-size:18px;margin:0 0 2px}.login-box .sub{font-size:12px;color:var(--muted);margin-bottom:18px}
.login-box input{width:100%;margin-bottom:10px}.login-box button{width:100%;justify-content:center;padding:10px}
"""

_HEAD = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
         '<meta name="viewport" content="width=device-width, initial-scale=1">'
         '<title>My account — SSH-Virt-Shell-Server</title><style>' + STYLE + '</style></head>')


def render(body, user="", csrf="", login=False):
    if login:
        return (_HEAD + '<body class="login">' + body + "</body></html>").encode()
    logout = ""
    if csrf:
        logout = ('<form method="post" action="/logout">'
                  f'<input type="hidden" name="csrf" value="{csrf}">'
                  '<button class="ghost">Log out</button></form>')
    sidebar = ('<aside class="sidebar"><div class="sidebar-header">'
               '<h1>SSH-Virt-Shell</h1><div class="sub">self-service</div></div>'
               '<ul class="nav"><li><a href="/">My account</a></li></ul>'
               f'<div class="sidebar-footer"><span class="who">{html.escape(user)}</span>'
               f"{logout}</div></aside>")
    return (_HEAD + "<body>" + sidebar + '<main class="content"><div class="inner">'
            + body + "</div></main></body></html>").encode()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SSHJailsPortal"

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
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == "portal":
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

    def log_message(self, fmt, *args):
        print("%s %s" % (self.address_string(), fmt % args), flush=True)

    def _client_ip(self):
        return self.client_address[0]

    # --- pages ------------------------------------------------------------
    def page_login(self, error=""):
        err = f'<div class="err">{html.escape(error)}</div>' if error else ""
        return render(f"""<div class="login-box">
<h1>My account</h1>
<div class="sub">Sign in with your SSH username &amp; password</div>
{err}
<form method="post" action="/login">
 <input type="text" name="username" placeholder="Username" autofocus autocomplete="username">
 <input type="password" name="password" placeholder="Password" autocomplete="current-password">
 <button>Sign in</button>
</form>
</div>""", login=True)

    def page_home(self, sess, msg="", err=""):
        user = sess["user"]
        safe = html.escape(user)
        csrf = f'<input type="hidden" name="csrf" value="{sess["csrf"]}">'
        st = user_state(user)
        keys_rows = ""
        for i, k in enumerate(st["keys"], 1):
            keys_rows += (f"<tr><td><code>{html.escape(k)}</code></td><td>"
                          f'<form class="inline" method="post" action="/key-del">{csrf}'
                          f'<input type="hidden" name="index" value="{i}">'
                          f'<button class="danger">Remove</button></form></td></tr>')
        if not keys_rows:
            keys_rows = '<tr><td colspan="2"><em>No keys installed.</em></td></tr>'
        if st["keyonly"]:
            keyonly = (f"<p>Password login is <b>disabled</b> (key-only). "
                       f'<form class="inline" method="post" action="/key-only">{csrf}'
                       f'<input type="hidden" name="mode" value="off">'
                       f"<button>Re-enable password login</button></form></p>")
        else:
            keyonly = (f"<p>Password login is <b>enabled</b>. "
                       f'<form class="inline" method="post" action="/key-only">{csrf}'
                       f'<input type="hidden" name="mode" value="on">'
                       f"<button>Switch to key-only</button></form>"
                       f" <small>(requires at least one key)</small></p>")
        msg_html = f'<div class="msg">{msg}</div>' if msg else ""
        err_html = f'<div class="err">{err}</div>' if err else ""
        return render(f"""<h1 class="page">{safe}</h1>{msg_html}{err_html}
<h2>Change password</h2>
<form method="post" action="/passwd">{csrf}
 <div class="row"><input type="password" name="current" placeholder="current password" required></div>
 <div class="row"><input type="password" name="new1" placeholder="new password (min 8)" required>
    <input type="password" name="new2" placeholder="repeat new password" required></div>
 <div class="row"><button>Change password</button></div>
</form>
<h2>Login keys</h2>
{keyonly}
<table><tr><th>Key</th><th></th></tr>{keys_rows}</table>
<form method="post" action="/key-add">{csrf}
 <div class="row"><textarea name="pubkey" rows="3" cols="70"
     placeholder="ssh-ed25519 AAAA... comment (one key per line)" required></textarea></div>
 <div class="row"><button>Add key(s)</button></div>
</form>""", user=user, csrf=sess["csrf"])

    # --- GET --------------------------------------------------------------
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        token, sess = self._session()
        if path == "/login":
            self._send(200, self.page_login())
        elif not sess:
            self._redirect("/login")
        elif path == "/":
            self._send(200, self.page_home(sess))
        else:
            self._redirect("/")

    # --- POST -------------------------------------------------------------
    def do_POST(self):
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
            user = form.get("username", "")
            if authenticate(user, form.get("password", "")):
                FAILS.pop(ip, None)
                tok = secrets.token_urlsafe(32)
                SESSIONS[tok] = {"exp": now + SESSION_TTL,
                                 "csrf": secrets.token_urlsafe(32), "user": user}
                self._redirect("/", cookie=(f"portal={tok}; Path=/; HttpOnly; Secure; "
                                            f"SameSite=Strict; Max-Age={SESSION_TTL}"))
            else:
                rec["count"] += 1
                if rec["count"] >= LOGIN_MAX:
                    rec["until"] = now + LOGIN_BAN
                    rec["count"] = 0
                FAILS[ip] = rec
                self._send(403, self.page_login("Invalid username or password."))
            return

        if not sess:
            self._redirect("/login")
            return
        if not secrets.compare_digest(form.get("csrf", ""), sess["csrf"]):
            self._send(403, render("<p>Invalid CSRF token. <a href='/'>Back</a></p>",
                                   user=sess["user"], csrf=sess["csrf"]))
            return

        user = sess["user"]  # ALWAYS the session user, never from the form

        if path == "/logout":
            SESSIONS.pop(token, None)
            self._redirect("/login", cookie="portal=; Path=/; Max-Age=0")
            return

        if path == "/passwd":
            cur = form.get("current", "")
            new1, new2 = form.get("new1", ""), form.get("new2", "")
            if not authenticate(user, cur):
                self._send(403, self.page_home(sess, err="Current password is wrong."))
            elif new1 != new2:
                self._send(400, self.page_home(sess, err="New passwords do not match."))
            elif len(new1) < 8:
                self._send(400, self.page_home(sess, err="New password must be at least 8 characters."))
            else:
                rc, _, e = run_priv("jail-user-passwd", user, "--password-stdin",
                                    input=new1, timeout=60)
                if rc == 0:
                    self._send(200, self.page_home(sess, msg="Password changed."))
                else:
                    self._send(500, self.page_home(
                        sess, err=f"Change failed:<pre>{html.escape(e[-400:])}</pre>"))
            return

        if path == "/key-add":
            pubkey = form.get("pubkey", "").strip()
            if not pubkey:
                self._send(400, self.page_home(sess, err="No key given."))
                return
            rc, _, e = run_priv("jail-user-key", "add", user, input=pubkey + "\n", timeout=60)
            if rc == 0:
                self._send(200, self.page_home(sess, msg="Key(s) added."))
            else:
                self._send(500, self.page_home(
                    sess, err=f"Key add failed:<pre>{html.escape(e[-400:])}</pre>"))
            return

        if path == "/key-del":
            index = form.get("index", "")
            if not index.isdigit():
                self._send(400, self.page_home(sess, err="Bad key index."))
                return
            rc, _, e = run_priv("jail-user-key", "remove", user, index, timeout=60)
            if rc == 0:
                self._send(200, self.page_home(sess, msg="Key removed."))
            else:
                self._send(500, self.page_home(
                    sess, err=f"Key removal failed:<pre>{html.escape(e[-400:])}</pre>"))
            return

        if path == "/key-only":
            mode = form.get("mode", "")
            if mode not in ("on", "off"):
                self._send(400, self.page_home(sess, err="Invalid mode."))
                return
            rc, _, e = run_priv("jail-user-key", "key-only", user, mode, timeout=60)
            if rc == 0:
                what = "disabled (key-only)" if mode == "on" else "re-enabled"
                self._send(200, self.page_home(sess, msg=f"Password login {what}."))
            else:
                self._send(500, self.page_home(
                    sess, err=f"Change failed:<pre>{html.escape(e[-400:])}</pre>"))
            return

        self._redirect("/")


def main():
    addr = (CFG.get("bind", "0.0.0.0"), int(CFG.get("port", 8444)))
    httpd = http.server.ThreadingHTTPServer(addr, Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CFG.get("cert") or os.path.join(APP_DIR, "cert.pem"),
                        CFG.get("key") or os.path.join(APP_DIR, "key.pem"))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"ssh-jails-portal listening on https://{addr[0]}:{addr[1]}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
