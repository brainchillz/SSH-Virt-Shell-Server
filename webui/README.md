# SSH-Virt-Shell-Server Web UI (optional addon)

A small HTTPS admin panel for provisioning jail users from a browser.
Entirely optional: the core system works identically without it, and it can
be added or removed at any time without touching the router or the jails.

It is deliberately boring: a single zero-dependency Python (stdlib-only)
process that shells out to the same `/opt/ssh-router/bin` management
scripts the CLI uses — one code path for all provisioning, no divergence.

## Install / update / remove

```sh
sudo ./install-webui.sh                          # install or update (idempotent)
sudo ./install-webui.sh --admin-password 'Pw…'   # also set the admin password
sudo ./install-webui.sh --uninstall              # remove completely (core untouched)
```

The installer refuses to start if the configured port is already held by
another process (change `WEBUI_PORT` and re-run).

Requires the core system to be installed first (`../install.sh`). The
installer prints the URL and a one-time generated `admin` password, then
runs everything as the `ssh-jails-webui` systemd service (auto-starts on
boot, auto-restarts on failure).

## What it does

- Lists users with container state, IP, sudo status and auth mode
- Adds users (generated or chosen password, shown once; optional
  "sudo in own jail" checkbox)
- Toggles per-user sudo on/off
- Resets a user's password (shown once; stored in the user's jail)
- Deletes a user + container behind an explicit confirmation page
- Per-user "Manage" page: resource-limit overrides (CPU/memory/disk),
  login keys incl. key-only mode, and backups (snapshot,
  restore behind a confirmation page, delete, export to tarball;
  `import` stays CLI-only since it takes a host-side file)
- fail2ban panel: currently banned IPs with one-click unban, and the
  never-ban whitelist

Provisioning a user launches a container, so the "Create" action takes
~30–60 seconds; the page waits for it.

## Configuration

Set in `../config/ssh-router.conf`, then re-run `install-webui.sh`:

| Variable | Default | Meaning |
|----------|---------|---------|
| `WEBUI_BIND` | `0.0.0.0` | Bind address (use `127.0.0.1` behind a reverse proxy) |
| `WEBUI_PORT` | `8443` | HTTPS port |
| `WEBUI_CERT` / `WEBUI_KEY` | *(empty)* | Custom TLS certificate/key paths |

## TLS

HTTPS is always on. By default the installer generates a self-signed
certificate (10-year, stored as `cert.pem`/`key.pem` in
`/opt/ssh-router/webui/`), so browsers show a warning until you accept it.

To use a real certificate, point `WEBUI_CERT` and `WEBUI_KEY` at your
fullchain/key files and re-run `install-webui.sh`. To go back to
self-signed, empty the two variables and re-run. (After renewing a cert at
the same paths, `systemctl restart ssh-jails-webui` is enough.)

## Security model

- Single `admin` account; password stored as PBKDF2-SHA256 (600k
  iterations) in `auth.json` (mode 600). Login is rate-limited.
- Session cookie is `HttpOnly; Secure; SameSite=Strict`, 1-hour idle expiry.
- Every mutating action carries a per-session CSRF token.
- Usernames are validated against the same pattern the scripts enforce
  before ever reaching a subprocess (invoked as argv, never via a shell).
- The service runs as root because the provisioning scripts require it.
  If exposing beyond a trusted LAN, bind to `127.0.0.1` and front it with
  a reverse proxy that adds its own auth layer.

## Admin password

- **Change from the browser**: the dashboard's "Admin password" form
  (requires the current password, min 8 chars).
- **Set from the CLI**: `sudo ./install-webui.sh --admin-password 'NewPw'`.
- **Lost it**: delete `/opt/ssh-router/webui/auth.json` and re-run
  `install-webui.sh` — a new random password is generated and printed.
