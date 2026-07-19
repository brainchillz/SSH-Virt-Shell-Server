# SSH-Virt-Shell-Server Web UI (optional addon)

Two optional HTTPS interfaces, both zero-dependency stdlib-only Python that
shell out to the same `/opt/ssh-router/bin` scripts the CLI uses (one code
path, no divergence). Entirely optional — the core system works identically
without either, and both add/remove cleanly without touching the router or
jails:

- **Admin panel** (`ssh-jails-webui`, port 8443) — provision and manage all
  users. Runs as root. Hardened: username+password login (generic error, no
  username enumeration), per-IP lockout, optional IP allowlist, opt-in TOTP
  2FA.
- **Self-service portal** (`ssh-jails-portal`, port 8444, optional
  `--with-portal`) — end users sign in with their SSH credentials to change
  their own password and manage their own login keys. Runs **unprivileged**
  (user `ssh-jails-web`) and can only ever touch the signed-in user's own
  account, via a narrow sudo rule.

## Install / update / remove

```sh
sudo ./install-webui.sh                          # admin panel: install/update (idempotent)
sudo ./install-webui.sh --with-portal            # also install the self-service portal
sudo ./install-webui.sh --admin-user 'name'      # set/rename the admin username
sudo ./install-webui.sh --admin-password 'Pw…'   # also set the admin password
sudo ./install-webui.sh --uninstall              # remove everything (core untouched)
```

Admins can also rename the account, change the password, and enable/disable
TOTP 2FA from the panel's **Account** view. The IP allowlist is set via
`WEBUI_ALLOW` in `../config/ssh-router.conf` (empty by default — the panel
stays remotely reachable).

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
- fail2ban view: currently banned IPs with one-click unban, and the
  never-ban whitelist
- Account view: rename the admin, change its password, enable/disable 2FA

## Self-service portal (`--with-portal`)

A separate, unprivileged service on port 8444 (`WEBUI_PORTAL_PORT`). End
users log in with the same username + password they SSH with (validated
against their own jail) and can:

- change their own password
- add / remove their own login public keys
- switch their account between password and key-only login

It never runs as root: it authenticates via `jail-user-auth` and performs
the two self-service operations through a sudo rule limited to exactly
`jail-user-auth`, `jail-user-passwd`, and `jail-user-key`. Every action
targets the logged-in user's own account only. The admin panel's
credentials remain unreadable to the portal.

Provisioning a user launches a container, so the "Create" action takes
~30–60 seconds; the page waits for it.

## Configuration

Set in `../config/ssh-router.conf`, then re-run `install-webui.sh`:

| Variable | Default | Meaning |
|----------|---------|---------|
| `WEBUI_BIND` | `0.0.0.0` | Bind address (use `127.0.0.1` behind a reverse proxy) |
| `WEBUI_PORT` | `8443` | Admin panel HTTPS port |
| `WEBUI_ALLOW` | *(empty)* | Admin-IP allowlist (space/comma IPs or CIDRs); empty = any |
| `WEBUI_CERT` / `WEBUI_KEY` | *(empty)* | Admin panel custom TLS cert/key paths |
| `WEBUI_PORTAL_PORT` | `8444` | Self-service portal HTTPS port |
| `WEBUI_PORTAL_CERT` / `WEBUI_PORTAL_KEY` | *(empty)* | Portal custom TLS cert/key paths |

## TLS / changing the certificates

HTTPS is always on for both interfaces, each with its own certificate.
By default the installer generates a self-signed pair (10-year) in
`/opt/ssh-router/webui/`:

- **Admin panel** → `cert.pem` / `key.pem`
- **Self-service portal** → `portal-cert.pem` / `portal-key.pem`

so browsers show a warning until you accept it.

**To use your own certificate:** set the matching pair of variables in
`../config/ssh-router.conf` and re-run the installer:

```sh
# Admin panel
WEBUI_CERT=/path/fullchain.pem   WEBUI_KEY=/path/privkey.pem
sudo ./install-webui.sh

# Self-service portal (only if you installed it)
WEBUI_PORTAL_CERT=/path/fullchain.pem   WEBUI_PORTAL_KEY=/path/privkey.pem
sudo ./install-webui.sh --with-portal
```

Both live on the same host, so one certificate whose SANs cover the
hostname works for both. To go back to self-signed, empty the variables
and re-run.

**On renewal, the two differ** because of privilege:

- The **admin panel** runs as root and reads `WEBUI_CERT`/`WEBUI_KEY`
  *directly at their paths*, so after renewing at the same paths a
  `sudo systemctl restart ssh-jails-webui` is enough.
- The **portal** runs unprivileged, so a custom cert/key is **copied**
  into `/opt/ssh-router/webui/` (readable by the portal user) at install
  time. After renewing the source files you must **re-run
  `sudo ./install-webui.sh --with-portal`** (a restart alone won't pick up
  the new file); then it restarts `ssh-jails-portal` for you.

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
