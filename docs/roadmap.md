# Web UI roadmap

Planned evolution of the optional web admin panel (`webui/`). Scoped in three
parts, sequenced by dependency and risk: harden what exists, build the new
user-facing surface on that hardened foundation, then take on the new public
surface separately.

## Status (2026-07-19)

- **Part 1 — DONE except one structural item.** Shipped and deployed:
  username + password login (constant-time, generic error, no username
  enumeration), account rename (UI + `--admin-user`), TOTP 2FA (stdlib,
  opt-in), per-IP login lockout, optional IP allowlist (`WEBUI_ALLOW`,
  empty = remotely reachable by default), and the fail2ban/Account
  separate views. Login-abuse protection is **app-level per-IP lockout**
  rather than a host fail2ban jail (the router's fail2ban can't see the
  host webui's journal; the app control is self-contained and equivalent).
  **Remaining:** make the ADMIN panel itself run non-root via a broker —
  today it's root but hardened; the broker pattern already exists (see
  Part 2) and would be applied with a separate `ssh-jails-admin` user +
  broader sudoers.
- **Part 2 — DONE.** The self-service portal ships as a separate
  UNPRIVILEGED service (`ssh-jails-portal`, user `ssh-jails-web`), install
  with `install-webui.sh --with-portal`. It authenticates users against
  their own jail (`jail-user-auth`) and self-services password + keys +
  key-only via a narrow sudo rule. Verified end-to-end + 47/47 e2e.
- **Part 3 — not started** (future scoping; see below).

## Decisions locked (do not re-litigate)

- **The admin panel stays remotely accessible.** This is typically deployed
  on a rented VPS, so the admin is not local to the box — binding it to
  localhost is wrong. Reduce its risk by *hardening* (below), not by making
  it unreachable.
- **No web-facing process runs as root.** Both panels become unprivileged
  HTTP frontends talking to a small privileged broker over a local socket;
  the broker does the `incus`/`bin/` work. A bug in the web tier then is not
  root.
- **The broker derives the target user from the authenticated session, never
  from a request parameter.** This one rule is what contains the user
  portal's blast radius.
- **Reuse the existing "user database."** There is no SQL DB; a user's
  password lives in their jail's `/etc/shadow`. The user portal authenticates
  against that (SSH username + jail password), so there is no second
  credential store.
- **Login failures return a single generic "invalid credentials"** — never
  "unknown user" vs "wrong password," and no timing/redirect difference.
  Otherwise an attacker enumerates the username and its value evaporates.
  Lockout stays global (one admin account) for the same reason.
- **State stays file-based, no database** — consistent with the rest of the
  system (pipes, keys, known_hosts are all files).
- **The CLI stays the source of truth; the web UI is always an optional thin
  wrapper.** The entire system must remain fully usable with the web
  interface uninstalled or never installed. Every web action — admin or
  self-service — maps to a `bin/` script (run as root directly, or via the
  broker for web-initiated calls); the broker is a web-frontend concern only,
  and root's direct CLI use never depends on it. In particular, Part 3 must
  ship hostname management as a `bin/` tool + a CLI-callable `regen_caddy`,
  not logic embedded in the Python — otherwise this invariant breaks.

---

## Design language (shared by both panels)

Both the admin panel and the self-service portal adopt the look of
**NexusDashboard-Modular** (github.com/brainchillz/NexusDashboard-Modular):
a dark-first homelab-dashboard aesthetic — left sidebar + card grid, warm
rust/burnt-orange accent on charcoal, rounded corners, glowing status dots.
Introduce it with the self-service portal (Part 2), then restyle the admin
panel to match (Part 1 polish).

**Hard constraint — adopt the *look*, not the *stack*.** NexusDashboard is a
Flask app with `static/` assets and vendored CSS. Our web UI stays a
**stdlib-only, single-file, zero-dependency** process. So the design is
reproduced as **inline CSS in the existing `PAGE` template** — no Flask, no
build step, no external stylesheets/fonts/vendor assets. Take the palette and
layout primitives; keep the self-contained architecture.

Palette (pin these; dark is the default, light is the `data-theme` variant):

| Token | Dark | Light |
|-------|------|-------|
| bg | `#1c1e22` | `#f2f1ef` |
| sidebar-bg | `#24262b` | `#ffffff` |
| card-bg | `#2a2d33` | `#ffffff` |
| border (accent) | `#7a4a22` | `#c98a5b` |
| border-soft | `#3a3d43` | `#ddd8d2` |
| text | `#d6d8dc` | `#26221e` |
| text-muted | `#9aa0a8` | `#6b655e` |
| primary | `#c1550f` | `#b34d0c` |
| primary-hover | `#d96a1e` | `#983f08` |
| green / yellow / red | `#22c55e` / `#eab308` / `#ef4444` | `#16a34a` / `#ca8a04` / `#dc2626` |

Layout primitives: `body` is a flex row; **240px** fixed sidebar (title +
nav + footer status dot) + flexible content (`padding: 32px 40px`,
scrollable); stat **cards** in a grid (`repeat(auto-fit, minmax(180px,
1fr))`, 16px gap) — card-bg, accent border, **8px** radius, big value +
muted label; buttons `8px 16px`, primary bg, 6px radius; inputs full-width
`8px 12px` with soft border; modals for confirmations; system font stack
(`-apple-system, Segoe UI, Roboto`).

**Role-gating comes free from this design.** NexusDashboard uses a
`body.readonly` class plus `.nav-admin-only` to hide privileged controls —
exactly the admin-vs-user split we need. One shared visual system, one
template, with elements gated by role: the admin sees everything, the
self-service user sees a restricted set. Reinforces the unified-frontend
approach.

---

## Part 1 — Harden the admin panel

Quick wins (land on the current single-file architecture, independent, low
risk — do these first):

- **Username + password login.** `auth.json` already stores a `user` field
  that the code never checks; start honoring it. Add a username input;
  replace `check_password(pw)` with `check_credentials(user, pw)` comparing
  both with `secrets.compare_digest`. Value: defeats bots that assume
  `admin`, and forces guessing two secrets — which *multiplies* with the
  rate-limit/fail2ban cap rather than adding. A username is not a real
  secret; treat it as defense-in-depth, not a control to rely on.
- **Admin can rename the account** via the dashboard form (current password
  required; change username and/or password). Add `install-webui.sh
  --admin-user`. Keep it strictly single-account — a rename, not a user
  table. Reset path unchanged: delete `auth.json` + reinstall regenerates a
  default username + random password (printed once); document that reset
  also resets the name.
- **Generic error + global lockout** (see Decisions).
- **fail2ban jail for the panel login**, reusing the router's fail2ban (the
  webui already logs failures to journald): a filter + jail, mirroring the
  SSH protection.
- **Optional IP allowlist**, config-driven, off by default (never locks out a
  dynamic-IP admin; big win for those with a static IP).
- **TOTP 2FA for the admin**, stdlib only (`hmac`/`hashlib`/`base64`), no new
  dependency — strongly recommended, optional.

Structural (the hinge into Part 2):

- **Split the admin panel into unprivileged frontend + privileged broker.**
  This is itself a hardening measure, and building it here means Part 2
  reuses an established pattern.

---

## Part 2 — End-user self-service portal

A separate, unprivileged service so the widely-used surface is never root.

- **Auth:** SSH username + jail password, verified against the jail's
  `/etc/shadow` via a small `jail-user-auth <user>` helper (the "existing
  user database").
- **Broker:** reuses Part 1's pattern; exposes ONLY self-service ops, each
  targeting the session user derived server-side — change own password,
  add/remove/list own login keys, toggle own key-only mode, view own
  status/limits.
- Same hardening posture as the admin panel (HTTPS, per-user rate-limit /
  lockout, generic errors).

Open question: **allow self-service login-key management, or restrict users
to password changes only?** Self-managing keys slightly relaxes the
"admin-managed front-door keys" model, but does not expand a user's
privilege over their *own* account (they can already reach their jail) —
provided portal auth is at least as strong as SSH auth. Recommendation:
allow it, gated behind the same hardening.

---

## Part 3 — Name-based web hosting (future scoping)

Bigger and separable — it turns jails into public web servers, a real
posture change. Keep it decoupled and opt-in, the way the web UI itself is
optional today.

- **Caddy in its own container** owning host 80/443 via an Incus proxy
  device — mirrors how `ssh-router` owns 22. Pinned + checksummed binary,
  same discipline as sshpiperd.
- **Host-header routing:** `blog.alice.example.com` → `jail-alice.incus:<port>`.
  Works because the host/proxy is non-isolated and reaches every jail, while
  `security.port_isolation` still blocks jail↔jail — one user's site can't
  reach another's.
- **Auto-HTTPS** via Caddy's native ACME — every user hostname gets a real
  cert with no extra tooling.
- **File-based mappings + `regen_caddy`** (per-user files under
  `/etc/ssh-router/vhosts/…`, generator rebuilds Caddy config and reloads via
  the admin API) — directly analogous to `regen_pipe`. The user portal
  (Part 2) writes mappings scoped to the session user.
- **Opt-in per user** — mapping a jail makes it internet-reachable on HTTP.

Open policy questions to settle before building:

- **Hostname ownership / DNS validation.** Recommend restricting users to
  subdomains of a controlled zone (`<user>.users.example.com`, auto-granted);
  allow arbitrary hostnames only with admin approval, relying on ACME failing
  if DNS doesn't point at the host as implicit proof.
- **Admin approval workflow** for hostnames, if arbitrary names are allowed.
- **Abuse / resource limits** for public-facing jails.
