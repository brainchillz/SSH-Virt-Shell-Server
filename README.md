# SSH-Virt-Shell-Server

An SSH "router" built on [Incus](https://linuxcontainers.org/incus/) containers.
One bastion container accepts SSH logins from the outside world on the host's
public port 22 and transparently relays each user into their own private jail
container, keyed by username. Users never get a shell on the router, never see
each other's data, and cannot reach each other's containers over the network.

> **A fork of SSH-Shell-Jails** that replaces the router's internals
> (sshd + forced shell + per-user Unix accounts) with an
> [sshpiper](https://github.com/tg123/sshpiper)-based pure protocol
> relay: **zero user processes and zero user accounts on the router**.
> The conversion is complete; see [DESIGN.md](DESIGN.md) for the
> architecture and the spike/validation record. The two projects are
> alternatives — install one or the other on a host, never both (they
> contend for port 22, `/opt/ssh-router` and container names).

```
Internet ──► host:22 ──► ssh-router container (sshpiperd relay, no accounts)
                             │  per-user pipe + ed25519 hop key
                             ├──► jail-alice   (alice's private container)
                             ├──► jail-bob     (bob's private container)
                             └──► jail-carol   (carol's private container)
```

## How it works

- **Router container** (`ssh-router`): runs **sshpiperd**, an SSH protocol
  relay — no sshd, no login shells, and **no Unix accounts for jail
  users**. sshpiper matches the incoming username to a generated pipe and
  relays the connection into `jail-<user>.incus`. Interactive logins,
  remote commands, scp, sftp and rsync pass through natively (sshpiper
  proxies the SSH channels themselves). See [DESIGN.md](DESIGN.md).
- **Authentication**: a user's **password lives in their own jail** —
  sshpiper forwards the login password to the jail's sshd, which validates
  it, so users can change it with plain `passwd`. Admins can also install
  per-user **public keys** (`jail-user-key`) in a root-owned directory on
  the router; keys and password work together, or password auth can be
  switched off per user (key-only mode). Under the hood a key login is
  re-signed upstream with the user's **hop key** (a dedicated ed25519
  keypair; private half root-only on the router, public half the jail's
  sole `authorized_keys`). Each pipe pins the jail's SSH host key, so the
  upstream hop cannot be MITM'd.
- **Brute-force protection**: fail2ban runs inside the router and watches
  sshpiperd's journal (via the chained `failtoban` plugin in log-only
  mode); sources with repeated auth failures are banned (tunables in
  `config/ssh-router.conf`). The public-port forward runs in NAT mode so
  sshpiperd sees real client IPs. `jail-fail2ban` shows status, lifts
  bans, and manages a whitelist of never-banned addresses.
- **Jail containers**: unprivileged, cloned from a golden `jail-base` image
  (Ubuntu 24.04 + sshd + sudo; password auth on, forwarding denied). The
  `ssh-jail` profile applies:
  - `security.port_isolation=true` on the NIC — jails cannot talk to each
    other on the bridge; the router (non-isolated) can reach every jail.
  - `security.mac_filtering` / `security.ipv4_filtering` — container root
    cannot spoof MAC/IP addresses on the bridge.
  - `security.idmap.isolated=true` — each jail maps to a disjoint host UID
    range, so even a container escape lands in IDs no other jail uses.
  - CPU / memory / disk quotas (btrfs or LVM thin pool), so one user can't
    starve others.
- **Reboot persistence**: `boot.autostart=true` on the router (priority 100)
  and every jail (priority 10). Incus restarts them all on daemon/host boot;
  pipes, hop keys and jail passwords are ordinary files on container disks,
  so there is no other runtime state to restore.
- **Public port**: an Incus `proxy` device forwards host port 22 to
  sshpiperd, in NAT (DNAT) mode so the router sees real client source
  addresses. NAT mode can't bind a wildcard, so it listens on the host's
  primary address (auto-detected; override with `ROUTER_LISTEN_ADDR`).
  The host's own sshd should live on another port (e.g. 2222).

## Layout

| Path | Purpose |
|------|---------|
| `install-prerequisites.sh` | Fresh-host bootstrap: packages, Incus init (btrfs/LVM), firewall (ufw/firewalld), SELinux, move host sshd 22→2222 |
| `install.sh` | Idempotent installer: files → `/opt/ssh-router`, profile, base image, sshpiperd router |
| `DESIGN.md` | This fork's mission + the spike-validated sshpiper architecture |
| `bin/jail-user-add` | Provision a user (container, jail password, hop key, pipe; `--sudo`, `--password`) |
| `bin/jail-user-del` | Remove a user and destroy their container |
| `bin/jail-user-list` | List users, container state, IPs, sudo, keys and auth mode |
| `bin/jail-user-passwd` | Reset a user's password (stored in their jail) |
| `bin/jail-user-sudo` | Grant/revoke passwordless sudo inside a user's own jail |
| `bin/jail-user-key` | Manage a user's login keys and key-only mode |
| `bin/jail-user-limits` | Per-user CPU/memory/disk overrides on top of the profile |
| `bin/jail-user-backup` | Snapshots and portable export/import per jail |
| `bin/jail-fail2ban` | fail2ban status, unban, and the never-ban whitelist |
| `bin/jail-update` | Apply/check OS package updates across router + all jails |
| `config/ssh-router.conf` | All tunables (names, ports, limits, pinned sshpiperd version) |
| `test/e2e-test.sh` | End-to-end test: routing, isolation, zero-footprint router, keys, fail2ban (incl. a real ban), backups, simulated reboot |
| `webui/` | **Optional** web admin panel — see [webui/README.md](webui/README.md) |

The system installs to `/opt/ssh-router`; management tools are symlinked
into `/usr/local/sbin` so `jail-user-add` etc. are on root's PATH. The
installed copy of `config/ssh-router.conf` is preserved across
re-installs — it is the copy to edit — and re-running `install.sh` both
honors those edits and appends any settings introduced since (with their
defaults), so upgrades never break older configs.

## Supported hosts

- **Ubuntu 24.04 / 26.04** — incus from the distro repos, btrfs loop pool
- **Rocky (or Alma/RHEL) 9 / 10** — incus from COPR (`neil/incus` on EL9,
  `pgdev/incus` on EL10, configurable in `config/ssh-router.conf`),
  LVM thin pool (RHEL-family kernels lack btrfs), firewalld and SELinux
  handled automatically (port labels, bridge in trusted zone)

The jail/router containers are Ubuntu-based on every host — containers
bring their own userspace, so the host distro doesn't affect them.

## Usage

On a fresh host, bootstrap first — it installs Incus and friends,
initializes storage/network, opens the firewall, and **moves the host's
own sshd to port 2222** (existing sessions survive; new logins need
`-p 2222`):

```sh
sudo ./install-prerequisites.sh   # fresh host only; idempotent, safe to re-run
```

Then:

```sh
sudo ./install.sh                 # one-time setup (and after code changes)
sudo jail-user-add alice          # prints the generated password
sudo jail-user-add bob --password 'S3cret!' --sudo   # root inside his own jail
sudo jail-user-list
sudo jail-user-sudo alice on      # grant/revoke sudo later: on|off
sudo jail-user-passwd alice
sudo jail-user-del bob            # destroys bob's container and data
sudo /opt/ssh-router/test/e2e-test.sh
```

Per-user keys, limits, backups, and brute-force bans:

```sh
sudo jail-user-key add alice ~/alice.pub     # or pipe the key on stdin
sudo jail-user-key key-only alice on         # disable her password auth (off to undo)
sudo jail-user-limits alice --cpu 2 --memory 2GiB --disk 10GiB
sudo jail-user-limits alice --reset          # back to profile defaults
sudo jail-user-backup alice snapshot         # instant on-pool snapshot
sudo jail-user-backup alice restore backup-20260718-120000
sudo jail-user-backup alice export           # portable tarball in /var/lib/ssh-router/backups
sudo jail-user-backup alice import <file>    # replaces the container; also
                                             # resurrects a fully deleted user
sudo jail-fail2ban status                    # sshpiperd jail incl. banned IPs
sudo jail-fail2ban whitelist add 203.0.113.5 # never ban this address
sudo jail-fail2ban unban 198.51.100.7
sudo jail-update --check              # pending OS updates, router + every jail
sudo jail-update                      # apply them (a daily systemd timer also does this)
```

`--sudo` grants **passwordless root inside the user's own jail only** — safe
because jails are unprivileged with isolated UID maps (container root is a
meaningless unprivileged UID on the host), and the jail NIC has MAC/IPv4
spoofing filters plus port isolation, so container root gains nothing on
the network either. Worst case, users break their own container.

Then from anywhere: `ssh alice@<host>` → password prompt → shell inside
`jail-alice`.

Note: because the public port binds the host's primary address (NAT mode,
see above), `ssh alice@127.0.0.1` does not work — always connect to the
host's real address, even from the host itself.

## Security notes

- **No user ever gets a process or an account on the router.** sshpiperd
  relays the SSH protocol without invoking a shell or authenticating a
  local user, so the router's attack surface is sshpiperd's protocol
  handling plus the pinned per-user pipes — nothing user-writable.
- Password auth is exposed to the internet by design (that's the login
  UX), but fail2ban bans repeat offenders, and per user you can install
  keys and turn password auth off (`jail-user-key add` + `key-only on`).
  Login keys live in a root-owned directory on the router, so key
  management stays with the admin, never the user.
- **sshpiperd is a vendored, pinned binary** (version + per-arch sha256 in
  `config/ssh-router.conf`, verified on install), not distro-patched
  OpenSSH. Track its releases and bump deliberately — see DESIGN.md.
- **Patching is layered.** A host `ssh-jails-update` systemd timer runs
  `jail-update` on `UPDATE_SCHEDULE` (default daily), updating the router
  and every jail (all Ubuntu, so apt-only on any host); each jail also
  self-applies security updates via unattended-upgrades. Two things this
  does NOT cover: the **host kernel** every container shares (patch the
  host with its own mechanism) and **sshpiperd**, a pinned binary — bump
  `SSHPIPER_VERSION` + `SSHPIPER_SHA256_*` and re-run `install.sh`.
  Container updates flagging `/var/run/reboot-required` are reported;
  restart those containers to fully apply (it drops live sessions).
- If the NAT-mode port forward cannot be set up (install.sh warns),
  sshpiperd sees all clients as one proxy address and fail2ban is
  effectively inert — it will not ban anyone (localhost is whitelisted)
  but cannot protect you either.

## Web interface (optional)

An optional HTTPS admin panel for provisioning users from a browser lives
in [`webui/`](webui/README.md). It wraps the same `bin/` scripts, installs
with `sudo webui/install-webui.sh`, and removes cleanly with
`--uninstall` — the core system never depends on it. Besides user
provisioning it covers everything above: per-user limits, login keys and
key-only mode, snapshots/restore/export, and a fail2ban panel with
one-click unban and whitelist management.
