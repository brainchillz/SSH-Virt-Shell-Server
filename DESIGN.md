# DESIGN — sshpiper-based router (the point of this fork)

Replace the router container's internals (OpenSSH sshd + forced
`router-shell` + per-user Unix accounts) with **sshpiperd**, a pure SSH
protocol relay: **zero user processes and zero user accounts on the
router**. Everything outside the router — jails, profiles, NAT proxy
device, limits, backups, sudo, web UI — is inherited from SSH-Shell-Jails
unchanged. Greenfield by design — no automated migration from the
parent — though a manual adoption of an existing forced-shell jail is possible
(keep the jail, copy the password hash into it, generate a new hop key
and pipe).

## Validated by live spike (2026-07-18, sshpiperd v1.5.4)

Every load-bearing assumption below was proven against a real container
before any code was written:

1. **Password passthrough**: a `to:` without `private_key` forwards the
   client's password to the jail sshd, which validates it. Wrong
   passwords are rejected. (The yaml plugin itself never checks
   passwords — a password pipe MUST NOT set `private_key`, or any
   password would be accepted.)
2. **Pubkey mode**: `from.authorized_keys` verifies the downstream key;
   `to.private_key` (our per-user hop key) re-signs upstream.
3. **Mixed mode** (password + admin keys for one user) = **two pipes for
   the same username**: one with `authorized_keys` + `private_key`, one
   with neither. Both auth methods then work.
4. **Key-only mode** = only the pubkey pipe exists. Presence of
   `authorized_keys` in a `from` automatically stops offering password.
5. **Hot reload**: the yaml plugin re-reads `--config` (glob supported)
   on every connection — config edits apply to the next login, no
   restart, no signal. Corollary: a malformed yaml blocks all new
   logins, so scripts must write configs atomically (tmp + mv).
   The plugin also enforces config-file perms (mask 0o077) across the
   WHOLE glob and rejects every login if ANY matched file is
   group/world-readable. The pipe dir is 700 root-owned, so we pass
   `--no-check-perm` (redundant check) and still write pipes 600.
6. **Upstream host-key pinning**: `to.known_hosts` is enforced (wrong
   pin → login fails). It is OPT-IN — omitting it silently disables
   verification, so every generated pipe must set it.
7. **scp and the sftp subsystem pass through** natively; no forced-shell
   `-c` tricks needed.
8. **Port forwarding passes through** to the jail, so denial is enforced
   by the jail sshd: base image sets `AllowTcpForwarding no`.
9. **failtoban plugin `--log-only`** emits WARN lines that fail2ban can
   consume. Actual observed format (differs from what the docs imply —
   the IP is inside the message, not a structured field):
   `time="..." level=warning msg="failtoban: 1.2.3.4 auth failed. current status: fail N times, max allowed 5"`
   plus `msg="failtoban: 1.2.3.4 pipe create failed, reason [...]..."`.
   A single wrong-password attempt can emit BOTH lines — set fail2ban
   maxretry with that double-count in mind, or match only `auth failed`.
10. Release bundle `sshpiperd_with_plugins_linux_x86_64.tar.gz`
    (v1.5.4, sha256
    `f03ab1a52d2856094180388727788f0dc4ef9b436c0d9348c1363bdd689b4ec7`)
    contains `sshpiperd` + `plugins/` (yaml, failtoban, …). Plugins are
    child processes resolved via PATH — install the bundle intact and
    put `plugins/` on the service PATH.

## Target architecture

```
Internet ─► host:22 (incus NAT proxy) ─► router container
                                           └─ sshpiperd :22
                                              failtoban --log-only -- yaml --config /etc/sshpiperd/pipes.d/*.yaml
                                                 │ (per-user pipe: hop key or password passthrough,
                                                 │  pinned known_hosts)
                                                 ├──► jail-alice.incus:22 (sshd: password yes, fwd no)
                                                 └──► jail-bob.incus:22
```

- **Passwords live in the jail** (`chpasswd` inside the jail at
  provision/reset time). Users can change their own with `passwd`.
  Backup import restores the password with the container — DR no longer
  needs a password reset.
- **Router state per user** (all root-owned, no Unix account):
  - `/etc/sshpiperd/pipes.d/<user>.yaml` — generated, never hand-edited
  - `/etc/ssh-router/keys/<user>` — hop private key (0400 root)
  - `/etc/ssh-router/authorized_keys/<user>` — admin-managed downstream keys
  - `/etc/ssh-router/known_hosts.d/<user>` — pinned jail host key
  - `/etc/ssh-router/key-only-users` — key-only toggle list
- **Pipe generator** (`regen_pipe <user>` in lib/common.sh) derives the
  pipe file from that state: keys file present → pubkey pipe; not
  key-only → also a password pipe. Atomic write (tmp + mv).
- **fail2ban stays** (parity: status/unban/persistent whitelist via our
  `jail-fail2ban` CLI). Jail name `sshpiperd`, `backend=systemd` on the
  sshpiperd unit, custom filter in
  `/etc/fail2ban/filter.d/sshpiperd.conf` matching the failtoban WARN
  lines above. The chained failtoban plugin runs `--log-only` (fail2ban
  does the banning; nftables banaction as in the parent).
- **Router build** (install.sh): Ubuntu container WITHOUT
  openssh-server; keeps openssh-client (ssh-keyscan for pinning).
  Download the pinned sshpiperd bundle (version + per-arch sha256 in
  config/ssh-router.conf), verify, unpack to /usr/local/lib/sshpiperd,
  generate an ed25519 host key, install a systemd unit running
  sshpiperd on :22 as container root.
- Session recording (`--screen-recording-dir`) is available as a future
  opt-in feature; not enabled by default.

## Deltas from the parent (user-visible)

- Users can change their own passwords (`passwd` in their jail).
- `MaxAuthTries`/`MaxSessions`-style sshd knobs are gone; grace time via
  `--login-grace-time`, rate control via fail2ban.
- Router host key is sshpiperd's ed25519 key (greenfield — no legacy
  host-key continuity).
- No `router-shell`, no `ssh-jail-users` group, no `/var/empty`.

## Validation status (2026-07-18)

Implemented; **e2e passes on a real Ubuntu 24.04 host (btrfs)**.
Earlier nested validation: 38/44. The
6 not passing are the `jail-user-backup import` trio + the reboot trio
that reuses the imported jail — all blocked by the nested + `dir`-pool
idmap-ACL-remap limitation of that environment, NOT a code fault. The
exact failing operation (isolated-idmap export → re-import forcing a new
base) was reproduced on a real **btrfs** pool and works
(container starts, data intact) — and subsequently the full suite
passed on a real btrfs host. EL (Rocky 9/10) validation still pending.

Nested testing earned its keep: it caught that the yaml plugin enforces
config-file perms across the whole glob and rejected every login until
`--no-check-perm` was added.

## Implementation checklist

All items landed (see git history for the conversion commit):
config pins, regen_pipe/common.sh rework, install.sh sshpiperd router,
password-auth base image, reworked bin/ scripts, sshpiperd fail2ban
jail+filter, zero-footprint e2e assertions, docs. Remaining:
- [ ] EL validation on Rocky 9/10 (VMs currently carry the parent)
