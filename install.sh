#!/bin/bash
#
# install.sh — deploy SSH-Virt-Shell-Server to /opt/ssh-router and build
# the container infrastructure: jail profile, golden base image, and the
# router container running sshpiperd wired to the host's public SSH port.
# Distro-agnostic: only talks to incus (see install-prerequisites.sh
# for the per-distro host preparation).
#
# Idempotent: safe to re-run. Existing config in /opt is preserved, the
# base image build is skipped if present, and the router is refreshed
# (sshpiperd binary/unit re-checked) rather than rebuilt.

set -euo pipefail
REPO_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
INSTALL_DIR="/opt/ssh-router"
BASE_DIR="${REPO_DIR}"
source "${REPO_DIR}/lib/common.sh"
# The installed config (preserved across re-installs, possibly admin-edited)
# takes precedence over the repo template, as its header promises.
# shellcheck source=/dev/null
[ -f "${INSTALL_DIR}/config/ssh-router.conf" ] && source "${INSTALL_DIR}/config/ssh-router.conf"

need_root
command -v incus >/dev/null 2>&1 || die "incus is not installed"

# --- 1. Install files to /opt --------------------------------------------
log "Installing files to ${INSTALL_DIR}"
install -d -m 755 "${INSTALL_DIR}" "${INSTALL_DIR}/config"
cp -a "${REPO_DIR}/bin" "${REPO_DIR}/lib" "${REPO_DIR}/test" "${INSTALL_DIR}/"
chmod 755 "${INSTALL_DIR}"/bin/* "${INSTALL_DIR}"/test/*
if [ -f "${INSTALL_DIR}/config/ssh-router.conf" ]; then
    log "Keeping existing ${INSTALL_DIR}/config/ssh-router.conf"
else
    cp -a "${REPO_DIR}/config/ssh-router.conf" "${INSTALL_DIR}/config/"
fi
# Migrate preserved configs from before a setting existed: installed tools
# run under 'set -u' and would die on the missing variable.
conf="${INSTALL_DIR}/config/ssh-router.conf"
add_conf() { # <var> <value> <comment>
    grep -q "^$1=" "${conf}" || {
        log "Adding new setting $1 to ${conf}"
        printf '\n# %s\n%s="%s"\n' "$3" "$1" "$2" >> "${conf}"
    }
}
add_conf KNOWN_HOSTS_DIR "${KNOWN_HOSTS_DIR}" "Per-user pinned jail host keys (referenced by generated pipes)."
add_conf PIPES_DIR "${PIPES_DIR}" "Generated sshpiper pipe definitions, one YAML per user."
add_conf SSHPIPER_VERSION "${SSHPIPER_VERSION}" "Pinned sshpiperd release (see DESIGN.md before bumping)."
add_conf SSHPIPER_SHA256_X86_64 "${SSHPIPER_SHA256_X86_64}" "sha256 of the linux_x86_64 release bundle."
add_conf SSHPIPER_SHA256_AARCH64 "${SSHPIPER_SHA256_AARCH64}" "sha256 of the linux_arm64 release bundle."
add_conf UPDATE_SCHEDULE "${UPDATE_SCHEDULE}" "systemd OnCalendar for auto container updates (empty disables)."
add_conf WEBUI_ALLOW "${WEBUI_ALLOW}" "Admin-panel IP allowlist (space/comma IPs or CIDRs; empty = any)."
add_conf WEBUI_PORTAL_PORT "${WEBUI_PORTAL_PORT}" "HTTPS port for the self-service portal (install-webui.sh --with-portal)."
add_conf WEBUI_PORTAL_CERT "${WEBUI_PORTAL_CERT}" "Custom TLS cert for the portal (empty = self-signed)."
add_conf WEBUI_PORTAL_KEY "${WEBUI_PORTAL_KEY}" "Custom TLS key for the portal (empty = self-signed)."
for tool in jail-user-add jail-user-del jail-user-list jail-user-passwd jail-user-sudo \
            jail-user-limits jail-user-key jail-user-backup jail-fail2ban jail-update \
            jail-user-auth; do
    ln -sf "${INSTALL_DIR}/bin/${tool}" "/usr/local/sbin/${tool}"
done

# --- 2. Jail profile ------------------------------------------------------
# port_isolation blocks jail<->jail traffic on the bridge (the router's
# non-isolated port can still reach every jail); isolated idmaps give each
# jail a disjoint host UID range so a container escape lands in unmapped IDs.
log "Configuring Incus profile '${JAIL_PROFILE}'"
pool_driver="$(incus storage show "${INCUS_POOL}" 2>/dev/null | awk '/^driver:/{print $2}')"
size_line="    size: ${JAIL_DISK}"
if [ "${pool_driver}" = "dir" ]; then
    warn "storage pool '${INCUS_POOL}' is 'dir' - per-jail disk quotas disabled"
    size_line=""
fi
incus profile show "${JAIL_PROFILE}" >/dev/null 2>&1 || incus profile create "${JAIL_PROFILE}"
incus profile edit "${JAIL_PROFILE}" <<EOF
description: SSH-Virt-Shell-Server user container
config:
  boot.autostart: "true"
  boot.autostart.priority: "10"
  limits.cpu: "${JAIL_CPU}"
  limits.memory: ${JAIL_MEMORY}
  security.idmap.isolated: "true"
devices:
  eth0:
    name: eth0
    network: ${INCUS_NETWORK}
    security.port_isolation: "true"
    security.mac_filtering: "true"
    security.ipv4_filtering: "true"
    type: nic
  root:
    path: /
    pool: ${INCUS_POOL}
    type: disk
${size_line}
EOF

# --- 3. Golden base image -------------------------------------------------
# Passwords are validated by the JAIL's sshd (sshpiper forwards the
# client's password), so unlike the parent project the jail accepts
# password auth. Forwarding is denied HERE because sshpiper relays
# forwarding requests to the jail instead of filtering them.
# NOTE: changing this config requires 'incus image delete jail-base' so
# the next install rebuilds the image.
if incus image info "${BASE_IMAGE_ALIAS}" >/dev/null 2>&1; then
    log "Base image '${BASE_IMAGE_ALIAS}' already present - skipping build"
else
    log "Building base image from ${SOURCE_IMAGE} (this downloads the image on first run)"
    incus launch "${SOURCE_IMAGE}" jail-base-build >/dev/null
    wait_for_container jail-base-build 120
    incus exec jail-base-build -- bash -euo pipefail -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get -q update
        apt-get -yq install openssh-server sudo unattended-upgrades
        cat > /etc/ssh/sshd_config.d/10-jail.conf <<CONF
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitRootLogin no
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
CONF
        # Second layer: each jail also applies SECURITY updates itself,
        # daily, so a jail is covered even between jail-update sweeps.
        systemctl enable unattended-upgrades >/dev/null 2>&1 || true
        systemctl disable --now ssh.socket >/dev/null 2>&1 || true
        systemctl enable ssh >/dev/null 2>&1
        apt-get clean
    '
    incus stop jail-base-build
    incus publish jail-base-build --alias "${BASE_IMAGE_ALIAS}" >/dev/null
    incus delete jail-base-build
    log "Base image published as '${BASE_IMAGE_ALIAS}'"
fi

# --- 4. Router container (sshpiperd, no sshd, no user accounts) -----------
if container_exists "${ROUTER_NAME}"; then
    log "Router '${ROUTER_NAME}' exists - refreshing sshpiperd install"
else
    log "Creating router container '${ROUTER_NAME}'"
    incus launch "${SOURCE_IMAGE}" "${ROUTER_NAME}" >/dev/null
    wait_for_container "${ROUTER_NAME}" 120
    # openssh-client only: ssh-keyscan (host-key pinning) and ssh-keygen
    # (the router's own host key). There is deliberately NO sshd here.
    incus exec "${ROUTER_NAME}" -- bash -euo pipefail -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get -q update
        apt-get -yq install openssh-client curl ca-certificates
        apt-get clean
    '
fi

router_exec install -d -m 755 /etc/ssh-router
router_exec install -d -m 700 "${KEYS_DIR}"
router_exec install -d -m 755 "${AUTH_KEYS_DIR}"
router_exec install -d -m 755 "${KNOWN_HOSTS_DIR}"
router_exec install -d -m 700 "${PIPES_DIR}"
# The yaml plugin errors if its --config glob matches nothing; an empty
# placeholder keeps sshpiperd healthy on a system with no users yet.
router_exec sh -c "[ -e '${PIPES_DIR}/00-placeholder.yaml' ] || { printf 'version: \"1.0\"\npipes: []\n' > '${PIPES_DIR}/00-placeholder.yaml'; chmod 600 '${PIPES_DIR}/00-placeholder.yaml'; }"
router_exec sh -c '[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key'

# Pinned sshpiperd release, verified against the per-arch checksum.
arch="$(router_exec uname -m)"
case "${arch}" in
    x86_64)  sp_asset="sshpiperd_with_plugins_linux_x86_64.tar.gz"; sp_sha="${SSHPIPER_SHA256_X86_64}" ;;
    aarch64) sp_asset="sshpiperd_with_plugins_linux_arm64.tar.gz";  sp_sha="${SSHPIPER_SHA256_AARCH64}" ;;
    *) die "unsupported router architecture: ${arch}" ;;
esac
have_ver="$(router_exec sh -c '/usr/local/lib/sshpiperd/sshpiperd --version 2>/dev/null | grep -oE "version [0-9.]+" | cut -d" " -f2' || true)"
if [ "${have_ver}" = "${SSHPIPER_VERSION}" ]; then
    log "sshpiperd ${SSHPIPER_VERSION} already installed"
else
    log "Installing sshpiperd ${SSHPIPER_VERSION} (${arch})"
    router_exec bash -euo pipefail -c "
        cd /tmp
        curl -fsSL -o sp.tar.gz 'https://github.com/tg123/sshpiper/releases/download/v${SSHPIPER_VERSION}/${sp_asset}'
        echo '${sp_sha}  sp.tar.gz' | sha256sum -c --quiet
        rm -rf /usr/local/lib/sshpiperd.new
        mkdir -p /usr/local/lib/sshpiperd.new
        tar xzf sp.tar.gz -C /usr/local/lib/sshpiperd.new
        rm -f sp.tar.gz
        rm -rf /usr/local/lib/sshpiperd
        mv /usr/local/lib/sshpiperd.new /usr/local/lib/sshpiperd
    "
fi

# systemd unit: failtoban runs --log-only (fail2ban does the banning,
# keeping our whitelist/unban tooling); yaml re-reads the pipes glob per
# connection. Plugins are child processes found via PATH.
router_exec sh -c "cat > /etc/systemd/system/sshpiperd.service <<EOF
# Managed by SSH-Virt-Shell-Server install.sh
[Unit]
Description=sshpiperd SSH relay
After=network-online.target
Wants=network-online.target

[Service]
Environment=PATH=/usr/local/lib/sshpiperd/plugins:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/usr/local/lib/sshpiperd/sshpiperd -i /etc/ssh/ssh_host_ed25519_key -l 0.0.0.0 -p 22 --log-format text failtoban --log-only -- yaml --no-check-perm --config '${PIPES_DIR}/*.yaml'
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF"
# The base Ubuntu image may ship an sshd; make sure only sshpiperd owns :22.
router_exec sh -c 'systemctl disable --now ssh.socket ssh sshd >/dev/null 2>&1 || true'
router_exec sh -c 'systemctl daemon-reload && systemctl enable sshpiperd >/dev/null 2>&1 && systemctl restart sshpiperd'
for _ in $(seq 1 10); do
    router_exec sh -c 'systemctl is-active sshpiperd >/dev/null 2>&1' && break
    sleep 1
done
router_exec sh -c 'systemctl is-active sshpiperd >/dev/null' || \
    die "sshpiperd did not start - check: incus exec ${ROUTER_NAME} -- journalctl -u sshpiperd"

# --- 4b. fail2ban in the router -------------------------------------------
# Bans source IPs after repeated auth failures. Needs the proxy device in
# NAT mode (step 5) to see real client IPs. The filter matches the
# failtoban plugin's --log-only WARN lines (format validated by spike,
# see DESIGN.md); note a wrong password can emit both an "auth failed"
# and a "pipe create failed" line, so bans can trigger a bit before
# maxretry distinct attempts.
if ! router_exec sh -c 'command -v fail2ban-client >/dev/null 2>&1 || exit 1'; then
    log "Installing fail2ban in the router"
    router_exec bash -euo pipefail -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get -q update
        apt-get -yq install fail2ban python3-systemd nftables
        apt-get clean
    '
fi
router_exec sh -c "cat > /etc/fail2ban/filter.d/sshpiperd.conf <<'EOF'
# Managed by SSH-Virt-Shell-Server install.sh.
# Matches sshpiperd's failtoban --log-only WARN lines, e.g.:
#   time=... level=warning msg=\"failtoban: 1.2.3.4 auth failed. current status: fail 1 times, max allowed 5\"
#   time=... level=warning msg=\"failtoban: 1.2.3.4 pipe create failed, reason [...]. current status: ...\"
[Definition]
failregex = level=warning msg=\"failtoban: <HOST> (auth failed|pipe create failed, reason \[.*\])\. current status:
journalmatch = _SYSTEMD_UNIT=sshpiperd.service
EOF"
router_exec sh -c "cat > /etc/fail2ban/jail.d/10-ssh-router.conf <<EOF
# Managed by SSH-Virt-Shell-Server install.sh; tune via
# config/ssh-router.conf (F2B_*) and re-run install.sh.
[sshpiperd]
enabled = true
backend = systemd
filter = sshpiperd
port = ${ROUTER_SSH_PORT}
banaction = nftables-multiport
bantime = ${F2B_BANTIME}
findtime = ${F2B_FINDTIME}
maxretry = ${F2B_MAXRETRY}
EOF"

# --- 5. Boot persistence and public port ----------------------------------
# boot.autostart makes Incus bring the router (first) and all jails back up
# whenever the daemon starts, i.e. after a host reboot. All other state
# (pipes, keys, jail passwords) lives on container disks and needs nothing.
incus config set "${ROUTER_NAME}" boot.autostart=true boot.autostart.priority=100

# Run the proxy in NAT (DNAT) mode so sshpiperd - and therefore fail2ban -
# sees real client source addresses instead of the userspace proxy's.
# NAT mode needs (a) the router NIC pinned to a static address and (b) a
# concrete host listen address - incus refuses a wildcard.
router_ip="$(jail_ip "${ROUTER_NAME}")"
nat_ready=false
if [ -n "${router_ip}" ]; then
    if incus config device show "${ROUTER_NAME}" | grep -q '^eth0:'; then
        incus config device set "${ROUTER_NAME}" eth0 ipv4.address "${router_ip}" 2>/dev/null && nat_ready=true
    else
        incus config device override "${ROUTER_NAME}" eth0 "ipv4.address=${router_ip}" >/dev/null 2>&1 && nat_ready=true
    fi
fi
listen_addr="${ROUTER_LISTEN_ADDR}"
if [ -z "${listen_addr}" ]; then
    listen_addr="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") print $(i+1)}' | head -1)"
fi
[ -n "${listen_addr}" ] || nat_ready=false

want_listen="tcp:${listen_addr}:${ROUTER_SSH_PORT}"
have_listen="$(incus config device get "${ROUTER_NAME}" ssh-inbound listen 2>/dev/null || true)"
have_nat="$(incus config device get "${ROUTER_NAME}" ssh-inbound nat 2>/dev/null || true)"
proxy_done=false
if [ -z "${have_listen}" ]; then
    log "Forwarding host port ${ROUTER_SSH_PORT} to the router"
elif ${nat_ready} && { [ "${have_nat}" != "true" ] || [ "${have_listen}" != "${want_listen}" ]; }; then
    log "Re-creating port ${ROUTER_SSH_PORT} forward in NAT mode on ${listen_addr} (real client IPs for fail2ban)"
    incus config device remove "${ROUTER_NAME}" ssh-inbound >/dev/null
else
    proxy_done=true   # already as wanted, or NAT impossible - leave it alone
fi
if ! ${proxy_done}; then
    if ${nat_ready} && incus config device add "${ROUTER_NAME}" ssh-inbound proxy \
        "listen=${want_listen}" connect=tcp:0.0.0.0:22 nat=true >/dev/null 2>&1; then
        log "Public SSH port: ${listen_addr}:${ROUTER_SSH_PORT} (NAT mode)"
    else
        warn "NAT-mode proxy unavailable - using userspace proxy (fail2ban will NOT see real client IPs)"
        incus config device add "${ROUTER_NAME}" ssh-inbound proxy \
            "listen=tcp:0.0.0.0:${ROUTER_SSH_PORT}" connect=tcp:127.0.0.1:22 >/dev/null
    fi
fi

# --- 5b. fail2ban whitelist baseline --------------------------------------
# Host-originated logins (admin checks, the e2e suite) reach the router
# from the bridge address (userspace proxy) or the listen address (NAT
# hairpin); banning either would lock the host out. Merge the baseline
# into the whitelist, keeping any addresses the admin added.
bridge_ip="$(incus network get "${INCUS_NETWORK}" ipv4.address 2>/dev/null | cut -d/ -f1)"
wl_file="/etc/fail2ban/jail.d/90-ssh-router-whitelist.conf"
current_wl="$(router_exec sh -c "grep -E '^ignoreip' '${wl_file}' 2>/dev/null | cut -d= -f2-" || true)"
merged_wl="${current_wl}"
for want in "127.0.0.1/8" "::1" ${bridge_ip:+"${bridge_ip}"} ${listen_addr:+"${listen_addr}"}; do
    case " ${merged_wl} " in *" ${want} "*) ;; *) merged_wl="${merged_wl} ${want}" ;; esac
done
merged_wl="$(echo "${merged_wl}" | xargs)"
router_exec sh -c "cat > '${wl_file}' <<EOF
# Managed by jail-fail2ban - do not edit (use: jail-fail2ban whitelist ...)
[sshpiperd]
ignoreip = ${merged_wl}
EOF"
router_exec sh -c 'systemctl enable fail2ban >/dev/null 2>&1; systemctl restart fail2ban'

# --- 6. Automatic container updates (host-side timer) ---------------------
# Primary layer: a host systemd timer runs jail-update across the router
# and every jail on UPDATE_SCHEDULE. (Each jail also self-patches security
# updates via unattended-upgrades - see the base image - so a jail is
# covered even between sweeps.) An empty schedule disables the timer.
if [ -n "${UPDATE_SCHEDULE}" ]; then
    log "Enabling automatic container updates (${UPDATE_SCHEDULE})"
    cat > /etc/systemd/system/ssh-jails-update.service <<EOF
# Managed by SSH-Virt-Shell-Server install.sh
[Unit]
Description=Update router and all jail container packages
After=incus.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/jail-update
EOF
    cat > /etc/systemd/system/ssh-jails-update.timer <<EOF
# Managed by SSH-Virt-Shell-Server install.sh (schedule: config UPDATE_SCHEDULE)
[Unit]
Description=Scheduled container package updates

[Timer]
OnCalendar=${UPDATE_SCHEDULE}
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now ssh-jails-update.timer >/dev/null 2>&1
else
    log "UPDATE_SCHEDULE empty - disabling automatic container updates"
    systemctl disable --now ssh-jails-update.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/ssh-jails-update.{service,timer}
    systemctl daemon-reload
fi

log "Install complete"
echo
echo "  Add a user : jail-user-add <name>"
echo "  Test       : ${INSTALL_DIR}/test/e2e-test.sh"
