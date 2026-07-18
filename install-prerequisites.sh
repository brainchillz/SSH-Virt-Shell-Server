#!/bin/bash
#
# install-prerequisites.sh — prepare a fresh host for SSH-Virt-Shell-Server.
# Supported: Ubuntu 24.04 / 26.04, Rocky (or Alma/RHEL) 9 / 10.
#
# Everything install.sh assumes, this script provides:
#
#   * packages: incus (distro repo on Ubuntu, COPR on EL), storage tools,
#     openssh server/client, sshpass, openssl
#   * a running Incus daemon with subordinate ID ranges for isolated idmaps
#   * an initialized Incus: storage pool (btrfs -> lvm-thin -> dir, best
#     the kernel supports), NAT bridge, default profile
#   * firewall openings (ufw or firewalld) for both SSH ports
#   * the HOST's own sshd moved off ROUTER_SSH_PORT (22) to HOST_SSH_PORT
#     (2222) - incl. SELinux port labeling - so the router container can
#     own the public SSH port
#
# Idempotent: safe to re-run; on an already-prepared host it changes nothing.
#
# !!! When this script moves the host sshd, existing SSH sessions keep
# !!! working, but NEW connections must use:  ssh -p <HOST_SSH_PORT> host

set -euo pipefail
REPO_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
BASE_DIR="${REPO_DIR}"
source "${REPO_DIR}/lib/common.sh"

need_root

# --- 0. OS detection ------------------------------------------------------
. /etc/os-release
OS_FAMILY=""
case "${ID:-}-${VERSION_ID:-}" in
    ubuntu-24.04|ubuntu-26.04)
        OS_FAMILY=debian; log "Detected ${PRETTY_NAME}" ;;
    rocky-9*|rocky-10*|almalinux-9*|almalinux-10*|rhel-9*|rhel-10*)
        OS_FAMILY=el; log "Detected ${PRETTY_NAME}" ;;
    *)
        case "${ID_LIKE:-}" in
            *rhel*|*fedora*) OS_FAMILY=el ;;
            *) OS_FAMILY=debian ;;
        esac
        warn "untested OS '${PRETTY_NAME:-unknown}' - continuing as ${OS_FAMILY}-family (validated: Ubuntu 24.04/26.04, Rocky 9/10)"
        ;;
esac
EL_MAJOR="${VERSION_ID%%.*}"

# --- 1. Packages ----------------------------------------------------------
log "Installing packages"
if [ "${OS_FAMILY}" = "el" ]; then
    dnf -yq install epel-release dnf-plugins-core >/dev/null
    # Incus is not in EPEL; enable the per-release COPR (see config).
    case "${EL_MAJOR}" in
        9)  dnf -y copr enable ${COPR_EL9} >/dev/null ;;
        10) dnf -y copr enable ${COPR_EL10} >/dev/null ;;
        *)  warn "no COPR configured for EL${EL_MAJOR} - assuming incus is already installable" ;;
    esac
    dnf -yq install lvm2 openssh-server openssh-clients sshpass \
        openssl ca-certificates policycoreutils-python-utils tar
    # Weak deps would pull the COPR's own qemu (for Incus VMs, which we
    # don't use) which conflicts with the distro's qemu-kvm packages.
    dnf -yq --setopt=install_weak_deps=False install incus
else
    export DEBIAN_FRONTEND=noninteractive
    apt-get -q update
    apt-get -yq install incus btrfs-progs openssh-server openssh-client \
        sshpass openssl ca-certificates
fi

# --- 2. Incus daemon ------------------------------------------------------
systemctl enable --now incus >/dev/null 2>&1 || true
for _ in $(seq 1 30); do incus info >/dev/null 2>&1 && break; sleep 2; done
incus info >/dev/null 2>&1 || die "incus daemon did not become ready"
log "Incus daemon is up ($(incus version | awk '/^Server/{print $3}'))"

# Some EL builds (e.g. incus 6.0.x COPR on EL10) serve the daemon socket at
# /run/incus/unix.socket while the container-start hooks default to
# /var/lib/incus/unix.socket - the mismatch makes EVERY container start
# fail with an opaque "hook exited with status 1". Exporting the real path
# through the unit lets hook processes inherit it.
if [ -S /run/incus/unix.socket ] && [ ! -e /var/lib/incus/unix.socket ]; then
    log "Pinning INCUS_SOCKET=/run/incus/unix.socket for container hooks"
    install -d /etc/systemd/system/incus.service.d
    cat > /etc/systemd/system/incus.service.d/socket-path.conf <<'EOF'
# Installed by SSH-Virt-Shell-Server: container pre-start hooks must find the
# daemon socket where this packaging actually serves it.
[Service]
Environment=INCUS_SOCKET=/run/incus/unix.socket
EOF
    systemctl daemon-reload
    systemctl restart incus
    for _ in $(seq 1 15); do incus info >/dev/null 2>&1 && break; sleep 2; done
fi

# --- 3. Subordinate IDs for isolated idmaps -------------------------------
# The incus packages normally add these; guard against hosts where
# /etc/subuid exists but lacks a root entry (which would silently break
# security.idmap.isolated on the jails).
for f in /etc/subuid /etc/subgid; do
    if [ -e "${f}" ] && ! grep -q '^root:' "${f}"; then
        log "Adding root subordinate ID range to ${f}"
        echo "root:1000000:1000000000" >> "${f}"
        restart_incus=1
    fi
    # When this "host" is itself an unprivileged container (nested testing),
    # only ~1B UIDs are mapped, so the stock 1000000:1000000000 range
    # overflows the namespace and every container fails to start. Shrink it.
    if systemd-detect-virt -cq 2>/dev/null && grep -q '^root:1000000:1000000000$' "${f}"; then
        log "Nested container detected - shrinking root subordinate IDs in ${f}"
        sed -i 's/^root:1000000:1000000000$/root:1000000:900000000/' "${f}"
        restart_incus=1
    fi
done
[ "${restart_incus:-}" = 1 ] && systemctl restart incus

# --- 4. Storage pool ------------------------------------------------------
# Best driver the kernel supports, in order: the configured POOL_DRIVER
# (btrfs by default; needs kernel support - absent on RHEL-family), btrfs
# subvolume if /var/lib/incus already sits on btrfs (nested testing),
# lvm thin pool (quotas + fast clones, works everywhere), plain dir last.
try_pool() { incus storage create "${INCUS_POOL}" "$@" >/dev/null 2>&1; }
kernel_btrfs() { grep -qw btrfs /proc/filesystems || modprobe -q btrfs 2>/dev/null; }

if incus storage show "${INCUS_POOL}" >/dev/null 2>&1; then
    log "Storage pool '${INCUS_POOL}' already exists"
else
    log "Creating storage pool '${INCUS_POOL}'"
    created=""
    if [ "${POOL_DRIVER}" != "btrfs" ] || kernel_btrfs; then
        if try_pool "${POOL_DRIVER}" size="${POOL_SIZE}"; then
            created="${POOL_DRIVER} (${POOL_SIZE} loop file)"
        fi
    fi
    if [ -z "${created}" ] && kernel_btrfs && \
       [ "$(stat -f -c %T /var/lib/incus 2>/dev/null)" = "btrfs" ] && \
       btrfs subvolume create /var/lib/incus/ssh-jails-pool >/dev/null 2>&1; then
        if try_pool btrfs source=/var/lib/incus/ssh-jails-pool; then
            created="btrfs subvolume (loop devices unavailable)"
        else
            btrfs subvolume delete /var/lib/incus/ssh-jails-pool >/dev/null 2>&1 || true
        fi
    fi
    if [ -z "${created}" ] && [ "${POOL_DRIVER}" != "lvm" ] && \
       command -v lvm >/dev/null 2>&1 && try_pool lvm size="${POOL_SIZE}"; then
        created="lvm thin (${POOL_SIZE} loop file)"
    fi
    if [ -z "${created}" ]; then
        warn "falling back to 'dir' storage pool - per-jail disk quotas will be unavailable"
        incus storage create "${INCUS_POOL}" dir >/dev/null
        created="dir"
    fi
    log "Created ${created} pool"
fi

# --- 5. Bridge network ----------------------------------------------------
if incus network show "${INCUS_NETWORK}" >/dev/null 2>&1; then
    log "Network '${INCUS_NETWORK}' already exists"
else
    log "Creating network '${INCUS_NETWORK}'"
    incus network create "${INCUS_NETWORK}" \
        ipv4.address=auto ipv4.nat=true ipv6.address=none >/dev/null
fi

# --- 6. Default profile devices -------------------------------------------
incus profile device get default root path >/dev/null 2>&1 || \
    incus profile device add default root disk path=/ pool="${INCUS_POOL}" >/dev/null
incus profile device get default eth0 name >/dev/null 2>&1 || \
    incus profile device add default eth0 nic network="${INCUS_NETWORK}" name=eth0 >/dev/null

# --- 7. Firewall (opened BEFORE the sshd move so the new port is usable) --
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    log "ufw is active - allowing ports ${HOST_SSH_PORT} and ${ROUTER_SSH_PORT}"
    ufw allow "${HOST_SSH_PORT}/tcp" >/dev/null
    ufw allow "${ROUTER_SSH_PORT}/tcp" >/dev/null
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    log "firewalld is active - allowing ports ${HOST_SSH_PORT} and ${ROUTER_SSH_PORT}"
    firewall-cmd -q --permanent --add-port="${HOST_SSH_PORT}/tcp"
    firewall-cmd -q --permanent --add-port="${ROUTER_SSH_PORT}/tcp"
    # Without this the bridge lands in the default zone, which blocks the
    # containers' DHCP/DNS traffic and they never get an address.
    firewall-cmd -q --permanent --zone=trusted --add-interface="${INCUS_NETWORK}"
    firewall-cmd -q --reload
    systemctl restart incus   # re-apply incus firewall rules post-reload
fi

# --- 8. Move host sshd off the router's public port -----------------------
install -d -m 755 /run/sshd   # sshd -T refuses to run without it pre-first-start
current_ports="$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' || true)"
if echo "${current_ports}" | grep -qx "${ROUTER_SSH_PORT}"; then
    log "Host sshd occupies port ${ROUTER_SSH_PORT} - moving it to ${HOST_SSH_PORT}"
    # Port directives accumulate in sshd, so every existing one must be
    # commented out or sshd would keep listening on 22 as well.
    sed -i -E 's/^[[:space:]]*Port[[:space:]]/#&/' /etc/ssh/sshd_config
    for f in /etc/ssh/sshd_config.d/*.conf; do
        [ -e "${f}" ] || continue
        [ "${f##*/}" = "00-ssh-shell-jails-host-port.conf" ] && continue
        sed -i -E 's/^[[:space:]]*Port[[:space:]]/#&/' "${f}"
    done
    install -d -m 755 /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/00-ssh-shell-jails-host-port.conf <<EOF
# Installed by SSH-Virt-Shell-Server: the host's own sshd lives on ${HOST_SSH_PORT}
# so the jail router container can own port ${ROUTER_SSH_PORT}.
Port ${HOST_SSH_PORT}
EOF
    grep -q 'sshd_config.d' /etc/ssh/sshd_config || \
        sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
    # SELinux only allows sshd to bind ports labeled ssh_port_t.
    if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ] && \
       command -v semanage >/dev/null 2>&1; then
        log "Labeling port ${HOST_SSH_PORT} as ssh_port_t for SELinux"
        semanage port -a -t ssh_port_t -p tcp "${HOST_SSH_PORT}" 2>/dev/null || \
            semanage port -m -t ssh_port_t -p tcp "${HOST_SSH_PORT}" 2>/dev/null || true
    fi
    sshd -t
    # Ubuntu may run sshd socket-activated (a generator derives the socket's
    # port from sshd_config on daemon-reload); EL uses classic sshd.service.
    systemctl daemon-reload
    if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
        systemctl restart ssh.socket
    elif systemctl cat sshd.service >/dev/null 2>&1; then
        systemctl enable sshd >/dev/null 2>&1 || true
        systemctl restart sshd
    else
        systemctl enable ssh >/dev/null 2>&1 || true
        systemctl restart ssh
    fi
    moved=false
    for _ in $(seq 1 15); do
        if ss -tln | grep -qE "[:.]${HOST_SSH_PORT}[[:space:]]"; then moved=true; break; fi
        sleep 1
    done
    ${moved} || die "host sshd is NOT listening on ${HOST_SSH_PORT} - investigate before disconnecting!"
    warn "host sshd moved: existing sessions keep working, NEW logins need: ssh -p ${HOST_SSH_PORT} <this-host>"
else
    log "Host sshd is not on port ${ROUTER_SSH_PORT} (ports: ${current_ports:-none}) - nothing to move"
fi

log "Prerequisites complete"
echo
echo "  Host sshd port : ${HOST_SSH_PORT}"
echo "  Public SSH port: ${ROUTER_SSH_PORT} (free for the router container)"
echo "  Storage pool   : ${INCUS_POOL} ($(incus storage show "${INCUS_POOL}" | awk '/^driver:/{print $2}'))"
echo "  Network        : ${INCUS_NETWORK}"
echo
echo "  Next: ./install.sh"
