# shellcheck shell=bash
# Shared helpers for SSH-Virt-Shell-Server scripts.
# Callers must set BASE_DIR (repo or /opt/ssh-router root) before sourcing.

CONF="${SSH_ROUTER_CONF:-${BASE_DIR}/config/ssh-router.conf}"
[ -r "${CONF}" ] || { echo "ssh-router: config not found: ${CONF}" >&2; exit 1; }
# shellcheck source=/dev/null
source "${CONF}"

log()  { echo "[ssh-router] $*"; }
warn() { echo "[ssh-router] WARNING: $*" >&2; }
die()  { echo "[ssh-router] ERROR: $*" >&2; exit 1; }

need_root() { [ "$(id -u)" -eq 0 ] || die "this command must be run as root"; }

# Usernames become Linux users in the jail and are embedded in container
# names and generated pipe files, so keep them conservative.
validate_username() {
    [[ "$1" =~ ^[a-z][a-z0-9-]{1,29}$ ]] || \
        die "invalid username '$1' (lowercase letter first, then a-z 0-9 -, 2-30 chars)"
    case "$1" in
        root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|\
        backup|list|irc|nobody|systemd-network|sshd|messagebus|ubuntu|admin)
            die "username '$1' is reserved" ;;
    esac
}

container_exists() { incus info "$1" >/dev/null 2>&1; }

router_exec() { incus exec "${ROUTER_NAME}" -- "$@"; }

# A user "exists" when their pipe file does: the router has no Unix
# accounts, so the generated sshpiper pipe is the source of truth.
user_exists() { router_exec test -e "${PIPES_DIR}/$1.yaml" 2>/dev/null; }

# Wait until a container's init is up and it has a default route.
wait_for_container() {
    local c="$1" tries="${2:-60}" i
    for ((i = 0; i < tries; i++)); do
        if incus exec "$c" -- sh -c \
            'test -e /run/systemd/system && ip -4 route show default 2>/dev/null | grep -q via' \
            >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    die "container '$c' did not become ready within ${tries}s"
}

jail_ip() { incus list "^$1\$" -c 4 -f csv | awk '{print $1}'; }

gen_password() { openssl rand -hex 8; }

# IPv4/IPv6 address, optionally with a /prefix (fail2ban ignoreip format).
validate_ip_or_cidr() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ || "$1" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]] || \
        die "invalid IP address or CIDR: '$1'"
}

# Snapshot names end up in incus commands and file paths.
validate_snapshot_name() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || \
        die "invalid snapshot name '$1' (alnum first, then alnum . _ -, max 64 chars)"
}

# --- provisioning building blocks -----------------------------------------

# Generate a fresh hop keypair: private half onto the router (root-only;
# sshpiperd signs upstream with it), public half as the jail user's sole
# authorized key.
install_hop_key() { # <user> <jail>
    local user="$1" jail="$2" tmp
    tmp="$(mktemp -d)"
    ssh-keygen -q -t ed25519 -N '' -C "ssh-router:${user}" -f "${tmp}/id"
    incus exec "${jail}" -- install -d -m 700 -o "${user}" -g "${user}" "/home/${user}/.ssh"
    incus file push -q "${tmp}/id.pub" "${jail}/home/${user}/.ssh/authorized_keys"
    incus exec "${jail}" -- sh -c \
        "chown ${user}:${user} /home/${user}/.ssh/authorized_keys && chmod 600 /home/${user}/.ssh/authorized_keys"
    incus file push -q --mode 400 --uid 0 --gid 0 "${tmp}/id" "${ROUTER_NAME}${KEYS_DIR}/${user}"
    rm -rf "${tmp}"
}

# Pin the jail's SSH host key: sshpiper only verifies the upstream when a
# pipe carries known_hosts, so every user gets a pinned file the pipe
# references. Retries because a fresh jail's sshd may still be starting.
pin_jail_hostkey() { # <user> <jail>
    local user="$1" jail="$2"
    for _ in $(seq 1 15); do
        if router_exec sh -c \
            "out=\$(ssh-keyscan -T 3 ${jail}.incus 2>/dev/null); [ -n \"\$out\" ] && printf '%s\n' \"\$out\" > '${KNOWN_HOSTS_DIR}/.${user}.tmp' && mv '${KNOWN_HOSTS_DIR}/.${user}.tmp' '${KNOWN_HOSTS_DIR}/${user}'"; then
            return 0
        fi
        sleep 2
    done
    die "could not record SSH host key for ${jail} - is its sshd running?"
}

# Regenerate a user's sshpiper pipe file from router-side state:
#   - authorized_keys file present -> pubkey pipe (hop key upstream)
#   - user not in key-only list    -> password pipe (passthrough; the
#     jail's sshd validates it - such a pipe must NOT carry a
#     private_key, or any password would be accepted)
# Written atomically (tmp name doesn't match the *.yaml glob) because the
# yaml plugin re-reads the glob on every connection - changes are live
# immediately, and a malformed file would block all new logins.
regen_pipe() { # <user>
    local user="$1" jail="${JAIL_PREFIX}$1"
    router_exec sh -c "
        set -e
        has_keys=false; [ -s '${AUTH_KEYS_DIR}/${user}' ] && has_keys=true
        keyonly=false; grep -qx '${user}' /etc/ssh-router/key-only-users 2>/dev/null && keyonly=true
        if [ \"\${has_keys}\" = false ] && [ \"\${keyonly}\" = true ]; then
            echo 'refusing to write a pipe with no auth methods (key-only without keys)' >&2
            exit 1
        fi
        tmp='${PIPES_DIR}/.${user}.tmp'
        {
            echo 'version: \"1.0\"'
            echo 'pipes:'
            if [ \"\${has_keys}\" = true ]; then
                echo '- from:'
                echo '    - username: \"${user}\"'
                echo '      authorized_keys: [\"${AUTH_KEYS_DIR}/${user}\"]'
                echo '  to:'
                echo '    host: \"${jail}.incus:22\"'
                echo '    username: \"${user}\"'
                echo '    private_key: \"${KEYS_DIR}/${user}\"'
                echo '    known_hosts: [\"${KNOWN_HOSTS_DIR}/${user}\"]'
            fi
            if [ \"\${keyonly}\" = false ]; then
                echo '- from:'
                echo '    - username: \"${user}\"'
                echo '  to:'
                echo '    host: \"${jail}.incus:22\"'
                echo '    username: \"${user}\"'
                echo '    known_hosts: [\"${KNOWN_HOSTS_DIR}/${user}\"]'
            fi
        } > \"\${tmp}\"
        chmod 600 \"\${tmp}\"
        mv \"\${tmp}\" '${PIPES_DIR}/${user}.yaml'
    "
}