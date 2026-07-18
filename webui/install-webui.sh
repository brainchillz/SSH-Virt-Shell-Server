#!/bin/bash
#
# install-webui.sh — install (or remove) the optional SSH-Virt-Shell-Server
# web interface. Deploys the app to /opt/ssh-router/webui, generates a
# self-signed TLS cert and admin credential on first install, and runs
# it as the systemd service 'ssh-jails-webui'.
#
#   ./install-webui.sh                          install / update (idempotent)
#   ./install-webui.sh --admin-password <pw>    also set the admin password
#   ./install-webui.sh --uninstall              stop and remove completely
#
# Custom TLS: set WEBUI_CERT / WEBUI_KEY in config/ssh-router.conf to
# your certificate and key paths, then re-run this script.

set -euo pipefail
REPO_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
BASE_DIR="${REPO_DIR}"
source "${REPO_DIR}/lib/common.sh"
# The installed config takes precedence over the repo template (matches
# install.sh behaviour), so WEBUI_* edits in /opt are honoured here.
# shellcheck source=/dev/null
[ -f /opt/ssh-router/config/ssh-router.conf ] && source /opt/ssh-router/config/ssh-router.conf

WEBUI_DIR="/opt/ssh-router/webui"
UNIT_FILE="/etc/systemd/system/ssh-jails-webui.service"

need_root

admin_password_arg=""
while [ $# -gt 0 ]; do
    case "$1" in
        --uninstall)
            log "Removing web UI"
            systemctl disable --now ssh-jails-webui >/dev/null 2>&1 || true
            rm -f "${UNIT_FILE}"
            systemctl daemon-reload
            rm -rf "${WEBUI_DIR}"
            log "Web UI removed (core system untouched)"
            exit 0
            ;;
        --admin-password)
            admin_password_arg="${2:?--admin-password needs a value}"; shift 2 ;;
        *)
            die "unknown option '$1' (usage: install-webui.sh [--uninstall] [--admin-password <pw>])" ;;
    esac
done
[ -n "${admin_password_arg}" ] && [ "${#admin_password_arg}" -lt 8 ] && \
    die "--admin-password must be at least 8 characters"

[ -x /opt/ssh-router/bin/jail-user-add ] || die "core system not installed - run ./install.sh first"
command -v python3 >/dev/null 2>&1 || die "python3 is required"

# --- App files ------------------------------------------------------------
log "Installing web UI to ${WEBUI_DIR}"
install -d -m 750 "${WEBUI_DIR}"
install -m 644 "${REPO_DIR}/webui/ssh-jails-webui.py" "${WEBUI_DIR}/"

# --- Runtime config -------------------------------------------------------
if [ -n "${WEBUI_CERT}" ] || [ -n "${WEBUI_KEY}" ]; then
    [ -r "${WEBUI_CERT}" ] || die "WEBUI_CERT '${WEBUI_CERT}' is not readable"
    [ -r "${WEBUI_KEY}" ]  || die "WEBUI_KEY '${WEBUI_KEY}' is not readable"
    log "Using custom TLS certificate: ${WEBUI_CERT}"
fi
python3 - "$WEBUI_BIND" "$WEBUI_PORT" "$WEBUI_CERT" "$WEBUI_KEY" > "${WEBUI_DIR}/webui.json" <<'EOF'
import json, sys
print(json.dumps({"bind": sys.argv[1], "port": int(sys.argv[2]),
                  "cert": sys.argv[3], "key": sys.argv[4]}))
EOF
chmod 640 "${WEBUI_DIR}/webui.json"

# --- Self-signed TLS pair (default; kept if already present) --------------
if [ ! -f "${WEBUI_DIR}/cert.pem" ]; then
    log "Generating self-signed TLS certificate"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -subj "/CN=ssh-jails-webui" \
        -keyout "${WEBUI_DIR}/key.pem" -out "${WEBUI_DIR}/cert.pem" 2>/dev/null
    chmod 600 "${WEBUI_DIR}/key.pem"
fi

# --- Admin credential (generated once, or set via --admin-password) -------
new_password=""
if [ -n "${admin_password_arg}" ] || [ ! -f "${WEBUI_DIR}/auth.json" ]; then
    if [ -n "${admin_password_arg}" ]; then
        admin_pw="${admin_password_arg}"
    else
        admin_pw="$(gen_password)"
        new_password="${admin_pw}"
    fi
    salt="$(openssl rand -hex 16)"
    hash="$(python3 -c 'import hashlib, sys
print(hashlib.pbkdf2_hmac("sha256", sys.argv[1].encode(), bytes.fromhex(sys.argv[2]), 600000).hex())' \
        "${admin_pw}" "${salt}")"
    cat > "${WEBUI_DIR}/auth.json" <<EOF
{"user": "admin", "salt": "${salt}", "hash": "${hash}", "iterations": 600000}
EOF
    chmod 600 "${WEBUI_DIR}/auth.json"
fi

# --- Port conflict check --------------------------------------------------
# Stop any previous instance of this service first, then whatever still
# holds the port belongs to someone else.
systemctl stop ssh-jails-webui >/dev/null 2>&1 || true
if ss -tln | grep -qE "[:.]${WEBUI_PORT}[[:space:]]"; then
    die "port ${WEBUI_PORT} is already in use by another process - set WEBUI_PORT in config/ssh-router.conf and re-run"
fi

# --- systemd service ------------------------------------------------------
cat > "${UNIT_FILE}" <<EOF
[Unit]
Description=SSH-Virt-Shell-Server web UI
After=network-online.target incus.service
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 ${WEBUI_DIR}/ssh-jails-webui.py
Restart=on-failure
RestartSec=3
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable ssh-jails-webui >/dev/null 2>&1
systemctl restart ssh-jails-webui

listening=false
for _ in $(seq 1 10); do
    if systemctl is-active ssh-jails-webui >/dev/null 2>&1 && \
       ss -tln | grep -qE "[:.]${WEBUI_PORT}[[:space:]]"; then listening=true; break; fi
    sleep 1
done
${listening} || die "web UI did not start - check: journalctl -u ssh-jails-webui"

# --- Firewall -------------------------------------------------------------
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "${WEBUI_PORT}/tcp" >/dev/null
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd -q --permanent --add-port="${WEBUI_PORT}/tcp"
    firewall-cmd -q --reload
fi

host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
log "Web UI running"
echo
echo "  URL      : https://${host_ip:-<this-host>}:${WEBUI_PORT}/"
if [ -n "${new_password}" ]; then
    echo "  Login    : admin"
    echo "  Password : ${new_password}   (shown once - store it now)"
elif [ -n "${admin_password_arg}" ]; then
    echo "  Login    : admin (password set to the one you provided)"
else
    echo "  Login    : admin (existing password unchanged)"
fi
[ -z "${WEBUI_CERT}" ] && echo "  TLS      : self-signed (browser warning is expected)"
