#!/bin/bash
#
# e2e-test.sh — end-to-end test of the SSH-Virt-Shell-Server system.
#
# Provisions two throwaway users, then exercises the whole path from the
# host's public SSH port through sshpiperd: routing, identity,
# persistence, scp/sftp, auth failures, jail-to-jail network isolation,
# the router's zero-account/zero-sshd footprint, limits, pubkeys +
# key-only, fail2ban (real client IPs, whitelist, real ban), backups incl.
# delete-then-import recovery (password survives in the jail), a simulated
# reboot (stop everything + restart the Incus daemon), and deprovisioning.
# Cleans up its users on exit. Exits non-zero if any check fails.

set -u
BASE_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
source "${BASE_DIR}/lib/common.sh"

need_root
command -v sshpass >/dev/null 2>&1 || die "sshpass is required for the e2e test"

# In NAT mode the public port listens on a specific host address, not on
# localhost - aim the tests at whatever the proxy device actually binds.
proxy_listen="$(incus config device get "${ROUTER_NAME}" ssh-inbound listen 2>/dev/null || true)"
default_host="${proxy_listen#tcp:}"; default_host="${default_host%:*}"
case "${default_host}" in ""|0.0.0.0) default_host="127.0.0.1" ;; esac
HOST="${TEST_HOST:-${default_host}}"
U1="e2etest1"; U2="e2etest2"
P1="t1-$(gen_password)"; P2="t2-$(gen_password)"
J1="${JAIL_PREFIX}${U1}"; J2="${JAIL_PREFIX}${U2}"

PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); echo "  PASS: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
expect_eq() { # expect_eq <desc> <expected> <actual>
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o ConnectTimeout=10)
PW_OPTS=(-o PreferredAuthentications=password -o PubkeyAuthentication=no)
s1() { sshpass -p "${P1}" ssh  -p "${ROUTER_SSH_PORT}" "${SSH_OPTS[@]}" "${PW_OPTS[@]}" "${U1}@${HOST}" "$@"; }
s2() { sshpass -p "${P2}" ssh  -p "${ROUTER_SSH_PORT}" "${SSH_OPTS[@]}" "${PW_OPTS[@]}" "${U2}@${HOST}" "$@"; }

F2B_TEST_IP=""
cleanup() {
    "${BASE_DIR}/bin/jail-user-del" "${U1}" --yes >/dev/null 2>&1 || true
    "${BASE_DIR}/bin/jail-user-del" "${U2}" --yes >/dev/null 2>&1 || true
    [ -n "${F2B_TEST_IP}" ] && ip addr del "${F2B_TEST_IP}/24" dev "${INCUS_NETWORK}" 2>/dev/null
    rm -rf "${WORK:-}"
}
trap cleanup EXIT
cleanup   # clear leftovers from any earlier aborted run
WORK="$(mktemp -d)"

echo "== Provisioning test users =="
"${BASE_DIR}/bin/jail-user-add" "${U1}" --password "${P1}"
"${BASE_DIR}/bin/jail-user-add" "${U2}" --password "${P2}" --sudo

echo "== Routing and identity =="
expect_eq "login as ${U1} lands in ${J1}" "${J1}" "$(s1 hostname)"
expect_eq "session runs as ${U1}"          "${U1}" "$(s1 whoami)"
expect_eq "login as ${U2} lands in ${J2}" "${J2}" "$(s2 hostname)"

echo "== Data persistence across sessions =="
token="hello-$$-${RANDOM}"
s1 "echo '${token}' > ~/persist.txt"
expect_eq "file written in one session readable in the next" "${token}" "$(s1 cat '~/persist.txt')"

echo "== File transfer =="
tmp="$(mktemp -d)"
echo "upload-${token}" > "${tmp}/up.txt"
if sshpass -p "${P1}" scp -P "${ROUTER_SSH_PORT}" "${SSH_OPTS[@]}" -q \
    "${tmp}/up.txt" "${U1}@${HOST}:/home/${U1}/up.txt"; then
    ok "scp upload"
else
    bad "scp upload"
fi
expect_eq "uploaded content correct" "upload-${token}" "$(s1 cat "/home/${U1}/up.txt")"
if printf 'get /home/%s/up.txt %s/down.txt\n' "${U1}" "${tmp}" | \
    sshpass -p "${P1}" sftp -P "${ROUTER_SSH_PORT}" "${SSH_OPTS[@]}" -q "${U1}@${HOST}" >/dev/null 2>&1 \
    && cmp -s "${tmp}/up.txt" "${tmp}/down.txt"; then
    ok "sftp download round-trip"
else
    bad "sftp download round-trip"
fi
rm -rf "${tmp}"

echo "== Authentication failures =="
if sshpass -p "wrong-password" ssh -p "${ROUTER_SSH_PORT}" "${SSH_OPTS[@]}" \
    "${U1}@${HOST}" true >/dev/null 2>&1; then
    bad "wrong password rejected"
else
    ok "wrong password rejected"
fi
if sshpass -p "whatever" ssh -p "${ROUTER_SSH_PORT}" "${SSH_OPTS[@]}" \
    "nosuchuser@${HOST}" true >/dev/null 2>&1; then
    bad "unknown user rejected"
else
    ok "unknown user rejected"
fi

echo "== Isolation between jails =="
ip2="$(jail_ip "${J2}")"
if [ -n "${ip2}" ]; then
    if s1 "timeout 3 bash -c 'echo > /dev/tcp/${ip2}/22'" >/dev/null 2>&1; then
        bad "jail1 cannot reach jail2 sshd (${ip2}:22)"
    else
        ok "jail1 cannot reach jail2 sshd (${ip2}:22)"
    fi
    if s1 "ping -c1 -W2 ${ip2}" >/dev/null 2>&1; then
        bad "jail1 cannot ping jail2"
    else
        ok "jail1 cannot ping jail2"
    fi
else
    bad "could not determine ${J2} IP for isolation test"
fi

echo "== Zero footprint on the router =="
# The session lands in the jail, so the router's key store must not exist there.
if s1 "test -e ${KEYS_DIR}" >/dev/null 2>&1; then
    bad "router key store not visible from a user session"
else
    ok "router key store not visible from a user session"
fi
# The whole point of this fork: no Unix account and no sshd on the router.
if router_exec id -u "${U1}" >/dev/null 2>&1; then
    bad "router has no Unix account for jail users"
else
    ok "router has no Unix account for jail users"
fi
if router_exec sh -c 'command -v sshd >/dev/null 2>&1 || exit 1' 2>/dev/null; then
    bad "router runs no sshd at all (sshpiperd only)"
else
    ok "router runs no sshd at all (sshpiperd only)"
fi

echo "== Sudo option =="
expect_eq "--sudo user gets passwordless root in own jail" "root" "$(s2 'sudo -n whoami' 2>/dev/null)"
if s1 "sudo -n true" >/dev/null 2>&1; then
    bad "non-sudo user cannot sudo"
else
    ok "non-sudo user cannot sudo"
fi
"${BASE_DIR}/bin/jail-user-sudo" "${U2}" off >/dev/null
if s2 "sudo -n true" >/dev/null 2>&1; then
    bad "sudo revocable via jail-user-sudo off"
else
    ok "sudo revocable via jail-user-sudo off"
fi
"${BASE_DIR}/bin/jail-user-sudo" "${U2}" on >/dev/null
expect_eq "sudo re-grantable via jail-user-sudo on" "root" "$(s2 'sudo -n whoami' 2>/dev/null)"

echo "== Port forwarding disabled =="
timeout 8 sshpass -p "${P1}" ssh -p "${ROUTER_SSH_PORT}" "${SSH_OPTS[@]}" \
    -N -R 39999:127.0.0.1:22 -o ExitOnForwardFailure=yes "${U1}@${HOST}" >/dev/null 2>&1
rc=$?
if [ ${rc} -ne 124 ] && [ ${rc} -ne 0 ]; then
    ok "remote port forwarding denied by router"
else
    bad "remote port forwarding denied by router (rc=${rc})"
fi

echo "== Per-user resource limits =="
"${BASE_DIR}/bin/jail-user-limits" "${U1}" --cpu 2 --memory 2GiB >/dev/null
expect_eq "cpu override applied"    "2"    "$(incus config get "${J1}" limits.cpu)"
expect_eq "memory override applied" "2GiB" "$(incus config get "${J1}" limits.memory)"
pool_driver="$(incus storage show "${INCUS_POOL}" | awk '/^driver:/{print $2}')"
if [ "${pool_driver}" != "dir" ]; then
    "${BASE_DIR}/bin/jail-user-limits" "${U1}" --disk 6GiB >/dev/null
    expect_eq "disk override applied" "6GiB" "$(incus config device get "${J1}" root size)"
fi
"${BASE_DIR}/bin/jail-user-limits" "${U1}" --reset >/dev/null
expect_eq "limits reset to profile defaults" "" "$(incus config get "${J1}" limits.cpu)"

echo "== Per-user public key auth =="
ssh-keygen -q -t ed25519 -N '' -f "${WORK}/ukey"
k1() { ssh -i "${WORK}/ukey" -o IdentitiesOnly=yes -o PreferredAuthentications=publickey \
        -p "${ROUTER_SSH_PORT}" "${SSH_OPTS[@]}" "${U1}@${HOST}" "$@"; }
"${BASE_DIR}/bin/jail-user-key" add "${U1}" "${WORK}/ukey.pub" >/dev/null
expect_eq "public key login lands in jail" "${J1}" "$(k1 hostname 2>/dev/null)"
"${BASE_DIR}/bin/jail-user-key" key-only "${U1}" on >/dev/null
if s1 true >/dev/null 2>&1; then
    bad "key-only blocks password login"
else
    ok "key-only blocks password login"
fi
expect_eq "key login still works in key-only mode" "${J1}" "$(k1 hostname 2>/dev/null)"
"${BASE_DIR}/bin/jail-user-key" key-only "${U1}" off >/dev/null
if s1 true >/dev/null 2>&1; then
    ok "password login re-enabled after key-only off"
else
    bad "password login re-enabled after key-only off"
fi
"${BASE_DIR}/bin/jail-user-key" remove "${U1}" all >/dev/null
if k1 true >/dev/null 2>&1; then
    bad "removed key is no longer accepted"
else
    ok "removed key is no longer accepted"
fi

echo "== fail2ban =="
if router_exec fail2ban-client status sshd >/dev/null 2>&1; then
    ok "fail2ban sshd jail is active in the router"
else
    bad "fail2ban sshd jail is active in the router"
fi
if [ "$(incus config device get "${ROUTER_NAME}" ssh-inbound nat 2>/dev/null)" = "true" ]; then
    # One deliberate failure from the host: failtoban logs the source IP
    # (the host is whitelisted in fail2ban, so nothing gets banned).
    sshpass -p "definitely-wrong" ssh -p "${ROUTER_SSH_PORT}" "${SSH_OPTS[@]}" "${PW_OPTS[@]}" \
        "${U1}@${HOST}" true >/dev/null 2>&1 || true
    sleep 1
    last_fail="$(router_exec sh -c "journalctl -u sshpiperd --no-pager -n 100 2>/dev/null | grep 'failtoban:' | tail -1")"
    case "${last_fail}" in
        ""|*"failtoban: 127.0.0.1"*) bad "sshpiperd sees real client IPs (got: ${last_fail:-nothing})" ;;
        *)                           ok  "sshpiperd sees real client IPs" ;;
    esac
else
    bad "proxy device is in NAT mode (real client IPs)"
fi
"${BASE_DIR}/bin/jail-fail2ban" whitelist add 203.0.113.99 >/dev/null
if "${BASE_DIR}/bin/jail-fail2ban" whitelist | grep -q '203\.0\.113\.99'; then
    ok "whitelist add is reflected"
else
    bad "whitelist add is reflected"
fi
"${BASE_DIR}/bin/jail-fail2ban" whitelist remove 203.0.113.99 >/dev/null
if "${BASE_DIR}/bin/jail-fail2ban" whitelist | grep -q '203\.0\.113\.99'; then
    bad "whitelist remove is reflected"
else
    ok "whitelist remove is reflected"
fi
# Real ban: hammer the router sshd directly (container IP) from a spare
# address on the bridge, so neither the host's whitelisted bridge IP nor
# any real client gets blocked.
bridge_net="$(incus network get "${INCUS_NETWORK}" ipv4.address)"   # e.g. 10.1.2.1/24
F2B_TEST_IP="${bridge_net%.*}.253"
router_ip="$(jail_ip "${ROUTER_NAME}")"
ip addr add "${F2B_TEST_IP}/24" dev "${INCUS_NETWORK}" 2>/dev/null || true
for _ in $(seq 1 6); do
    sshpass -p "wrong-password" ssh -b "${F2B_TEST_IP}" -p 22 "${SSH_OPTS[@]}" "${PW_OPTS[@]}" \
        "${U1}@${router_ip}" true >/dev/null 2>&1 || true
done
banned_now=""
for _ in $(seq 1 5); do
    banned_now="$("${BASE_DIR}/bin/jail-fail2ban" status 2>/dev/null | grep -F 'Banned IP list' || true)"
    echo "${banned_now}" | grep -qF "${F2B_TEST_IP}" && break
    sleep 2
done
if echo "${banned_now}" | grep -qF "${F2B_TEST_IP}"; then
    ok "repeated failures get the source IP banned"
else
    bad "repeated failures get the source IP banned (${banned_now:-no status})"
fi
if "${BASE_DIR}/bin/jail-fail2ban" unban "${F2B_TEST_IP}" >/dev/null 2>&1; then
    ok "banned IP can be unbanned"
else
    bad "banned IP can be unbanned"
fi
ip addr del "${F2B_TEST_IP}/24" dev "${INCUS_NETWORK}" 2>/dev/null || true
F2B_TEST_IP=""

echo "== Package update tooling =="
if "${BASE_DIR}/bin/jail-update" --check "${U1}" 2>&1 | grep -qE "up to date|update\\(s\\) pending"; then
    ok "jail-update --check reports a jail's status"
else
    bad "jail-update --check reports a jail's status"
fi
if incus exec "${J1}" -- systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then
    ok "jail ships the unattended-upgrades self-patch layer"
else
    bad "jail ships the unattended-upgrades self-patch layer"
fi

echo "== Backups: snapshot, restore, export, import =="
s1 "echo snapdata > ~/snap.txt"
"${BASE_DIR}/bin/jail-user-backup" "${U1}" snapshot e2esnap >/dev/null
s1 "rm ~/snap.txt && echo late > ~/late.txt"
"${BASE_DIR}/bin/jail-user-backup" "${U1}" restore e2esnap --yes >/dev/null
for _ in $(seq 1 10); do s1 true >/dev/null 2>&1 && break; sleep 2; done
expect_eq "snapshot restore brings data back" "snapdata" "$(s1 cat '~/snap.txt' 2>/dev/null)"
if s1 "test -e ~/late.txt" >/dev/null 2>&1; then
    bad "post-snapshot changes rolled back"
else
    ok "post-snapshot changes rolled back"
fi
"${BASE_DIR}/bin/jail-user-backup" "${U1}" delete e2esnap >/dev/null
export_file="${WORK}/${J1}-e2e.tar.gz"
"${BASE_DIR}/bin/jail-user-backup" "${U1}" export "${export_file}" >/dev/null
if [ -s "${export_file}" ]; then ok "export produced a tarball"; else bad "export produced a tarball"; fi
# Full disaster recovery: deprovision the user entirely, then import.
# The password lives in the jail, so it must survive the round-trip.
"${BASE_DIR}/bin/jail-user-del" "${U1}" --yes >/dev/null
"${BASE_DIR}/bin/jail-user-backup" "${U1}" import "${export_file}" --yes >/dev/null
if router_exec test -e "${PIPES_DIR}/${U1}.yaml" 2>/dev/null; then
    ok "import recreated the router pipe"
else
    bad "import recreated the router pipe"
fi
expect_eq "imported user logs in with the ORIGINAL password" "${J1}" "$(s1 hostname 2>/dev/null)"
expect_eq "imported jail data intact" "snapdata" "$(s1 cat '~/snap.txt' 2>/dev/null)"

echo "== Reboot simulation (stop containers, restart Incus daemon) =="
incus stop -f "${J1}" "${J2}" "${ROUTER_NAME}"
systemctl restart incus
up=false
for _ in $(seq 1 45); do
    r1="$(incus list "^${J1}\$" -c s -f csv 2>/dev/null)"
    r2="$(incus list "^${J2}\$" -c s -f csv 2>/dev/null)"
    rr="$(incus list "^${ROUTER_NAME}\$" -c s -f csv 2>/dev/null)"
    if [ "${r1}" = "RUNNING" ] && [ "${r2}" = "RUNNING" ] && [ "${rr}" = "RUNNING" ]; then
        up=true; break
    fi
    sleep 2
done
if ${up}; then ok "router and jails auto-started after daemon restart"; else bad "router and jails auto-started after daemon restart"; fi
relogin=""
for _ in $(seq 1 20); do
    relogin="$(s1 hostname 2>/dev/null)" && [ -n "${relogin}" ] && break
    sleep 3
done
expect_eq "login works again after restart" "${J1}" "${relogin}"
expect_eq "user data survived the restart" "${token}" "$(s1 cat '~/persist.txt' 2>/dev/null)"

echo "== Deprovisioning =="
"${BASE_DIR}/bin/jail-user-del" "${U2}" --yes >/dev/null
if container_exists "${J2}"; then bad "container ${J2} removed"; else ok "container ${J2} removed"; fi
if s2 true >/dev/null 2>&1; then bad "deleted user can no longer log in"; else ok "deleted user can no longer log in"; fi

echo
echo "=============================================="
echo "  RESULT: ${PASS} passed, ${FAIL} failed"
echo "=============================================="
[ ${FAIL} -eq 0 ]
