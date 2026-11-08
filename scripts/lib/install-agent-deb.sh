#!/bin/sh
# Installs one signed agent package on this machine; run as root by
# scripts/update-linux-agents.sh over the machine's root channel.
#
#   install-agent-deb.sh VERSION SHA256
#   install-agent-deb.sh --restore
#
# The operator checked the release signature on the package whose digest this
# gets, so the digest is the proof here. The package comes from the hub the
# agent already talks to, into the folder the detector knows as the agent's
# update download. After the install the new binary must start and stay running;
# otherwise the previous binary goes back and this exits non-zero. The previous
# binary stays in that folder so --restore can put it back when the machine
# stayed up but the hub never heard from it.
set -eu

ROOT="${OMINULL_INSTALL_ROOT:-}"
CONF="${ROOT}/etc/ominull/agent.conf"
B="${ROOT}/opt/ominull/bin/ominulld"
UPDATES="${ROOT}/var/lib/ominull/updates"
PREVIOUS="${UPDATES}/ominulld.previous"
U=ominull-agent.service
SETTLE="${OMINULL_INSTALL_SETTLE:-45}"

put_back() {
    install -m 0755 "${PREVIOUS}" "${B}"
    systemctl reset-failed "${U}" || true
    systemctl restart "${U}"
}

if [ "${1:-}" = --restore ]; then
    [ -f "${PREVIOUS}" ] || { echo "no previous agent binary here"; exit 1; }
    put_back
    echo "previous agent binary restored"
    exit 0
fi

V="$1"
SHA="$2"
conf() { sed -n "s/^$1=//p" "${CONF}" | head -n1; }

HUB="$(conf hub_url)"
CA="$(conf ca_path)"
[ -n "${HUB}" ] || { echo "no hub_url in ${CONF}"; exit 1; }
[ ! -L "${UPDATES}" ] || { echo "refusing symlinked ${UPDATES}"; exit 1; }
install -d -m 0700 "${UPDATES}"
PKG="${UPDATES}/agent.deb"
trap 'rm -f "${PKG}"' EXIT

URL="${HUB}/download/ominull-agent_${V}_amd64.deb"
if [ "$(conf pin_hub_ca)" = 1 ] && [ -n "${CA}" ]; then
    curl -fsSL --cacert "${CA}" --proto =https -m 300 -o "${PKG}" "${URL}"
else
    curl -fsSL --proto =https -m 300 -o "${PKG}" "${URL}"
fi
echo "${SHA}  ${PKG}" | sha256sum -c -

cp -p "${B}" "${PREVIOUS}"
rollback() {
    echo "v${V} $1; restoring the previous agent binary"
    put_back
    exit 1
}
dpkg -i "${PKG}" || rollback "did not install"
"${B}" --version >/dev/null 2>&1 || rollback "does not start on this machine"
systemctl restart "${U}" || rollback "did not restart"
# systemd clears the restart count on a manual restart, so count from here.
R0="$(systemctl show -p NRestarts --value "${U}" 2>/dev/null || echo 0)"
sleep "${SETTLE}"
R1="$(systemctl show -p NRestarts --value "${U}" 2>/dev/null || echo 0)"
if ! systemctl is-active --quiet "${U}" || [ "${R1}" != "${R0}" ]; then
    rollback "did not stay running"
fi
echo "v${V} is running"
