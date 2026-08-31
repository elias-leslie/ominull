#!/usr/bin/env bash
# Exercise retained package ownership without touching the host package database.
# The Debian flow runs as uid 0 inside an unshared user/network namespace; the
# MSI flow is checked by extraction and table inspection on Linux.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
VERSION="${OMINULL_RELEASE_VERSION:-$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")}"
AGENT_DEB="${DIST_DIR}/ominull-agent_${VERSION}_amd64.deb"
HUB_DEB="${DIST_DIR}/ominull-hub_${VERSION}_amd64.deb"
MSI="${DIST_DIR}/ominull-agent-windows-${VERSION}.msi"

for file in "${AGENT_DEB}" "${HUB_DEB}" "${MSI}"; do
    [ -f "${file}" ] || { echo "[-] Missing $(basename "${file}"). Build the release first." >&2; exit 1; }
done
command -v bwrap >/dev/null || { echo "[-] bwrap is required for rootless package lifecycle tests." >&2; exit 1; }
command -v dpkg-deb >/dev/null || { echo "[-] dpkg-deb is required." >&2; exit 1; }
command -v msiextract >/dev/null || { echo "[-] msiextract is required." >&2; exit 1; }
command -v msiinfo >/dev/null || { echo "[-] msiinfo is required." >&2; exit 1; }

for deb in "${AGENT_DEB}" "${HUB_DEB}"; do
	package="$(dpkg-deb -f "${deb}" Package)"
	version="$(dpkg-deb -f "${deb}" Version)"
	arch="$(dpkg-deb -f "${deb}" Architecture)"
    [ "${arch}" = amd64 ] || { echo "[-] ${deb} has architecture ${arch}." >&2; exit 1; }
    case "${deb}" in
        *ominull-agent_*) [ "${package}" = ominull-agent ] || exit 1 ;;
        *ominull-hub_*) [ "${package}" = ominull-hub ] || exit 1 ;;
    esac
    [ "${version}" = "${VERSION}" ] || { echo "[-] ${deb} is version ${version}, expected ${VERSION}." >&2; exit 1; }
done

MSI_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ominull-msi-check.XXXXXX")"
DEB_WORK="$(mktemp -d "${TMPDIR:-/tmp}/ominull-deb-check.XXXXXX")"
SANDBOX_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ominull-dpkg-check.XXXXXX")"
trap 'rm -rf "${MSI_ROOT}" "${DEB_WORK}" "${SANDBOX_ROOT}"' EXIT

msiextract --directory "${MSI_ROOT}" "${MSI}" >/dev/null
[ -f "${MSI_ROOT}/Ominull/ominulld.exe" ] || {
    echo "[-] MSI has no package-owned agent executable." >&2
    exit 1
}
[ -f "${MSI_ROOT}/Ominull/ominull_wfp_user.exe" ] || {
    echo "[-] MSI has no standalone WFP recovery executable." >&2
    exit 1
}
if find "${MSI_ROOT}" -type f \( -iname '*.sys' -o -iname '*driver*' \) -print -quit | grep -q .; then
    echo "[-] MSI contains a retired kernel-driver payload." >&2
    exit 1
fi
msi_tables="${MSI_ROOT}/tables"
mkdir -p "${msi_tables}"
msiinfo export "${MSI}" ServiceInstall > "${msi_tables}/ServiceInstall.idt"
msiinfo export "${MSI}" ServiceControl > "${msi_tables}/ServiceControl.idt"
msiinfo export "${MSI}" CustomAction > "${msi_tables}/CustomAction.idt"
msiinfo export "${MSI}" InstallExecuteSequence > "${msi_tables}/InstallExecuteSequence.idt"
msiinfo export "${MSI}" Registry > "${msi_tables}/Registry.idt"
grep -q 'ominulld' "${msi_tables}/ServiceInstall.idt"
grep -q 'ominulld' "${msi_tables}/ServiceControl.idt"
if grep -q $'ominulld\t163\t' "${msi_tables}/ServiceControl.idt"; then
    echo "[-] MSI starts an unconfigured service during clean install." >&2
    exit 1
fi
grep -q 'OminullAgent' "${msi_tables}/Registry.idt"
grep -q 'DisplayName' "${msi_tables}/Registry.idt"
grep -q 'DisplayVersion' "${msi_tables}/Registry.idt"
grep -q 'uninstall' "${msi_tables}/CustomAction.idt"
grep -q 'NOT REINSTALL' "${msi_tables}/InstallExecuteSequence.idt"
echo "[+] MSI ${VERSION}: files, service registration, recovery action, and no driver payload verified."

make_versioned_deb() {
    local source="$1" version="$2" output="$3" tree
    tree="${DEB_WORK}/$(basename "${output}").root"
    mkdir -p "${tree}"
    dpkg-deb --raw-extract "${source}" "${tree}"
    sed -i "s/^Version: .*/Version: ${version}/" "${tree}/DEBIAN/control"
    sed -i "s/@VERSION@/${version}/g" "${tree}/DEBIAN/preinst"
    dpkg-deb --build --root-owner-group "${tree}" "${output}" >/dev/null
}

mkdir -p "${SANDBOX_ROOT}"/{etc/dpkg,var/lib/dpkg,var/log,opt,run,tmp,lib/systemd/system,lib/x86_64-linux-gnu,lib64,bin,sbin,usr/bin,usr/sbin,usr/lib,usr/lib64,usr/share/doc,usr/share/dpkg,release}
mkdir -p "${SANDBOX_ROOT}/etc/alternatives"
for file in passwd group nsswitch.conf ld.so.cache debian_version os-release; do
    cp -a "/etc/${file}" "${SANDBOX_ROOT}/etc/${file}"
done
cp -a /etc/dpkg/. "${SANDBOX_ROOT}/etc/dpkg/"
# Several host administrative commands are alternatives symlinks. Copy only
# the alternatives directory into the disposable root; no host state is bound
# writable.
cp -a /etc/alternatives/. "${SANDBOX_ROOT}/etc/alternatives/"
cp "${AGENT_DEB}" "${SANDBOX_ROOT}/release/base-agent.deb"
cp "${HUB_DEB}" "${SANDBOX_ROOT}/release/base-hub.deb"
make_versioned_deb "${AGENT_DEB}" "${VERSION}.1" "${DEB_WORK}/next-agent.deb"
make_versioned_deb "${HUB_DEB}" "${VERSION}.1" "${DEB_WORK}/next-hub.deb"
cp "${DEB_WORK}/next-agent.deb" "${SANDBOX_ROOT}/release/next-agent.deb"
cp "${DEB_WORK}/next-hub.deb" "${SANDBOX_ROOT}/release/next-hub.deb"

SANDBOX=(
    bwrap --unshare-user --unshare-net --uid 0 --gid 0
    --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    --bind "${SANDBOX_ROOT}" /
    --ro-bind /usr/bin /usr/bin --ro-bind /usr/sbin /usr/sbin
    --ro-bind /usr/lib /usr/lib --ro-bind /usr/lib64 /usr/lib64
    --ro-bind /usr/share/dpkg /usr/share/dpkg
    --ro-bind /usr/bin /bin --ro-bind /usr/sbin /sbin
    --ro-bind /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu
    --ro-bind /usr/lib64 /lib64
    --proc /proc --dev /dev
)
sandbox() { "${SANDBOX[@]}" "$@"; }

sandbox /usr/bin/dpkg --force-depends -i /release/base-agent.deb >/dev/null
sandbox /usr/bin/dpkg --force-depends -i /release/base-hub.deb >/dev/null
[ "$(sandbox /usr/bin/dpkg-query -W -f='${Status}' ominull-agent)" = 'install ok installed' ]
[ "$(sandbox /usr/bin/dpkg-query -W -f='${Status}' ominull-hub)" = 'install ok installed' ]
[ "$(sandbox /usr/bin/dpkg-query -S /opt/ominull/bin/ominulld)" = 'ominull-agent: /opt/ominull/bin/ominulld' ]
printf '%s\n' 'hub_url=https://example.invalid' 'endpoint_id=lifecycle' > "${SANDBOX_ROOT}/etc/ominull/agent.conf"
printf '%s\n' 'database=/var/lib/ominull/ominull.db' > "${SANDBOX_ROOT}/etc/ominull/hub.env"
printf '%s\n' 'production-data' > "${SANDBOX_ROOT}/var/lib/ominull/ominull.db"
printf '%s\n' 'pki-data' > "${SANDBOX_ROOT}/var/lib/ominull/pki-marker"

sandbox /usr/bin/dpkg --force-depends -i /release/next-agent.deb >/dev/null
sandbox /usr/bin/dpkg --force-depends -i /release/next-hub.deb >/dev/null
[ "$(sandbox /usr/bin/dpkg-query -W -f='${Version}' ominull-agent)" = "${VERSION}.1" ]
[ "$(sandbox /usr/bin/dpkg-query -W -f='${Version}' ominull-hub)" = "${VERSION}.1" ]
grep -q 'endpoint_id=lifecycle' "${SANDBOX_ROOT}/etc/ominull/agent.conf"

if sandbox /usr/bin/dpkg --force-depends -i /release/base-agent.deb >/dev/null 2>&1; then
    echo "[-] Agent preinst allowed a downgrade." >&2
    exit 1
fi
if sandbox /usr/bin/dpkg --force-depends -i /release/base-hub.deb >/dev/null 2>&1; then
    echo "[-] Hub preinst allowed a downgrade." >&2
    exit 1
fi
[ "$(sandbox /usr/bin/dpkg-query -W -f='${Version}' ominull-agent)" = "${VERSION}.1" ]
[ "$(sandbox /usr/bin/dpkg-query -W -f='${Version}' ominull-hub)" = "${VERSION}.1" ]

sandbox /usr/bin/dpkg --force-depends --purge ominull-agent >/dev/null
[ "$(sandbox /usr/bin/dpkg-query -W -f='${Status}' ominull-agent 2>/dev/null || true)" != 'install ok installed' ]
[ ! -e "${SANDBOX_ROOT}/etc/ominull/agent.conf" ]
[ -s "${SANDBOX_ROOT}/var/lib/ominull/ominull.db" ]
[ -s "${SANDBOX_ROOT}/var/lib/ominull/pki-marker" ]

sandbox /usr/bin/dpkg --force-depends --purge ominull-hub >/dev/null
[ "$(sandbox /usr/bin/dpkg-query -W -f='${Status}' ominull-hub 2>/dev/null || true)" != 'install ok installed' ]
[ -s "${SANDBOX_ROOT}/var/lib/ominull/ominull.db" ]
[ -s "${SANDBOX_ROOT}/var/lib/ominull/pki-marker" ]
[ -s "${SANDBOX_ROOT}/etc/ominull/hub.env" ]
echo "[+] Debian lifecycle ${VERSION}: registration, upgrade, downgrade refusal, identity preservation, purge, and hub data/PKI preservation verified."
