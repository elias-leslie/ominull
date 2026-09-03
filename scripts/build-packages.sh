#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
BUILD_DIR="${ROOT_DIR}/build"
VERSION="${OMINULL_RELEASE_VERSION:-$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")}"

case "${VERSION}" in
    ''|*[!0-9.]*|.*|*.)
        echo "[-] Invalid release version: ${VERSION}" >&2
        exit 1
        ;;
esac
if ! [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "[-] Release version must be major.minor.patch: ${VERSION}" >&2
    exit 1
fi

for tool in gcc x86_64-w64-mingw32-gcc go dpkg-deb wixl; do
    command -v "${tool}" >/dev/null || {
        echo "[-] Required build tool is missing: ${tool}" >&2
        exit 1
    }
done

mkdir -p "${DIST_DIR}" "${BUILD_DIR}"
# Do not let a stale artifact silently become part of a later signed release.
# These are exact release-output name families; persistent source and the
# tracked checksum index are left alone until signing regenerates that index.
find "${DIST_DIR}" -maxdepth 1 -type f \( \
    -name 'ominull-agent_*.deb' -o -name 'ominull-agent_*.deb.sig' -o -name 'ominull-agent_*.deb.sha256' -o \
    -name 'ominull-agent-windows-*.msi' -o -name 'ominull-agent-windows-*.msi.sig' -o -name 'ominull-agent-windows-*.msi.sha256' -o \
    -name 'ominull-hub_*.deb' -o -name 'ominull-hub_*.deb.sig' -o -name 'ominull-hub_*.deb.sha256' \
\) -delete
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ominull-packages.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT

echo "[*] Building retained Ominull packages v${VERSION}."

echo "[*] Building Linux agent."
gcc -Wall -Wextra -Wformat=2 -O2 -I"${ROOT_DIR}/agent/include" \
    "${ROOT_DIR}/agent/linux/main.c" -lcurl -o "${BUILD_DIR}/ominulld"

echo "[*] Building hub and response authority."
(cd "${ROOT_DIR}/hub" && CGO_ENABLED=0 go build -trimpath \
    -ldflags "-X main.version=${VERSION}" -o "${BUILD_DIR}/ominull-hub" ./cmd)
(cd "${ROOT_DIR}/hub" && CGO_ENABLED=0 go build -trimpath \
    -o "${BUILD_DIR}/ominullctl" ./cmd/ominullctl)
(cd "${ROOT_DIR}/hub" && CGO_ENABLED=0 go build -trimpath \
    -o "${BUILD_DIR}/ominull-response-authority" ./cmd/ominull-response-authority)

echo "[*] Building Windows user-mode agent and recovery tool."
x86_64-w64-mingw32-gcc -Wall -Wextra -Wformat=2 -O2 \
	-DOMINULL_WFP_EMBEDDED \
    -I"${ROOT_DIR}/agent/include" \
    "${ROOT_DIR}/agent/src/main.c" \
    "${ROOT_DIR}/agent/src/hub_client.c" \
    "${ROOT_DIR}/agent/src/hub_tls.c" \
    "${ROOT_DIR}/agent/src/service.c" \
    "${ROOT_DIR}/agent/src/updater.c" \
    "${ROOT_DIR}/agent/src/provenance_windows.c" \
    "${ROOT_DIR}/agent/src/response_windows.c" \
    "${ROOT_DIR}/agent/windows/wfp_user.c" \
    -o "${BUILD_DIR}/ominulld.exe" \
    -lws2_32 -lwinhttp -liphlpapi -ladvapi32 -lbcrypt -lcrypt32 -lncrypt \
    -lfwpuclnt -lole32
x86_64-w64-mingw32-gcc -Wall -Wextra -Wformat=2 -O2 \
    -I"${ROOT_DIR}/agent/include" "${ROOT_DIR}/agent/windows/wfp_user.c" \
    -o "${BUILD_DIR}/ominull_wfp_user.exe" \
    -lws2_32 -ladvapi32 -lfwpuclnt -lole32

make_deb() {
    local name="$1" control="$2" preinst="$3" service="$4" postinst="$5" prerm="$6" postrm="$7" binary="$8" package="$9" ctl="${10:-}"
    local root="${WORK_DIR}/${name}"
    mkdir -p "${root}/DEBIAN" "${root}/opt/ominull/bin" "${root}/usr/share/doc/${package}"
    install -m 0755 "${binary}" "${root}/opt/ominull/bin/$(basename "${binary}")"
    if [ -n "${ctl}" ]; then
        mkdir -p "${root}/usr/bin"
        install -m 0755 "${ctl}" "${root}/usr/bin/ominullctl"
    fi
    if [ "${name}" = "ominull-hub" ]; then
        if [ -f "${BUILD_DIR}/ominull-response-authority" ]; then
            install -m 0755 "${BUILD_DIR}/ominull-response-authority" "${root}/opt/ominull/bin/ominull-response-authority"
        fi
        if [ -f "${ROOT_DIR}/packaging/linux/hub/response-authority.service" ]; then
            mkdir -p "${root}/lib/systemd/system"
            install -m 0644 "${ROOT_DIR}/packaging/linux/hub/response-authority.service" "${root}/lib/systemd/system/ominull-response-authority.service"
        fi
    fi
    install -m 0644 "${ROOT_DIR}/LICENSE" "${root}/usr/share/doc/${package}/LICENSE"
    sed "s/@VERSION@/${VERSION}/g" "${ROOT_DIR}/${control}" > "${root}/DEBIAN/control"
    sed "s/@VERSION@/${VERSION}/g" "${ROOT_DIR}/${preinst}" > "${root}/DEBIAN/preinst"
    chmod 0755 "${root}/DEBIAN/preinst"
    sed "s/@VERSION@/${VERSION}/g" "${ROOT_DIR}/${postinst}" > "${root}/DEBIAN/postinst"
    chmod 0755 "${root}/DEBIAN/postinst"
    install -m 0755 "${ROOT_DIR}/${prerm}" "${root}/DEBIAN/prerm"
    install -m 0755 "${ROOT_DIR}/${postrm}" "${root}/DEBIAN/postrm"
    mkdir -p "${root}/lib/systemd/system"
    install -m 0644 "${ROOT_DIR}/${service}" "${root}/lib/systemd/system/${name}.service"
    find "${root}" -type d -exec chmod 0755 {} +
    dpkg-deb --root-owner-group --build "${root}" "${DIST_DIR}/${name}_${VERSION}_amd64.deb" >/dev/null
}

echo "[*] Packaging Linux agent .deb."
make_deb "ominull-agent" \
    packaging/linux/agent/control.in \
    packaging/linux/agent/preinst \
    packaging/linux/agent/service \
    packaging/linux/agent/postinst \
    packaging/linux/agent/prerm \
    packaging/linux/agent/postrm \
    "${BUILD_DIR}/ominulld" ominull-agent ""

echo "[*] Packaging Linux hub .deb."
make_deb "ominull-hub" \
    packaging/linux/hub/control.in \
    packaging/linux/hub/preinst \
    packaging/linux/hub/service \
    packaging/linux/hub/postinst \
    packaging/linux/hub/prerm \
    packaging/linux/hub/postrm \
    "${BUILD_DIR}/ominull-hub" ominull-hub "${BUILD_DIR}/ominullctl"

for deb in "${DIST_DIR}/ominull-agent_${VERSION}_amd64.deb" "${DIST_DIR}/ominull-hub_${VERSION}_amd64.deb"; do
    bad_owner="$(dpkg-deb -c "${deb}" | awk '$2 != "root/root"')"
    if [ -n "${bad_owner}" ]; then
        echo "[-] Package contains a non-root-owned member: ${deb}" >&2
        echo "${bad_owner}" >&2
        exit 1
    fi
    bad_mode="$(dpkg-deb -c "${deb}" | awk '$1 ~ /^[-l]/ && (substr($1,6,1) == "w" || substr($1,9,1) == "w")')"
    if [ -n "${bad_mode}" ]; then
        echo "[-] Package contains a group/world-writable member: ${deb}" >&2
        echo "${bad_mode}" >&2
        exit 1
    fi
done

echo "[*] Packaging Windows MSI."
wixl --arch x64 \
    -o "${DIST_DIR}/ominull-agent-windows-${VERSION}.msi" \
    <(sed -e "s|@VERSION@|${VERSION}|g" \
         -e "s|@AGENT_EXE@|${BUILD_DIR}/ominulld.exe|g" \
         -e "s|@WFP_EXE@|${BUILD_DIR}/ominull_wfp_user.exe|g" \
         "${ROOT_DIR}/packaging/windows/ominull.wxs.in")

echo "[+] Built packages:"
printf '    %s\n' "${DIST_DIR}/ominull-agent_${VERSION}_amd64.deb" \
    "${DIST_DIR}/ominull-hub_${VERSION}_amd64.deb" \
    "${DIST_DIR}/ominull-agent-windows-${VERSION}.msi"
