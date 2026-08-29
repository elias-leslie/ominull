#!/usr/bin/env bash
# Sign the built release packages with the Ominull release key.
#
# Agents verify against a public key compiled into them, not against anything
# the hub serves, so an unsigned package is one no agent will install. Run this
# after scripts/build-packages.sh and before the packages reach the hub.
#
# The private key lives in the operations vault. It is never in this repo, on
# the hub, or in CI. Point OMINULL_SIGNING_KEY at it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
KEY="${OMINULL_SIGNING_KEY:-}"

if [ -z "${KEY}" ]; then
    echo "[-] Set OMINULL_SIGNING_KEY to the release signing key (it lives in the ops vault)." >&2
    exit 1
fi
if [ ! -f "${KEY}" ]; then
    echo "[-] Signing key not found: ${KEY}" >&2
    exit 1
fi

# Refuse to sign with a key anyone but its owner can read. A release key with
# loose permissions is a key that should be assumed copied.
mode="$(stat -c '%a' "${KEY}" 2>/dev/null || stat -f '%Lp' "${KEY}")"
if [ "$(( 8#${mode} & 8#077 ))" -ne 0 ]; then
    echo "[-] Signing key ${KEY} is mode ${mode}; it must not be group- or world-readable." >&2
    exit 1
fi

# The pinned public key is the contract. Signing with a key the fleet will not
# recognise produces packages every agent rejects, which is a fleet-wide outage
# discovered one endpoint at a time. Catch it here instead.
embedded="$(sed -n '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p' "${ROOT_DIR}/agent/include/release_key.h" \
    | sed 's/^ *"//; s/\\n" *\\*$//; s/" *\\*$//')"
signing_pub="$(openssl ec -in "${KEY}" -pubout 2>/dev/null)"
if [ "${embedded}" != "${signing_pub}" ]; then
    echo "[-] ${KEY} is not the key pinned in agent/include/release_key.h." >&2
    echo "    Agents would reject every package signed with it. Rotate deliberately, not by accident." >&2
    exit 1
fi

shopt -s nullglob
packages=("${DIST_DIR}"/ominull-agent_*_amd64.deb "${DIST_DIR}"/ominull-agent-windows-*.tar.gz "${DIST_DIR}"/ominull-agent-macos-*.tar.gz)
if [ ${#packages[@]} -eq 0 ]; then
    echo "[-] No packages in ${DIST_DIR}; run scripts/build-packages.sh first." >&2
    exit 1
fi

echo "[*] Signing ${#packages[@]} package(s) with the release key..."
for pkg in "${packages[@]}"; do
    openssl dgst -sha256 -sign "${KEY}" -out "${pkg}.sig" "${pkg}"
    sha256sum "${pkg}" | awk '{print $1}' > "${pkg}.sha256"

    # Verify with the pinned public key exactly as an agent will, so a bad
    # signature is caught here and not on an endpoint mid-upgrade.
    printf '%s\n' "${embedded}" > "${DIST_DIR}/.verify.pub"
    if ! openssl dgst -sha256 -verify "${DIST_DIR}/.verify.pub" -signature "${pkg}.sig" "${pkg}" >/dev/null 2>&1; then
        rm -f "${DIST_DIR}/.verify.pub"
        echo "[-] Signature over $(basename "${pkg}") failed verification against the pinned key." >&2
        exit 1
    fi
    rm -f "${DIST_DIR}/.verify.pub"
    echo "  [+] $(basename "${pkg}").sig  ($(cat "${pkg}.sha256"))"
done

echo "[+] All packages signed and verified against the pinned release key."
