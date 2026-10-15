#!/usr/bin/env bash
# Sign the built release packages with the Ominull release key.
#
# Agents verify against a public key compiled into them, not against anything
# the hub serves, so an unsigned package is one no agent will install. Run this
# after scripts/build-packages.sh and before the packages reach the hub.
#
# Backends (OMINULL_SIGNING_BACKEND):
#   file     (default) OMINULL_SIGNING_KEY is a PEM EC private key. It may be an
#            encrypted PEM on removable media (scripts/release-key-offline.sh
#            writes one); the passphrase is asked once on the terminal, or read
#            from OMINULL_SIGNING_PASSFILE, and reaches openssl only through a
#            pipe, never argv, the environment or a file.
#   command  OMINULL_SIGNING_COMMAND is an executable for a token, HSM or an
#            approval signer: "CMD pubkey" prints the PEM public key, "CMD sign
#            FILE" prints the DER ECDSA-SHA256 signature over FILE. The key never
#            leaves it. Nightshift's nightshift-release-signer asks the owner
#            once for the whole release (begin/end in lib/signing-backend.sh).
# The private key is never in this repo, on the hub, or in CI.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${OMINULL_DIST_DIR:-${ROOT_DIR}/dist}"
VERSION="${OMINULL_RELEASE_VERSION:-$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")}"
# shellcheck source=lib/signing-backend.sh
. "${SCRIPT_DIR}/lib/signing-backend.sh"

agent_deb="${DIST_DIR}/ominull-agent_${VERSION}_amd64.deb"
hub_deb="${DIST_DIR}/ominull-hub_${VERSION}_amd64.deb"
windows_msi="${DIST_DIR}/ominull-agent-windows-${VERSION}.msi"
packages=("${agent_deb}" "${hub_deb}" "${windows_msi}")
for pkg in "${packages[@]}"; do
    [ -f "${pkg}" ] || { echo "[-] Missing $(basename "${pkg}"); run scripts/build-packages.sh first." >&2; exit 1; }
done

# One approval for the whole release: the endpoint packages by digest, the hub
# by name (it is rebuilt below with the endpoint signatures inside).
signing_begin release "${VERSION}" \
    "$(basename "${agent_deb}")=$(sha256sum "${agent_deb}" | awk '{print $1}')" \
    "$(basename "${windows_msi}")=$(sha256sum "${windows_msi}" | awk '{print $1}')" \
    "$(basename "${hub_deb}")"

sign_package() {
    local pkg="$1" name sha statement
    name="$(basename "${pkg}")"
    sign_file "${pkg}" "${pkg}.sig"
    sha="$(sha256sum "${pkg}" | awk '{print $1}')"
    printf '%s\n' "${sha}" > "${pkg}.sha256"

    # The release statement binds name, version and digest under the same key,
    # so an agent can refuse an older, genuinely signed package offered as an
    # update (agents from 1.8.59 require it; the hub serves it as release_sig).
    statement="$(mktemp "${TMPDIR:-/tmp}/ominull-release-statement.XXXXXX")"
    printf 'OMINULL-RELEASE-V1\npackage=%s\nversion=%s\nsha256=%s\n' "${name}" "${VERSION}" "${sha}" > "${statement}"
    sign_file "${statement}" "${pkg}.release.sig"

    # Verify with the pinned public key exactly as an agent will, so a bad
    # signature is caught here and not on an endpoint mid-upgrade.
    if ! verify_sig "${pkg}" "${pkg}.sig" || ! verify_sig "${statement}" "${pkg}.release.sig"; then
        rm -f "${statement}"
        echo "[-] Signature over ${name} failed verification against the pinned key." >&2
        exit 1
    fi
    rm -f "${statement}"
    echo "  [+] ${name}.sig + .release.sig  (${sha})"
}

echo "[*] Signing endpoint packages with the release key..."
sign_package "${agent_deb}"
sign_package "${windows_msi}"

# A hub package downloaded by a new operator must be enough to reach the
# enrollment screen and serve the retained native agents. Bundle the already
# signed endpoint artifacts as data, outside the package's running binary
# path; postinst copies them into the configured download directory. The copy
# survives hub package purge so artifact availability follows the data-retention
# contract, while the signed source remains part of the release package.
bundle_dir="$(mktemp -d "${TMPDIR:-/tmp}/ominull-hub-bundle.XXXXXX")"
trap 'signing_end; find "${bundle_dir}" -depth -delete; rm -f "${verify_pub}"' EXIT
dpkg-deb --raw-extract "${hub_deb}" "${bundle_dir}/root"
install -d -m 0755 "${bundle_dir}/root/usr/share/ominull/packages"
for artifact in "${agent_deb}" "${agent_deb}.sig" "${agent_deb}.sha256" "${agent_deb}.release.sig" \
                "${windows_msi}" "${windows_msi}.sig" "${windows_msi}.sha256" "${windows_msi}.release.sig"; do
    install -m 0644 "${artifact}" "${bundle_dir}/root/usr/share/ominull/packages/$(basename "${artifact}")"
done
bundled_hub="${bundle_dir}/ominull-hub_${VERSION}_amd64.deb"
dpkg-deb --build --root-owner-group "${bundle_dir}/root" "${bundled_hub}" >/dev/null
mv "${bundled_hub}" "${hub_deb}"

echo "[*] Signing bundled hub package..."
sign_package "${hub_deb}"

mapfile -t package_names < <(printf '%s\n' "${packages[@]}" | xargs -n1 basename | sort)
(cd "${DIST_DIR}" && sha256sum "${package_names[@]}") > "${DIST_DIR}/SHA256SUMS.txt"

echo "[+] All packages signed and verified against the pinned release key."
