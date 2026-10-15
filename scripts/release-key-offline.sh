#!/usr/bin/env bash
# Move the release signing key onto offline media as an encrypted PEM.
#
#   release-key-offline.sh export SRC DEST_DIR   write DEST_DIR/ominull-release-signing.key.pem,
#                                                AES-256 encrypted under a passphrase openssl asks for
#   release-key-offline.sh check KEY             confirm KEY opens and is the key agents pin
#
# Nothing here prints key material. The plaintext source is left alone: shred
# it yourself only after a release has been signed from the new location
# (operations.md, release key custody). sign-release.sh reads the encrypted
# file with OMINULL_SIGNING_KEY=<DEST_DIR>/ominull-release-signing.key.pem.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pinned_pub() {
    sed -n '/^[[:space:]]*"-----BEGIN PUBLIC KEY-----/,/^[[:space:]]*"-----END PUBLIC KEY-----/p' "${ROOT_DIR}/agent/include/release_key.h" \
        | sed -E 's/^[[:space:]]*"//; s/\\n".*$//'
}

check_key() {
    local key="$1" pub
    pub="$(openssl ec -in "${key}" -pubout 2>/dev/null)" || { echo "[-] ${key} did not open (wrong passphrase or not an EC key)." >&2; return 1; }
    if [ "${pub}" != "$(pinned_pub)" ]; then
        echo "[-] ${key} is not the release key pinned in agent/include/release_key.h." >&2
        return 1
    fi
    echo "[+] ${key} opens and matches the pinned release key."
}

case "${1:-}" in
export)
    src="${2:?source key}"; dest_dir="${3:?destination directory on the offline medium}"
    [ -f "${src}" ] || { echo "[-] No key at ${src}." >&2; exit 1; }
    [ -d "${dest_dir}" ] || { echo "[-] ${dest_dir} is not a directory (is the medium mounted?)." >&2; exit 1; }
    dest="${dest_dir%/}/ominull-release-signing.key.pem"
    [ ! -e "${dest}" ] || { echo "[-] ${dest} exists; refusing to overwrite a key." >&2; exit 1; }
    # The destination must be its own mounted filesystem, not the one the key
    # (or the root) is on: compare device ids, which bind mounts and btrfs
    # subvolumes cannot hide behind a different SOURCE string.
    source_dev="$(stat -c '%d' "${src}")"
    dest_dev="$(stat -c '%d' "${dest_dir}")"
    root_dev="$(stat -c '%d' /)"
    dest_mnt="$(findmnt -no TARGET --target "${dest_dir}" 2>/dev/null || true)"
    if [ "${dest_dev}" = "${source_dev}" ] || [ "${dest_dev}" = "${root_dev}" ] || [ -z "${dest_mnt}" ] || [ "${dest_mnt}" = "/" ]; then
        echo "[-] ${dest_dir} is not a separate mounted medium (same filesystem as the key or /); pick the offline medium." >&2
        exit 1
    fi
    umask 077
    echo "[*] openssl asks for the new passphrase twice. Keep it in your password manager, not on the medium."
    openssl pkey -in "${src}" -aes-256-cbc -out "${dest}"
    chmod 0600 "${dest}"
    mode="$(stat -c '%a' "${dest}")"
    if [ "${mode}" != "600" ]; then
        echo "[!] ${dest} is mode ${mode}: this filesystem has no Unix modes, so sign-release.sh will refuse it." >&2
        echo "    Use an ext4 or LUKS-formatted medium." >&2
    fi
    sync
    echo "[*] Re-opening the copy to prove it (passphrase once more)."
    check_key "${dest}"
    echo "[+] Written ${dest}. Sign one release from it, then shred ${src}."
    ;;
check)
    check_key "${2:?key file}"
    ;;
*)
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
