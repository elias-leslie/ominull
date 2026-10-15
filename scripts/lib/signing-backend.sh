# Release-key signing backend, sourced by sign-release.sh and
# sign-trust-bundle.sh (needs ROOT_DIR). See sign-release.sh for the backends.
# After sourcing: sign_file IN OUT, verify_sig FILE SIG (against the pinned
# key), and the signing key is known to be the pinned one.
BACKEND="${OMINULL_SIGNING_BACKEND:-file}"
KEY="${OMINULL_SIGNING_KEY:-}"
PASSPHRASE=""

case "${BACKEND}" in
file)
    if [ -z "${KEY}" ]; then
        echo "[-] Set OMINULL_SIGNING_KEY to the release signing key (ops vault or offline media)." >&2
        exit 1
    fi
    if [ ! -f "${KEY}" ]; then
        echo "[-] Signing key not found: ${KEY} (is the offline medium attached?)" >&2
        exit 1
    fi
    # Refuse to sign with a key anyone but its owner can read. A release key
    # with loose permissions is a key that should be assumed copied. (Media
    # without Unix modes, such as exFAT, show 0755 here: keep the encrypted
    # key on ext4/LUKS or use the command backend.)
    mode="$(stat -c '%a' "${KEY}" 2>/dev/null || stat -f '%Lp' "${KEY}")"
    if [ "$(( 8#${mode} & 8#077 ))" -ne 0 ]; then
        echo "[-] Signing key ${KEY} is mode ${mode}; it must not be group- or world-readable." >&2
        exit 1
    fi
    if grep -q -e '^-----BEGIN ENCRYPTED ' -e '^Proc-Type: 4,ENCRYPTED' "${KEY}"; then
        if [ -n "${OMINULL_SIGNING_PASSFILE:-}" ]; then
            IFS= read -r PASSPHRASE < "${OMINULL_SIGNING_PASSFILE}" || true
        elif [ -r /dev/tty ]; then
            IFS= read -r -s -p "Release key passphrase: " PASSPHRASE < /dev/tty || true
            echo >&2
        fi
        if [ -z "${PASSPHRASE}" ]; then
            echo "[-] ${KEY} is encrypted and no passphrase was given." >&2
            exit 1
        fi
    fi
    ;;
command)
    if [ -z "${OMINULL_SIGNING_COMMAND:-}" ] || [ ! -x "${OMINULL_SIGNING_COMMAND}" ]; then
        echo "[-] Set OMINULL_SIGNING_COMMAND to an executable signer (pubkey | sign FILE)." >&2
        exit 1
    fi
    ;;
*)
    echo "[-] Unknown OMINULL_SIGNING_BACKEND ${BACKEND} (file or command)." >&2
    exit 1
    ;;
esac

# openssl reads the passphrase from fd 3, a pipe fed by the shell builtin.
passin=()
[ -z "${PASSPHRASE}" ] || passin=(-passin fd:3)
with_pass() {
    if [ -n "${PASSPHRASE}" ]; then
        "$@" 3< <(printf '%s\n' "${PASSPHRASE}")
    else
        "$@"
    fi
}

signing_pubkey() {
    case "${BACKEND}" in
    file) with_pass openssl ec -in "${KEY}" "${passin[@]}" -pubout 2>/dev/null ;;
    command) "${OMINULL_SIGNING_COMMAND}" pubkey ;;
    esac
}

# sign_file IN OUT writes the DER ECDSA-SHA256 signature over IN to OUT.
sign_file() {
    case "${BACKEND}" in
    file) with_pass openssl dgst -sha256 -sign "${KEY}" "${passin[@]}" -out "$2" "$1" ;;
    command) "${OMINULL_SIGNING_COMMAND}" sign "$1" > "$2" ;;
    esac
    [ -s "$2" ] || { echo "[-] The ${BACKEND} signer produced no signature for $(basename "$1")." >&2; exit 1; }
}

# The pinned public key is the contract. Signing with a key the fleet will not
# recognise produces packages every agent rejects, which is a fleet-wide outage
# discovered one endpoint at a time. Catch it here instead.
embedded="$(sed -n '/^[[:space:]]*"-----BEGIN PUBLIC KEY-----/,/^[[:space:]]*"-----END PUBLIC KEY-----/p' "${ROOT_DIR}/agent/include/release_key.h" \
    | sed -E 's/^[[:space:]]*"//; s/\\n".*$//')"
signing_pub="$(signing_pubkey || true)"
if [ -z "${signing_pub}" ]; then
    echo "[-] Could not read the public half of the signing key (wrong passphrase?)." >&2
    exit 1
fi
if [ "${embedded}" != "${signing_pub}" ]; then
    echo "[-] The ${BACKEND} signing key is not the key pinned in agent/include/release_key.h." >&2
    echo "    Agents would reject every package signed with it. Rotate deliberately, not by accident." >&2
    exit 1
fi
verify_pub="$(mktemp "${TMPDIR:-/tmp}/ominull-release-pub.XXXXXX")"
trap 'rm -f "${verify_pub}"' EXIT
printf '%s\n' "${embedded}" > "${verify_pub}"


verify_sig() {
    openssl dgst -sha256 -verify "${verify_pub}" -signature "$2" "$1" >/dev/null 2>&1
}
