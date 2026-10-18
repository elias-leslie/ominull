# Release-key signing backend, sourced by sign-release.sh and
# sign-trust-bundle.sh (needs ROOT_DIR). See sign-release.sh for the backends.
# After sourcing: sign_file IN OUT, verify_sig FILE SIG (against the pinned
# key), signing_begin/signing_end, and the signing key is known to be the
# pinned one.
#
# Rotation release (the build pins the incoming key, the fleet still pins the
# outgoing one): OMINULL_SIGNING_ROTATE_FROM=<git ref of the last release>.
# The release is then signed with, and verified against, the key pinned at that
# ref, and the build must pin a different key.
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
        echo "[-] Set OMINULL_SIGNING_COMMAND to an executable signer (pubkey | sign FILE; optional begin/end)." >&2
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
    command)
        if [ "${OMINULL_SIGNING_ROUTINE:-0}" = 1 ]; then
            "${OMINULL_SIGNING_COMMAND}" pubkey routine
        else
            "${OMINULL_SIGNING_COMMAND}" pubkey
        fi ;;
    esac
}

# Routine mode (OMINULL_SIGNING_ROUTINE=1, Nightshift's session signing): the
# signer's routine key must be one the pinned release key listed on the hub
# (GET /api/v1/trust/routine-keys). That signed list goes beside the packages
# as dist/routine-keys.json, which the hub installer on Proxmox reads; agents
# get it from the hub.
routine_list() {
    # OMINULL_ROUTINE_LIST: a saved copy of that GET (offline checks and tests).
    if [ -n "${OMINULL_ROUTINE_LIST:-}" ]; then cat "${OMINULL_ROUTINE_LIST}"; return; fi
    local url="${OMINULL_HUB_URL:?routine signing needs OMINULL_HUB_URL}" ca="${OMINULL_HUB_CA:-/etc/ominull/ca.crt}"
    curl -fsS --max-time 20 --cacert "${ca}" -K <(printf 'header = "X-API-Key: %s"\n' "${OMINULL_ADMIN_KEY:?routine signing needs OMINULL_ADMIN_KEY}") \
        "${url}/api/v1/trust/routine-keys"
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
pinned_pem() {
    sed -n '/^[[:space:]]*"-----BEGIN PUBLIC KEY-----/,/^[[:space:]]*"-----END PUBLIC KEY-----/p' | sed -E 's/^[[:space:]]*"//; s/\\n".*$//'
}
embedded="$(pinned_pem < "${ROOT_DIR}/agent/include/release_key.h")"
# The hub verifies trust bundles with its own copy (response.ReleasePublicKeyPEM).
# A rotation that changes one and not the other leaves the hub refusing every
# bundle the new key signs.
hub_pem="$(sed -n '/^const ReleasePublicKeyPEM = `/,/^-----END PUBLIC KEY-----/p' "${ROOT_DIR}/hub/pkg/response/trust.go" \
    | sed 's/^const ReleasePublicKeyPEM = `//')"
if [ "${hub_pem}" != "${embedded}" ]; then
    echo "[-] hub/pkg/response/trust.go ReleasePublicKeyPEM differs from agent/include/release_key.h; pin the same key in both." >&2
    exit 1
fi
# Windows agents verify with the raw X||Y bytes in the same header, not the PEM.
pinned_xy="$(sed -n '/OMINULL_RELEASE_PUBKEY_XY\[/,/};/p' "${ROOT_DIR}/agent/include/release_key.h" \
    | grep -o '0x[0-9a-fA-F]\{2\}' | sed 's/^0x//' | tr -d '\n' | tr 'A-F' 'a-f')"
pem_xy="$(printf '%s\n' "${embedded}" | openssl pkey -pubin -outform DER 2>/dev/null | tail -c 64 | od -An -v -tx1 | tr -d ' \n')"
if [ "${#pem_xy}" -ne 128 ] || [ "${pinned_xy}" != "${pem_xy}" ]; then
    echo "[-] agent/include/release_key.h OMINULL_RELEASE_PUBKEY_XY is not the key in OMINULL_RELEASE_PUBKEY_PEM; pin the same key in both." >&2
    exit 1
fi
if [ -n "${OMINULL_SIGNING_ROTATE_FROM:-}" ]; then
    outgoing="$(git -C "${ROOT_DIR}" show "${OMINULL_SIGNING_ROTATE_FROM}:agent/include/release_key.h" | pinned_pem)"
    if [ -z "${outgoing}" ] || [ "${outgoing}" = "${embedded}" ]; then
        echo "[-] OMINULL_SIGNING_ROTATE_FROM=${OMINULL_SIGNING_ROTATE_FROM} pins no key or the same key as this build; not a rotation." >&2
        exit 1
    fi
    echo "[*] Rotation release: signing with the key pinned at ${OMINULL_SIGNING_ROTATE_FROM}; this build pins the new key." >&2
    embedded="${outgoing}"
fi
signing_pub="$(signing_pubkey || true)"
if [ -z "${signing_pub}" ]; then
    echo "[-] Could not read the public half of the signing key (wrong passphrase?)." >&2
    exit 1
fi
if [ "${OMINULL_SIGNING_ROUTINE:-0}" = 1 ]; then
    [ "${BACKEND}" = command ] || { echo "[-] Routine signing needs the command backend (Nightshift's signer)." >&2; exit 1; }
    list="$(routine_list)" || { echo "[-] Could not read the hub's routine release keys." >&2; exit 1; }
    signing_xy="$(printf '%s\n' "${signing_pub}" | openssl pkey -pubin -outform DER 2>/dev/null | tail -c 64 | od -An -v -tx1 | tr -d ' \n')"
    routine_id="$(printf '%s' "${list}" | jq -r --arg xy "${signing_xy}" '.keys[] | select(.xy == $xy) | .id')"
    if [ "${#signing_xy}" -ne 128 ] || [ -z "${routine_id}" ]; then
        echo "[-] The signer's routine key is not on the hub's list signed by the pinned release key." >&2
        exit 1
    fi
    printf '%s' "${list}" | jq -c '{epoch: .epoch, keys: ([.keys[] | .id + ":" + .xy] | sort | join(",")), sig: .signature}' \
        > "${DIST_DIR:-${ROOT_DIR}/dist}/routine-keys.json"
    echo "[*] Routine signing in the owner's session with routine key ${routine_id} (epoch $(printf '%s' "${list}" | jq -r .epoch))." >&2
    embedded="${signing_pub}"
elif [ "${embedded}" != "${signing_pub}" ]; then
    echo "[-] The ${BACKEND} signing key is not the key pinned in agent/include/release_key.h." >&2
    echo "    Agents would reject every package signed with it. Rotate deliberately, not by accident." >&2
    exit 1
fi
verify_pub="$(mktemp "${TMPDIR:-/tmp}/ominull-release-pub.XXXXXX")"
trap 'signing_end; rm -f "${verify_pub}"' EXIT
printf '%s\n' "${embedded}" > "${verify_pub}"


verify_sig() {
    openssl dgst -sha256 -verify "${verify_pub}" -signature "$2" "$1" >/dev/null 2>&1
}

# A command backend may put a whole run behind one approval (Nightshift's
# nightshift-release-signer: the owner approves once with a passkey):
#   CMD begin release VERSION NAME[=SHA256]...   or   CMD begin trust TENANT FILE
# prints a session token that later "CMD sign" calls get as
# OMINULL_SIGNING_SESSION; "CMD end" closes it. A signer without sessions exits
# 64 on begin and is called per file as before. The file backend needs none.
signing_begin() {
    [ "${BACKEND}" = command ] || return 0
    local token rc=0
    token="$("${OMINULL_SIGNING_COMMAND}" begin "$@")" || rc=$?
    case "${rc}" in
    0) OMINULL_SIGNING_SESSION="${token}"; export OMINULL_SIGNING_SESSION ;;
    64) ;;
    *) echo "[-] The signer opened no signing session (not approved, or it failed)." >&2; exit 1 ;;
    esac
}
signing_end() {
    [ -z "${OMINULL_SIGNING_SESSION:-}" ] || "${OMINULL_SIGNING_COMMAND}" end >/dev/null 2>&1 || true
}
