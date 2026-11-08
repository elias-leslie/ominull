#!/usr/bin/env bash
# Sign a tenant's trust bundle with the Ominull release key and hand it to the
# hub. Agents from 1.8.59 pin the tenant's three public grant keys only with
# this signature, so a hub cannot make an agent pin keys of its own.
#
#   OMINULL_HUB_URL=https://HUB:9443 OMINULL_ADMIN_KEY=... \
#   OMINULL_SIGNING_KEY=/media/.../ominull-release-signing.enc.pem \
#   scripts/sign-trust-bundle.sh [TENANT]
#
# The statement carries the hub's trust epoch (it moves up whenever the tenant's
# keys change; root on the hub can raise its floor with
# OMINULL_GRANT_TRUST_EPOCH_FLOOR). Agents never pin a bundle older than one they
# pinned. It is signed, verified against the pinned release key, and posted.
# Signing backends: see sign-release.sh. Run it again after the grant keys change
# (a restored state dir).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TENANT="${1:-default}"
HUB_URL="${OMINULL_HUB_URL:?set OMINULL_HUB_URL}"
: "${OMINULL_ADMIN_KEY:?export OMINULL_ADMIN_KEY}"

case "${TENANT}" in
*[!A-Za-z0-9._-]* | "") echo "[-] Invalid tenant ${TENANT}." >&2; exit 1 ;;
esac

# The admin key travels only over TLS checked against the hub CA.
# shellcheck source=scripts/hub-request.sh
. "${SCRIPT_DIR}/hub-request.sh"
hub_url_safe "${HUB_URL}" || exit 1

# shellcheck source=lib/signing-backend.sh
. "${SCRIPT_DIR}/lib/signing-backend.sh"

work="$(mktemp -d "${TMPDIR:-/tmp}/ominull-trust-bundle.XXXXXX")"
trap 'signing_end; rm -rf "${work}"; rm -f "${verify_pub}"' EXIT

hub_call() {
    local method="$1" path="$2"
    shift 2
    curl -fsS --connect-timeout 5 --max-time 20 -X "${method}" \
        -K <(hub_curl_config "${OMINULL_ADMIN_KEY}" "${HUB_URL}") "$@" "${HUB_URL}${path}"
}

hub_call GET "/api/v1/trust/statement?tenant=${TENANT}" > "${work}/hub.json"
python3 -I -c 'import json,sys; sys.stdout.write(json.load(open(sys.argv[1]))["statement"])' "${work}/hub.json" > "${work}/hub.statement"
first="$(head -n1 "${work}/hub.statement")"
EPOCH="$(sed -n 3p "${work}/hub.statement" | sed -n 's/^epoch=\([1-9][0-9]*\)$/\1/p')"
[ -n "${EPOCH}" ] || { echo "[-] The hub's statement carries no epoch; not signing." >&2; exit 1; }
tenant_line="$(sed -n 2p "${work}/hub.statement")"
if [ "${first}" != "OMINULL-TRUST-BUNDLE-V1" ] || [ "${tenant_line}" != "tenant=${TENANT}" ] \
    || [ "$(sed -n 3p "${work}/hub.statement")" != "epoch=${EPOCH}" ] \
    || [ "$(wc -l < "${work}/hub.statement")" -ne 6 ]; then
    echo "[-] Unexpected statement format; not signing." >&2
    exit 1
fi

echo "[*] Signing the trust bundle for tenant ${TENANT}, epoch ${EPOCH}:"
sed -n '4,6p' "${work}/hub.statement" | sed 's/^/      /'
signing_begin trust "${TENANT}" "${work}/hub.statement"
sign_file "${work}/hub.statement" "${work}/bundle.sig"
if ! verify_sig "${work}/hub.statement" "${work}/bundle.sig"; then
    echo "[-] The bundle signature does not verify against the pinned release key." >&2
    exit 1
fi
sig="$(base64 -w0 < "${work}/bundle.sig")"
printf '{"tenant_id":"%s","epoch":%s,"signature":"%s"}' "${TENANT}" "${EPOCH}" "${sig}" > "${work}/body.json"
hub_call POST /api/v1/trust/bundle -H 'Content-Type: application/json' --data @"${work}/body.json" >/dev/null
echo "[+] Trust bundle for ${TENANT} signed and accepted by the hub; agents pin on their next beat."
