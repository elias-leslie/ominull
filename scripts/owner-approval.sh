#!/bin/bash
# owner_approved HUB_URL KEY_VAR PATH BODY
#
# POST a request the hub holds for the owner's phone approval. The hub answers
# 202 with an approval id; this waits for the owner's decision on the phone,
# then sends the same body again with X-Approval-ID, which the hub accepts
# once. KEY_VAR names the variable holding the API key (never on a command line).

# The hub key travels over TLS, checked against the hub CA that enrolment pins
# on every agent (OMINULL_HUB_CA, default /etc/ominull/ca.crt), or to a
# loopback listener on the hub host itself; never as plain HTTP on the LAN.
hub_url_safe() {
    case "$1" in
        https://*|http://127.0.0.1:*|http://localhost:*) return 0 ;;
    esac
    echo "[-] Refusing to send the hub key to $1 over plain HTTP; use https://HUB:9443." >&2
    return 1
}

# hub_curl_config KEY URL: a curl -K config with the key header and, for an
# HTTPS hub, the hub CA. Read it from a descriptor, never a command line.
hub_curl_config() {
    printf 'header = "X-API-Key: %s"\n' "$1"
    case "$2" in https://*) printf 'cacert = "%s"\n' "${OMINULL_HUB_CA:-/etc/ominull/ca.crt}" ;; esac
}

owner_approved() {
    local hub="$1" keyvar="$2" path="$3" body="$4" out code id state=""
    hub_url_safe "${hub}" || return 1
    _oa_curl() {
        exec 3< <(hub_curl_config "${!keyvar}" "${hub}")
        curl -sS --connect-timeout 5 --max-time 40 -K /dev/fd/3 "$@"
    }
    out="$(_oa_curl -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' --data "${body}" "${hub}${path}")" || return 1
    code="${out##*$'\n'}"
    out="${out%$'\n'*}"
    if [ "${code}" != 202 ]; then
        printf '%s\n' "${out}"
        [ "${code:0:1}" = 2 ]
        return
    fi
    id="$(jq -r '.approval_id // empty' <<<"${out}")"
    [ -n "${id}" ] || { printf '%s\n' "${out}"; return 1; }
    echo "[*] Owner approval needed: $(jq -r '(.action // "") + " - " + (.summary // "")' <<<"${out}")" >&2
    echo "    Approve on the phone (approval ${id}, expires $(jq -r '.expires_at // "?"' <<<"${out}"))." >&2
    for _ in $(seq 1 60); do
        state="$(_oa_curl "${hub}/api/v1/approvals?wait=20&id=${id}" | jq -r '.state // empty')" || state=""
        case "${state}" in
            approved) break ;;
            denied | expired | consumed)
                echo "[-] Approval ${id} was ${state}." >&2
                return 1
                ;;
            "") sleep 2 ;;
        esac
    done
    [ "${state}" = approved ] || { echo "[-] No owner decision on approval ${id}." >&2; return 1; }
    out="$(_oa_curl -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' -H "X-Approval-ID: ${id}" \
        --data "${body}" "${hub}${path}")" || return 1
    code="${out##*$'\n'}"
    printf '%s\n' "${out%$'\n'*}"
    [ "${code:0:1}" = 2 ]
}
