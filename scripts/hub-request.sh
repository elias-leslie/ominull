#!/bin/bash
# hub_post HUB_URL KEY_VAR PATH BODY
#
# POST a JSON request to the hub and print the answer; fails on a non-2xx
# status. The hub authorizes admin actions itself, so there is nothing to wait
# for. KEY_VAR names the variable holding the API key (never on a command line).

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

hub_post() {
    local hub="$1" keyvar="$2" path="$3" body="$4" out code
    hub_url_safe "${hub}" || return 1
    exec 3< <(hub_curl_config "${!keyvar}" "${hub}")
    out="$(curl -sS --connect-timeout 5 --max-time 40 -K /dev/fd/3 -w '\n%{http_code}' -X POST \
        -H 'Content-Type: application/json' --data "${body}" "${hub}${path}")" || return 1
    code="${out##*$'\n'}"
    printf '%s\n' "${out%$'\n'*}"
    [ "${code:0:1}" = 2 ]
}
