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
#
# Every agent holds the same admin key, so the hub records an admin-key call as
# "admin" unless the caller names itself in X-Ominull-Agent. The name is
# $OMINULL_AGENT (e.g. "summitflow offsite backup (task-341f8c5b)"), else the
# agent session this runs in: "cc:<id>" (Claude Code) or "codex:<id>", six
# characters of the session id, plus " (Aico <window>)". The hub shows it as
# a claim: agent "cc:f5c210 (Aico b33f5536)" (admin key). A name the hub would
# refuse (over 64 characters, not printable ASCII, quotes, backslashes, a
# leading or trailing space) is left out.
hub_curl_config() {
    local agent="${OMINULL_AGENT:-}" id="${CLAUDE_CODE_SESSION_ID:-}" kind=cc
    if [ -z "${agent}" ]; then
        if [ -z "${id}" ]; then id="${CODEX_THREAD_ID:-}"; kind=codex; fi
        if [ -n "${id}" ]; then agent="${kind}:${id:0:6}${AICO_WIDGET_ID:+ (Aico ${AICO_WIDGET_ID})}"; fi
    fi
    case "${agent}" in *\"*|*\\*|" "*|*" ") agent="" ;; esac
    if [ "${#agent}" -gt 64 ] || [ -n "$(printf '%s' "${agent}" | LC_ALL=C tr -d ' -~')" ]; then agent=""; fi
    printf 'header = "X-API-Key: %s"\n' "$1"
    if [ -n "${agent}" ]; then printf 'header = "X-Ominull-Agent: %s"\n' "${agent}"; fi
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
