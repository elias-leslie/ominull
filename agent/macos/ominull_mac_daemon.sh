#!/bin/bash
set -u

# Kept in step with the banner and the reported driver_version by
# scripts/version.sh, which owns every site the release version appears in.
AGENT_VERSION="1.7.13"

# Answered before anything else is parsed. The arguments below are positional,
# so without this "--version" is read as the hub URL and the daemon starts
# against a hub of that name instead of printing anything - the same trap the
# Linux and Windows agents had, where an unrecognised argument silently
# launched an unsupervised agent.
if [[ "${1:-}" == "--version" ]]; then
    echo "${AGENT_VERSION}"
    exit 0
fi

HUB_URL="${1:-https://10.0.0.58:9443}"
API_KEY="${2:-<provision-via-bootstrap>}"
# The second argument may be the key or the path to a file holding it. `ps` on
# macOS shows every argument of every process to every local account, and a
# LaunchDaemon's arguments are on screen for as long as it runs - so the key
# passed inline was the fleet's shared tenant credential, permanently readable
# by anyone with a shell on this Mac. A path is not a secret; the file is 0600.
API_KEY_FILE=""
if [[ -f "$API_KEY" && -r "$API_KEY" ]]; then
    API_KEY_FILE="$API_KEY"
    API_KEY="$(head -n 1 "$API_KEY_FILE" | tr -d '\r\n')"
    if [[ -z "$API_KEY" ]]; then
        echo "[-] API key file $API_KEY_FILE holds no key on its first line." >&2
        exit 1
    fi
fi
ROLE_TAG="${3:-workstation}"
LOCATION_ID="${4:-loc-home}"
# Endpoint identity is pinned at enrolment when supplied. Deriving it from the hostname
# alone forks a renamed host into a second fleet record with no history.
ENDPOINT_ID="${5:-macos-$(hostname -s)}"
# The hub's CA, planted by enrolment. Every connection below is verified against
# this file and nothing else - not the system keychain, which any admin-installed
# anchor could widen without anyone noticing.
CA_PATH="${6:-/opt/ominull/ca.crt}"
# This endpoint's own certificate, issued by the hub at enrolment. Presenting it
# is what lets the hub tell one endpoint from another: the API key is shared by
# every agent on the tenant, so on its own it proves membership and not identity.
# Both halves have to be readable before either is passed to curl - handing curl
# a --cert it cannot open fails the request outright, which would turn a
# half-finished enrolment into a host that has stopped reporting rather than one
# that has simply not started presenting a certificate yet.
CLIENT_CERT="${7:-/opt/ominull/client.crt}"
CLIENT_KEY="${8:-/opt/ominull/client.key}"
IS_ISOLATED="false"
# A sentinel, not an empty list: the first beat must reconcile unconditionally,
# which is what picks up state applied before this daemon restarted.
APPLIED_PEERS="__unreconciled__"
APPLIED_ALLOW="__unreconciled__"
APPLIED_BASELINE="__unreconciled__"
# The dead-man timer. An isolation the hub cannot lift is not a containment, it
# is a lost endpoint - so a host that has been isolated and has then failed this
# many consecutive heartbeats releases itself and says so. Beats are three
# seconds apart, so 100 is five minutes: long enough to outlast a hub restart, a
# brief network event or a rolling release, and short enough that the person who
# just isolated the host is still watching when it comes back.
DEADMAN_BEATS=100
MISSED_BEATS=0
DEADMAN_NOTE=""
ATTEMPTED_VERSION=""
# The helper repair below runs at most once per daemon start.
HELPER_REPAIR_TRIED=false
# Bounded retry, not a single shot: a dropped download would otherwise wedge this
# host on the offered version until launchd restarted the daemon, while retrying
# forever would refetch an unverifiable package every heartbeat.
ATTEMPT_COUNT=0

# Releases are staged here, never in /tmp. The directory is created root-owned
# and unreadable to anyone else, so a downloaded package cannot be swapped
# between the moment its signature is verified and the moment it is installed.
UPDATE_DIR="/opt/ominull/updates"

# The Ominull release signing key, pinned into this agent. Trust deliberately
# does not route through the hub: a package is installed only if it verifies
# against this key, so a compromised hub - or anyone on the plain-HTTP LAN path
# to it - can serve whatever it likes and none of it will be installed.
read -r -d '' OMINULL_RELEASE_PUBKEY <<'PUBKEY' || true
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE71CpMPEGtyUpx3ZSuvcf+YMiwM1F
0e6k7D05y7jLxXQblk3d7ZirBH3MNJlo7aUbtmlQ2izz/u5wTG2ztJ9TBw==
-----END PUBLIC KEY-----
PUBKEY

# ---------------------------------------------------------------------------
# Hub transport
#
# The telemetry payload, the API key that authenticates it and the isolation
# state read back from the hub all cross the LAN on every pass of the loop. On
# plain HTTP every one of those is readable and forgeable by anyone on the path,
# so the transport is checked before the first byte is sent.
#
# There is no fallback. A daemon that cannot verify the hub keeps its packet
# filter rules exactly as they are and repeats the reason; it never retries in
# the clear, because a silent downgrade is what an on-path attacker is trying
# to provoke.
# ---------------------------------------------------------------------------

# Every hub connection goes through hub_curl, which pins the CA: trust this one
# and no other, and refuse a redirect off TLS - without that a redirect to
# http:// would carry the API key to the next hop in the clear.
#
# The odd-looking expansion is for macOS's bash 3.2, where "${arr[@]}" on an
# empty array is an unbound variable under set -u. The array is empty exactly in
# the deliberate plaintext case, which is the one that must not crash the daemon
# in a different way than it already warns about.
HUB_CURL_ARGS=()
if [[ "$HUB_URL" == https://* ]]; then
    HUB_CURL_ARGS=(--cacert "$CA_PATH" --proto "=https" --proto-redir "=https")
    if [[ -r "$CLIENT_CERT" && -r "$CLIENT_KEY" ]]; then
        HUB_CURL_ARGS+=(--cert "$CLIENT_CERT" --key "$CLIENT_KEY")
    fi
fi

# The credential reaches curl through a pipe rather than an argument, for the
# same reason the key itself is read from a file: -H "X-API-Key: ..." put it in
# `ps` output on every heartbeat, once per request, for every local account to
# read. curl's own config syntax quotes the value, so the two characters that
# syntax reserves are escaped on the way in.
hub_curl_credentials() {
    local escaped
    escaped="$(printf '%s' "$API_KEY" | sed -e 's/[\\"]/\\&/g')"
    printf 'header = "X-API-Key: %s"\n' "$escaped"
}

hub_curl() {
    curl -K <(hub_curl_credentials) ${HUB_CURL_ARGS[@]+"${HUB_CURL_ARGS[@]}"} "$@"
}

LAST_TRANSPORT_COMPLAINT=0
# Repeats at most once a minute: the failure persists until an operator fixes
# it, and a line every three seconds would bury everything else in the log.
report_transport_refusal() {
    local now
    now=$(date +%s)
    if [[ "$LAST_TRANSPORT_COMPLAINT" -ne 0 && $((now - LAST_TRANSPORT_COMPLAINT)) -lt 60 ]]; then
        return 0
    fi
    LAST_TRANSPORT_COMPLAINT="$now"
    echo "[!] Refusing to talk to the hub: $1" >&2
}

# --cacert is passed above and is not, on its own, a pin here. Apple's curl is
# built MultiSSL and defaults to Secure Transport, which accepts --cacert and
# then ignores it: trust comes from the system keychain instead. A rogue CA
# handed to curl on this platform still reaches the hub, and an impostor holding
# any keychain-trusted certificate would be reached just the same. That is the
# silent downgrade this whole change exists to prevent, so the pin is proved
# separately, before anything carrying the API key is sent.
#
# openssl does enforce -CAfile, so the hub's certificate is fetched and checked
# against the enrolled CA directly. openssl checks the chain, not the name; the
# name is what Secure Transport checks on the request itself, so between them
# both halves are covered.
#
# Cached: long enough that the three-second telemetry loop is not opening a
# handshake of its own each pass, short enough that a replaced hub identity is
# caught quickly.
PIN_REVALIDATE_SECS=900
PIN_LAST_OK=0

hub_pin_ok() {
    local now hostport host port leaf
    now=$(date +%s)
    if [[ "$PIN_LAST_OK" -ne 0 && $((now - PIN_LAST_OK)) -lt "$PIN_REVALIDATE_SECS" ]]; then
        return 0
    fi

    hostport="${HUB_URL#https://}"
    hostport="${hostport%%/*}"
    host="${hostport%%:*}"
    port="${hostport##*:}"
    [[ "$port" == "$host" ]] && port=443

    # No -servername for a bare address: SNI carries host names, not IPs.
    local sni=()
    case "$host" in
        *[!0-9.]*) sni=(-servername "$host") ;;
    esac

    # The probe has to introduce itself like any other request. A hub started
    # with --client-certs required asks for a certificate during this handshake
    # too, and s_client with none to offer sends an empty one - which the hub
    # rejects and logs as "client didn't provide a certificate". The pin still
    # passed, because the server's certificate arrives before the client's is
    # asked for, but a hub log filling with that line trains an operator to
    # ignore the one message that means an endpoint really has lost its
    # identity.
    local pincert=()
    if [[ -r "$CLIENT_CERT" && -r "$CLIENT_KEY" ]]; then
        pincert=(-cert "$CLIENT_CERT" -key "$CLIENT_KEY")
    fi

    leaf=$(/usr/bin/openssl s_client -connect "$host:$port" ${sni[@]+"${sni[@]}"} \
               ${pincert[@]+"${pincert[@]}"} \
               -showcerts </dev/null 2>/dev/null | /usr/bin/openssl x509 2>/dev/null)
    if [[ -z "$leaf" ]]; then
        report_transport_refusal "no TLS handshake with $host:$port, so the hub could not prove its identity."
        return 1
    fi
    if ! printf '%s\n' "$leaf" | /usr/bin/openssl verify -CAfile "$CA_PATH" /dev/stdin >/dev/null 2>&1; then
        report_transport_refusal "the certificate $host:$port presented does not chain to the CA this endpoint was enrolled with. Something other than the hub answered, and nothing it says will be acted on."
        return 1
    fi

    PIN_LAST_OK="$now"
    return 0
}

hub_transport_ready() {
    if [[ "$HUB_URL" != https://* ]]; then
        if [[ "${OMINULL_ALLOW_PLAINTEXT:-0}" == "1" ]]; then
            return 0
        fi
        report_transport_refusal "the configured hub URL is not https://. Re-enrol this endpoint against the hub's TLS address, or set OMINULL_ALLOW_PLAINTEXT=1 to accept a cleartext transport deliberately."
        return 1
    fi
    if [[ ! -r "$CA_PATH" ]]; then
        report_transport_refusal "the CA certificate $CA_PATH cannot be read. Enrolment installs it; without it the hub's identity cannot be checked."
        return 1
    fi
    hub_pin_ok
}

# json_field pulls one string value out of a flat JSON object body.
json_field() {
    printf '%s' "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"
}

# hub_path takes only the path from a descriptor URL, and only if it points at
# the hub's package route. The advertised host is ignored on purpose: behind a
# reverse proxy the hub legitimately advertises a host the agent does not dial,
# and ignoring it means no hub response can redirect the download elsewhere.
hub_path() {
    case "$1" in
        *[!A-Za-z0-9./:_~%+-]*) return 1 ;;
    esac
    case "$1" in
        */download/*) ;;
        *) return 1 ;;
    esac
    printf '%s' "/download/${1##*/download/}"
}

# The hub answers a rejected batch with a status and a body, and curl calls that
# success. report_hub_rejection makes the refusal visible: an endpoint whose
# credentials the hub no longer accepts is otherwise indistinguishable, in this
# log, from one that is working - it posts every few seconds, curl exits 0, and
# nothing is written. The only place it shows is the hub's last_seen column.
#
# Rate-limited to once a minute, because a rejection repeats on every heartbeat
# and a line every few seconds would bury the one that says when it started.
HUB_STATUS_MARKER="OMINULL_HTTP:"
HUB_REJECT_LAST=0
HUB_REJECT_STATUS=""
HUB_EVER_ACCEPTED=""

report_hub_rejection() {
    local status="$1" now
    case "$status" in
        ""|2??)
            if [[ -n "$HUB_REJECT_STATUS" ]]; then
                echo "[+] The hub is accepting telemetry again (HTTP ${status:-none})."
                HUB_REJECT_STATUS=""
            elif [[ -z "$HUB_EVER_ACCEPTED" && -n "$status" ]]; then
                # Reported from evidence rather than at startup: a daemon that
                # says it is connected before it has posted anything tells an
                # operator nothing about whether it can reach the hub.
                HUB_EVER_ACCEPTED=1
                echo "[+] The hub accepted this endpoint's first telemetry batch (HTTP $status)."
            fi
            return 1
            ;;
    esac

    now=$(date +%s)
    if [[ "$status" != "$HUB_REJECT_STATUS" ]] || (( now - HUB_REJECT_LAST >= 60 )); then
        if [[ "$status" == "403" && -r "$CLIENT_CERT" ]]; then
            # 403 while presenting a certificate is the identity check and not
            # the key: the hub compares the name in the certificate against the
            # endpoint id being reported and refuses the two disagreeing.
            echo "[!] The hub refused this endpoint's telemetry with HTTP $status. It reports as \"$ENDPOINT_ID\", which is not the endpoint named by $CLIENT_CERT; re-enrol or correct the id in the LaunchDaemon plist. Nothing is being recorded until it is fixed."
        elif [[ "$status" == "401" || "$status" == "403" ]]; then
            echo "[!] The hub refused this endpoint's telemetry with HTTP $status. The API key in the LaunchDaemon plist is not one it accepts; nothing is being recorded until it is fixed."
        else
            echo "[!] The hub refused this endpoint's telemetry with HTTP $status; nothing is being recorded."
        fi
        HUB_REJECT_LAST=$now
        HUB_REJECT_STATUS="$status"
    fi
    return 0
}

# apply_agent_update installs a newer agent when the hub offers one, and only
# after proving the package is genuine. Any failure leaves the running agent
# exactly as it is.
apply_agent_update() {
    local resp="$1" block version url sig_url sha pkg_path sig_path target
    block=$(printf '%s' "$resp" | sed -n 's/.*"agent_update":{\([^}]*\)}.*/\1/p')
    [[ -z "$block" ]] && return 0

    version=$(json_field "$block" version)
    url=$(json_field "$block" url)
    sig_url=$(json_field "$block" signature)
    sha=$(json_field "$block" sha256)

    [[ -z "$version" ]] && return 0
    if [[ "$version" != "$ATTEMPTED_VERSION" ]]; then
        ATTEMPTED_VERSION="$version"
        ATTEMPT_COUNT=0
    fi
    [[ "$ATTEMPT_COUNT" -ge 3 ]] && return 0
    ATTEMPT_COUNT=$((ATTEMPT_COUNT + 1))

    if [[ "$(id -u)" != "0" ]]; then
        echo "[!] Agent v$version is available but this daemon is not running as root; skipping self-update."
        return 0
    fi
    # No signature, no install. There is no degraded mode worth having: an
    # unverified root install is precisely the thing being prevented.
    if [[ -z "$url" || -z "$sig_url" || -z "$sha" ]]; then
        echo "[!] Rejected agent update v$version: the hub offered it without a signature and digest."
        return 0
    fi
    if [[ ! "$sha" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "[!] Rejected agent update v$version: advertised digest is not a SHA-256 hex string."
        return 0
    fi
    pkg_path=$(hub_path "$url") || { echo "[!] Rejected agent update v$version: package is not on a hub download path."; return 0; }
    sig_path=$(hub_path "$sig_url") || { echo "[!] Rejected agent update v$version: signature is not on a hub download path."; return 0; }

    # Replace this script at the path launchd actually started it from, rather
    # than a hardcoded one, so a non-default install is upgraded correctly.
    target="$0"
    if [[ "$target" != /* || ! -f "$target" ]]; then
        echo "[!] Rejected agent update v$version: cannot resolve this daemon's own path."
        return 0
    fi

    rm -rf "$UPDATE_DIR"
    mkdir -p "$UPDATE_DIR" || return 0
    chown root:wheel "$UPDATE_DIR" 2>/dev/null || true
    chmod 700 "$UPDATE_DIR" || return 0

    echo "[*] Hub published agent v$version; fetching and verifying before install."
    (
        set -e
        printf '%s\n' "$OMINULL_RELEASE_PUBKEY" > "$UPDATE_DIR/release.pub"
        chmod 600 "$UPDATE_DIR/release.pub"
        hub_curl -fsSL -m 300 -o "$UPDATE_DIR/agent.tar.gz" "${HUB_URL}${pkg_path}"
        hub_curl -fsSL -m 60 -o "$UPDATE_DIR/agent.tar.gz.sig" "${HUB_URL}${sig_path}"
        echo "$sha  $UPDATE_DIR/agent.tar.gz" | shasum -a 256 -c -
        /usr/bin/openssl dgst -sha256 -verify "$UPDATE_DIR/release.pub" \
            -signature "$UPDATE_DIR/agent.tar.gz.sig" "$UPDATE_DIR/agent.tar.gz"
        echo "[+] v$version verified against the pinned release key; installing"

        mkdir -p "$UPDATE_DIR/extract"
        tar -xzf "$UPDATE_DIR/agent.tar.gz" -C "$UPDATE_DIR/extract" ./ominull_mac_daemon.sh
        bash -n "$UPDATE_DIR/extract/ominull_mac_daemon.sh"

        # The helper is upgraded with the daemon, from the same signed archive.
        # It used to be left at whatever version the original bootstrap wrote,
        # so a daemon that had learned a new enforcement verb was calling a
        # helper that did not know it: the host was reported isolated and stayed
        # on the network. Archives from before the helper was included still
        # install, they just leave the existing one alone.
        if tar -xzf "$UPDATE_DIR/agent.tar.gz" -C "$UPDATE_DIR/extract" ./pf_engine.sh 2>/dev/null; then
            bash -n "$UPDATE_DIR/extract/pf_engine.sh"
            chown root:wheel "$UPDATE_DIR/extract/pf_engine.sh"
            chmod 755 "$UPDATE_DIR/extract/pf_engine.sh"
            mv -f "$UPDATE_DIR/extract/pf_engine.sh" /opt/ominull/pf_engine.sh
            echo "[+] Packet filter helper updated from the same signed archive."
        else
            echo "[!] v$version carries no pf_engine.sh; keeping the installed helper." >&2
        fi

        # Only the script is replaced. The installed LaunchDaemon plist carries
        # this host's pinned endpoint id, hub URL and API key; the one in the
        # package carries placeholders, so overwriting it would change the
        # host's identity and break its auth.
        #
        # And never write over this script in place: bash reads a script
        # incrementally as it runs, so rewriting the file underneath the running
        # shell splices new bytes into the current execution. Renaming swaps the
        # directory entry while this process keeps its original inode.
        chown root:wheel "$UPDATE_DIR/extract/ominull_mac_daemon.sh"
        chmod 755 "$UPDATE_DIR/extract/ominull_mac_daemon.sh"
        mv -f "$UPDATE_DIR/extract/ominull_mac_daemon.sh" "$target"
    )
    if [[ $? -ne 0 ]]; then
        echo "[!] Agent update v$version failed verification or install; staying on the running version."
        rm -rf "$UPDATE_DIR"
        return 0
    fi

    rm -rf "$UPDATE_DIR"
    echo "[+] Agent updated to v$version; exiting so launchd restarts from the new script."
    exit 0
}

echo "[+] Starting Ominull macOS Network Defense & Telemetry Daemon (v1.7.13)..."
echo "[+] Endpoint ID: $ENDPOINT_ID | Role: $ROLE_TAG | Hub: $HUB_URL"
if [[ "$HUB_URL" == https://* ]]; then
    echo "[+] Hub trust: TLS, pinned to $CA_PATH"
    if [[ -r "$CLIENT_CERT" && -r "$CLIENT_KEY" ]]; then
        echo "[+] Identity: client certificate $CLIENT_CERT"
    else
        echo "[+] Identity: API key only (no client certificate at $CLIENT_CERT)"
    fi
else
    echo "[+] Hub trust: NONE - cleartext transport"
fi

# pf_engine runs the packet filter helper, and refuses to run it unless root
# owns it and nobody else can write it.
#
# This daemon runs as root, so whatever it executes runs as root. The helper is
# downloaded by the installer, and on this fleet it was found owned by a local
# account: anyone who could write that file owned the next isolation event. The
# check is here as well as in the installer because the file outlives the
# install - an upgrade, a restore or a stray editor can hand it back.
# hub_address_literal reduces HUB_URL to an address.
#
# Isolation has to leave a hole for the hub or it can never be lifted. This used
# to be the literal 10.0.0.58 with 10.0.0.57 as a fallback - the placeholder
# addresses the public repository substitutes for the real ones - so isolating a
# Mac on this fleet would have pinholed a host that is not the hub and stranded
# it with no way back. It comes from the configured hub URL now.
hub_address_literal() {
    local host="${HUB_URL#*://}"
    host="${host%%/*}"
    host="${host%%:*}"
    [[ -z "$host" ]] && return 1
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        printf '%s' "$host"
        return 0
    fi
    local resolved
    resolved=$(dscacheutil -q host -a name "$host" 2>/dev/null | awk '/^ip_address:/ {print $2; exit}')
    [[ -z "$resolved" ]] && resolved=$(host -t A "$host" 2>/dev/null | awk '/has address/ {print $4; exit}')
    [[ -z "$resolved" ]] && return 1
    printf '%s' "$resolved"
}

# repair_pf_engine reinstalls the packet filter helper from this agent's own
# signed release archive.
#
# Older daemons upgraded themselves and left the helper behind, so a Mac could
# end up running a current daemon against a helper from its original bootstrap -
# one that did not implement the verb it was being given. Nothing detected it:
# the hub recorded the quarantine, the daemon announced it, the helper printed
# its usage banner, and the host kept routing. A daemon that finds itself in
# that state now fixes it instead of waiting for someone to notice.
#
# The archive is fetched at this daemon's own version, from the hub's download
# path, and is installed only if the detached signature verifies against the
# pinned release key - the same trust root as any update. There is no
# unverified fallback.
repair_pf_engine() {
    local helper="/opt/ominull/pf_engine.sh"
    local archive="ominull-agent-macos-${AGENT_VERSION}.tar.gz"

    [[ "$(id -u)" == "0" ]] || { echo "[!] The packet filter helper is stale, but this daemon is not root and cannot replace it." >&2; return 1; }

    echo "[*] Repairing the packet filter helper from the signed v${AGENT_VERSION} archive."
    rm -rf "$UPDATE_DIR/repair"
    mkdir -p "$UPDATE_DIR/repair" || return 1
    chmod 700 "$UPDATE_DIR/repair" || return 1
    (
        set -e
        printf '%s\n' "$OMINULL_RELEASE_PUBKEY" > "$UPDATE_DIR/repair/release.pub"
        chmod 600 "$UPDATE_DIR/repair/release.pub"
        hub_curl -fsSL -m 300 -o "$UPDATE_DIR/repair/agent.tar.gz" "${HUB_URL}/download/${archive}"
        hub_curl -fsSL -m 60 -o "$UPDATE_DIR/repair/agent.tar.gz.sig" "${HUB_URL}/download/${archive}.sig"
        /usr/bin/openssl dgst -sha256 -verify "$UPDATE_DIR/repair/release.pub" \
            -signature "$UPDATE_DIR/repair/agent.tar.gz.sig" "$UPDATE_DIR/repair/agent.tar.gz"
        tar -xzf "$UPDATE_DIR/repair/agent.tar.gz" -C "$UPDATE_DIR/repair" ./pf_engine.sh
        bash -n "$UPDATE_DIR/repair/pf_engine.sh"
        chown root:wheel "$UPDATE_DIR/repair/pf_engine.sh"
        chmod 755 "$UPDATE_DIR/repair/pf_engine.sh"
        mv -f "$UPDATE_DIR/repair/pf_engine.sh" "$helper"
    )
    local rc=$?
    rm -rf "$UPDATE_DIR/repair"
    if [[ $rc -ne 0 ]]; then
        echo "[-] Could not repair the packet filter helper; this host cannot enforce the hub's decisions. Reinstall the agent bundle." >&2
        return 1
    fi
    echo "[+] Packet filter helper repaired and verified."
    return 0
}

# json_ip_list reduces one flat JSON array of address literals to a
# comma-separated list.
#
# Anything that is not an address literal is dropped rather than passed on. The
# helper writes these straight into a pf rule file, so an entry the hub did not
# validate would be read by pfctl as syntax rather than as an address.
json_ip_list() {
    printf '%s' "$1" \
        | sed -n "s/.*\"$2\":\\[\\([^]]*\\)\\].*/\\1/p" \
        | tr -d '" ' | tr ',' '\n' \
        | grep -E '^([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7})$' \
        | sort -u | paste -sd, -
}

# json_baseline flattens the resolved baseline policy the hub sends into the
# records pf_engine takes: service|destination|protocol|port, comma separated.
# The pipe is the field separator because an IPv6 destination is full of colons.
#
# Three answers, and they mean different things:
#   __legacy__  the hub sent no baseline key at all - a hub too old to have a
#               policy. The built-in permits stay; tightening the floor under a
#               fleet whose hub never asked for it would cut hosts off.
#   __none__    the hub sent an empty policy. Hub and loopback only. Obeyed.
#   records     the policy, as rules.
#
# Everything here is re-validated even though the hub validated it: these values
# are written straight into a pf rule file, and pfctl reads an unexpected entry
# as syntax rather than as an address.
json_baseline() {
    local body records
    printf '%s' "$1" | grep -q '"isolation_baseline":' || { printf '__legacy__'; return 0; }
    body=$(printf '%s' "$1" | sed -n 's/.*"isolation_baseline":\[\([^]]*\)\].*/\1/p')
    records=$(printf '%s' "$body" | tr '}' '\n' | awk '
        {
            s = ""; d = ""; p = ""; pt = "";
            if (match($0, /"service":"[^"]*"/))     s  = substr($0, RSTART+11, RLENGTH-12);
            if (match($0, /"destination":"[^"]*"/)) d  = substr($0, RSTART+15, RLENGTH-16);
            if (match($0, /"protocol":"[^"]*"/))    p  = substr($0, RSTART+12, RLENGTH-13);
            if (match($0, /"port":[0-9]+/))         pt = substr($0, RSTART+7,  RLENGTH-7);
            if (s == "" || d == "" || pt == "") next;
            if (p != "udp" && p != "tcp") next;
            if (pt+0 < 1 || pt+0 > 65535) next;
            # Interval expressions are deliberately avoided: this awk is not
            # guaranteed to support them, and a regex that silently never
            # matched would drop every rule and read as an empty policy.
            if (d !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && d !~ /^[0-9A-Fa-f:]+$/) next;
            print s "|" d "|" p "|" pt;
        }' | paste -sd, -)
    if [[ -z "$records" ]]; then
        printf '__none__'
    else
        printf '%s' "$records"
    fi
}

# observed_services_json reports what this host actually uses the network for at
# the infrastructure layer, so the hub can check the baseline policy against
# reality rather than against an assumption. It reports; it never authors.
observed_services_json() {
    local sep="" out="[" iface pkt server ns
    for ns in $(scutil --dns 2>/dev/null | awk '/nameserver\[[0-9]+\]/ {print $3}' | sort -u); do
        case "$ns" in
            *:*) ;;
            *[!0-9.]*) continue ;;
        esac
        out="${out}${sep}{\"service\":\"dns\",\"destination\":\"${ns}\",\"source\":\"scutil --dns\"}"
        sep=","
    done
    iface=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}' | head -1)
    if [[ -n "$iface" ]]; then
        pkt=$(ipconfig getpacket "$iface" 2>/dev/null || true)
        server=$(printf '%s' "$pkt" | awk '/server_identifier/ {print $NF}' | tr -d '{}' | head -1)
        if [[ -n "$server" ]]; then
            out="${out}${sep}{\"service\":\"dhcp\",\"destination\":\"${server}\",\"source\":\"ipconfig getpacket\"}"
            sep=","
        fi
    fi
    printf '%s]' "$out"
}

# address_origin says whether the DHCP permit is on this host's critical path at
# all. A statically addressed host does not lose its address when a lease it does
# not have fails to renew.
address_origin() {
    local iface
    iface=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}' | head -1)
    if [[ -n "$iface" ]] && ipconfig getpacket "$iface" >/dev/null 2>&1; then
        printf 'dhcp'
    else
        printf 'static'
    fi
}

# enforcement_engine_status answers "can this agent apply rules at all", which is
# what decides whether an isolation would be a containment or a host taken off
# the network with nothing underneath it. Computed once: the failures it looks
# for - no helper, a helper that is not root-owned, a pf that will not enable -
# do not come and go between heartbeats.
enforcement_engine_status() {
    if [[ -n "${ENFORCEMENT_STATUS:-}" ]]; then
        printf '%s' "$ENFORCEMENT_STATUS"
        return 0
    fi
    local helper="/opt/ominull/pf_engine.sh" meta owner mode
    if ! meta=$(stat -f '%Su %Lp' "$helper" 2>/dev/null); then
        ENFORCEMENT_STATUS="the packet filter helper is not installed at $helper"
    else
        owner="${meta%% *}"; mode="${meta##* }"
        if [[ "$owner" != "root" ]]; then
            ENFORCEMENT_STATUS="the packet filter helper is owned by $owner, not root, so it will not be run"
        elif (( (8#$mode & 8#022) != 0 )); then
            ENFORCEMENT_STATUS="the packet filter helper is mode $mode: writable by group or other, so it will not be run"
        elif ! grep -q -- '--baseline)' "$helper" 2>/dev/null; then
            ENFORCEMENT_STATUS="the installed packet filter helper predates the baseline policy, so it would apply the old permissive floor"
        elif ! pfctl -s info >/dev/null 2>&1; then
            ENFORCEMENT_STATUS="pfctl would not report its state, so pf cannot be driven on this host"
        else
            ENFORCEMENT_STATUS="ok"
        fi
    fi
    printf '%s' "$ENFORCEMENT_STATUS"
}

# deadman_tick is the backstop the readiness gate cannot be. The gate is a
# prediction made before the host is cut off; this is what happens when the
# prediction was wrong.
#
# Without it, a defect in the isolation floor means a host is gone until somebody
# reaches it out of band. With it, the same defect means the host comes back
# after five minutes and reports why - a containment that did not hold, which is
# recoverable and loud, rather than an endpoint that is lost.
#
# The release rebuilds rather than tears down: the mesh quarantine this host was
# also holding is not this timer's to lift. Only the default-deny goes.
deadman_tick() {
    if [[ "$1" == "accepted" ]]; then
        if [[ -n "$DEADMAN_NOTE" ]]; then
            echo "[+] The hub is reachable again after a dead-man release. Its current answer decides what this host enforces from here."
            DEADMAN_NOTE=""
        fi
        MISSED_BEATS=0
        return 0
    fi
    if [[ "$IS_ISOLATED" != "true" ]]; then
        MISSED_BEATS=0
        return 0
    fi
    MISSED_BEATS=$((MISSED_BEATS + 1))
    (( MISSED_BEATS >= DEADMAN_BEATS )) || return 0

    echo "[!] Isolated, and the hub has not answered for $MISSED_BEATS consecutive heartbeats. Releasing this host's isolation: an isolation the hub cannot lift is not a containment, it is a lost endpoint." >&2
    if pf_engine apply --isolated 0 --hub "" --allow "" --peers "$APPLIED_PEERS" --baseline "$APPLIED_BASELINE"; then
        IS_ISOLATED="false"
        # Forget what was applied so the hub's next answer is treated as new and
        # the isolation is re-applied if it still wants one.
        APPLIED_PEERS="__unreconciled__"
        APPLIED_ALLOW="__unreconciled__"
        APPLIED_BASELINE="__unreconciled__"
        DEADMAN_NOTE="released by the dead-man timer after losing contact with the hub"
    else
        echo "[-] The dead-man release failed; this host is still isolated and still cannot reach the hub." >&2
    fi
    MISSED_BEATS=0
}

pf_engine() {
    local helper="/opt/ominull/pf_engine.sh"
    local meta
    if ! meta=$(stat -f '%Su %Lp' "$helper" 2>/dev/null); then
        echo "[-] $helper is missing; isolation cannot be applied." >&2
        return 1
    fi
    local owner="${meta%% *}" mode="${meta##* }"
    if [[ "$owner" != "root" ]]; then
        echo "[-] $helper is owned by $owner, not root. Refusing to run it as root." >&2
        return 1
    fi
    if (( (8#$mode & 8#022) != 0 )); then
        echo "[-] $helper is mode $mode: writable by group or other. Refusing to run it as root." >&2
        return 1
    fi
    # A helper that does not implement the subcommand prints its usage banner and
    # exits non-zero, which is indistinguishable at a glance from a rule that
    # failed to load. Say which it is: a stale helper is an upgrade problem and
    # needs a different fix than a pfctl error.
    # The verb is only half the question. The baseline isolation policy arrived
    # as a new *option* on an existing verb, and a helper that has `apply)` but
    # not `--baseline` does not print a usage banner - it hits the unknown-option
    # arm and exits 1, so the host enforces nothing at all. Both are checked, and
    # each names a capability rather than a version number.
    local missing=""
    if ! grep -q "^[[:space:]]*${1}[)|]" "$helper" 2>/dev/null; then
        missing="the '${1}' command"
    elif [[ "$*" == *--baseline* ]] && ! grep -q -- '--baseline)' "$helper" 2>/dev/null; then
        missing="the --baseline option, so the isolation floor it applied would be the old permissive one"
    fi
    if [[ -n "$missing" ]]; then
        echo "[-] $helper does not implement $missing: it is older than this daemon, so the hub's order cannot be carried out on this host." >&2
        if [[ "$HELPER_REPAIR_TRIED" == "true" ]]; then
            return 1
        fi
        HELPER_REPAIR_TRIED=true
        repair_pf_engine || return 1
        if ! grep -q "^[[:space:]]*${1}[)|]" "$helper" 2>/dev/null \
           || { [[ "$*" == *--baseline* ]] && ! grep -q -- '--baseline)' "$helper" 2>/dev/null; }; then
            echo "[-] The repaired helper still does not implement $missing." >&2
            return 1
        fi
    fi
    "$helper" "$@"
}

while true; do
    if ! hub_transport_ready; then
        deadman_tick missed
        sleep 3
        continue
    fi

    # Report nothing rather than something invented. A fixed fallback address
    # and a shared placeholder MAC used to stand in here; both are harmful now
    # that the hub keys asset identity on what the agent reports, because every
    # Mac that failed detection would land on one asset record. Empty lets the
    # hub fall back to the connection's own address and to address-plus-subnet
    # identity. Note the MAC pipeline ends in awk, which succeeds on no input,
    # so the old `|| echo` fallback was mostly unreachable anyway.
    IP=$(ipconfig getifaddr en0 2>/dev/null || ifconfig | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | head -n 1)
    MAC=$(ifconfig en0 2>/dev/null | awk '/ether/ {print $2; exit}')

    # Report the OS this machine actually runs. A hardcoded literal here is the
    # same defect v1.2.0 removed from the Windows agent: the hub records what an
    # agent reports as a first-party claim at full confidence, so a wrong string
    # outranks real scan evidence and never ages out.
    OS_STR="$(sw_vers -productName 2>/dev/null || echo macOS) $(sw_vers -productVersion 2>/dev/null) ($(uname -m))"

    # 1. Collect active socket flows with process name & PID
    EVENTS_JSON=$(lsof -iTCP -iUDP -n -P 2>/dev/null | awk '
    BEGIN { first = 1; printf "[" }
    /->/ {
        cmd = $1; pid = $2; proto = $8;
        split($9, ep, "->");
        split(ep[1], src, ":");
        split(ep[2], dst, ":");
        if (dst[1] != "" && dst[2] != "" && dst[1] != "0.0.0.0" && dst[1] != "127.0.0.1") {
            if (!first) printf ",";
            first = 0;
            # Zero, not a hash of the pid. These were
            # 1420 + (pid * 37 % 4096) and 512 + (pid * 19 % 2048), sent as
            # measured traffic and totalled on the console as bandwidth. lsof
            # reports which sockets are open, not how much has crossed them.
            b_in = 0;
            b_out = 0;
            proc_path = (cmd ~ /^\//) ? cmd : ("/Applications/" cmd);
            printf "{\"layer\":\"PF_SOCKET\",\"action\":\"PERMIT\",\"direction\":\"OUTBOUND\",\"protocol\":%s,\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%d,\"dst_port\":%d,\"bytes_in\":%d,\"bytes_out\":%d,\"process_path\":\"%s\",\"process_id\":%d}", (proto == "TCP" ? 6 : 17), src[1], dst[1], src[2], dst[2], b_in, b_out, proc_path, pid;
        }
    }
    END { printf "]" }
    ')

    if [[ -z "$EVENTS_JSON" || "$EVENTS_JSON" == "" ]]; then
        EVENTS_JSON="[]"
    fi

    # 2. Build full telemetry batch payload
    PAYLOAD=$(cat << JSON
{
  "type": "telemetry",
  "endpoint_id": "$ENDPOINT_ID",
  "tenant_id": "default",
  "location_id": "$LOCATION_ID",
  "role": "$ROLE_TAG",
  "hostname": "$(hostname -s)",
  "os": "$OS_STR",
  "ip": "$IP",
  "mac": "$MAC",
  "driver_version": "1.7.13 (PF)",
  "update_capability": "pkg",
  "events": $EVENTS_JSON,
  "observed_services": $(observed_services_json),
  "isolation_readiness": {
    "enforcement_engine": "$(enforcement_engine_status)",
    "hub_literal": "$(hub_address_literal || true)",
    "address_origin": "$(address_origin)",
    "last_applied": "$DEADMAN_NOTE"
  }
}
JSON
)

    # 3. Stream Telemetry Batch to Hub
    # Keep the response: the hub answers a telemetry POST with the agent_update
    # descriptor, which is how this agent learns a release exists at all.
    # stderr is deliberately not discarded: a rejected certificate is the one
    # failure this daemon must not swallow, and it used to look exactly like the
    # hub being unreachable.
    #
    # -w appends the status, because curl without -f calls a 401 a success: the
    # body arrives, the exit status is 0, and a daemon the hub is refusing looks
    # exactly like a healthy one in this log. -f would report it but discard the
    # body, and the body is what carries the agent_update descriptor.
    # The body goes down stdin, not into an argument: the payload carries every
    # process path this daemon observed, and `ps` would put all of it on screen
    # for every local account. The key is gone from the URL for the same reason
    # it left the argument list - a query string is copied into every access log
    # on the path, and the header already carries it.
    RESPONSE=$(printf '%s' "$PAYLOAD" | hub_curl -sSL -m 5 -w "\n${HUB_STATUS_MARKER}%{http_code}" \
        -X POST -H "Content-Type: application/json" --data-binary @- \
        "$HUB_URL/api/v1/events" || true)
    HUB_STATUS=$(printf '%s' "$RESPONSE" | sed -n "s/^${HUB_STATUS_MARKER}//p" | tail -1)
    RESPONSE=${RESPONSE%%$'\n'${HUB_STATUS_MARKER}*}

    # A refused batch carries no descriptor and no isolation state worth acting
    # on, so the rest of this pass is skipped rather than run against an error
    # body. The loop's own cadence is kept.
    if report_hub_rejection "$HUB_STATUS"; then
        deadman_tick missed
        sleep 3
        continue
    fi
    deadman_tick accepted

    apply_agent_update "$RESPONSE"

    # 4. Enforce what the hub decided: isolation, and the mesh peer list.
    #
    # Both come off the heartbeat reply now. Isolation used to need a second
    # request to /api/v1/endpoints, which handed every agent the whole fleet
    # list to find one boolean about itself; the quarantined-peer list was in
    # this reply all along and this agent ignored it, so a mesh quarantine
    # reached the Linux endpoints and no Mac.
    NEW_ISOLATED=$(printf '%s' "$RESPONSE" | sed -n 's/.*"is_isolated":\([a-z]*\).*/\1/p' | head -1)
    [[ "$NEW_ISOLATED" == "true" || "$NEW_ISOLATED" == "false" ]] || NEW_ISOLATED="$IS_ISOLATED"

    NEW_PEERS=$(json_ip_list "$RESPONSE" quarantined_peers)
    NEW_ALLOW=$(json_ip_list "$RESPONSE" isolation_allow_ips)
    # grep -c, not wc -l: the list has no trailing newline, so wc counts one
    # fewer than there are entries and reported "0 allow-listed address(es)"
    # for a list that had one in it.
    NEW_ALLOW_COUNT=0
    [[ -n "$NEW_ALLOW" ]] && NEW_ALLOW_COUNT=$(printf '%s' "$NEW_ALLOW" | tr ',' '\n' | grep -c .)

    # The baseline isolation policy: what this host is still permitted to reach
    # while it is cut off. It replaces the DNS-and-DHCP-to-anywhere permits that
    # used to be written into this helper.
    NEW_BASELINE=$(json_baseline "$RESPONSE")
    NEW_BASELINE_COUNT=0
    case "$NEW_BASELINE" in
        __legacy__|__none__) ;;
        *) NEW_BASELINE_COUNT=$(printf '%s' "$NEW_BASELINE" | tr ',' '\n' | grep -c .) ;;
    esac

    if [[ "$NEW_ISOLATED" != "$IS_ISOLATED" || "$NEW_PEERS" != "$APPLIED_PEERS" \
          || "$NEW_ALLOW" != "$APPLIED_ALLOW" || "$NEW_BASELINE" != "$APPLIED_BASELINE" ]]; then
        if [[ "$NEW_ISOLATED" == "true" ]]; then
            if HUB_IP=$(hub_address_literal); then
                if [[ "$NEW_BASELINE" == "__legacy__" ]]; then
                    echo "[!] Threat Nullification: isolating this host. This hub sends no baseline policy, so the built-in floor applies: hub $HUB_IP, loopback, DHCP and DNS to any destination, $NEW_ALLOW_COUNT allow-listed address(es)."
                else
                    echo "[!] Threat Nullification: isolating this host. Permitted: hub $HUB_IP, loopback, $NEW_BASELINE_COUNT baseline rule(s), $NEW_ALLOW_COUNT allow-listed address(es)."
                fi
                if pf_engine apply --isolated 1 --hub "$HUB_IP" --allow "$NEW_ALLOW" --peers "$NEW_PEERS" --baseline "$NEW_BASELINE"; then
                    IS_ISOLATED="true"
                    APPLIED_PEERS="$NEW_PEERS"
                    APPLIED_ALLOW="$NEW_ALLOW"
                    APPLIED_BASELINE="$NEW_BASELINE"
                else
                    # The order is not recorded as applied, so the next beat
                    # tries again. Swallowing this is what let a Mac report
                    # itself quarantined while it was still routing.
                    echo "[-] The packet filter helper refused or failed; this host is NOT isolated. Retrying on the next heartbeat." >&2
                fi
            else
                # Refused deliberately: an isolation with no hole for the hub can
                # never be lifted by the hub. The order stands and is retried on
                # the next beat.
                echo "[-] Isolation ordered, but the hub address could not be resolved from $HUB_URL. Refusing to isolate: this host could not be released afterwards." >&2
            fi
        else
            [[ "$IS_ISOLATED" == "true" ]] && echo "[+] Threat neutralized: lifting host isolation."
            HUB_IP=$(hub_address_literal || true)
            if pf_engine apply --isolated 0 --hub "$HUB_IP" --allow "" --peers "$NEW_PEERS" --baseline "$NEW_BASELINE"; then
                IS_ISOLATED="false"
                APPLIED_PEERS="$NEW_PEERS"
                APPLIED_ALLOW="$NEW_ALLOW"
                APPLIED_BASELINE="$NEW_BASELINE"
            else
                echo "[-] The packet filter helper refused or failed; this host's enforcement state is unchanged. Retrying on the next heartbeat." >&2
            fi
        fi
    fi

    sleep 3
done
