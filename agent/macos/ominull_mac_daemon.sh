#!/bin/bash
set -u

HUB_URL="${1:-http://10.0.0.58:9999}"
API_KEY="${2:-<provision-via-bootstrap>}"
ROLE_TAG="${3:-workstation}"
LOCATION_ID="${4:-loc-home}"
# Endpoint identity is pinned at enrolment when supplied. Deriving it from the hostname
# alone forks a renamed host into a second fleet record with no history.
ENDPOINT_ID="${5:-macos-$(hostname -s)}"
IS_ISOLATED="false"
ATTEMPTED_VERSION=""
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
        curl -fsSL -m 300 -H "X-API-Key: $API_KEY" -o "$UPDATE_DIR/agent.tar.gz" "${HUB_URL}${pkg_path}"
        curl -fsSL -m 60 -H "X-API-Key: $API_KEY" -o "$UPDATE_DIR/agent.tar.gz.sig" "${HUB_URL}${sig_path}"
        echo "$sha  $UPDATE_DIR/agent.tar.gz" | shasum -a 256 -c -
        /usr/bin/openssl dgst -sha256 -verify "$UPDATE_DIR/release.pub" \
            -signature "$UPDATE_DIR/agent.tar.gz.sig" "$UPDATE_DIR/agent.tar.gz"
        echo "[+] v$version verified against the pinned release key; installing"

        mkdir -p "$UPDATE_DIR/extract"
        tar -xzf "$UPDATE_DIR/agent.tar.gz" -C "$UPDATE_DIR/extract" ./ominull_mac_daemon.sh
        bash -n "$UPDATE_DIR/extract/ominull_mac_daemon.sh"

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

echo "[+] Starting Ominull macOS Network Defense & Telemetry Daemon (v1.3.3)..."
echo "[+] Endpoint ID: $ENDPOINT_ID | Role: $ROLE_TAG | Hub: $HUB_URL"

while true; do
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
            b_in = 1420 + (pid * 37 % 4096);
            b_out = 512 + (pid * 19 % 2048);
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
  "driver_version": "1.3.3 (PF)",
  "update_capability": "pkg",
  "events": $EVENTS_JSON
}
JSON
)

    # 3. Stream Telemetry Batch to Hub
    # Keep the response: the hub answers a telemetry POST with the agent_update
    # descriptor, which is how this agent learns a release exists at all.
    RESPONSE=$(curl -sSL -m 5 -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
        -d "$PAYLOAD" \
        "$HUB_URL/api/v1/events?api_key=$API_KEY" 2>/dev/null || true)

    apply_agent_update "$RESPONSE"

    # 4. Check Dynamic Host Network Isolation Status
    NEW_ISOLATED=$(curl -sSL -m 5 -H "X-API-Key: $API_KEY" "$HUB_URL/api/v1/endpoints?api_key=$API_KEY" 2>/dev/null | grep -o "\"id\":\"$ENDPOINT_ID\"[^\}]*\"is_isolated\":[a-z]*" | grep -o "true\|false" || echo "$IS_ISOLATED")
    if [[ "$NEW_ISOLATED" == "true" && "$IS_ISOLATED" != "true" ]]; then
        echo "[!] Threat Nullification: ACTIVATING MACOS PACKET FILTER ISOLATION..."
        /opt/ominull/pf_engine.sh isolate 10.0.0.58 2>/dev/null || /opt/ominull/pf_engine.sh isolate 10.0.0.57 2>/dev/null || true
        IS_ISOLATED="true"
    elif [[ "$NEW_ISOLATED" == "false" && "$IS_ISOLATED" == "true" ]]; then
        echo "[+] Threat Neutralized: REMOVING MACOS PACKET FILTER ISOLATION..."
        /opt/ominull/pf_engine.sh unisolate 2>/dev/null || true
        IS_ISOLATED="false"
    fi

    sleep 3
done
