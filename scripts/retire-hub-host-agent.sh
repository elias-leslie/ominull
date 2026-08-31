#!/usr/bin/env bash
# Remove only a co-installed Ominull endpoint agent from the hub host.
# The hub, database, PKI, release directory, and listeners are out of scope.
set -euo pipefail

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=1
elif [ "$#" -ne 0 ]; then
    echo "usage: $0 [--dry-run]" >&2
    exit 2
fi

run() {
    if [ "${DRY_RUN}" -eq 1 ]; then
        printf '+ '
        printf '%q ' "$@"
        printf '\n'
        return 0
    fi
    "$@"
}

echo "[*] Recording hub-host endpoint-agent state before retirement."
for unit in ominull-agent.service ominulld.service; do
    if command -v systemctl >/dev/null 2>&1; then
        echo "    ${unit}: $(systemctl is-active "${unit}" 2>/dev/null || true)"
        echo "    ${unit} main pid: $(systemctl show -p MainPID --value "${unit}" 2>/dev/null || true)"
    fi
done
for tool in iptables ip6tables; do
    if command -v "${tool}" >/dev/null 2>&1; then
        echo "    ${tool} Ominull state:"
        "${tool}" -S 2>/dev/null | grep -E 'OMINULL|ominull' || echo "      (none)"
    else
        echo "    ${tool}: unavailable; no table to clear"
    fi
done

for unit in ominull-agent.service ominulld.service; do
    if command -v systemctl >/dev/null 2>&1; then
        run systemctl stop "${unit}" || true
        run systemctl disable "${unit}" || true
    fi
done

# Let the installed agent perform its own ordered teardown before dpkg removes
# its executable. The fallback below uses exact chain names only.
if [ -x /opt/ominull/bin/ominulld ]; then
    if ! run /opt/ominull/bin/ominulld --cleanup; then
        echo "[*] Installed legacy agent has no cleanup command; applying exact teardown fallback."
    fi
fi
for tool in iptables ip6tables; do
    if command -v "${tool}" >/dev/null 2>&1; then
        for hook in INPUT OUTPUT; do
            for chain in OMINULL_ISO_IN OMINULL_ISO_OUT; do
                if [ "${DRY_RUN}" -eq 1 ]; then
                    echo "+ ${tool} -D ${hook} -j ${chain} (repeat until absent)"
                else
                    while "${tool}" -C "${hook}" -j "${chain}" >/dev/null 2>&1; do
                        "${tool}" -D "${hook}" -j "${chain}"
                    done
                fi
            done
        done
        for chain in OMINULL_ISO_IN OMINULL_ISO_OUT; do
            run "${tool}" -F "${chain}" || true
            run "${tool}" -X "${chain}" || true
        done
    fi
done

if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status}' ominull-agent 2>/dev/null | grep -q 'install ok installed'; then
    run dpkg --purge ominull-agent
fi

# Remove manual registrations left by pre-package releases. These paths are
# agent-specific and do not overlap /opt/ominull/bin/ominull-hub or hub state.
for path in \
    /etc/systemd/system/ominull-agent.service \
    /etc/systemd/system/ominulld.service \
    /etc/init.d/ominull-agent \
    /opt/ominull/bin/ominulld \
    /etc/ominull/agent.conf \
    /etc/ominull/agent.key \
    /etc/ominull/ca.crt \
    /etc/ominull/client.crt \
    /etc/ominull/client.key \
    /var/lib/ominull/updates; do
    if [ -d "${path}" ]; then
        run rm -rf -- "${path}"
    else
        run rm -f -- "${path}"
    fi
done
if command -v systemctl >/dev/null 2>&1; then run systemctl daemon-reload; fi
rmdir /etc/ominull 2>/dev/null || true
rmdir /var/lib/ominull 2>/dev/null || true

if [ "${DRY_RUN}" -eq 1 ]; then
    echo "[+] Dry run complete."
    exit 0
fi

if pgrep -x ominulld >/dev/null 2>&1; then
    echo "[-] Endpoint-agent process remains on hub host." >&2
    exit 1
fi
for unit in ominull-agent.service ominulld.service; do
    if systemctl is-enabled "${unit}" >/dev/null 2>&1 || systemctl is-active "${unit}" >/dev/null 2>&1; then
        echo "[-] Endpoint-agent service remains: ${unit}" >&2
        exit 1
    fi
done
for tool in iptables ip6tables; do
    if command -v "${tool}" >/dev/null 2>&1 && "${tool}" -S 2>/dev/null | grep -Eiq 'OMINULL|ominull'; then
        echo "[-] Ominull firewall state remains in ${tool}." >&2
        exit 1
    fi
done
if ! systemctl is-active --quiet ominull-hub.service; then
    echo "[-] Hub service is not active after endpoint-agent retirement." >&2
    exit 1
fi
if [ ! -s /var/lib/ominull/ominull.db ]; then
    echo "[-] Hub database is missing or empty after endpoint-agent retirement." >&2
    exit 1
fi
for listener in 9999 9443; do
    if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq ":${listener}$"; then
        echo "[-] Hub listener :${listener} is not active after retirement." >&2
        exit 1
    fi
done

echo "[+] Hub-host endpoint agent retired; hub process, database, PKI, and listeners remain healthy."
