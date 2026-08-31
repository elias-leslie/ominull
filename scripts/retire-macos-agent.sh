#!/usr/bin/env bash
# Narrow, idempotent retirement of the removed macOS endpoint agent.
# This is migration tooling only. It never installs or starts an agent.
set -euo pipefail

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=1
elif [ "$#" -ne 0 ]; then
    echo "usage: $0 [--dry-run]" >&2
    exit 2
fi

if [ "${DRY_RUN}" -eq 0 ] && [ "$(uname -s)" != "Darwin" ]; then
    echo "[-] macOS is required for live retirement; use --dry-run to inspect targets." >&2
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

echo "[*] Retiring Ominull macOS endpoint state."

# These are the labels used by released and bootstrap-era launch definitions.
# Only exact Ominull labels are touched; unrelated LaunchDaemons remain loaded.
for label in dev.summitflow.ominull dev.ominull.daemon com.ominull.agent com.ominull.pf com.ominull.mac.daemon; do
    run launchctl bootout "system/${label}" 2>/dev/null || true
    run launchctl remove "${label}" 2>/dev/null || true
done

# Empty the exact Ominull anchor, then reload Apple's main ruleset only when the
# old Ominull wrapper exists. This removes its main-ruleset attachment without
# editing or flushing unrelated anchors.
run pfctl -a ominull_isolation -F all
if [ -f /etc/ominull/pf.conf ]; then
    run pfctl -f /etc/pf.conf
fi

for path in \
    /opt/ominull/ominull_mac_daemon.sh \
    /opt/ominull/pf_engine.sh \
    /opt/ominull/agent.key \
    /opt/ominull/ca.crt \
    /opt/ominull/client.crt \
    /opt/ominull/client.key \
    /opt/ominull/agent.conf \
    /opt/ominull/flowbytes \
    /opt/ominull/updates \
    /opt/ominull/logs \
    /etc/ominull/pf.conf \
    /etc/pf.anchors/ominull_isolation \
    /Library/LaunchDaemons/dev.summitflow.ominull.plist \
    /Library/LaunchDaemons/dev.ominull.daemon.plist \
    /Library/LaunchDaemons/com.ominull.agent.plist \
    /Library/LaunchDaemons/com.ominull.pf.plist \
    /Library/LaunchDaemons/com.ominull.mac.daemon.plist; do
    if [ -d "${path}" ]; then
        run rm -rf -- "${path}"
    else
        run rm -f -- "${path}"
    fi
done
if [ -d /opt/ominull ]; then run rmdir /opt/ominull 2>/dev/null || true; fi
if [ -d /etc/ominull ]; then run rmdir /etc/ominull 2>/dev/null || true; fi
if [ -d /etc/pf.anchors ]; then run rmdir /etc/pf.anchors 2>/dev/null || true; fi

for receipt in com.ominull.agent dev.ominull.daemon dev.summitflow.ominull; do
    if [ "${DRY_RUN}" -eq 1 ]; then
        echo "+ pkgutil --forget ${receipt} (if installed)"
    elif pkgutil --pkg-info "${receipt}" >/dev/null 2>&1; then
        pkgutil --forget "${receipt}" >/dev/null
    fi
done

if [ "${DRY_RUN}" -eq 1 ]; then
    echo "[+] Dry run complete."
    exit 0
fi

if ps -axo command= | grep -F '/opt/ominull/ominull_mac_daemon.sh' | grep -v grep >/dev/null 2>&1; then
    echo "[-] Ominull macOS agent process remains." >&2
    exit 1
fi
for label in dev.summitflow.ominull dev.ominull.daemon com.ominull.agent com.ominull.pf com.ominull.mac.daemon; do
    if launchctl print "system/${label}" >/dev/null 2>&1; then
        echo "[-] Ominull LaunchDaemon remains: ${label}" >&2
        exit 1
    fi
done
if pfctl -s rules 2>/dev/null | grep -Eiq 'ominull|ominull_isolation'; then
    echo "[-] Ominull PF state remains in the active main ruleset." >&2
    exit 1
fi
if find /opt/ominull /etc/ominull /etc/pf.anchors -maxdepth 1 -print 2>/dev/null | grep -Eiq 'ominull'; then
    echo "[-] Ominull filesystem residue remains." >&2
    exit 1
fi

echo "[+] macOS agent retired; unrelated PF configuration and system trust were left intact."
