#!/usr/bin/env bash
# check-agent-glibc.sh BINARY: print the newest glibc symbol version the Linux
# agent needs, and fail when it is newer than the oldest glibc the agent
# supports (OMINULL_AGENT_GLIBC_MAX, default 2.36 = Debian 12). A build on a
# newer host can silently pick up symbols (glibc 2.38's __isoc23_strtol) that
# older hosts lack; such an agent installs and then never starts.
set -euo pipefail
binary="${1:?usage: check-agent-glibc.sh BINARY}"
max="${OMINULL_AGENT_GLIBC_MAX:-2.36}"
need="$(objdump -T "${binary}" | grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' | sed 's/^GLIBC_//' | sort -V | tail -n 1)"
[ -n "${need}" ] || { echo "[-] ${binary}: no glibc symbol versions found" >&2; exit 1; }
if [ "$(printf '%s\n%s\n' "${need}" "${max}" | sort -V | tail -n 1)" != "${max}" ]; then
    echo "[-] ${binary} needs glibc ${need}; the agent must run on glibc ${max}. Symbols:" >&2
    objdump -T "${binary}" | grep -E "GLIBC_${need//./\\.}([^0-9.]|$)" >&2 || true
    exit 1
fi
printf '%s\n' "${need}"
