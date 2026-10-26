#!/usr/bin/env bash
# check-agent-libbpf.sh [BINARY]: run in the environment that builds the Linux
# agent. Fails when that environment's libbpf is newer than the oldest libbpf
# the agent supports (OMINULL_AGENT_LIBBPF_MAX, default 1.3.0 = Ubuntu 24.04),
# and, with BINARY, when the binary imports a LIBBPF_ symbol version newer than
# that. The skeleton compiled into the agent embeds struct bpf_object_skeleton
# from the build-time libbpf headers; a newer header's layout makes an older
# runtime libbpf misread it (the 1.8.96 agent segfaulted on libbpf 1.3 hosts
# after a build on Ubuntu 26.04's libbpf 1.6.3). The symbol versions alone do
# not show that, so the build-time libbpf is checked directly.
set -euo pipefail
binary="${1:-}"
max="${OMINULL_AGENT_LIBBPF_MAX:-1.3.0}"
newer() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n 1)" != "$2" ]; }
have="$(pkg-config --modversion libbpf)"
if newer "${have}" "${max}"; then
    echo "[-] The build environment has libbpf ${have}; the agent must run on libbpf ${max}. Build it with scripts/build-linux-agent.sh." >&2
    exit 1
fi
if [ -n "${binary}" ]; then
    need="$(objdump -T "${binary}" | grep -oE 'LIBBPF_[0-9]+\.[0-9]+\.[0-9]+' | sed 's/^LIBBPF_//' | sort -V | tail -n 1)"
    if [ -n "${need}" ] && newer "${need}" "${max}"; then
        echo "[-] ${binary} imports libbpf symbols from LIBBPF_${need}; the agent must run on libbpf ${max}." >&2
        exit 1
    fi
fi
printf '%s\n' "${have}"
