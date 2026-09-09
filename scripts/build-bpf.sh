#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BPF_BUILD="${ROOT_DIR}/build/bpf"
BPF_TOOL="${BPFTOOL:-$(command -v bpftool || true)}"
if [ -z "${BPF_TOOL}" ]; then BPF_TOOL="/usr/lib/linux-tools/$(uname -r)/bpftool"; fi
if [ -z "${BPFTOOL:-}" ] && ! "${BPF_TOOL}" version >/dev/null 2>&1; then
    # Distribution tools packages need not match the running runner kernel.
    for candidate in /usr/lib/linux-tools/*/bpftool; do
        if [ -x "$candidate" ] && "$candidate" version >/dev/null 2>&1; then
            BPF_TOOL="$candidate"
            break
        fi
    done
fi
BTF_INPUT="${OMINULL_VMLINUX_BTF:-/sys/kernel/btf/vmlinux}"
if [ ! -x "${BPF_TOOL}" ] || ! "${BPF_TOOL}" version >/dev/null 2>&1 || [ ! -r "${BTF_INPUT}" ]; then
    echo "BPF build requires bpftool and readable kernel BTF (or OMINULL_VMLINUX_BTF)." >&2
    exit 1
fi
pkg-config --exists libbpf
mkdir -p "${BPF_BUILD}"
"${BPF_TOOL}" btf dump file "${BTF_INPUT}" format c > "${BPF_BUILD}/vmlinux.h"
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I"${BPF_BUILD}" -I"${ROOT_DIR}/agent/include" \
    -c "${ROOT_DIR}/agent/linux/bpf/udp.bpf.c" -o "${BPF_BUILD}/udp.bpf.o"
"${BPF_TOOL}" gen skeleton "${BPF_BUILD}/udp.bpf.o" > "${BPF_BUILD}/udp.skel.h"
