#!/usr/bin/env bash
# build-linux-agent.sh [OUTDIR]: build the shipped Linux agent (BPF object,
# skeleton, ominulld) in a pinned baseline container, so the binary and the
# skeleton match the oldest libbpf/glibc the agent supports instead of
# whatever the build host has. Writes OUTDIR/ominulld (default build/) and
# OUTDIR/udp.skel.h, owned by the calling user, then runs the release gates.
# The repo's own build/bpf (host-built, used by the host tests) is untouched.
#
# OMINULL_AGENT_BUILD_IMAGE overrides the pinned base image; OMINULL_DOCKER
# overrides the docker command (default: docker, or sudo -n docker when the
# user cannot reach the daemon).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="$(realpath -m "${1:-${ROOT_DIR}/build}")"
BASE_IMAGE="${OMINULL_AGENT_BUILD_IMAGE:-ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac}"
BTF_INPUT="${OMINULL_VMLINUX_BTF:-/sys/kernel/btf/vmlinux}"

if [ -n "${OMINULL_DOCKER:-}" ]; then
    read -r -a docker <<<"${OMINULL_DOCKER}"
elif docker info >/dev/null 2>&1; then
    docker=(docker)
else
    docker=(sudo -n docker)
fi
[ -r "${BTF_INPUT}" ] || { echo "[-] Kernel BTF is not readable: ${BTF_INPUT} (set OMINULL_VMLINUX_BTF)" >&2; exit 1; }

# Tagged by input so a changed image or Dockerfile rebuilds and anything else reuses the cache.
tag="ominull-agent-build:$(printf '%s\n' "${BASE_IMAGE}" | cat - "${ROOT_DIR}/packaging/linux/agent/build.Dockerfile" | sha256sum | cut -c1-12)"
echo "[*] Linux agent baseline image ${tag} (${BASE_IMAGE%%@*})."
build_log="$(mktemp "${TMPDIR:-/tmp}/ominull-agent-image.XXXXXX")"
trap 'rm -f "${build_log}"' EXIT
"${docker[@]}" build -q -t "${tag}" --build-arg "BASE_IMAGE=${BASE_IMAGE}" \
    -f "${ROOT_DIR}/packaging/linux/agent/build.Dockerfile" "${ROOT_DIR}/packaging/linux/agent" >"${build_log}" 2>&1 \
    || { cat "${build_log}" >&2; exit 1; }

mkdir -p "${OUT_DIR}"
# The container writes as root-mapped uid of the caller; the mounted source is read-only.
"${docker[@]}" run --rm --user "$(id -u):$(id -g)" --network none \
    -v "${ROOT_DIR}:/src:ro" -v "${OUT_DIR}:/out" -v "${BTF_INPUT}:/btf/vmlinux:ro" \
    -e OMINULL_VMLINUX_BTF=/btf/vmlinux -e HOME=/tmp "${tag}" bash -euo pipefail -c '
        mkdir /tmp/w && cd /tmp/w && cp -r /src/agent /src/scripts . && mkdir build
        bash scripts/check-agent-libbpf.sh >/dev/null
        bash scripts/build-bpf.sh
        gcc -Wall -Wextra -Wformat=2 -O2 -Iagent/include agent/linux/main.c \
            -lbpf -lcurl -lutil -o build/ominulld
        bash scripts/check-agent-libbpf.sh build/ominulld >/dev/null
        bash scripts/check-agent-glibc.sh build/ominulld >/dev/null
        cp build/ominulld /out/ominulld
        cp build/bpf/udp.skel.h /out/udp.skel.h
        echo "[*] Container toolchain: gcc $(gcc -dumpversion), libbpf $(pkg-config --modversion libbpf), $(/usr/lib/linux-tools/*/bpftool version | head -n 1)"'


echo "[*] Linux agent needs glibc $("${ROOT_DIR}/scripts/check-agent-glibc.sh" "${OUT_DIR}/ominulld"); libbpf within the baseline."
