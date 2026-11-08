#!/usr/bin/env bash
# build-hub-input.sh [TARGET...]: builds the agent's hub-input library
# (agent/hubinput), for Linux and Windows unless targets are named, offline from
# its vendored, lock-pinned crates, into build/hubinput/<target>/.
# The Linux agent's container build reads the archive from there through /src.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CRATE="${ROOT_DIR}/agent/hubinput"
OUT="${ROOT_DIR}/build/hubinput"

# A fresh CI checkout has no vendor directory: fetch what Cargo.lock pins there.
if [ ! -d "${CRATE}/vendor" ]; then
    if [ "${CI:-}" != "true" ]; then
        echo "[-] agent/hubinput/vendor is missing; run: mv agent/hubinput/.cargo/config.toml{,.off}; (cd agent/hubinput && cargo vendor --locked vendor); mv agent/hubinput/.cargo/config.toml{.off,}" >&2
        exit 1
    fi
    mv "${CRATE}/.cargo/config.toml" "${CRATE}/.cargo/config.toml.off"
    (cd "${CRATE}" && cargo vendor --locked --quiet vendor >/dev/null)
    mv "${CRATE}/.cargo/config.toml.off" "${CRATE}/.cargo/config.toml"
    if command -v rustup >/dev/null; then
        rustup target add x86_64-pc-windows-gnu
    fi
fi

[ "$#" -gt 0 ] || set -- x86_64-unknown-linux-gnu x86_64-pc-windows-gnu
for target in "$@"; do
    (cd "${CRATE}" && \
        RUSTFLAGS="--remap-path-prefix=${ROOT_DIR}=/ominull --remap-path-prefix=${CARGO_HOME:-${HOME}/.cargo}=/cargo" \
        CARGO_TARGET_DIR="${OUT}/target" \
        cargo build --release --locked --offline --target "${target}" --quiet)
    mkdir -p "${OUT}/${target}"
    cp "${OUT}/target/${target}/release/libominull_hubinput.a" "${OUT}/${target}/"
    echo "[+] ${target}: $(wc -c < "${OUT}/${target}/libominull_hubinput.a") bytes"
done
