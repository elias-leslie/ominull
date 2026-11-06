#!/usr/bin/env bash
# Build ominull-release-signer and install it: root-owned at /usr/local/sbin (the part that opens the
# key, run through sudo -n) and a link in ~/.local/bin for OMINULL_SIGNING_COMMAND.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
(cd "${ROOT_DIR}/hub" && CGO_ENABLED=0 go build -trimpath -o "${tmp}/ominull-release-signer" ./cmd/ominull-release-signer)
sudo -n install -o root -g root -m 0755 "${tmp}/ominull-release-signer" /usr/local/sbin/ominull-release-signer
mkdir -p "${HOME}/.local/bin"
ln -sfn /usr/local/sbin/ominull-release-signer "${HOME}/.local/bin/ominull-release-signer"
echo "[+] ominull-release-signer installed (/usr/local/sbin, linked in ~/.local/bin)"
