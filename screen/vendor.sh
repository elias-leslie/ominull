#!/usr/bin/env bash
# Regenerate the vendored crate sources for the remote screen crates from their
# Cargo.lock files. cargo checks every downloaded crate against the checksum
# pinned in Cargo.lock, so this cannot drift from what was reviewed. The
# release build (scripts/build-packages.sh) then builds with --offline --locked.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for crate in helper viewer; do
    echo "[*] Vendoring screen/${crate}"
    (cd "${ROOT}/${crate}" && cargo vendor --locked --quiet vendor >/dev/null)
done
echo "[+] Vendored sources are in screen/*/vendor (ignored by git)."
