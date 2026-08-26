#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-1.0.0}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${PROJECT_ROOT}/dist"

echo "========================================================="
echo "  Building Ominull Enterprise Release Matrix (v${VERSION})"
echo "========================================================="

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}/bin"

# 1. Build Multi-Platform Hub
echo "[+] Compiling Ominull Multi-Tenant Hub (Linux AMD64)..."
(
    cd "${PROJECT_ROOT}/hub"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.version=${VERSION}" -o "${DIST_DIR}/bin/ominull-hub" cmd/main.go
)

# 2. Build Linux Agent
echo "[+] Compiling Ominull Linux eBPF Agent..."
(
    cd "${PROJECT_ROOT}/agent/linux"
    make
    cp "${PROJECT_ROOT}/build/ominulld" "${DIST_DIR}/bin/ominulld-linux-amd64"
)

# 3. Build Windows Kernel Driver & User-Mode Control Suite
echo "[+] Compiling Windows WFP Kernel Driver & CLI..."
(
    cd "${PROJECT_ROOT}"
    ./scripts/build.sh
    ./scripts/sign.sh
)

# 4. Package Artifacts
echo "[+] Packaging Distribution Bundles..."

# Hub Tarball
tar -czf "${DIST_DIR}/ominull-hub-v${VERSION}-linux-amd64.tar.gz" -C "${DIST_DIR}/bin" ominull-hub

# Linux Agent Bundle
tar -czf "${DIST_DIR}/ominull-agent-v${VERSION}-linux-amd64.tar.gz" -C "${DIST_DIR}/bin" ominulld-linux-amd64

# Windows Agent Bundle
(
    cd "${PROJECT_ROOT}"
    zip -q -j "${DIST_DIR}/ominull-agent-v${VERSION}-windows-x64.zip" build/ominull.sys build/ominullctl.exe certs/ominull_test.cer
)

# 5. Generate Checksums
echo "[+] Generating Cryptographic SHA256 Checksums..."
(
    cd "${DIST_DIR}"
    sha256sum *.tar.gz *.zip > SHA256SUMS.txt
)

echo "========================================================="
echo "  Release Packages Successfully Generated in dist/"
echo "========================================================="
ls -lh "${DIST_DIR}"
cat "${DIST_DIR}/SHA256SUMS.txt"
