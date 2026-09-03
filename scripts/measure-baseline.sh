#!/usr/bin/env bash
# measure-baseline.sh - Automated Phase 0 baseline performance & resource capture
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "=========================================================="
echo "    OMINULL CYBEROPS - PHASE 0 BASELINE MEASUREMENT       "
echo "=========================================================="
date -u +"Date (UTC): %Y-%m-%dT%H:%M:%SZ"

echo ""
echo "[*] System & Hardware Environment:"
echo "  - OS: $(uname -srm)"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "  - Distribution: ${PRETTY_NAME:-Linux}"
fi
CPU_MODEL="$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs || echo "Unknown")"
CPU_CORES="$(nproc || echo "1")"
TOTAL_RAM_KB="$(grep 'MemTotal' /proc/meminfo | awk '{print $2}')"
TOTAL_RAM_MB=$((TOTAL_RAM_KB / 1024))
echo "  - CPU: ${CPU_MODEL} (${CPU_CORES} cores)"
echo "  - Memory: ${TOTAL_RAM_MB} MB RAM"
echo "  - Go: $(go version)"
echo "  - GCC: $(gcc --version | head -n1)"
echo "  - MinGW GCC: $(x86_64-w64-mingw32-gcc --version | head -n1)"

echo ""
echo "[*] 1. Compiling retained binaries..."
./scripts/build.sh >/dev/null
echo "  Binary sizes and SHA-256 digests:"
for bin in build/ominulld build/ominull-hub build/ominulld.exe build/ominull_wfp_user.exe; do
    if [ -f "${bin}" ]; then
        sz="$(stat -c %s "${bin}")"
        sha="$(sha256sum "${bin}" | awk '{print $1}')"
        printf "    %-30s %10d bytes  sha256:%s\n" "${bin}" "${sz}" "${sha}"
    fi
done

echo ""
echo "[*] 2. Measuring package lifecycle execution time..."
LIFECYCLE_START=$(date +%s%N)
./scripts/test-package-lifecycle.sh >/dev/null 2>&1
LIFECYCLE_END=$(date +%s%N)
LIFECYCLE_MS=$(( (LIFECYCLE_END - LIFECYCLE_START) / 1000000 ))
echo "  [+] Package lifecycle verification completed in ${LIFECYCLE_MS} ms"

echo ""
echo "[*] 3. Running Go hub benchmarks (Heartbeat, SQLite, Gate Fail-Closed)..."
(cd hub && go test -bench=Benchmark -benchtime=1s -run=^$ ./pkg/server)

echo ""
echo "[*] 4. Running C agent baseline tests..."
gcc -Wall -Wextra -Wformat=2 -O2 -Iagent/include -o build/test_baseline agent/tests/test_baseline.c -lcurl
./build/test_baseline
rm -f build/test_baseline

echo ""
echo "[*] 5. Running C response cross-language & canonical encoder tests..."
gcc -Wall -Wextra -Wformat=2 -O2 -Iagent/include -o build/test_response_canonical agent/tests/test_response_canonical.c
./build/test_response_canonical hub/tests/fixtures/response/grant_v2_canonical.bin
rm -f build/test_response_canonical

gcc -Wall -Wextra -Wformat=2 -O2 -o build/test_response_fixtures agent/tests/test_response_fixtures.c
./build/test_response_fixtures hub/tests/fixtures/response
rm -f build/test_response_fixtures

echo ""
echo "=========================================================="
echo "[+] Baseline measurement capture successfully complete."
echo "=========================================================="
