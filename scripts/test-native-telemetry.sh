#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
bash scripts/build-bpf.sh
for fixture in test_tcp_pending test_telemetry_json; do
    gcc -O2 -Wall -Wextra -Wformat=2 -Iagent/include "agent/tests/${fixture}.c" \
        -o "build/${fixture}" -lcurl -lbpf -lutil
done
build/test_tcp_pending
python3 scripts/test-telemetry-json.py build/test_telemetry_json
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -Iagent/include \
    agent/tests/test_udp_windows_live.c -o build/test_udp_windows_live.exe -lws2_32 -ladvapi32 -lbcrypt
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -Iagent/include \
    agent/tests/test_udp_windows_lifecycle.c -o build/test_udp_windows_lifecycle.exe -lws2_32 -ladvapi32 -lbcrypt
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -Iagent/include \
    agent/tests/test_windows_telemetry_json.c agent/src/hub_client.c agent/src/hub_tls.c \
    -o build/test_windows_telemetry_json.exe -lws2_32 -lwinhttp -liphlpapi -ladvapi32 -lbcrypt -lcrypt32 -lncrypt
