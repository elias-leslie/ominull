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
    agent/tests/test_windows_telemetry_json.c agent/src/hub_client.c agent/src/hub_tls.c agent/src/trust_windows.c \
    -o build/test_windows_telemetry_json.exe -lws2_32 -lwinhttp -liphlpapi -ladvapi32 -lbcrypt -lcrypt32 -lncrypt
# Agent trust: the shared grant/manifest/key core against fixtures signed by
# the hub's Go encoders, on both file backends (POSIX here, Win32 on the
# native Windows runner, and under wine when it is installed).
gcc -O2 -Wall -Wextra -Wformat=2 -Iagent/include agent/tests/test_agent_trust.c -o build/test_agent_trust
build/test_agent_trust
# The same vectors under ASan and UBSan: signature and parser arithmetic must
# be defined behaviour, not whatever the optimizer makes of it.
gcc -O1 -g -fsanitize=undefined,address -fno-sanitize-recover=undefined -Wall -Wextra -Iagent/include \
    agent/tests/test_agent_trust.c -o build/test_agent_trust_san
build/test_agent_trust_san >/dev/null
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -Wformat=2 -Iagent/include \
    agent/tests/test_agent_trust.c -o build/test_agent_trust.exe -ladvapi32
if command -v wine >/dev/null 2>&1; then
    WINEDEBUG=-all wine build/test_agent_trust.exe
fi
