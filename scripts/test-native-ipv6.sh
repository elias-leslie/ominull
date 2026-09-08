#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
mkdir -p build
gcc -O2 -Wall -Wextra -Iagent/include agent/tests/test_forensics_ipv6.c -o build/test_forensics_ipv6 -lcurl
build/test_forensics_ipv6
gcc -O2 -Wall -Wextra agent/tests/test_hub_address.c -o build/test_hub_address
build/test_hub_address
gcc -O2 -Wall -Wextra -Iagent/include agent/tests/test_linux_hub_pinhole.c -o build/test_linux_hub_pinhole -lcurl -lbpf -lutil
build/test_linux_hub_pinhole
gcc -O2 -Wall -Wextra -Iagent/include agent/tests/test_linux_isolation_live.c -o build/test_linux_isolation_live -lcurl -lbpf -lutil
for fixture in test_windows_tcp6 test_windows_tcp6_live; do
    x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -DOMINULL_WFP_EMBEDDED \
        -D_WIN32_WINNT=0x0A00 -DNTDDI_VERSION=0x0A000006 -Iagent/include \
        "agent/tests/${fixture}.c" agent/src/hub_client.c agent/src/hub_tls.c \
        agent/src/updater.c agent/src/provenance_windows.c agent/src/response_windows.c \
        agent/windows/wfp_user.c -o "build/${fixture}.exe" \
        -lws2_32 -liphlpapi -ladvapi32 -lbcrypt -lcrypt32 -lncrypt -lwinhttp \
        -lfwpuclnt -lole32 -lpsapi -lwtsapi32
done
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -Iagent/include \
    agent/tests/test_windows_ipv6_json.c agent/src/hub_client.c agent/src/hub_tls.c \
    -o build/test_windows_ipv6_json.exe -lws2_32 -lwinhttp -liphlpapi -ladvapi32 -lbcrypt -lcrypt32 -lncrypt
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -Iagent/include \
    agent/tests/test_wfp_transaction.c -o build/test_wfp_transaction.exe -lws2_32 -lfwpuclnt
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -Iagent/include \
    agent/tests/test_windows_adapter.c agent/src/hub_tls.c -o build/test_windows_adapter.exe \
    -lws2_32 -lwinhttp -liphlpapi -ladvapi32 -lbcrypt -lcrypt32 -lncrypt
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -Iagent/include \
    agent/tests/test_wfp_ipv6_live.c -o build/test_wfp_ipv6_live.exe -lws2_32 -lfwpuclnt -liphlpapi
