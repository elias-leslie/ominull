#!/usr/bin/env bash
# The Rust hub-input library: its unit tests, the differential test against the
# agent's C readers, and the agent's own tests with the library in place of them,
# on Linux and on Windows under wine.
#
#   scripts/test-agent-hub-input.sh [--mutations N] [DIR-OR-FILE...]
#
# Extra paths (a fuzz corpus, say) are replayed along with the seeds and saved
# crashes. Run through admission: st tools run --label "ominull hub input" -- scripts/test-agent-hub-input.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${ROOT_DIR}/build/hubinput"
FUZZ_SRC="${ROOT_DIR}/agent/tests/fuzz"
mutations=20000
if [ "${1:-}" = "--mutations" ]; then mutations="$2"; shift 2; fi

(cd "${ROOT_DIR}/agent/hubinput" && cargo test --locked --offline --quiet)
"${ROOT_DIR}/scripts/build-hub-input.sh"

WORK="$(mktemp -d "${BUILD}/diff.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT
gcc -O1 -Wall -o "${WORK}/gen_seeds" "${FUZZ_SRC}/gen_seeds.c"
"${WORK}/gen_seeds" "${WORK}/seeds" >/dev/null

# A throwaway key and one signature for the P-256 comparison.
P256="${WORK}/p256"
mkdir -p "${P256}"
openssl ecparam -name prime256v1 -genkey -noout -out "${P256}/key.pem" 2>/dev/null
openssl ec -in "${P256}/key.pem" -pubout -out "${P256}/pub.pem" 2>/dev/null
openssl ec -in "${P256}/key.pem" -pubout -outform DER 2>/dev/null | tail -c 64 > "${P256}/xy.bin"
printf 'OMINULL-TEST-MESSAGE\n' > "${P256}/msg"
openssl dgst -sha256 -sign "${P256}/key.pem" -out "${P256}/sig.der" "${P256}/msg"
rm -f "${P256}/key.pem"

gcc -g -O1 -Wall -Wextra -I"${ROOT_DIR}/agent/include" "${FUZZ_SRC}/test_hub_input_diff.c" \
    "${BUILD}/x86_64-unknown-linux-gnu/libominull_hubinput.a" -o "${WORK}/diff" -lcurl -lutil
HUB_INPUT_P256="${P256}" "${WORK}/diff" --mutations "${mutations}" "${WORK}/seeds" "${FUZZ_SRC}/crashes" "$@"

if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 && command -v wine >/dev/null 2>&1; then
    x86_64-w64-mingw32-gcc -g -O1 -Wall -Wextra -D_WIN32_WINNT=0x0A00 -I"${ROOT_DIR}/agent/include" "${FUZZ_SRC}/test_hub_input_diff.c" \
        "${BUILD}/x86_64-pc-windows-gnu/libominull_hubinput.a" -o "${WORK}/diff.exe" \
        -lws2_32 -lwinhttp -liphlpapi -ladvapi32 -lbcrypt -lcrypt32 -lncrypt -lole32 -lpsapi -lwtsapi32 -luserenv -lntdll
    HUB_INPUT_P256="${P256}" WINEDEBUG=-all wine "${WORK}/diff.exe" --mutations "${mutations}" "${WORK}/seeds" "${FUZZ_SRC}/crashes" "$@"
else
    echo "[~] no mingw or wine here: the Windows side was not run"
fi

# The agent's tests with the library switched in, as the shipped agent builds it.
LIB_LINUX="${BUILD}/x86_64-unknown-linux-gnu/libominull_hubinput.a"
LIB_WIN="${BUILD}/x86_64-pc-windows-gnu/libominull_hubinput.a"
cd "${ROOT_DIR}"
agent_test() { # name args...
    local name="$1" libs="$2"
    shift 2
    # shellcheck disable=SC2086
    gcc -O2 -Wall -Wextra -Wformat=2 -DOMINULL_HUB_INPUT -Iagent/include "agent/tests/${name}.c" "${LIB_LINUX}" -o "${WORK}/${name}" ${libs}
    "${WORK}/${name}" "$@" >"${WORK}/${name}.log" 2>&1 || { tail -40 "${WORK}/${name}.log"; echo "[-] ${name} failed with the library"; exit 1; }
    echo "[+] ${name} (library)"
}
agent_test test_terminal_frame ""
agent_test test_response_dispatcher ""
agent_test test_agent_trust ""
agent_test test_cert_renewal ""
agent_test test_script_exec_linux ""
agent_test test_agent_update_linux ""
agent_test test_terminal_linux "-lcurl -lutil"
agent_test test_forensics_linux ""
agent_test test_response_canonical "" hub/tests/fixtures/response/grant_v2_canonical.bin
agent_test test_response_fixtures "" hub/tests/fixtures/response

if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 && command -v wine >/dev/null 2>&1; then
    WIN_LIBS="-lws2_32 -lwinhttp -liphlpapi -ladvapi32 -lbcrypt -lcrypt32 -lncrypt -lole32 -lpsapi -lwtsapi32 -luserenv -lshlwapi -lrpcrt4"
    agent_test_win() {
        local name="$1" libs="$2"
        # shellcheck disable=SC2086
        x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -Wformat=2 -DOMINULL_HUB_INPUT -Iagent/include "agent/tests/${name}.c" "${LIB_WIN}" -o "${WORK}/${name}.exe" ${libs} ${WIN_LIBS}
        WINEDEBUG=-all wine "${WORK}/${name}.exe" >"${WORK}/${name}.win.log" 2>&1 || { tail -40 "${WORK}/${name}.win.log"; echo "[-] ${name}.exe failed with the library"; exit 1; }
        echo "[+] ${name}.exe (library)"
    }
    agent_test_win test_response_dispatcher_win ""
    agent_test_win test_agent_trust ""
    agent_test_win test_script_exec_windows ""
    agent_test_win test_terminal_windows ""
    agent_test_win test_forensics_windows ""
fi
