#!/usr/bin/env bash
# Fuzz the agent's hub-input parsers under ASan and UBSan (libFuzzer, clang).
#
#   scripts/fuzz-agent.sh                 fuzz each harness for 60 s (FUZZ_SECONDS)
#   scripts/fuzz-agent.sh --regress       replay the seeds and agent/tests/fuzz/crashes only (release gate)
#   scripts/fuzz-agent.sh NAME...         only these harnesses (fuzz_offers, fuzz_trust_reply, ...)
#
# The working corpus lives in ${FUZZ_DIR:-/srv/scratch/ominull-fuzz} (replaceable). A crash
# lands there as crash-*; copy it into agent/tests/fuzz/crashes/<harness>/ with the fix so
# --regress keeps it fixed. Run through admission: st tools run --label "ominull agent fuzz" -- scripts/fuzz-agent.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_SRC="${ROOT_DIR}/agent/tests/fuzz"
WORK="${FUZZ_DIR:-/srv/scratch/ominull-fuzz}"
SECONDS_EACH="${FUZZ_SECONDS:-60}"
CC="${FUZZ_CC:-clang}"
regress=0
names=()
for a in "$@"; do
    case "$a" in
        --regress) regress=1 ;;
        -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
        fuzz_*) names+=("$a") ;;
        *) echo "unknown argument: $a" >&2; exit 2 ;;
    esac
done
[ "${#names[@]}" -gt 0 ] || names=(fuzz_offers fuzz_trust_reply fuzz_term_frame fuzz_cert_renewal)

declare -A libs=([fuzz_offers]="-lcurl -lutil" [fuzz_trust_reply]="" [fuzz_term_frame]="" [fuzz_cert_renewal]="")

mkdir -p "${WORK}/bin" "${WORK}/seeds"
"${CC}" -O1 -Wall -o "${WORK}/bin/gen_seeds" "${FUZZ_SRC}/gen_seeds.c"
rm -rf "${WORK}/seeds"
"${WORK}/bin/gen_seeds" "${WORK}/seeds"

export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:abort_on_error=1}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1:halt_on_error=1}"
failed=0
for n in "${names[@]}"; do
    [ -f "${FUZZ_SRC}/${n}.c" ] || { echo "no harness ${n}" >&2; exit 2; }
    # shellcheck disable=SC2086
    "${CC}" -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
        -Wall -Wextra -I"${ROOT_DIR}/agent/include" "${FUZZ_SRC}/${n}.c" -o "${WORK}/bin/${n}" ${libs[$n]}
    inputs=("${WORK}/seeds/${n}")
    [ -d "${FUZZ_SRC}/crashes/${n}" ] && inputs+=("${FUZZ_SRC}/crashes/${n}")
    if [ "${regress}" -eq 1 ]; then
        files=()
        for d in "${inputs[@]}"; do for f in "${d}"/*; do [ -f "$f" ] && files+=("$f"); done; done
        if "${WORK}/bin/${n}" -runs=0 "${files[@]}" >"${WORK}/${n}.log" 2>&1; then
            echo "[+] ${n}: ${#files[@]} inputs replay clean"
        else
            echo "[-] ${n}: replay failed (${WORK}/${n}.log)"; tail -30 "${WORK}/${n}.log"; failed=1
        fi
        continue
    fi
    corpus="${WORK}/corpus/${n}"
    mkdir -p "${corpus}" "${WORK}/artifacts/${n}"
    if "${WORK}/bin/${n}" -max_total_time="${SECONDS_EACH}" -max_len=65536 -timeout=10 -rss_limit_mb=4096 \
        -artifact_prefix="${WORK}/artifacts/${n}/" "${corpus}" "${inputs[@]}" >"${WORK}/${n}.log" 2>&1; then
        echo "[+] ${n}: $(grep -E '^#[0-9]+.*DONE' "${WORK}/${n}.log" | tail -1 | sed 's/  */ /g')"
    else
        echo "[-] ${n}: crash, see ${WORK}/artifacts/${n}/ and ${WORK}/${n}.log"; failed=1
    fi
done
exit "${failed}"
