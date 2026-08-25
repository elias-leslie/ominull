# Evidence Directory

This directory stores verification artifacts, test transcripts, and diagnostic logs for `wfpsentinel`.

## Structure
- `m0-toolchain/`: WinDbg transcript and loader logs proving build -> sign -> deploy -> break -> unload toolchain.
- `m1-callout/`: Connection inspection logs, `netsh wfp` diffs, and clean unload logs.
- `m2-policy/`: Block/allow policy enforcement traces.
- `m3-telemetry/`: User-mode telemetry stream captures.
- `m6-verifier/`: Driver Verifier configuration, clean-run logs, and deliberate bugcheck stack analysis (`!analyze -v`).
