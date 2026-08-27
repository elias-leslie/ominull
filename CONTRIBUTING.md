# Contributing to Ominull

Thanks for your interest in Ominull.

This repository is published as a working public cyber security platform. Contributions are welcome, with code review and merge decisions handled on a best-effort basis.

## Development & Testing Standards

1. **Safety & Stability:** Kernel driver (`driver/`) and eBPF code (`ebpf/`) must maintain zero-leak cleanup guarantees on unload and pass all local testbench harnesses without BSODs or kernel panics.
2. **Deterministic Quality Gates:** All Go code under `hub/` must pass `go test -v -race ./...` with 100% pass rate. C code must compile cleanly under `-Wall -Wextra -Werror` or equivalent compiler flags.
3. **Secret Hygiene:** Never commit private certificates, API keys, or production tokens. All tests must use synthetic or mock credentials.
4. **Focused Scope:** Keep pull requests modular and focused on specific capabilities, bug fixes, or behavioral heuristics.

## Local Build & Validation

Instructions for building the Go Hub, C agents, and running automated test suites are documented in [README.md](README.md) and [TESTING.md](TESTING.md).

## Licensing

By submitting a pull request, you agree that your contribution will be licensed under the [Apache License, Version 2.0](LICENSE).
