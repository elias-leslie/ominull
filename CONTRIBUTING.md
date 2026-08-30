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

Ominull™ is released under the [Business Source License 1.1](LICENSE) (`BUSL-1.1`): free in production for individuals, education and small non-profits, and free for everyone to evaluate, develop and test. Businesses, public-sector bodies, larger non-profits, and anyone delivering a paid service with it need a commercial licence. Each version converts to Apache 2.0 two years after it is published. See the [LICENSE](LICENSE) for the exact wording.

By submitting a pull request, you agree that:

1. You own the copyright in your contribution, or have the right to submit it.
2. Your contribution is licensed to the project under the terms of the [LICENSE](LICENSE) file.
3. You grant Elias Leslie a perpetual, irrevocable, worldwide, royalty-free right to relicense your contribution under any other licence terms, including a commercial licence.

Point 3 exists so the project can keep the arrangement that funds it — free for the uses listed in the README, licensed commercially for the rest — without having to track down every past contributor. It does not take anything from you: you keep the copyright in your own work and may use it however you like.

If you would rather not grant that, open an issue describing the change instead of a pull request and it can be implemented independently.
