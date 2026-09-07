# UDP observations and collector coverage

Linux uses an embedded libbpf CO-RE program. It observes UDP send submissions and
receive consumption in the endpoint's network namespace. It records addresses,
ports, direction, payload byte count, process identity and observation time.
It does not copy payload content or change packets or policy. An accepted send
submission is not confirmation of delivery on the network. Repeated `MSG_PEEK`
reads do not count a datagram again. Receive byte counts include the consumed
datagram, including a tail the application discarded with a short read buffer.

Windows runs an actual real-time ETW consumer for the manifest
Microsoft-Windows-Kernel-Network provider. Its session filters event IDs 42/43
and 58/59 for IPv4/IPv6 UDP. The decoder accepts the inspected version-0 layouts;
an unknown layout increments loss rather than being interpreted by guessed offsets.
The native Windows 11 fixture verifies that the size field counts UDP payload bytes.

ETW sessions survive controller crashes. A protected per-owner registry record and
mutex serialize startup. Recovery requires a terminated controller or a different
process creation time, plus the exact recorded session GUID. A reused name alone
never authorizes stopping a trace. Native probes use separate ownership from the
installed agent and verify recovery and mismatched-GUID refusal.

## Identity and timing

The local endpoint remains `src_ip` on both directions. `direction` distinguishes
outbound and inbound observations; ports remain local/remote respectively. A UDP
socket inventory is never emitted as a communication with an invented peer.

Linux retains the observed PID and process start time. It checks the start time
again before reading a path; an exited or recycled PID keeps only the observed
command name. Windows caches process handles and creation times, checks that the
process existed at the event time, and leaves protected/exited processes
unattributed when it cannot establish identity. Process instance IDs use the same
format as TCP lineage. Unknown attribution is not a claim that `System` sent traffic.

Each record carries `observation.source`, `byte_basis`, `timing`, `count`, `first_at`
and `last_at`. Event `timestamp` equals `last_at`. UDP basis is `udp_payload` and
TCP measured deltas use `tcp_socket_counter`; unavailable counters use `unknown`.
TCP timing is `counter_sample`, never packet timing. Queued records retain their
original interval, even when the socket closes before upload.

The wire cap remains 64 records. Each transport gets capacity before spare slots
are lent to the other. Pending flow queues hold at most 1,024 keys per transport
and drain by rotating slots. Queue overflow and failed uploads count as lost
observations. TCP socket scans rotate through bounded candidate windows and report
how many eligible rows were deferred. A scan still cannot recover a TCP socket that
opened and closed entirely between samples.

Endpoint `collector_health` reports source, state, error, cumulative dropped
observations, queued keys, unmeasured TCP readings and deferred socket rows.
`scope_omitted` and `schema_omitted` explain known Windows omissions within the
`dropped` total. `buffers_lost` counts ETW buffers separately; it never pretends to
know how many records a missing buffer contained. Those intervals are marked
`observation.incomplete`. Known link-local omissions do not invalidate unrelated
public-peer cadence. These counters describe coverage, not traffic volume. UDP ring/map loss
is included. Restarted counters are not interpreted as negative loss.

A new-agent beacon finding requires individual, intact socket-I/O observations.
Counter polling, coalesced records and known loss cannot establish packet cadence.
Known collector gaps invalidate earlier histories, including on health-only uploads.
Rate detection compares measured bytes per second over the recorded interval, with
a one-second denominator floor to avoid extrapolating a microsecond burst. Its
baseline and evidence use the same unit. Protocols and byte bases stay separate.
Detector histories are capped at 8,192 entries each; least-recently-used eviction
starts an empty baseline. `GET /api/v1/detection/coverage` reports counts and evictions.

## Coverage limits

Linux needs readable kernel BTF and permission to load/attach BPF. Unsupported
function signatures or restricted containers report `unavailable`; they do not
fall back to fabricated UDP flows. Native fixtures exercised kernels 6.8 and 6.17.
The program observes its network namespace, not every container on a host.

Windows ETW version 0 supplies no interface scope for IPv6 link-local addresses.
Those observations are omitted and counted as loss rather than merging identical
addresses from separate interfaces. IPv6 TCP and enforcement parity are separate
release work. Neither platform claims this collector covers every offload or
alternative kernel I/O path without a native fixture.

## Build and native verification

Build Linux with `clang`, `bpftool`, `libbpf-dev`, `libelf-dev`, `pkg-config` and the
existing native dependencies. `scripts/build-bpf.sh` generates ignored skeleton
artifacts under `build/bpf`; it uses `/sys/kernel/btf/vmlinux`, or an explicit
`OMINULL_VMLINUX_BTF` file. `BPFTOOL` can name the tool binary. Build and package
scripts invoke it automatically. The Linux package requires `libbpf1`.

`scripts/test-native-telemetry.sh` checks bounded retention and full-batch JSON,
and cross-compiles the Windows native probes. Kernel/ETW live fixtures require an
isolated lab and appropriate privileges. `test_udp_live` uses an isolated echo
peer, `test_udp_pressure_live` checks closed sockets and `MSG_PEEK`, and
`test_udp_loopback_live` checks another kernel in an isolated namespace.
`test_udp_windows_live.exe pressure` checks native ETW saturation. Run
`scripts/test-windows-udp.ps1 -BinaryDirectory <native-test-directory>` on the Windows
lab for lifecycle, pressure and serialization checks. Loopback
verification is not cross-host IPv6 or production enforcement verification.

Primary references: [Linux libbpf](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html),
[BPF ring buffer](https://docs.kernel.org/bpf/ringbuf.html),
[Microsoft event-ID filters](https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_event_id).
