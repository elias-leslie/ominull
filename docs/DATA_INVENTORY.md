# Data inventory

OmniNull collects, Nightshift decides. The Linux agent reports what data a host holds as metadata only; the hub keeps
the latest picture and hands a bounded copy to Nightshift (findings contract v3), which classifies it and turns it into
a per-asset data map, posture deductions and drift findings.

## Agent (Linux)

`agent/include/data_inventory_linux.h` (walker, sandbox, scheduling) and `data_inventory_core.h` (rules, policy parser,
document). The header comment of the Linux file is the reference. In short:

- The scan runs in a forked child: only CAP_DAC_READ_SEARCH and CAP_FOWNER, no_new_privs, RLIMIT_FSIZE 0, a seccomp
  allow-list with no write, rename, unlink, exec, fork or socket syscall (openat must carry O_NOFOLLOW and no write
  flags), nice 19, SCHED_IDLE, idle I/O class.
- No symlinks, only regular files and directories, one filesystem, no network/FUSE/pseudo filesystems. Caches and
  regenerable trees (CACHEDIR.TAG, node_modules, .cache, virtualenvs, ...) are skipped by rule.
- Canary paths are skipped by path before any stat or open.
- Budgets per run (max_files, max_seconds, content_budget_bytes); a resumable cursor saved only after the hub accepted
  the run (HTTP 200); a full cycle every full_every_days, otherwise content is re-read only for changed files.
- Secret detection runs in the child. A file leaves the host as a rule id, mode, owner, size and mtime; never content,
  matched text or a hash of it. A file the run could not read (content budget, open error) keeps its last verdict.
- Paths are reported in the contract's encoding: `%`, C0/DEL/C1 control bytes and bytes that are not valid UTF-8
  become `%XX`, so every name is a printable, valid string and distinct names stay distinct. Times before 1970 are
  reported as 0.

The agent fetches `POST /api/v1/data/policy` hourly (404 or an unparseable policy switches scanning off) and posts a
run to `POST /api/v1/data/inventory` without blocking its main loop (a curl multi transfer stepped each second, 300 s
limit). Both routes accept only the endpoint's own device credential (and its certificate when presented); the
legacy tenant key only in migration mode and only inside its tenant. No console or admin role can use them.

## Policy (hub)

Text format `ominull-data-policy/1`, versioned by content. Layers merge default -> `role:<tag>` -> `endpoint:<id>`.
Defaults: disabled; roots /home /root /etc /srv /opt; store_depth 2; max_files 300000; max_seconds 900; content
256 KiB per file, 256 MiB per run; every 24 h, resume after 60 min, full cycle weekly; one filesystem; 3000 stores,
1000 items. The agent and the hub enforce the same ranges.

An endpoint's scanning stays disabled (reason `canaries_not_synced`) until its canary list has been synced once.

Admin endpoints (fleet-wide, not for tenant administrators):

| Endpoint | Use |
|---|---|
| `GET /api/v1/data/policies[?endpoint_id=ID]` | layers, defaults, and an endpoint's effective policy |
| `POST /api/v1/data/policies` `{scope, policy, reason}` | set a layer (`default`, `role:<tag>`, `endpoint:<id>`); audited `DATA_POLICY_SET` |
| `POST /api/v1/data/canaries` `{source, endpoints: [{endpoint_id, paths}]}` | canary paths per endpoint; an empty list is a valid sync; audited with counts only |
| `GET /api/v1/data/canaries?endpoint_id=ID` | synced or not, and the count |
| `GET /api/v1/data/inventory?endpoint_id=ID` | the latest picture |

`scripts/sync-data-canaries.sh` (with `OMINULL_HUB_URL`, `OMINULL_ADMIN_KEY_FILE`) syncs Nightshift's canaries
(`nightshift canary paths --json`) to the workstation's endpoint and an empty list to every other endpoint. It stops,
sending nothing, when a decoy's placement names no file path. Run it again whenever canaries change or an endpoint is
enrolled.

## Hub storage and the Nightshift feed

The hub validates every run (schema `ominull.data-inventory/1`, path and rule formats, counts, at most 20000 stores
and 5000 items, start time no more than 5 minutes ahead of the hub) and drops anything at or under a canary path
(compared in the encoded form; audited `DATA_INVENTORY_CANARY_DROPPED`). Items are replaced per store; a store cut
short (`partial`) or whose content was not all read (`content_partial`), and a run that dropped items for
`max_items`, only add. A completed cycle removes the stores it did not see, with their items, and (when no items
were dropped) the items it did not see outside cut-short stores. A run older than the last one stored is
acknowledged and ignored.

The v3 feed (`?contract=v3`, and v4, which adds each anomaly record's `tier`; `hub/pkg/server/data_inventory_feed.go`) adds `data_inventory`: one block per endpoint
with the scan summary, host facts (left out above 32 KiB), at most 400 stores and 400 items, and truncation flags;
at most 64 blocks, the whole document fitted to 960 KiB. Nightshift's side of the contract is its `docs/ingest.md` (v3).
