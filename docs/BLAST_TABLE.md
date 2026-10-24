# Blast table: what each ask is classed as

For Nightshift's approvals model. The hub signs `{class, verdict, why}` into
every ask (`hub/pkg/responseauth/approval_blast.go`, `blastFor` and
`blastForRun`; tests in `approval_model_test.go`). Verdicts: **safe** changes
nothing that matters, **undoable** can be put back, **dangerous** cannot easily
be, **core** is the protected core that asks the owner whatever the rows or the
session say. Packages are the ones in `packages/` (header line 1 gives risk and
the careful params). No hostnames or addresses appear here.

## 1. Package runs

Rule for a package run (`blastForRun`), per item, in this order:

1. Mode `audit` on every item: **safe** ("audit only: changes nothing").
2. Otherwise any of these makes the run **dangerous**: header `risk: careful`
   in mode `enforce`; or any careful step turned on (a bool param marked
   `careful` and set true), in any non-audit mode (revert included).
   Roles `reboot` are skipped by this check.
3. Otherwise, if a `reboot`-role package runs in `enforce`: **undoable**
   (class `reboot`: restart after a warning, nothing lasting changes).
4. Otherwise: **undoable** ("released safe packages").

The strictest item wins for the whole run. A script item with no package
header (not a released package) is classed like a one-off script (section 3).
An unreadable package run is **core**.

| Package | OS | Risk | Careful steps | audit | enforce | revert |
|---|---|---|---|---|---|---|
| windows-audit | Windows | safe | none | safe | undoable | undoable |
| windows-maintenance-mode | Windows | safe | none | safe | undoable | undoable |
| windows-updates | Windows | safe | none | safe | undoable | undoable |
| windows-cleanup | Windows | safe | none | safe | undoable (note 1) | undoable |
| windows-privacy | Windows | safe | none | safe | undoable | undoable |
| windows-performance | Windows | safe | `gpu_scheduling` (off by default) | safe | undoable; **dangerous** if `gpu_scheduling=true` | undoable; **dangerous** if `gpu_scheduling=true` |
| windows-debloat | Windows | careful | none | safe | **dangerous** | undoable |
| windows-software-removal | Windows | careful | none | safe | **dangerous** | undoable |
| windows-reboot | Windows | careful (role reboot) | none | safe | undoable (class reboot) | undoable |
| linux-maintenance-mode | Linux | safe | none | safe | undoable | undoable |
| linux-reboot | Linux | careful (role reboot) | none | safe | undoable (class reboot) | undoable |
| linux-cleanup | Linux | safe | none | safe | undoable (note 4) | undoable |

Notes:

1. windows-cleanup deletes old temp files, crash dumps, error reports and
   update caches, empties Recycle Bin items deleted more than `recycle_bin_days`
   (30 by default) ago on every fixed drive, then compacts the component store.
   The header calls it safe, so it classes **undoable**, but the deleted files do not come back.
   They are regenerable by design, which is why it stays out of dangerous.
   If Nightshift wants to count deletion as dangerous, change the package risk
   to careful or add a
   careful flag to a `delete` step; that is a package decision, not a table one.
2. Revert of a careful package is undoable because it restores what the
   package recorded before its first change.
3. Combined runs: one dangerous item makes the whole run dangerous; reboot only
   matters when nothing else is dangerous.
4. linux-cleanup trims the journal, empties the apt package cache and removes
   disabled Snap revisions. Old journal entries do not come back; the caches
   and revisions are regenerable. It stays safe, as windows-cleanup does (note 1).

## 2. Non-script asks

| Ask | Class | Verdict | Why |
|---|---|---|---|
| Agent update, owner-signed release inside the rollout rule | agent_update | undoable | canaries first; agents can be rolled back (retire, then roll forward) |
| Agent update signed in the owner's session (routine key) | agent_update | undoable | same, signed in the owner's session |
| Agent update outside any rollout rule | agent_update | dangerous | not an owner-signed release |
| Terminal session | remote | dangerous (lab machine: undoable) | a person's machine |
| Remote screen session | remote | dangerous (lab machine: undoable) | a person's machine |
| Isolate a machine | isolation | undoable | the hub can release it |
| Isolate a host-locked machine | isolation | **core** | could cut off access to it |
| Allow-isolation route | capability | **core** | lets the hub isolate what it could not before |
| Capability change | capability | **core** | loosens what the hub may do on a machine |
| Detection policy: enrolment window | enrol | **core** | opens LAN self-enrolment |
| Detection policy: terminal limits, screen ask-first, remote access | capability | **core** | loosens remote access limits |
| Detection policy: software catalog | capability | undoable | saving the old list undoes it |
| Detection policy with a drill that blinds a floor case | detection | dangerous | the floor case or its drill could not run |
| Any other detection policy change | detection | undoable | saving the previous policy undoes it |
| Detection change the hub cannot read | detection | **core** | unreadable |
| Unreadable package run | package | **core** | unreadable |
| Anything not classed | other | dangerous | default |

## 3. Scripts that are not released packages

| Ask | Class | Verdict |
|---|---|---|
| One-off script | script | dangerous (lab machine: undoable) |
| Script item without a package header | script | dangerous (lab machine: undoable) |

The "approval_rules ask" (changing the approval rows themselves) is classed
core in Nightshift's own model, outside this table.
