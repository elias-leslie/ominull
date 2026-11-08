# AI-agent egress: which session made a connection, and what may it reach

Traffic shows the agent session behind a connection. Agent rules (Traffic, **Rules**) say what should happen to it: allow, flag or block.

## How a connection gets its session

The Linux agent walks the kernel's process ancestry from the process that made the connection, itself included, to the first installed agent binary (`kLinuxAgentBinaries`), crossing users so that `sudo curl` stays the agent's. It reads the Aico window id from that process and sends `agent_session: "claude:<window>"`. A process with no agent above it that still carries an Aico window id is `aico:<window>`, which covers runtimes with no installed binary to recognise.

Older agents send only `actor`, which names what an agent ran but not its own traffic, and the hub uses that until they update. The Windows agent doesn't send sessions.

Names come from Aico. The routine `ominull-agent-session-names` runs `scripts/sync-agent-sessions.py`, which posts names to `/api/v1/traffic/agent-sessions`. A flow stores only the window id, so a renamed session shows its new name on old rows. Neri and Neri Hunters sessions appear by name only; nothing reads their case data.

## Rules

Rules live in `DetectionTuning.agent_egress_policy` and are edited like the rest of detection tuning, with the same audit log. The first matching rule wins.

| Mode | Allow | Flag | Block |
|---|---|---|---|
| **Observe** (default) | Row shows the rule | Row shows "would flag" | Row shows "would block" |
| **Enforce** | Row shows the rule | Writes a record-class finding | Held by the agent on machines in **Block rules hold on**, with no finding |

The verdict on a Traffic row is worked out when the row is read, so a saved rule shows straight away on the rows already there.

Flag findings are low severity, one per machine, session, rule and destination per hour. They never page or reach Needs you.

## Blocking

A firewall sees addresses, not names, so a block rule must name public address ranges, no wider than /8 or a /32 for IPv6, and sit above every allow and flag rule. It names a session by its key or window id, not its name. A policy that comes to more than 32 firewall entries is refused.

The hub only accepts lab machines in the block list (`egressBlockTargetsLab`): an explicit lab role, or no role and a lab address as saved before this change. It checks again on every heartbeat, so a machine that leaves the lab loses its blocks. The agent adds an `OUTPUT` chain, `OMINULL_SESS_A` or `_B`, using `-m cgroup --path`, and swaps chains only when the set changes. With no block rules for a machine it makes no `/proc` scan or firewall call after startup.

A rule holds only where the session has a cgroup of its own: every process in it belongs to that session or its window, and it has no child groups. Aico windows get this from their tmux scope. A login shell's scope doesn't qualify, since `sshd` lives in it. A refused session is reported in the machine's last-applied note and the audit log, with the reason.

A block covers the session's whole cgroup, so a rule naming one tool is refused if its window also runs another agent. Name the window instead.

Proven on a lab VM with real Codex and a real tmux window on 2026-11-08: the blocked session's Codex and curl were refused within one beat, while a second session and a process outside any session reached the same address. Other addresses stayed open, a window running no known agent binary and a rule naming only a window held too, a process from outside landing in the group lifted the rules with the note above, and they came back when it left. Real Claude wouldn't run on that VM because its virtual CPU lacks SSE4.2, so blocking Claude isn't proven, though it goes through the same code.

## Known limits

- A session started since the last heartbeat isn't blocked until the next one.
- A process moved out of the session's cgroup (`systemd-run`, `docker run`) escapes the block, and a socket is matched by the cgroup it was created in.
- A Traffic row says **blocks this** only for a Linux machine on 1.8.122 or later that the hub still sends the rule to; otherwise it says **would block this**. That reads the agent's version, not its answer: a refusal shows only on the machine page.
- Cold storage keeps hourly flow totals without the session, so which session made a connection is only known while the raw flows are kept.
- Flows are seen on the machine that made them, so what an agent does over `ssh` on another host has no session there unless the agent's own connection is the row you're reading.
- This is attribution, not authentication. A process that scrubs its environment or installs itself at an agent's path can change what it's called. It's for seeing and limiting our own agents, not for containing a hostile one.
