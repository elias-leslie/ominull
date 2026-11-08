# BloodHound CE and OpenGraph: are they a good base for a weak-point finder?

Evaluated 2026-11-08 from public docs and repos only. Nothing was installed.

**Answer: no, don't run it. Build the weak-point finder on a small graph in the hub's own database, and keep OpenGraph JSON as an optional export.**

This estate is a handful of Linux and Windows machines with no Active Directory and no Entra ID. BloodHound's value is its built-in knowledge of those two, and none of that applies here.

## What it is

- BloodHound CE is Apache-2.0 and very actively maintained: v9.9.2 shipped this month, with a push the day before this was written.
- It runs as three containers: the API and UI, Postgres, and Neo4j. The quickstart asks for at least 8 GB of RAM, 4 cores and 10 GB of disk.
- OpenGraph lets you load your own nodes and edges as JSON, by file upload or through the API. It's in both CE and Enterprise. Generic graphs arrived in v8.0.0, and structured graphs with an extension schema in v9.0.0.

## What it would take

- **Pathfinding needs a schema.** Cypher search works on any OpenGraph data, but edges in a generic graph don't count for pathfinding. We'd write an extension schema marking which edges can be walked.
- **The paid parts are the useful ones.** Relationship-based findings, remediation guidance and risk metrics are Enterprise-only, so CE gives us a graph and a query box, not findings.
- **Non-AD collectors exist but are young.** GoLinHound covers SSH keys, `authorized_keys`, agent forwarding, SSH certificates, sudoers and keytabs. It's GPL-3.0, started in December 2025, has about 96 stars, and doesn't cover services or network reachability. The OpenGraph library says its listed code is unaudited.
- **Our data would be copied twice.** The hub already holds machines, flows, trust and now agent sessions. BloodHound would mirror that into Neo4j and Postgres on a host big enough to hold them, and need a sync we'd have to keep working.

## Why not

| | BloodHound CE + OpenGraph | Graph in the hub's database |
|---|---|---|
| Runs on | New 3-container stack, 8 GB RAM floor | What's already running |
| Data | Exported and kept in sync | Already there |
| Paths | Needs an extension schema | Recursive query over edge tables |
| Findings and fix advice | Enterprise only | The finder writes them |
| Windows domain knowledge | Excellent, unused here | None, not needed |

## What to do instead

1. Keep edges in the hub: who can log in where (SSH keys, sudo, service credentials), who can reach what (observed flows), what an agent session can touch.
2. Walk them with a recursive query, and have the AI explain the paths it finds.
3. If an estate with a domain ever joins the fleet, export the same edges as OpenGraph JSON and look at them in a throwaway BloodHound. The format is simple enough that this stays a small job.

**Look again if** a real Active Directory or Entra ID tenant joins the fleet, or if CE gains pathfinding over generic graphs or the risk features move out of Enterprise.

## Not verified

- How big an OpenGraph upload can be.
- Whether a newer CE release adds pathfinding over generic graphs.
- Whether the docs' feature table agrees with their FAQ: its checkmarks didn't render, so the pathfinding limit above comes from the FAQ.
- What GoLinHound needs to run, and its full data format.
- The claim that a recursive query is enough is a judgment, not a test on real edges.

## Sources

- [BloodHound repository](https://github.com/SpecterOps/BloodHound) and [releases](https://github.com/SpecterOps/BloodHound/releases)
- [Docker Compose file](https://raw.githubusercontent.com/SpecterOps/BloodHound/main/examples/docker-compose/docker-compose.yml)
- [CE quickstart](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart.md)
- [OpenGraph overview](https://bloodhound.specterops.io/opengraph/overview.md), [FAQ](https://bloodhound.specterops.io/opengraph/faq), [best practices](https://bloodhound.specterops.io/opengraph/best-practices.md) and [library](https://bloodhound.specterops.io/opengraph/library.md)
- [GoLinHound](https://github.com/RantaSec/golinhound)
