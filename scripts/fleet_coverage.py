#!/usr/bin/env python3
"""Status row "fleet machines without an OmniNull agent" (ominull.fleet.coverage).

Aico's fleet is the machines that report a machine row to Aico Status; OmniNull's is the hub's enrolled, not retired
endpoints. This compares the two each run, so neither list can drift from the other unnoticed, and writes one row to
Aico Status on this machine (POST /api/status/rows on loopback):

  ok    every fleet machine has an enrolled agent, apart from machines that are off
  warn  N fleet machines that are not off have none, named; or the hub or Aico could not be read (unknown is never "all covered")

Two kinds of machine row are not counted:
  - the hub's own (row ominull.machine): the hub is the detection backend, not an endpoint; its co-installed agent was
    retired on purpose (docs/DESIGN_HISTORY.md) and the hub reports its own health on that row.
  - a machine Aico shows as off (shown "off": on demand and stopped, parked, or powered off). Nothing runs there to
    protect; the meaning names it, and it counts again as soon as it runs.

Where it reads, all overridable for tests and other hosts:
  AICO_WEB_URL         Aico on this machine (default http://127.0.0.1:3002)
  OMINULL_SITE_FILE    the site file naming the hub and its CA, as Aico reads it (default /etc/aico/site.json)
  OMINULL_RELAY_KEY    the relay key file Aico's "That was me" uses (default ~/.config/aico/ominull-relay.key);
                       it opens the hub's agent-builds route (every enrolled agent with its host name)
Run by the user timer ominull-fleet-coverage.timer (scripts/install-fleet-coverage.sh). Stdlib only.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROW_ID = "ominull.fleet.coverage"
HUB_ROW_ID = "ominull.machine"  # the hub's own machine row (hub/pkg/server/aico_push.go)
BUILDS_ROUTE = "/api/v1/integrations/nightshift/agent-builds"
EVERY_MIN = 15  # the timer's period; the row shows late after two missed runs
MEANING_MAX = 300


def _machine_rows(status: dict[str, Any]) -> list[dict[str, Any]]:
    rows = status.get("rows") if isinstance(status, dict) else None
    return [r for r in rows or [] if isinstance(r, dict) and r.get("kind") == "machine"
            and isinstance(r.get("machine"), str) and r["machine"]]


def fleet_machines(status: dict[str, Any]) -> set[str]:
    """The machines with a machine row in Aico Status (GET /api/status), less the hub's own machine."""
    rows = _machine_rows(status)
    hub = {str(r["machine"]).lower() for r in rows if r.get("id") == HUB_ROW_ID}
    return {str(r["machine"]).lower() for r in rows} - hub


def off_machines(status: dict[str, Any]) -> set[str]:
    """Fleet machines Aico shows as off now. A machine with several rows is off only when every one says so."""
    shown: dict[str, set[str]] = {}
    for r in _machine_rows(status):
        shown.setdefault(str(r["machine"]).lower(), set()).add(str(r.get("shown") or r.get("state")))
    return {m for m, s in shown.items() if s == {"off"}} & fleet_machines(status)


def protected_hosts(builds: dict[str, Any]) -> set[str]:
    """Host names (short, lower case) of the hub's enrolled agents; the route already leaves retired ones out."""
    eps = builds.get("endpoints") if isinstance(builds, dict) else None
    if not isinstance(eps, list):
        raise ValueError("the hub answered without an endpoint list")
    return {str(e["hostname"]).split(".")[0].lower() for e in eps if isinstance(e, dict) and e.get("hostname")}


def _cut(text: str) -> str:
    return text if len(text) <= MEANING_MAX else text[: MEANING_MAX - 1] + "…"


def row(machine: str, now: dt.datetime, fleet: set[str] | None, hosts: set[str] | None, error: str = "",
        off: set[str] | frozenset[str] = frozenset()) -> dict[str, Any]:
    """The Status row: ok, warn naming the uncovered machines that are not off, or warn saying what could not be read."""
    base = {"id": ROW_ID, "what": "Fleet machines without an OmniNull agent", "kind": "check", "machine": machine,
            "project": "ominull", "last_run": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "next_run": (now + dt.timedelta(minutes=2 * EVERY_MIN)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if error or fleet is None or hosts is None:
        return {**base, "state": "warn", "meaning": _cut(f"Not known which fleet machines are covered: {error or 'nothing read'}")}
    if not fleet:
        return {**base, "state": "warn", "meaning": "Not known which fleet machines are covered: Aico Status lists no machines"}
    idle = sorted((fleet - hosts) & off)  # no agent, but nothing runs there now
    counted = fleet - set(idle)
    missing = sorted(counted - hosts)
    note = f"; not counted while off: {', '.join(idle)}" if idle else ""
    if not missing:
        return {**base, "state": "ok", "meaning": _cut(f"All {len(counted)} fleet machines have an OmniNull agent{note}")}
    n = len(missing)
    return {**base, "state": "warn", "meaning": _cut(
        f"{n} of {len(counted)} fleet machines {'has' if n == 1 else 'have'} no OmniNull agent: "
        f"{', '.join(missing)}{note}")}


def hub_source(site_file: str) -> tuple[str, str]:
    """(hub origin, CA file) from the site file's ominull ingest source, read the way Aico reads it."""
    site = json.loads(Path(site_file).read_text())
    sources = ((site.get("config") or site).get("ingest") or {}).get("sources") or []
    for s in sources:
        if isinstance(s, dict) and s.get("name") == "ominull" and str(s.get("url", "")).startswith("https://") \
                and isinstance(s.get("ca_file"), str):
            u = urllib.parse.urlparse(s["url"])
            return f"{u.scheme}://{u.netloc}", s["ca_file"]
    raise ValueError("the site file has no https OmniNull source")


def _relay_key(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise ValueError("the relay key file must be yours and mode 0600")
        key = os.read(fd, 256).decode().split("\n")[0].strip()
    finally:
        os.close(fd)
    if not key:
        raise ValueError("the relay key file is empty")
    return key


def _get(url: str, headers: dict[str, str], ctx: ssl.SSLContext | None = None) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:  # noqa: S310 (fixed https/loopback URLs)
        return json.load(r)


def main() -> int:
    aico = os.environ.get("AICO_WEB_URL", "http://127.0.0.1:3002").rstrip("/")
    site = os.environ.get("OMINULL_SITE_FILE", "/etc/aico/site.json")
    key_file = Path(os.environ.get("OMINULL_RELAY_KEY", "~/.config/aico/ominull-relay.key")).expanduser()
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    status = _get(f"{aico}/api/status", {})
    machine = str(status.get("machine") or os.uname().nodename.split(".")[0]).lower()
    fleet, hosts, error = fleet_machines(status), None, ""
    try:
        base, ca = hub_source(site)
        hosts = protected_hosts(_get(base + BUILDS_ROUTE, {"X-API-Key": _relay_key(key_file)},
                                     ssl.create_default_context(cafile=ca)))
    except Exception as e:  # unreachable hub, no key, unreadable site file: say so on the row
        error = f"the OmniNull hub was not read ({type(e).__name__}: {str(e)[:120]})"
    out = row(machine, now, fleet, hosts, error, off_machines(status))
    req = urllib.request.Request(f"{aico}/api/status/rows", data=json.dumps(out).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310
        r.read()
    print(f"{out['state']}: {out['meaning']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
