#!/usr/bin/env python3
"""Monthly live drill: proves each paging path reaches the phone.

Run by the Aico routine ominull-live-drill on the workstation. It starts the lab
guest (if it is off), and from it touches a decoy address, sweeps ports on a
home-network decoy and sends a little more than the new-place line to a place
it never reached; from this machine it looks up a name under the decoy name a
planted credential points at. Each must raise a page whose incident reached
Aico after the drill began and was sent to the phone. It then resolves every
finding it raised as a drill, closes the "Was this you?" asks they raised, forgets the place it uploaded to (so next month
it is new again), shuts the guest down if it started it, and posts a Status
row: drill passed or failed, with the date.

    live-drill.py [--config scripts/st_extension/production.local.json] [--keep-vm]

Config: ssh_alias, lxc_id, hub_base_url and a "drill" section (real values stay
in the ignored local file; production.sample.json shows the shape):
  vm, endpoint     the lab guest's Proxmox id and its OmniNull endpoint id
  lab_decoy        a decoy address in the lab (decoy_addrs)
  scan_target      a decoy address on the home network (decoy_addrs)
  decoy_name       a name in decoy_names (the host in a planted credential)
  upload_url       an https URL that accepts a POST (a public echo service)
  key_file         the hub admin key (line 1), mode 0600
  ca_file          the hub CA
Exit 0 when every path paged and reached the phone, 1 otherwise.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shlex
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

ROW_ID = "ominull.live-drill"
SCAN_PORTS = 40           # above the port-sweep floor (30 distinct ports in 10 s)
WAIT_FINDINGS_S = 15 * 60  # the gateway's DNS log arrives in batches of a few minutes
PUSH_PASS_S = 90           # the hub pushes to Aico once a minute
SKEW = dt.timedelta(minutes=2)  # agent findings carry the guest's clock
UUID_RE = re.compile(r"^[0-9a-f-]{36}$")
NAME_RE = re.compile(r"^[a-z0-9.-]+$")


def log(msg: str) -> None:
    print(msg, flush=True)


def load_config(path: Path) -> dict[str, Any]:
    st = path.lstat()
    if not path.is_file() or path.is_symlink() or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ValueError(f"{path} must be a regular file you own with mode 0600")
    cfg = json.loads(path.read_text())
    if not isinstance(cfg.get("drill"), dict):
        raise ValueError(f"{path} has no drill section")
    return cfg


class Hub:
    def __init__(self, base: str, key_file: str, ca_file: str) -> None:
        self.base = base.rstrip("/")
        if not self.base.startswith("https://"):
            raise ValueError("hub_base_url must be https")
        with open(os.path.expanduser(key_file)) as f:
            self.key = f.readline().strip()
        self.ctx = ssl.create_default_context(cafile=ca_file)

    def call(self, path: str, body: Any = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method="POST" if data else "GET",
                                     headers={"X-API-Key": self.key, "Content-Type": "application/json",
                                              "X-Ominull-Agent": "live drill (Aico routine)"})
        with urllib.request.urlopen(req, timeout=40, context=self.ctx) as r:  # noqa: S310 (configured https hub)
            return json.load(r)

    def endpoint(self, endpoint_id: str) -> dict[str, Any]:
        for ep in self.call("/api/v1/endpoints"):
            if ep.get("id") == endpoint_id:
                return ep
        raise ValueError(f"the hub has no endpoint {endpoint_id}")

    def findings_since(self, since: dt.datetime) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for a in self.call("/api/v1/anomalies?limit=500&held=all").get("alerts") or []:
            if parse_ts(a["timestamp"]) >= since:
                ev = a.get("evidence") or {}
                a["ev"] = json.loads(ev) if isinstance(ev, str) and ev else (ev if isinstance(ev, dict) else {})
                out.append(a)
        return out


def parse_ts(v: str) -> dt.datetime:
    head, _, rest = v.rstrip("Z").partition(".")
    frac = "".join(ch for ch in rest if ch.isdigit())[:6]
    return dt.datetime.fromisoformat(f"{head}.{frac or '0'}+00:00")


def ssh(alias: str, remote: str, timeout: int = 180) -> str:
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", alias, remote], capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"ssh {alias}: {r.stderr.strip()[:300]}")
    return r.stdout


def guest(alias: str, vm: int, script: str, timeout: int = 120) -> str:
    """Run script with sh in the lab guest through the QEMU guest agent."""
    out = json.loads(ssh(alias, f"qm guest exec {vm} --timeout {timeout} -- sh -c {shlex.quote(script)}", timeout + 30))
    if out.get("exitcode") not in (0, None) and not out.get("out-data"):
        raise RuntimeError(f"guest command failed: {out.get('err-data', '')[:300]}")
    return out.get("out-data", "")


def vm_running(alias: str, vm: int) -> bool:
    return "status: running" in ssh(alias, f"qm status {vm}")


def wait_agent(hub: Hub, endpoint_id: str, after: dt.datetime, limit_s: int = 600) -> None:
    deadline = time.monotonic() + limit_s
    while time.monotonic() < deadline:
        ep = hub.endpoint(endpoint_id)
        if ep.get("last_seen_at") and parse_ts(ep["last_seen_at"]) > after:
            return
        time.sleep(15)
    raise RuntimeError(f"{endpoint_id} did not report within {limit_s // 60} minutes of the guest starting")


def aico_query(sql: str) -> list[dict[str, Any]]:
    r = subprocess.run(["aico", "db", "query", sql, "--store", "notify"], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"aico db query: {r.stderr.strip()[:300]}")
    return json.loads(r.stdout or "[]")


def notice_match(finding_id: str) -> str:
    """SQL matching the hub's notices that carry a finding: its key is
    alerts:<newest>,...,<first> for every open page of the incident."""
    return f"(n.key = 'alerts:{finding_id}' or n.key like 'alerts:%,{finding_id}' or n.key like 'alerts:{finding_id},%' or n.key like 'alerts:%,{finding_id},%')"


def phone_state(incident: str, since: dt.datetime) -> str:
    """'sent' when Aico received the incident's notice after since and sent it to a phone;
    otherwise what is missing."""
    first = incident.removeprefix("inc-")
    if not UUID_RE.match(first):
        return f"incident {incident!r} is not a finding id"
    rows = aico_query("select n.received_at, o.state from notices n left join outbox o on o.notice_id = n.id "
                      f"where n.source = 'ominull' and {notice_match(first)}")
    fresh = [r for r in rows if int(r.get("received_at") or 0) >= since.timestamp() * 1000]
    if not fresh:
        return ("Aico has no notice for it" if not rows else
                "it joined an incident that paged before the drill (a rerun within page_incident_hours)")
    if any(r.get("state") == "sent" for r in fresh):
        return "sent"
    return f"Aico has the notice but did not send it to a phone ({', '.join(str(r.get('state')) for r in fresh)})"


def post_status(state: str, meaning: str, now: dt.datetime) -> None:
    aico = os.environ.get("AICO_WEB_URL", "http://127.0.0.1:3002").rstrip("/")
    row = {"id": ROW_ID, "what": "Monthly OmniNull live drill: every paging path reaches the phone", "kind": "check",
           "machine": socket.gethostname().split(".")[0].lower(), "project": "ominull", "state": state,
           "meaning": meaning[:800], "last_run": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
           "next_run": (now + dt.timedelta(days=38)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    req = urllib.request.Request(f"{aico}/api/status/rows", data=json.dumps(row).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 (loopback Aico)
        r.read()


def run(cfg: dict[str, Any], keep_vm: bool) -> tuple[bool, str]:
    d = cfg["drill"]
    alias, lxc, vm, ep_id = cfg["ssh_alias"], int(cfg["lxc_id"]), int(d["vm"]), d["endpoint"]
    for v in (ep_id, d["decoy_name"], d["lab_decoy"], d["scan_target"]):
        if not NAME_RE.match(v):
            raise ValueError(f"{v!r} is not a plain name or address")
    url = d["upload_url"]
    if not url.startswith("https://"):
        raise ValueError("upload_url must be https")
    hub = Hub(cfg["hub_base_url"], d["key_file"], d["ca_file"])
    started, start = False, None
    result: dict[str, str] = {}
    upload_ips: set[str] = set()
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%d%H%M%S")
    lookup = f"drill-{stamp}.{d['decoy_name']}"
    # Only the drill's own findings count and are resolved: lab guests run
    # untrusted code, and a real escape during the drill must stay open.
    want: dict[str, Any] = {
        "decoy touch": lambda a: a["anomaly_type"] == "DECOY_TOUCH" and a["endpoint_id"] == ep_id and a.get("dst_ip") == d["lab_decoy"],
        "port sweep": lambda a: a["anomaly_type"] == "PORT_SCAN_RECON" and a["endpoint_id"] == ep_id and a.get("dst_ip") == d["scan_target"],
        "upload to a new place": lambda a: (a["anomaly_type"] == "NEW_PLACE_UPLOAD" and a["endpoint_id"] == ep_id
                                            and a.get("dst_ip") in upload_ips and (a.get("process_path") or "").endswith("/curl")),
        "canary credential": lambda a: a["anomaly_type"] == "DECOY_TOUCH" and a["ev"].get("domain") == lookup,
    }
    # The sweep also reaches outside the lab and touches a home decoy.
    side = lambda a: (a["endpoint_id"] == ep_id and a.get("dst_ip") == d["scan_target"]  # noqa: E731
                      and a["anomaly_type"] in ("LAB_ESCAPE", "DECOY_TOUCH", "PORT_SCAN_RECON"))
    try:
        if not vm_running(alias, vm):
            log(f"starting lab guest {vm}")
            boot = dt.datetime.now(dt.UTC)
            started = True
            subprocess.run(["aico", "vm", "start", str(vm), "--hours", "1", "--reason", "OmniNull monthly live drill"],
                           check=True, timeout=180)
            wait_agent(hub, ep_id, boot)
        start = dt.datetime.now(dt.UTC).replace(microsecond=0)
        line_mb = float(hub.call("/api/v1/detection/tuning")["tuning"].get("new_dest_upload_mb") or 1)
        part = int(line_mb * 1_000_000 * 0.9)  # two parts: about 1.7 lines once the agent's sampling is counted
        rate = 100_000
        ports = " ".join(str(p) for p in range(20001, 20001 + SCAN_PORTS))

        log(f"drill {stamp}: decoy touch, port sweep and upload from guest {vm}; decoy-name lookup here")
        guest(alias, vm, f"timeout 6 nc -z -w3 {d['lab_decoy']} 22; true")
        guest(alias, vm, f"for p in {ports}; do timeout 5 nc -z -w3 {d['scan_target']} $p & done; wait; true")
        # Slow, so the agent's socket sampling sees the bytes (a fast POST ends between samples).
        secs = part // rate + 30
        out = guest(alias, vm, f"for i in 1 2; do head -c {part} /dev/urandom | curl -s -m {secs} --limit-rate {rate} -H Expect: "
                               f"-H 'Content-Type: application/octet-stream' -o /dev/null -w '%{{remote_ip}}\\n' "
                               f"-X POST --data-binary @- {shlex.quote(url)}; done; true", timeout=2 * secs + 30)
        upload_ips.update(ln.strip() for ln in out.splitlines() if ln.strip())
        try:
            socket.getaddrinfo(lookup, 443)
        except socket.gaierror:
            pass  # nothing answers for a decoy name; the lookup is the point

        deadline = time.monotonic() + WAIT_FINDINGS_S
        while True:
            findings = hub.findings_since(start - SKEW)
            for path, match in want.items():
                hit = [a for a in findings if match(a)]
                if not hit:
                    result[path] = "no finding"
                elif hit[0]["ev"].get("class") != "page":
                    result[path] = f"{hit[0]['anomaly_type']} was {hit[0]['ev'].get('class') or 'unclassed'}, not a page"
                else:
                    result[path] = phone_state(hit[0]["ev"].get("incident", ""), start)
            if all(v == "sent" for v in result.values()) or time.monotonic() > deadline:
                break
            time.sleep(20)
    finally:
        problems = []
        if start is not None:
            try:
                clean_up(hub, alias, lxc, ep_id, start, lambda a: side(a) or any(m(a) for m in want.values()))
            except Exception as e:  # noqa: BLE001 (reported on the row; the guest still goes down)
                problems.append(f"clean-up failed ({type(e).__name__}: {str(e)[:200]})")
        if started and not keep_vm:
            try:
                subprocess.run(["aico", "vm", "shutdown", str(vm)], timeout=180, check=True)
            except Exception as e:  # noqa: BLE001
                problems.append(f"guest {vm} not shut down ({type(e).__name__})")
        if problems:
            result["after the drill"] = "; ".join(problems)

    failed = {p: why for p, why in result.items() if why != "sent"}
    day = f"{start:%Y-%m-%d}"
    if not failed:
        return True, f"Drill passed {day}: decoy touch, port sweep, upload to a new place and canary credential each paged and reached the phone."
    return False, f"Drill failed {day}: " + "; ".join(f"{p}: {why}" for p, why in failed.items())


def clean_up(hub: Hub, alias: str, lxc: int, ep_id: str, start: dt.datetime, drills: Any) -> None:
    """Resolve the drill's findings, forget the places the guest first reached
    during it (so next month's upload is a first contact again, even after a
    failed run) and close the "Was this you?" asks the pages raised."""
    mine = [a for a in hub.findings_since(start - SKEW) if drills(a)]
    if mine:
        hub.call("/api/v1/anomalies/resolve", {"ids": [a["id"] for a in mine],
                                               "reason": f"drill: monthly live drill {start:%Y-%m-%d}"})
    since = (start - SKEW).strftime("%Y-%m-%d %H:%M:%S")
    sql = (f"delete from agent_egress_destinations where endpoint_id = {sql_str(ep_id)} and runtime = '*'"
           f" and first_seen >= {sql_str(since)};")
    ssh(alias, f"pct exec {lxc} -- sqlite3 -cmd '.timeout 10000' /var/lib/ominull/ominull.db {shlex.quote(sql)}")
    log(f"resolved {len(mine)} drill findings")
    # A push already in flight lands within a pass; then the drill answers its
    # own asks so none reaches the owner's Needs you.
    time.sleep(PUSH_PASS_S)
    ids = [a["id"] for a in mine if UUID_RE.match(a["id"])]
    if ids:
        rows = aico_query("select n.ask_id from notices n where n.source = 'ominull' and n.ask_id is not null and ("
                          + " or ".join(notice_match(i) for i in ids) + ")")
        for r in rows:
            subprocess.run(["tether", "ask", "done", str(r["ask_id"])], timeout=60, capture_output=True)
        log(f"closed {len(rows)} drill asks in Needs you")


def sql_str(v: str) -> str:
    return "'" + v.replace("'", "''") + "'"


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("--config", default=str(Path(__file__).resolve().parent / "st_extension" / "production.local.json"))
    ap.add_argument("--keep-vm", action="store_true", help="leave the lab guest running if the drill started it")
    args = ap.parse_args()
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    try:
        ok, meaning = run(load_config(Path(args.config)), args.keep_vm)
    except Exception as e:  # the row says what broke; the routine shows failed
        ok, meaning = False, f"Drill failed {now:%Y-%m-%d}: {type(e).__name__}: {str(e)[:300]}"
    post_status("ok" if ok else "failed", meaning, dt.datetime.now(dt.UTC).replace(microsecond=0))
    log(("ok: " if ok else "failed: ") + meaning)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
