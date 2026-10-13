#!/usr/bin/env python3
"""Weekly prove-out measurement: anomaly volume and the share judged real.

Reads every anomaly from the hub API (admin key from a file, sent through a
header, never on the command line), keeps those raised in the window, groups
them by signature (type, program, host) and labels each group with the first
matching triage rule. Rules are written by triage (agent first, owner only for
"ambiguous") and kept outside the repository with the measurements, because
they name real hosts and programs.

    proveout-weekly.py --hub http://hub.lan:9999 --key-file admin.key \\
        --rules rules.json --out-dir weekly/ [--end 2026-10-13] [--days 7]

rules.json: [{"type": "OFF_HOURS_*", "process": "python3*", "host": "*",
              "label": "noise", "reason": "agent host runs around the clock"}]
Labels: real, expected, noise, ambiguous. Unmatched groups are "untriaged".
Share judged real = real / (real + expected + noise), by anomaly count;
ambiguous and untriaged are reported separately and left out of the share.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
import urllib.request
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

LABELS = ("real", "expected", "noise", "ambiguous")
PAGE = 500


def read_key(path: str) -> str:
    with open(path) as f:
        return f.readline().strip()


def fetch_all(hub: str, key: str) -> list[dict]:
    out: list[dict] = []
    offset = 0
    while True:
        req = urllib.request.Request(f"{hub.rstrip('/')}/api/v1/anomalies?limit={PAGE}&offset={offset}&held=all",
                                     headers={"X-API-Key": key, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            page = json.load(resp)
        alerts = page.get("alerts") or []
        out += alerts
        offset += len(alerts)
        if not alerts or offset >= int(page.get("total") or 0):
            return out


def parse_ts(v: str) -> datetime:
    # Go writes nanoseconds; Python parses at most microseconds.
    head, _, rest = v.rstrip("Z").partition(".")
    frac = "".join(ch for ch in rest if ch.isdigit())[:6]
    return datetime.fromisoformat(f"{head}.{frac or '0'}+00:00")


def program(a: dict) -> str:
    p = (a.get("process_path") or "").replace("\\", "/")
    return p.rsplit("/", 1)[-1] or "-"


def label_for(sig: tuple[str, str, str], rules: list[dict]) -> tuple[str, str]:
    typ, prog, host = sig
    for r in rules:
        if (fnmatch.fnmatchcase(typ, r.get("type", "*")) and fnmatch.fnmatchcase(prog, r.get("process", "*"))
                and fnmatch.fnmatchcase(host, r.get("host", "*"))):
            label = r.get("label")
            if label not in LABELS:
                raise SystemExit(f"rule {r} has label {label!r}; expected one of {LABELS}")
            return label, r.get("reason", "")
    return "untriaged", ""


def measure(alerts: list[dict], rules: list[dict], start: datetime, end: datetime) -> dict:
    window = [a for a in alerts if start <= parse_ts(a["timestamp"]) < end]
    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for a in window:
        groups[(a["anomaly_type"], program(a), a.get("hostname") or "-")].append(a)
    by_label: Counter[str] = Counter()
    group_labels: Counter[str] = Counter()
    rows = []
    for sig, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        label, reason = label_for(sig, rules)
        by_label[label] += len(items)
        group_labels[label] += 1
        rows.append({"type": sig[0], "process": sig[1], "host": sig[2], "count": len(items), "label": label, "reason": reason,
                     "severity": dict(Counter(a["severity"] for a in items)),
                     "held": sum(1 for a in items if a.get("held_reason")), "acknowledged": sum(1 for a in items if a.get("acknowledged"))})
    judged = by_label["real"] + by_label["expected"] + by_label["noise"]
    days = {d: 0 for d in ((start + timedelta(days=i)).date().isoformat() for i in range((end - start).days))}
    for a in window:
        days[parse_ts(a["timestamp"]).date().isoformat()] = days.get(parse_ts(a["timestamp"]).date().isoformat(), 0) + 1
    return {
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "total": len(window),
        "per_day": days,
        "days_with_data": sum(1 for v in days.values() if v),
        "by_severity": dict(Counter(a["severity"] for a in window)),
        "by_type": dict(Counter(a["anomaly_type"] for a in window).most_common()),
        "by_host_count": len({a.get("hostname") for a in window}),
        "held": sum(1 for a in window if a.get("held_reason")),
        "acknowledged": sum(1 for a in window if a.get("acknowledged")),
        "by_label": dict(by_label),
        "groups_by_label": dict(group_labels),
        "groups": len(groups),
        "share_real": round(by_label["real"] / judged, 4) if judged else None,
        "real_groups": [r for r in rows if r["label"] == "real"],
        "signatures": rows,
    }


def summary_line(m: dict) -> str:
    share = "n/a" if m["share_real"] is None else f"{100 * m['share_real']:.1f}%"
    lab = m["by_label"]
    return (f"{m['window']['start'][:10]}..{m['window']['end'][:10]}: {m['total']} anomalies in {m['groups']} signatures "
            f"({m['days_with_data']} days with data); real {lab.get('real', 0)}, expected {lab.get('expected', 0)}, "
            f"noise {lab.get('noise', 0)}, ambiguous {lab.get('ambiguous', 0)}, untriaged {lab.get('untriaged', 0)}; "
            f"share judged real {share}; critical {m['by_severity'].get('CRITICAL', 0)}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("--hub", required=True)
    ap.add_argument("--key-file", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--end", help="window end date (UTC, exclusive); default today")
    ap.add_argument("--days", type=int, default=7)
    args = ap.parse_args(argv)
    end = datetime.fromisoformat(args.end).replace(tzinfo=UTC) if args.end else datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    start = end - timedelta(days=args.days)
    rules = json.loads(Path(args.rules).read_text())
    m = measure(fetch_all(args.hub, read_key(args.key_file)), rules, start, end)
    m["generated_at"] = datetime.now(UTC).isoformat()
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"week-{end.date().isoformat()}.json"
    path.write_text(json.dumps(m, indent=1, sort_keys=True) + "\n")
    print(summary_line(m))
    print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
