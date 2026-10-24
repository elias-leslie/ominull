#!/usr/bin/env python3
"""Prints the released Linux maintenance packages as JSON, for tools that run them without the hub.

packages/linux/*.sh is the one source of the packages. Nightshift's hub-down copy (its upkeep timers
that run when the hub is not reachable) is generated from this output and never kept by hand: each entry
carries the file, the sha256 of its bytes (the digest the hub's released list holds), the header fields
the schedule needs and every parameter's default as the environment value the script reads
(OMINULL_PARAM_<NAME>; a list is its items joined by commas, "-" when empty).

    python3 -I scripts/package-manifest.py [DIR]      (DIR defaults to packages/linux next to this script)
    run one:  env -i OMINULL_PARAM_MODE=enforce OMINULL_PARAM_KIND=short sh <file>   (as root)
"""
import hashlib
import json
import os
import sys

HEADER = "# ominull-package:"


def wire(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ",".join(value) if value else "-"
    return str(value)


def manifest(directory):
    out = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".sh"):
            continue
        raw = open(os.path.join(directory, name), "rb").read()
        first = raw.split(b"\n", 1)[0].decode()
        if not first.startswith(HEADER):
            raise SystemExit(f"{name}: line 1 is not a package header")
        h = json.loads(first[len(HEADER):])
        if h.get("platform") != "linux":
            continue
        out.append({
            "name": h["name"], "file": name, "sha256": hashlib.sha256(raw).hexdigest(),
            "title": h["title"], "risk": h["risk"], "role": h.get("role", ""),
            "interval": h["interval"], "timeout": h["timeout"],
            "params": {p["name"]: wire(p["default"]) for p in h["params"]},
        })
    return out


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    directory = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "packages", "linux")
    print(json.dumps(manifest(directory), indent=1, sort_keys=True))
