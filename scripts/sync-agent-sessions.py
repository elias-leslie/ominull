#!/usr/bin/env python3
"""Tell the hub the names of this machine's agent sessions.

Flows carry a session's window id, which is all an endpoint agent can see. The
names live in the session daemon here, so an Aico routine posts them. Prints one
line. The hub and its key come from the owner's production.local.json, or from
OMINULL_HUB_URL, OMINULL_HUB_CA and OMINULL_API_KEY_FILE when those are set.
"""
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

TOOLS = {"claude-code": "claude"}
CONFIG = Path(os.environ.get("OMINULL_PRODUCTION_CONFIG") or Path(__file__).resolve().parent / "st_extension/production.local.json")


def target():
    cfg = json.loads(CONFIG.read_text()) if CONFIG.is_file() else {}
    drill = cfg.get("drill") or {}
    url = os.environ.get("OMINULL_HUB_URL") or cfg.get("hub_base_url") or ""
    key = os.environ.get("OMINULL_API_KEY_FILE") or drill.get("key_file") or "~/.config/credstore/ominull/hub-admin.key"
    ca = os.environ.get("OMINULL_HUB_CA") or drill.get("ca_file") or None
    if not url:
        sys.exit(f"no hub address: set OMINULL_HUB_URL or fill {CONFIG}")
    return url.rstrip("/"), os.path.expanduser(key), ca


def sessions():
    raw = subprocess.run(["tether", "--json", "sessions"], check=True, capture_output=True, text=True, timeout=60).stdout
    out = []
    for s in json.loads(raw).get("items", []):
        name = s.get("name") or s.get("autoName") or s.get("taskName") or s.get("label") or ""
        if not s.get("id") or not name or s.get("tool") == "shell":
            continue
        tool = s.get("tool") or ""
        out.append({"window": s["id"], "name": name, "tool": TOOLS.get(tool, tool), "project": s.get("projectId") or ""})
    return out


def post(found):
    url, key_file, ca = target()
    with open(key_file, encoding="utf-8") as fh:
        key = fh.readline().strip()
    ctx = ssl.create_default_context(cafile=ca)
    req = urllib.request.Request(url + "/api/v1/traffic/agent-sessions", data=json.dumps({"sessions": found}).encode(), method="POST", headers={
        "Content-Type": "application/json", "X-API-Key": key, "X-Ominull-Agent": "agent session names"})
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        return json.load(resp)


def main():
    found = sessions()
    try:
        saved = post(found).get("saved", 0)
    except urllib.error.HTTPError:
        raise
    except urllib.error.URLError as e:
        # The hub is off or restarting (no connection at all): not a failure, the next run sends the names.
        if not isinstance(e.reason, OSError) or isinstance(e.reason, ssl.SSLError):
            raise
        print("skipped: the hub did not answer; the next run tries again")
        return None
    except TimeoutError:
        print("skipped: the hub did not answer; the next run tries again")
        return None
    print(f"ok: {saved} of {len(found)} session names saved")
    return None


if __name__ == "__main__":
    sys.exit(main())
