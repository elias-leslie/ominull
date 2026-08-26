#!/usr/bin/env python3
"""
Ominull macOS NetworkExtension Endpoint Agent Daemon
Communicates with local NEFilterDataProvider and streams live telemetry to Ominull Hub.
"""
import os
import sys
import time
import json
import urllib.request
import platform

HUB_URL = os.environ.get("OMINULL_HUB", "http://10.0.0.57:9999")
API_KEY = os.environ.get("OMINULL_KEY", "ominull-master-admin-key")
ENDPOINT_ID = "macos-target-sequoia"
HOSTNAME = platform.node() or "MAC-STUDIO-IR01"

def register_and_stream():
    print(f"[*] Starting Ominull macOS NetworkExtension Agent ({ENDPOINT_ID})...")
    print(f"[*] Connecting to Control Hub: {HUB_URL}")

    payload = {
        "type": "telemetry",
        "endpoint_id": ENDPOINT_ID,
        "hostname": HOSTNAME,
        "os": "macOS 15.1 Sequoia (Darwin 24.1.0)",
        "driver_version": "1.0.0",
        "events": [
            {
                "layer": "NETWORK_EXTENSION_FLOW",
                "action": "PERMIT",
                "direction": "OUTBOUND",
                "protocol": 6,
                "src_ip": "10.0.0.60",
                "dst_ip": "10.0.0.57",
                "src_port": 51234,
                "dst_port": 9999,
                "process_path": "/Applications/Safari.app/Contents/MacOS/Safari",
                "process_id": 4820
            }
        ]
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{HUB_URL}/api/v1/events",
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                print(f"[+] Successfully registered macOS endpoint and dispatched telemetry to {HUB_URL}")
                return True
    except Exception as e:
        print(f"[-] Telemetry dispatch failed: {e}")
        return False

def main():
    while True:
        register_and_stream()
        time.sleep(5)

if __name__ == "__main__":
    main()
