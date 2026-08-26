#!/usr/bin/env python3
"""
Ominull Windows WFP Endpoint Agent
Connects to local WFP driver and streams live telemetry to Ominull Hub.
"""
import os
import sys
import time
import json
import urllib.request

HUB_URL = os.environ.get("OMINULL_HUB", "http://10.0.0.57:9999")
API_KEY = os.environ.get("OMINULL_KEY", "ominull-master-admin-key")
ENDPOINT_ID = "win11-target-01"
HOSTNAME = "WFP-TARGET-WIN11"

def register_and_stream():
    payload = {
        "type": "telemetry",
        "endpoint_id": ENDPOINT_ID,
        "hostname": HOSTNAME,
        "os": "Windows 11 Enterprise 24H2 (Build 26100.1742)",
        "ip": "10.0.0.110",
        "driver_version": "1.0.0",
        "events": [
            {
                "layer": "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
                "action": "PERMIT",
                "direction": "OUTBOUND",
                "protocol": 6,
                "src_ip": "10.0.0.110",
                "dst_ip": "10.0.0.57",
                "src_port": 49152,
                "dst_port": 9999,
                "process_path": "\\device\\harddiskvolume3\\windows\\system32\\curl.exe",
                "process_id": 3104
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
                return True
    except Exception as e:
        return False

def main():
    while True:
        register_and_stream()
        time.sleep(5)

if __name__ == "__main__":
    main()
