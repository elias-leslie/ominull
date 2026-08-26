#!/usr/bin/env python3
import http.server
import socketserver
import threading
import time
import os
import sys
import subprocess

EVIDENCE_DIR = "/srv/workspaces/projects/ominull/evidence/m1-callout"
os.makedirs(EVIDENCE_DIR, exist_ok=True)

PORT = 9998
received_files = {}
received_traffic = []
stop_server = False

class EvidenceHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"[+] HTTP GET: {self.path} from {self.client_address[0]}:{self.client_address[1]}")
        received_traffic.append({"path": self.path, "client": self.client_address[0], "time": time.time()})
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"Ominull Test Server: Traffic Received\n")

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(length)
        filename = os.path.basename(self.path.rstrip('/'))
        if not filename or filename == "evidence":
            filename = f"post_{len(received_files)}.txt"

        print(f"[+] HTTP POST: {self.path} -> {filename} ({length} bytes) from {self.client_address[0]}")
        received_files[filename] = data

        filepath = os.path.join(EVIDENCE_DIR, filename)
        with open(filepath, "wb") as f:
            f.write(data)
        print(f"[+] Saved to {filepath}")

        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"OK\n")

    def log_message(self, format, *args):
        pass

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

def start_http_server():
    httpd = ReusableTCPServer(('0.0.0.0', PORT), EvidenceHandler)
    while not stop_server:
        httpd.handle_request()
    httpd.server_close()

def main():
    global stop_server
    print("=== STARTING LIVE M1 VERIFICATION SUITE ===")

    # 1. Free port 9998
    subprocess.run(["fuser", "-k", f"{PORT}/tcp"], capture_output=True)
    time.sleep(0.5)

    # 2. Start HTTP evidence server
    print("[1] Starting HTTP listener on port 9998...")
    http_thread = threading.Thread(target=start_http_server, daemon=True)
    http_thread.start()

    # 3. Start VM 110
    print("[2] Starting VM 110...")
    subprocess.run(["ssh", "-o", "BatchMode=yes", "hypervisor-01", "qm start 110"], check=True)

    # 4. Wait for execution and evidence receipt (up to 120s)
    print("[3] Waiting for automated execution and evidence receipt (up to 120 seconds)...")
    start_time = time.time()
    expected_files = ["m1_log.txt", "wfp_baseline.xml", "wfp_loaded.xml", "wfp_post_unload.xml"]

    while time.time() - start_time < 120:
        if all(f in received_files for f in expected_files):
            print("\n[+] All expected evidence files successfully received!")
            break
        time.sleep(2)

    stop_server = True
    try:
        import urllib.request
        urllib.request.urlopen(f"http://127.0.0.1:{PORT}/shutdown", timeout=1)
    except Exception:
        pass

    # 5. Summary
    print("\n=== VERIFICATION SUMMARY ===")
    print(f"Files received: {list(received_files.keys())}")
    print(f"Traffic hits received: {len(received_traffic)}")
    for t in received_traffic:
        print(f"  Traffic: {t['path']} from {t['client']}")

    if "m1_log.txt" in received_files:
        log_text = received_files["m1_log.txt"].decode('utf-8', errors='replace')
        print("\n--- VM EXECUTION LOG ---")
        print(log_text)

    # Validate WFP objects in wfp_loaded.xml
    if "wfp_loaded.xml" in received_files:
        loaded_xml = received_files["wfp_loaded.xml"].decode('utf-8', errors='replace')
        has_sublayer = "OminullSubLayer" in loaded_xml
        has_callout = "OminullAleConnectCallout" in loaded_xml
        has_filter = "OminullAleConnectFilter" in loaded_xml
        print("\n--- WFP ENGINE STATE VALIDATION (LOADED) ---")
        print(f"  [+] OminullSubLayer present: {has_sublayer}")
        print(f"  [+] OminullAleConnectCallout present: {has_callout}")
        print(f"  [+] OminullAleConnectFilter present: {has_filter}")

    # Validate zero leaks in wfp_post_unload.xml
    if "wfp_post_unload.xml" in received_files:
        post_xml = received_files["wfp_post_unload.xml"].decode('utf-8', errors='replace')
        has_sublayer_post = "OminullSubLayer" in post_xml
        has_callout_post = "OminullAleConnectCallout" in post_xml
        has_filter_post = "OminullAleConnectFilter" in post_xml
        print("\n--- ZERO-LEAK VALIDATION (POST-UNLOAD) ---")
        print(f"  [+] OminullSubLayer leaked: {has_sublayer_post} (Expected: False)")
        print(f"  [+] OminullAleConnectCallout leaked: {has_callout_post} (Expected: False)")
        print(f"  [+] OminullAleConnectFilter leaked: {has_filter_post} (Expected: False)")

        if not has_sublayer_post and not has_callout_post and not has_filter_post:
            print("\n>>> ZERO WFP OBJECT LEAKS CONFIRMED: PASS <<<")
        else:
            print("\n>>> WARNING: LEAKED OBJECTS DETECTED <<<")

if __name__ == "__main__":
    main()
