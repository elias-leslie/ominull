#!/usr/bin/env python3
import http.server
import socketserver
import os
import sys

PORT = 9998
OUTPUT_DIR = "/srv/workspaces/projects/wfpsentinel/evidence/m1-callout"
os.makedirs(OUTPUT_DIR, exist_ok=True)

class EvidenceHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"[+] HTTP GET: {self.path} from {self.client_address}")
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"WfpSentinel Test Server: OK\n")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        print(f"[+] HTTP POST: {self.path} ({content_length} bytes) from {self.client_address}")

        filename = os.path.basename(self.path)
        if not filename or filename == "evidence":
            filename = "upload.log"

        if "m2" in filename or "m2" in self.path:
            out_dir = "/srv/workspaces/projects/wfpsentinel/evidence/m2-enforcement"
        else:
            out_dir = "/srv/workspaces/projects/wfpsentinel/evidence/m1-callout"
        os.makedirs(out_dir, exist_ok=True)

        filepath = os.path.join(out_dir, filename)
        with open(filepath, "wb") as f:
            f.write(post_data)
        print(f"[+] Saved {content_length} bytes to {filepath}")

        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"Received\n")

def run():
    print(f"[*] Starting Evidence Receiver on port {PORT}...")
    with socketserver.TCPServer(("", PORT), EvidenceHandler) as httpd:
        httpd.serve_forever()

if __name__ == "__main__":
    run()
