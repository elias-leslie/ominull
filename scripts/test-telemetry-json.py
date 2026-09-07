"""Exercise the native HTTP serializer with a full, long-field wire batch."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import subprocess
import sys
import threading

bodies = []
class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        bodies.append(self.rfile.read(int(self.headers['Content-Length'])))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{}')
    def log_message(self, format: str, *args: object) -> None:
        pass

server = HTTPServer(('127.0.0.1', 0), Receiver)
worker = threading.Thread(target=server.serve_forever, daemon=True)
worker.start()
try:
    subprocess.run([sys.argv[1], f'http://127.0.0.1:{server.server_port}'], check=True, timeout=20)
    assert len(bodies) == 1, f'expected one batch, received {len(bodies)}'
    data = json.loads(bodies[0])
    assert len(data['events']) == 64
    assert data['events'][0]['process_path'][4] == '\n'
    assert data['role'] == 'role\"with\ncontrols'
    assert len(data['events'][0]['process_path']) == 511
    assert len(data['events'][0]['command_line']) == 1023
    print(f'64 records, valid JSON, {len(bodies[0])} bytes')
finally:
    server.shutdown()
    server.server_close()
