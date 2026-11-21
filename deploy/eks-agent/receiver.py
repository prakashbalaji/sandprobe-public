"""Run-owned nonce receiver. No provider endpoint, credentials or arbitrary logs."""
import json
import os
from pathlib import Path
import re
import socketserver

NONCES = json.loads(os.environ["SANDPROBE_RECEIVER_NONCES"])
if len(NONCES) != 3 or len(set(NONCES)) != 3 or any(not re.fullmatch(r"[a-f0-9]{48}", n) for n in NONCES):
    raise SystemExit(2)
SEEN = set()


def persist():
    target = Path("/tmp/receipts.json")
    fd = os.open("/tmp/receipts.new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump({"nonces": sorted(SEEN)}, output)
        output.flush()
        os.fsync(output.fileno())
    os.replace("/tmp/receipts.new", target)


class Receiver(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            data = self.request.recv(128).strip().decode("ascii")
            if data in NONCES:
                SEEN.add(data)
                persist()
                self.request.sendall(data.encode() + b"\n")
        except (OSError, UnicodeError):
            pass


persist()
with socketserver.TCPServer(("0.0.0.0", 8080), Receiver) as server:
    server.serve_forever()
