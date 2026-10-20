#!/usr/bin/env python3
"""Answers every request (after 15 s with arg 3 "hang") 401 authentication_error, as Anthropic does for a
revoked or wrong token. Logs path and whether the canary was presented."""
import json, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
PORT, LOG = int(sys.argv[1]), sys.argv[2]
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _do(self):
        if sys.argv[3:] == ["hang"]: time.sleep(15)
        n = int(self.headers.get("content-length") or 0); self.rfile.read(n)
        a = self.headers.get("authorization") or ""
        with open(LOG, "a") as f:
            f.write(json.dumps({"method": self.command, "path": self.path,
                                "canary": "PLACEHOLDER-S8" in a}) + "\n")
        b = json.dumps({"type": "error", "error": {"type": "authentication_error",
                        "message": "Invalid bearer token"}}).encode()
        self.send_response(401); self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
    do_GET = do_POST = do_HEAD = _do
ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
