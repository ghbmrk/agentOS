#!/usr/bin/env python3
"""Stand-in for the ChatGPT Codex backend and for the broker's egress injector.

Logs each request Codex CLI makes in ChatGPT sign-in mode (path, which token the
Authorization header carried), answers the Responses stream with one shell
call and then a final message, and attaches the x-codex-* quota headers.
Token values are synthetic canaries.

Usage: stub_codex.py PORT LOGFILE
"""
import json, os, sys, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, LOG = int(sys.argv[1]), sys.argv[2]
PLACEHOLDER, REAL = "PLACEHOLDER-S8", "CANARY-REAL-S8"

def log(rec):
    with open(LOG, "a") as f: f.write(json.dumps(rec) + "\n")

def classify(v):
    if v is None: return None
    return "placeholder" if PLACEHOLDER in v else "real" if REAL in v else "other:" + v[:16]

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass

    def _rec(self, body):
        h = {k.lower(): v for k, v in self.headers.items()}
        rec = {"method": self.command, "path": self.path,
               "authorization": classify(h.get("authorization")),
               "chatgpt-account-id": h.get("chatgpt-account-id"),
               "user-agent": (h.get("user-agent") or "")[:60],
               "upgrade": h.get("upgrade")}
        if body:
            try:
                j = json.loads(body)
                rec["model"] = j.get("model")
                rec["keys"] = sorted(j.keys())
                rec["tools"] = sorted(str(t.get("name") or t.get("type")) for t in (j.get("tools") or []))
                outs = [i for i in j.get("input", []) if i.get("type") in ("function_call_output", "custom_tool_call_output")]
                rec["tool_output"] = str(outs[-1].get("output"))[:300] if outs else None
            except Exception as e:
                rec["body_err"] = str(e)[:100]
        log(rec); return rec

    def _send(self, code, ctype, b, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def do_CONNECT(self):
        self._rec(None); self._send(403, "text/plain", b"")

    def do_GET(self):
        self._rec(None)
        if self.headers.get("Upgrade"):
            return self._send(426, "text/plain", b"no websockets in the stub")
        self._send(404, "application/json", b"{}")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        if self.headers.get("Content-Encoding") == "zstd":
            import subprocess
            raw = subprocess.run(["zstd", "-dc"], input=raw, capture_output=True).stdout
        rec = self._rec(raw)
        if not self.path.rstrip("/").endswith("/responses"):
            return self._send(404, "application/json", b"{}")
        now = int(time.time())
        if os.environ.get("STUB_MODE") == "exhausted":
            # Plan window used up: what a run sees at the 5-hour limit.
            b = json.dumps({"error": {"type": "usage_limit_reached", "message": "stub: usage limit reached",
                                      "plan_type": "plus", "resets_at": now + 3600}}).encode()
            return self._send(429, "application/json", b, {
                "x-codex-primary-used-percent": "100.0", "x-codex-primary-window-minutes": "300",
                "x-codex-primary-reset-at": str(now + 3600)})
        rid = "resp_" + uuid.uuid4().hex[:16]
        tools = rec.get("tools") or []
        if rec.get("tool_output") is None:
            # Codex sends no tool list when the stub serves no model catalog;
            # TOOL picks the name to call anyway.
            name = next((t for t in ("shell_command", "exec_command", "shell", "local_shell") if t in tools), os.environ.get("TOOL", "exec_command"))
            cmd = "echo S8-codex-tool-ran > s8_marker.txt && cat s8_marker.txt"
            args = {"command": cmd} if name in ("shell_command",) else {"cmd": cmd} if name == "exec_command" else {"command": ["bash", "-lc", cmd]}
            item = {"type": "function_call", "id": "fc_1", "call_id": "call_" + uuid.uuid4().hex[:12],
                    "name": name, "arguments": json.dumps(args), "status": "completed"}
        else:
            item = {"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": "S8 codex stub done.", "annotations": []}]}
        evs = [
            {"type": "response.created", "response": {"id": rid}},
            {"type": "response.output_item.done", "output_index": 0, "item": item},
            {"type": "response.completed", "response": {"id": rid, "usage": {
                "input_tokens": 100, "input_tokens_details": {"cached_tokens": 0},
                "output_tokens": 20, "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 120}}},
        ]
        b = b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in evs)
        now = int(time.time())
        self._send(200, "text/event-stream", b, {
            "x-codex-primary-used-percent": "42.0",
            "x-codex-primary-window-minutes": "300",
            "x-codex-primary-reset-at": str(now + 3600),
            "x-codex-secondary-used-percent": "81.0",
            "x-codex-secondary-window-minutes": "10080",
            "x-codex-secondary-reset-at": str(now + 5 * 86400),
        })

ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
