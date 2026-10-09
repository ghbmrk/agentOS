#!/usr/bin/env python3
"""Stand-in for the Anthropic API and for the broker's egress injector.

Logs every request the CLI makes (path, which auth header carried what), answers
/v1/messages with a scripted tool_use then a final text, and attaches
subscription-style rate-limit headers so we can see what the CLI surfaces.
The token values are synthetic canaries (CLAUDE.md: no real credentials).

Usage: stub_anthropic.py PORT LOGFILE
"""
import json, os, sys, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, LOG = int(sys.argv[1]), sys.argv[2]
PLACEHOLDER = "sk-ant-oat01-PLACEHOLDER-S8"     # what the sandbox holds
REAL = "sk-ant-oat01-CANARY-REAL-S8"            # what the broker would hold
RESET5 = int(time.time()) + 3600
RESET7 = int(time.time()) + 5 * 86400

def log(rec):
    with open(LOG, "a") as f:
        f.write(json.dumps(rec) + "\n")

def classify(v):
    if v is None: return None
    if PLACEHOLDER in v: return "placeholder"
    if REAL in v: return "real"
    return "other:" + v[:12]

def sse(ev, data):
    return f"event: {ev}\ndata: {json.dumps(data)}\n\n".encode()

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass

    def _rec(self, body):
        h = {k.lower(): v for k, v in self.headers.items()}
        rec = {"method": self.command, "path": self.path,
               "authorization": classify(h.get("authorization")),
               "x-api-key": classify(h.get("x-api-key")),
               "anthropic-beta": h.get("anthropic-beta"),
               "user-agent": h.get("user-agent")}
        if body:
            try:
                j = json.loads(body)
                rec["model"] = j.get("model")
                rec["n_messages"] = len(j.get("messages", []))
                rec["n_tools"] = len(j.get("tools", []) or [])
                rec["tool_names"] = sorted(t.get("name") for t in (j.get("tools") or []))[:40]
                rec["stream"] = j.get("stream")
                rec["has_tool_result"] = any(
                    isinstance(m.get("content"), list) and
                    any(c.get("type") == "tool_result" for c in m["content"])
                    for m in j.get("messages", []))
                if rec["has_tool_result"]:
                    for m in j["messages"]:
                        if isinstance(m.get("content"), list):
                            for c in m["content"]:
                                if c.get("type") == "tool_result":
                                    rec["tool_result"] = str(c.get("content"))[:300]
            except Exception as e:
                rec["body_err"] = str(e)
        log(rec)
        return rec

    def _rl_headers(self):
        return {
            "anthropic-ratelimit-unified-status": "allowed",
            "anthropic-ratelimit-unified-5h-utilization": "0.42",
            "anthropic-ratelimit-unified-5h-reset": str(RESET5),
            "anthropic-ratelimit-unified-7d-utilization": "0.81",
            "anthropic-ratelimit-unified-7d-reset": str(RESET7),
            "anthropic-ratelimit-unified-7d-surpassed-threshold": "0.75",
            "anthropic-ratelimit-unified-representative-claim": "seven_day",
            "anthropic-ratelimit-unified-reset": str(RESET7),
            "request-id": "req_stub",
        }

    def do_CONNECT(self):
        # Anything the CLI tries to reach other than the base URL lands here
        # when HTTPS_PROXY points at this stub: logged, then refused.
        self._rec(None); self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers()

    def do_GET(self):
        self._rec(None)
        self._json(404, {"type": "error", "error": {"type": "not_found_error", "message": "stub"}})

    def do_HEAD(self):
        self._rec(None); self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()

    def _json(self, code, obj, extra=None):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        rec = self._rec(body)
        if not self.path.startswith("/v1/messages"):
            return self._json(404, {"type": "error", "error": {"type": "not_found_error", "message": "stub"}})
        if os.environ.get("STUB_MODE") == "exhausted":
            # Subscription window used up: what a run sees at the 5-hour limit.
            h = self._rl_headers()
            h.update({"anthropic-ratelimit-unified-status": "rejected",
                      "anthropic-ratelimit-unified-5h-utilization": "1.0",
                      "anthropic-ratelimit-unified-representative-claim": "five_hour",
                      "anthropic-ratelimit-unified-reset": str(RESET5),
                      "retry-after": "3600"})
            return self._json(429, {"type": "error", "error": {"type": "rate_limit_error",
                              "message": "stub: usage limit reached"}}, h)
        if "count_tokens" in self.path:
            return self._json(200, {"input_tokens": 100})
        if rec.get("n_tools", 0) == 0 or rec.get("has_tool_result"):
            content = [{"type": "text", "text": "S8 stub done."}]
            stop = "end_turn"
        else:
            content = [{"type": "tool_use", "id": "toolu_" + uuid.uuid4().hex[:20], "name": "Bash",
                        "input": {"command": os.environ.get("STUB_CMD") or "echo S8-tool-ran > s8_marker.txt && cat s8_marker.txt",
                                  "description": "Write the S8 marker"}}]
            stop = "tool_use"
        msg = {"id": "msg_" + uuid.uuid4().hex[:20], "type": "message", "role": "assistant",
               "model": rec.get("model") or "stub", "content": [], "stop_reason": None,
               "stop_sequence": None, "usage": {"input_tokens": 100, "output_tokens": 0}}
        if not rec.get("stream"):
            msg["content"] = content; msg["stop_reason"] = stop; msg["usage"]["output_tokens"] = 20
            return self._json(200, msg, self._rl_headers())
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        for k, v in self._rl_headers().items(): self.send_header(k, v)
        self.send_header("Connection", "close")
        self.end_headers()
        out = [sse("message_start", {"type": "message_start", "message": msg})]
        for i, c in enumerate(content):
            if c["type"] == "text":
                out.append(sse("content_block_start", {"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}}))
                out.append(sse("content_block_delta", {"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": c["text"]}}))
            else:
                out.append(sse("content_block_start", {"type": "content_block_start", "index": i, "content_block": {"type": "tool_use", "id": c["id"], "name": c["name"], "input": {}}}))
                out.append(sse("content_block_delta", {"type": "content_block_delta", "index": i, "delta": {"type": "input_json_delta", "partial_json": json.dumps(c["input"])}}))
            out.append(sse("content_block_stop", {"type": "content_block_stop", "index": i}))
        out.append(sse("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None}, "usage": {"output_tokens": 20}}))
        out.append(sse("message_stop", {"type": "message_stop"}))
        self.wfile.write(b"".join(out)); self.wfile.flush()
        self.close_connection = True

ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
