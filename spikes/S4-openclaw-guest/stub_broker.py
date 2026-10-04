#!/usr/bin/env python3
"""Stub broker for spike S4: the guest's only reachable endpoint.

Serves two things on one loopback port:
  /v1/chat/completions  OpenAI-compatible model endpoint. The guest holds only
                        PLACEHOLDER_KEY; a real broker would swap it for the vault
                        key at egress. Here a scripted model answers instead.
  /mcp                  MCP (streamable HTTP, JSON responses) exposing one broker
                        tool, `effect_request`, which journals the request (spec section 9).

Every request is appended to `events`; with --log, also to a JSONL file.
Scripted model: a user message containing SCENARIO:<word> makes the model call the
first offered tool whose name contains <word>, then summarize the tool result.
SCENARIO:loop calls `exec` forever, to show what bounds a runaway guest.
"""
import argparse
import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PLACEHOLDER_KEY = "placeholder-not-a-secret"
TOOL_ARGS = {
    "effect_request": {"action": "message.send", "params": {"to": "owner", "text": "S4 hello"}},
    "exec": {"command": "uname -a; id -u"},
}
MAX_TOOL_CALLS = 4
BROKER_TOOL = {
    "name": "effect_request",
    "description": "Request an external effect through the broker. Returns the intent state.",
    "inputSchema": {
        "type": "object",
        "properties": {"action": {"type": "string"}, "params": {"type": "object"}},
        "required": ["action"],
    },
}


def scripted_reply(messages, tools):
    want = None
    for m in messages:
        text = _text(m.get("content")) if m.get("role") == "user" else ""
        if "SCENARIO:" in text:
            want = text.split("SCENARIO:", 1)[1].split()[0]
    names = [t.get("function", {}).get("name", "") for t in tools or []]
    # Skip trailing runtime-context blocks the guest appends as user messages.
    convo = list(messages)
    while convo and convo[-1].get("role") == "user" and "SCENARIO:" not in _text(convo[-1].get("content")):
        convo.pop()
    last = convo[-1] if convo else {}
    if want == "loop" and "exec" in names:
        return _call(messages, "exec", {"command": "true"})  # a model that never stops
    if sum(1 for m in convo if m.get("tool_calls")) >= MAX_TOOL_CALLS:
        return {"role": "assistant", "content": "S4 stopping: tool-call cap reached"}
    if last.get("role") == "tool":
        prev = _called(messages)
        if prev == "tool_search":
            ids = re.findall(r'"id"\s*:\s*"([^"]*%s[^"]*)"' % re.escape(want or "\0"), _text(last.get("content")))
            if ids:
                return _call(messages, "tool_call", {"id": ids[0], "args": TOOL_ARGS.get(want, {})})
        return {"role": "assistant", "content": "S4 done. Tool said: %s" % _text(last.get("content"))}
    hit = next((n for n in names if want and want in n), None)
    if hit:
        return _call(messages, hit, TOOL_ARGS.get(want, {}))
    if want and "tool_search" in names:
        return _call(messages, "tool_search", {"query": want})
    return {"role": "assistant", "content": "S4 no tool for %r; offered: %s" % (want, ",".join(names))}


def _call(messages, name, args):
    return {"role": "assistant", "content": None, "tool_calls": [{
        "id": "call_s4_%d" % len(messages), "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)}}]}


def _called(messages):
    for m in reversed(messages):
        if m.get("role") == "assistant" and m.get("tool_calls"):
            return m["tool_calls"][-1]["function"]["name"]
    return None


def _text(content):
    if isinstance(content, list):
        return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return content or ""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def _send(self, code, obj=None, ctype="application/json"):
        data = b"" if obj is None else (obj if isinstance(obj, bytes) else json.dumps(obj).encode())
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.server.record({"path": self.path, "method": "GET"})
        if self.path.startswith("/v1/models"):
            return self._send(200, {"object": "list", "data": [{"id": "stub", "object": "model"}]})
        self._send(404 if not self.path.startswith("/mcp") else 405, {"error": "not here"})

    def do_DELETE(self):
        self._send(200, {})

    def do_POST(self):
        body = self._body()
        if self.path.startswith("/mcp"):
            return self._mcp(body)
        if self.path.startswith("/v1/chat/completions"):
            return self._chat(body)
        self.server.record({"path": self.path, "method": "POST"})
        self._send(404, {"error": "not here"})

    def _chat(self, body):
        if self.server.log_path:
            with open(self.server.log_path + ".bodies", "a") as f:
                f.write(json.dumps(body) + "\n")
        auth = self.headers.get("Authorization", "")
        ok = auth == "Bearer " + PLACEHOLDER_KEY
        tools = body.get("tools") or []
        self.server.record({"path": "/v1/chat/completions", "key_injected": ok,
                            "stream": bool(body.get("stream")), "n_messages": len(body.get("messages", [])),
                            "tools": [t.get("function", {}).get("name") for t in tools]})
        if not ok:
            return self._send(401, {"error": {"message": "guest must present the placeholder key"}})
        msg = scripted_reply(body.get("messages", []), tools)
        finish = "tool_calls" if msg.get("tool_calls") else "stop"
        base = {"id": "s4", "created": int(time.time()), "model": body.get("model", "stub")}
        if not body.get("stream"):
            return self._send(200, dict(base, object="chat.completion", choices=[
                {"index": 0, "message": msg, "finish_reason": finish}],
                usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}))
        delta = {"role": "assistant"}
        if msg.get("content"):
            delta["content"] = msg["content"]
        if msg.get("tool_calls"):
            delta["tool_calls"] = [dict(c, index=i) for i, c in enumerate(msg["tool_calls"])]
        chunks = [dict(base, object="chat.completion.chunk", choices=[{"index": 0, "delta": delta, "finish_reason": None}]),
                  dict(base, object="chat.completion.chunk", choices=[{"index": 0, "delta": {}, "finish_reason": finish}],
                       usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})]
        data = b"".join(b"data: " + json.dumps(c).encode() + b"\n\n" for c in chunks) + b"data: [DONE]\n\n"
        self._send(200, data, "text/event-stream")

    def _mcp(self, body):
        method, rid = body.get("method"), body.get("id")
        ev = {"path": "/mcp", "method": method}
        if method == "tools/call":
            ev["arguments"] = (body.get("params") or {}).get("arguments")
        self.server.record(ev)
        if rid is None:
            return self._send(202)
        if method == "initialize":
            result = {"protocolVersion": (body.get("params") or {}).get("protocolVersion", "2025-06-18"),
                      "capabilities": {"tools": {}}, "serverInfo": {"name": "agentos-broker-stub", "version": "0"}}
        elif method == "tools/list":
            result = {"tools": [BROKER_TOOL]}
        elif method == "tools/call":
            args = (body.get("params") or {}).get("arguments") or {}
            self.server.journal.append(args)
            state = {"intent_id": "i%d" % len(self.server.journal), "state": "authorized", "dispatched": False}
            result = {"content": [{"type": "text", "text": json.dumps(state)}]}
        elif method == "ping":
            result = {}
        else:
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": method}})
        self._send(200, {"jsonrpc": "2.0", "id": rid, "result": result})


class StubBroker(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, log_path=None):
        super().__init__(addr, Handler)
        self.events, self.journal, self.log_path = [], [], log_path

    def record(self, ev):
        ev = dict(ev, t=round(time.time(), 3))
        self.events.append(ev)
        if self.log_path:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(ev) + "\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--log")
    a = ap.parse_args()
    StubBroker(("127.0.0.1", a.port), a.log).serve_forever()
