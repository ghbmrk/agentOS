# Fake responses endpoint for CliSandboxTest in tests/test_codex_worker.py: stands where the
# in-worker forwarder listens. The first turn asks the CLI to run one tool command (env FAKE_CMD);
# once the request carries that command's output it answers "done". Each request is logged as one
# JSON line holding only what the test checks: method, path, a WebSocket upgrade, the model asked
# for, whether the Authorization header carries the synthetic canary (env FAKE_CANARY), and the
# tool output. No login is involved; the CLI's auth.json is a synthetic placeholder.
# argv: port, log path. env FAKE_TOOL=legacy asks with a plain function call instead of code mode.
import http.server
import itertools
import json
import os
import shutil
import subprocess
import sys
import threading

PORT, LOG = int(sys.argv[1]), sys.argv[2]
CMD = os.environ.get("FAKE_CMD", "true")
CANARY = os.environ.get("FAKE_CANARY", "")
LEGACY = os.environ.get("FAKE_TOOL") == "legacy"
# env FAKE_REFRESH names a JSON file {"status", "body"}: the answer to the CLI's refresh request, as
# the egress route gives it (a JSON body, or a string sent as text). Then the first tool command
# yields after FAKE_YIELD_MS and the request carrying its output is refused with 401 until the CLI
# has refreshed, so the refresh lands while that command still runs.
REFRESH = os.environ.get("FAKE_REFRESH")
YIELD_MS = int(os.environ.get("FAKE_YIELD_MS", "10000"))
refreshed = threading.Event()
OUTPUTS = ("function_call_output", "custom_tool_call_output")
turns = itertools.count()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def record(self, body):
        outputs = []
        if isinstance(body, dict):
            outputs = [x.get("output") for x in body.get("input", [])
                       if isinstance(x, dict) and x.get("type") in OUTPUTS]
        entry = {
            "method": self.command,
            "path": self.path,
            "upgrade": self.headers.get("Upgrade"),
            "model": body.get("model") if isinstance(body, dict) else None,
            "auth_canary": bool(CANARY) and CANARY in (self.headers.get("Authorization") or ""),
            "outputs": outputs,
        }
        with open(LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
        return outputs

    def do_GET(self):
        self.record(None)
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def send(self, status, data, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if REFRESH and self.path.endswith("/oauth/token"):
            try:
                sent = json.loads(raw).get("refresh_token")
            except (ValueError, AttributeError):
                sent = None
            with open(LOG, "a") as f:
                f.write(json.dumps({"method": self.command, "path": self.path,
                                    "refresh_token": sent}) + "\n")
            with open(REFRESH) as f:
                answer = json.load(f)
            refreshed.set()
            if isinstance(answer["body"], str):
                return self.send(answer["status"], answer["body"].encode(), "text/plain")
            return self.send(answer["status"], json.dumps(answer["body"]).encode())
        if self.headers.get("Content-Encoding") == "zstd" and shutil.which("zstd"):
            raw = subprocess.run(["zstd", "-dc"], input=raw, capture_output=True).stdout
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        outputs = self.record(body)
        if REFRESH and outputs and not refreshed.is_set():
            return self.send(401, b'{"error": {"code": "token_expired"}}')
        i = next(turns)
        events = [{"type": "response.created", "response": {"id": f"r{i}"}}]
        if not outputs:
            if LEGACY:
                item = {"type": "function_call", "name": "exec_command", "call_id": f"c{i}",
                        "id": f"fc{i}", "arguments": json.dumps({"cmd": CMD})}
            else:
                js = ("const r = await tools.exec_command({cmd: %s, yield_time_ms: %d}); "
                      "text(JSON.stringify(r));" % (json.dumps(CMD), YIELD_MS))
                item = {"type": "custom_tool_call", "name": "exec", "input": js,
                        "call_id": f"c{i}", "id": f"ct{i}"}
        else:
            item = {"type": "message", "role": "assistant", "id": f"m{i}",
                    "content": [{"type": "output_text", "text": "done"}]}
        events.append({"type": "response.output_item.done", "item": item})
        events.append({"type": "response.completed", "response": {
            "id": f"r{i}", "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
                                     "input_tokens_details": None,
                                     "output_tokens_details": None}}})
        data = "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()
        self.send(200, data, "text/event-stream")


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
