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

PORT, LOG = int(sys.argv[1]), sys.argv[2]
CMD = os.environ.get("FAKE_CMD", "true")
CANARY = os.environ.get("FAKE_CANARY", "")
LEGACY = os.environ.get("FAKE_TOOL") == "legacy"
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

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.headers.get("Content-Encoding") == "zstd" and shutil.which("zstd"):
            raw = subprocess.run(["zstd", "-dc"], input=raw, capture_output=True).stdout
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        outputs = self.record(body)
        i = next(turns)
        events = [{"type": "response.created", "response": {"id": f"r{i}"}}]
        if not outputs:
            if LEGACY:
                item = {"type": "function_call", "name": "exec_command", "call_id": f"c{i}",
                        "id": f"fc{i}", "arguments": json.dumps({"cmd": CMD})}
            else:
                js = ("const r = await tools.exec_command({cmd: %s, yield_time_ms: 10000}); "
                      "text(JSON.stringify(r));" % json.dumps(CMD))
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
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
