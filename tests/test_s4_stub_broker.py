# Spike S4 harness test: the stub broker the OpenClaw guest talks to.
# Makes no coverage claims; the stub is test scaffolding, not the broker.
import json
import pathlib
import sys
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "spikes" / "S4-openclaw-guest"))
import stub_broker as sb  # noqa: E402

USER = {"role": "user", "content": "SCENARIO:effect_request send hello"}


def fn(*names):
    return [{"type": "function", "function": {"name": n}} for n in names]


class StubBrokerTest(unittest.TestCase):
    def setUp(self):
        self.broker = sb.StubBroker(("127.0.0.1", 0))
        threading.Thread(target=self.broker.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.broker.server_address[1]

    def tearDown(self):
        self.broker.shutdown()
        self.broker.server_close()

    def post(self, path, body, key=sb.PLACEHOLDER_KEY):
        req = urllib.request.Request(self.base + path, json.dumps(body).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        if key:
            req.add_header("Authorization", "Bearer " + key)
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read() or b"null")

    def chat(self, messages, tools):
        body = {"model": "stub", "messages": messages, "tools": tools}
        return self.post("/v1/chat/completions", body)["choices"][0]["message"]

    def test_model_rejects_missing_placeholder_key(self):
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.post("/v1/chat/completions", {"messages": []}, key=None)
        self.assertEqual(e.exception.code, 401)

    def test_model_calls_offered_tool_then_finishes(self):
        tools = fn("exec", "broker__effect_request")
        r1 = self.chat([USER], tools)
        call = r1["tool_calls"][0]
        self.assertEqual(call["function"]["name"], "broker__effect_request")
        done = {"role": "tool", "tool_call_id": call["id"], "content": '{"state":"authorized"}'}
        self.assertIn("authorized", self.chat([USER, r1, done], tools)["content"])
        self.assertEqual(self.broker.events[0]["key_injected"], True)

    def test_model_reaches_deferred_tool_through_search(self):
        tools = fn("exec", "tool_search", "tool_call")
        r1 = self.chat([USER], tools)
        self.assertEqual(r1["tool_calls"][0]["function"]["name"], "tool_search")
        found = {"role": "tool", "tool_call_id": "a",
                 "content": '{"results":[{"id":"mcp:broker:effect_request","name":"effect_request"}]}'}
        r2 = self.chat([USER, r1, found], tools)
        call = r2["tool_calls"][0]["function"]
        self.assertEqual(call["name"], "tool_call")
        self.assertEqual(json.loads(call["arguments"])["id"], "mcp:broker:effect_request")
        done = {"role": "tool", "tool_call_id": "b", "content": '{"state":"authorized"}'}
        self.assertIn("authorized", self.chat([USER, r1, found, r2, done], tools)["content"])

    def test_trailing_runtime_context_does_not_hide_tool_result(self):
        # OpenClaw appends a user-role context block after tool results.
        ctx = {"role": "user", "content": [{"type": "text", "text": "<<<BEGIN_OPENCLAW_INTERNAL_CONTEXT>>> none"}]}
        r1 = self.chat([USER, ctx], fn("broker__effect_request"))
        done = {"role": "tool", "tool_call_id": "a", "content": '{"state":"authorized"}'}
        self.assertIn("authorized", self.chat([USER, r1, done, ctx], fn("broker__effect_request"))["content"])

    def test_mcp_lists_and_journals_effect_request(self):
        init = self.post("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertIn("tools", init["result"]["capabilities"])
        tools = self.post("/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual([t["name"] for t in tools["result"]["tools"]], ["effect_request"])
        args = {"action": "message.send", "params": {"to": "owner", "text": "hi"}}
        res = self.post("/mcp", {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                 "params": {"name": "effect_request", "arguments": args}})
        self.assertIn("authorized", res["result"]["content"][0]["text"])
        self.assertEqual(self.broker.journal, [args])


if __name__ == "__main__":
    unittest.main()
