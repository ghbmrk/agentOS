"""Measurement forwarder for #809: stands where #1014's in-worker forwarder will (127.0.0.1:18432),
relays to the real hosts through the session proxy, and logs only what the measurements need:
paths, statuses, x-codex-* response headers, the tools of responses requests (top-level `tools` and
`additional_tools` input items), and key names (never values) of auth bodies. Secrets are never
written. In relay mode it refuses every model call, so a run spends no plan usage, credits or API
usage (Mark, 2026-10-14). Usage: fwd.py LOG relay|stub SOCKET"""
import json, os, sys, threading, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import requests

LOG = sys.argv[1]
MODE = sys.argv[2] if len(sys.argv) > 2 else "relay"  # relay | stub (no upstream)
lock = threading.Lock()
PROBED = False
HOP = {"host", "connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade",
       "proxy-authorization", "proxy-connection", "content-length", "accept-encoding"}
SECRET_HDR = {"authorization", "cookie", "set-cookie", "chatgpt-account-id", "openai-organization"}


def log(rec):
    rec["t"] = round(time.time(), 3)
    with lock, open(LOG, "a") as f:
        f.write(json.dumps(rec) + "\n")


def upstream(path):
    if path.startswith("/backend-api/") or path.startswith("/public-api/"):
        return "https://chatgpt.com"
    return "https://auth.openai.com"


def keys(obj):
    if isinstance(obj, dict):
        return {k: keys(v) if isinstance(v, (dict, list)) else type(v).__name__ for k, v in obj.items()}
    if isinstance(obj, list):
        return [keys(obj[0])] if obj else []
    return type(obj).__name__


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def handle_any(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n) if n else b""
        rec = {"dir": "req", "method": self.command, "path": self.path.split("?")[0],
               "req_headers": sorted(k.lower() for k in self.headers.keys())}
        ctype = self.headers.get("content-type", "")
        if body and "json" in ctype:
            try:
                j = json.loads(body)
                if isinstance(j, dict) and "tools" in j:
                    rec["tools"] = [{k: t.get(k) for k in ("type", "name") if k in t} for t in j["tools"]]
                    rec["model"] = j.get("model")
                    rec["include"] = j.get("include")
                    rec["tool_choice"] = j.get("tool_choice")
                def tt(ts):
                    return [dict({k: t.get(k) for k in ("type", "name") if k in t},
                                 **({"tools": tt(t["tools"])} if isinstance(t.get("tools"), list) else {}))
                            for t in ts if isinstance(t, dict)]
                if isinstance(j, dict):
                    rec["input_tools"] = [{"item_type": it.get("type"), "role": it.get("role"), "tools": tt(it["tools"])}
                                          for it in j.get("input", []) if isinstance(it, dict) and isinstance(it.get("tools"), list)]
                    rec["model"] = j.get("model"); rec["include"] = j.get("include"); rec["tool_choice"] = j.get("tool_choice")
                rec["body_keys"] = keys(j)
            except Exception:
                rec["body_keys"] = "unparsed"
        elif body:
            rec["body_form_keys"] = sorted({kv.split("=")[0] for kv in body.decode(errors="replace").split("&")})
        # Mark's approval (2026-10-14 22:31Z): the device flow's redirect_uri is built from the
        # overridden issuer; swap it to the registered one. Only the fact of the swap is logged.
        if body and self.path.split("?")[0] == "/oauth/token" and "x-www-form-urlencoded" in ctype:
            from urllib.parse import parse_qsl, urlencode
            pairs = []
            for k, v in parse_qsl(body.decode()):
                if k == "redirect_uri" and v.startswith("http://127.0.0.1:18432/"):
                    v = "https://auth.openai.com/" + v[len("http://127.0.0.1:18432/"):]
                    rec["redirect_uri_swapped"] = True
                pairs.append((k, v))
            body = urlencode(pairs).encode()
        # One read-only quota readout per run: GET /backend-api/wham/usage, the endpoint behind the
        # CLI's own /usage, with the CLI's auth headers. It spends nothing; only its plan, rate-limit
        # and credits fields are logged.
        global PROBED
        if MODE == "relay" and not PROBED and self.path.startswith("/backend-api/") and self.headers.get("authorization"):
            PROBED = True
            ph = {k: v for k, v in self.headers.items()
                  if k.lower() in ("authorization", "chatgpt-account-id", "user-agent", "originator")}
            pr = {"dir": "probe", "path": "/backend-api/wham/usage"}
            try:
                q = requests.get("https://chatgpt.com/backend-api/wham/usage", headers=ph, timeout=60)
                pr["status"] = q.status_code
                pr["resp_xcodex"] = {k.lower(): v for k, v in q.headers.items() if k.lower().startswith("x-codex")}
                try:
                    j = q.json()
                    pr["resp_keys"] = keys(j)
                    pr["resp_fields"] = {k: j[k] for k in ("plan_type", "rate_limit", "credits", "spend_control")
                                         if isinstance(j, dict) and k in j}
                except Exception:
                    pr["resp_len"] = len(q.content)
            except Exception as e:
                pr["error"] = repr(e)[:300]
            log(pr)
        # No model calls upstream: Mark wants no credits or API usage spent.
        if MODE == "relay" and self.path.split("?")[0].endswith("/responses"):
            rec["blocked"] = "model call"
            log(rec)
            self.send_response(403)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        if MODE == "stub":
            log(rec)
            self.send_response(503)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        hdrs = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        hdrs["accept-encoding"] = "identity"
        url = upstream(self.path) + self.path
        rec["upstream"] = url.split("?")[0]
        try:
            r = requests.request(self.command, url, headers=hdrs, data=body, stream=True,
                                 allow_redirects=False, timeout=600)
        except Exception as e:
            rec["error"] = repr(e)[:300]
            log(rec)
            self.send_response(502)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        rec["status"] = r.status_code
        rec["resp_xcodex"] = {k.lower(): v for k, v in r.headers.items()
                              if k.lower().startswith(("x-codex", "x-ratelimit", "retry-after", "openai-"))
                              and k.lower() not in SECRET_HDR}
        rec["resp_ctype"] = r.headers.get("content-type")
        self.send_response(r.status_code)
        for k, v in r.headers.items():
            if k.lower() not in HOP and k.lower() != "content-encoding":
                self.send_header(k, v)
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()
        buf = b""
        events = {}
        for chunk in r.iter_content(chunk_size=None):
            if not chunk:
                continue
            buf += chunk
            self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()
        if "event-stream" in (rec["resp_ctype"] or ""):
            for line in buf.decode(errors="replace").splitlines():
                if line.startswith("data: "):
                    try:
                        ev = json.loads(line[6:])
                    except Exception:
                        continue
                    t = ev.get("type", "?")
                    events[t] = events.get(t, 0) + 1
                    if t in ("codex.rate_limits", "response.failed", "error") or "rate" in t:
                        rec.setdefault("rate_events", []).append(ev if t != "response.failed" else
                                                                  {"type": t, "error": (ev.get("response") or {}).get("error")})
            rec["sse_types"] = events
        else:
            try:
                j = json.loads(buf)
                rec["resp_keys"] = keys(j)
                # Non-secret shape fields the measurement reports.
                for k in ("verification_uri", "verification_uri_complete", "interval", "error", "detail",
                          "plan_type", "rate_limit", "credits"):
                    if isinstance(j, dict) and k in j:
                        rec.setdefault("resp_fields", {})[k] = j[k]
            except Exception:
                rec["resp_len"] = len(buf)
        log(rec)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = handle_any


import socketserver
SOCK = sys.argv[3]
if os.path.exists(SOCK):
    os.unlink(SOCK)


class U(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def get_request(self):
        c, _ = super().get_request()
        return c, ("uds", 0)


U(SOCK, H).serve_forever()
