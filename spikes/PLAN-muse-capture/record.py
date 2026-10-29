"""Default-deny recording gate for the PLAN-muse capture (#1379 slice (b)): a mitmproxy addon
between Muse Code and Meta. It refuses everything except what it is told to pass, and logs the
shape of everything it sees (hosts, methods, paths with ids replaced, statuses, header names,
quota-like header values, body key names and kinds, JWT claim names), never a token, cookie,
prompt, reply or account value.

What passes:
- No-prompt phases (sign-in, reads, Contributor reads): an HTTP request whose method, host and
  normalised path are a line of the allow file and whose body is empty, JSON or a form with no
  model key. Its exact URL is added to the seen file.
- Prompt phases (MUSE_CAP_STRICT=1): only a GET or HEAD with no body whose exact URL is in the
  seen file, i.e. one already sent before any prompt existed. Nothing derived from a prompt can
  leave in a URL or body; header values are the one channel not compared.
Every other request is refused with 503 before it leaves, and every non-HTTP flow (raw TCP,
UDP, websockets) is killed. An error in a hook refuses the request.

Environment: MUSE_CAP_LOG (JSONL, required), MUSE_CAP_PHASE, MUSE_CAP_ALLOW (allow file),
MUSE_CAP_SEEN (seen-URL file), MUSE_CAP_STRICT."""
import base64, json, os, re, threading, time

LOG = os.environ.get("MUSE_CAP_LOG", "")
PHASE = os.environ.get("MUSE_CAP_PHASE", "")
_lock = threading.Lock()
ALLOW = os.environ.get("MUSE_CAP_ALLOW", "")
SEEN = os.environ.get("MUSE_CAP_SEEN", "")
STRICT = os.environ.get("MUSE_CAP_STRICT", "") == "1"

# String values kept verbatim only under these keys, and only when short and token-free: they
# name item types, roles, grant types, error codes and the like, which the declaration needs.
SAFE_KEYS = {"type", "role", "object", "model", "grant_type", "response_type", "token_type",
             "error", "code", "error_code", "status", "kind", "event", "scope", "alg", "typ",
             "method", "tool_choice", "reasoning_effort", "effort", "finish_reason", "stop_reason",
             "interval", "plan", "tier", "mode", "unit", "window"}
# Numbers are kept only under usage-like keys; anywhere else a number may be an account id.
NUM_KEY = re.compile(r"(^|_)(limit|limits|remaining|used|usage|quota|reset|resets|window|percent|interval|expires|in|retry|after|count|tokens|seconds|at)(_|$)")
SAFE_VAL = re.compile(r"^[A-Za-z0-9_.:/ +-]{0,64}$")
LONG_RUN = re.compile(r"[A-Za-z0-9_\-]{24,}")
QUOTA_HDR = re.compile(r"^(x-)?(ratelimit|rate-limit|quota|usage|retry-after|x-.*(limit|quota|usage|remaining|reset))", re.I)
SECRET_HDR = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}
MODEL_KEYS = {"messages", "message", "input", "prompt", "contents"}
# A device or authorization code under `code` is shaped; only lower-case error codes are kept.
ERROR_CODE = re.compile(r"^[a-z][a-z0-9_.]*$|^[0-9]{1,6}$")
ALNUM_RUN = re.compile(r"[A-Za-z0-9]{10,}")


def id_like(s):
    """True for a token-like run, or a run of 10 or more letters and digits that mixes both."""
    return bool(LONG_RUN.search(s)) or any(re.search(r"\d", r) and re.search(r"[A-Za-z]", r)
                                           for r in ALNUM_RUN.findall(s))


def norm_path(p):
    """The path with id-like segments (long digit runs, UUIDs, token-like runs) replaced by {id}."""
    segs = p.split("?")[0].split("/")
    return "/".join("{id}" if re.match(r"^\d{4,}$", x) or id_like(x) or re.match(r"^[0-9a-f-]{32,36}$", x)
                    else x for x in segs)


def log(rec):
    rec["t"] = round(time.time(), 3)
    rec["phase"] = PHASE
    with _lock, open(LOG, "a") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


def _b64json(seg):
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def sshape(s):
    """The shape of a string that is not kept: length, character classes, a typed prefix, and for
    a JWT its header names and claim names."""
    out = {"len": len(s)}
    cls = "".join(c for c, rx in (("A", "[A-Z]"), ("a", "[a-z]"), ("0", "[0-9]"), ("_", "_"),
                                  ("-", "-"), (".", r"\."), ("%", "@"), ("~", r"[^A-Za-z0-9_.@-]"))
                  if re.search(rx, s))
    out["cls"] = cls
    # A typed prefix (rt_, sk-) is kept only on a long value, so a short code never shows half.
    m = re.match(r"^([A-Za-z]{1,6}[_-])", s)
    if m and len(s) - len(m.group(1)) >= 16:
        out["prefix"] = m.group(1)
    parts = s.split(".")
    if s.startswith("eyJ") and len(parts) in (3, 5):
        out["segments"] = ".".join(str(len(p)) for p in parts)
        try:
            out["jwt_header"] = sorted(_b64json(parts[0]))
            out["jwt_alg"] = _b64json(parts[0]).get("alg")
            out["jwt_claims"] = sorted(_b64json(parts[1]))
        except Exception:
            out["jwt"] = "undecoded"
    return out


def shape(v, key=""):
    if isinstance(v, dict):
        return {k: shape(x, k) for k, x in v.items()}
    if isinstance(v, list):
        # Distinct shapes of the items, so each item type of a model body shows once.
        seen, out = set(), []
        for x in v:
            s = shape(x, key)
            k = json.dumps(s, sort_keys=True)
            if k not in seen:
                seen.add(k)
                out.append(s)
        return out[:20]
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)):
        snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower().replace("-", "_")
        return v if NUM_KEY.search(snake) else type(v).__name__
    if isinstance(v, str):
        if key.lower() in SAFE_KEYS and SAFE_VAL.match(v) and not id_like(v):
            if key.lower() != "code" or ERROR_CODE.match(v):
                return v
        return sshape(v)
    return type(v).__name__


def body_shape(raw, ctype):
    if not raw:
        return None
    ctype = (ctype or "").lower()
    if "json" in ctype or raw[:1] in (b"{", b"["):
        try:
            return {"json": shape(json.loads(raw))}
        except Exception:
            pass
    if "x-www-form-urlencoded" in ctype:
        from urllib.parse import parse_qsl
        return {"form": {k: shape(v, k) for k, v in parse_qsl(raw.decode(errors="replace"))}}
    if "event-stream" in ctype:
        events = []
        for line in raw.decode(errors="replace").splitlines():
            if line.startswith("data:"):
                try:
                    s = shape(json.loads(line[5:].strip()))
                except Exception:
                    continue
                if s not in events:
                    events.append(s)
        return {"sse": events[:30]}
    return {"ctype": ctype, "len": len(raw)}


def headers(h, quota_values):
    names = sorted({k.lower() for k in h.keys()})
    out = {"names": names}
    auth = h.get("authorization", "")
    if auth:
        out["auth_scheme"] = auth.split(" ", 1)[0][:16]
    if quota_values:
        out["quota"] = {k.lower(): v for k, v in h.items()
                        if QUOTA_HDR.match(k) and k.lower() not in SECRET_HDR and not LONG_RUN.search(v)}
    return out


def has_model_key(v, depth=0):
    if depth > 32:
        return True
    if isinstance(v, dict):
        return bool(MODEL_KEYS & {str(k).lower() for k in v}) or any(has_model_key(x, depth + 1) for x in v.values())
    if isinstance(v, list):
        return any(has_model_key(x, depth + 1) for x in v)
    if isinstance(v, str) and v.strip()[:1] in ("{", "["):
        try:
            return has_model_key(json.loads(v), depth + 1)
        except Exception:
            return False
    return False


def lines(path):
    try:
        with open(path) as f:
            return {l.strip() for l in f if l.strip() and not l.startswith("#")}
    except FileNotFoundError:
        return set()


def body_ok(req):
    """Empty, or JSON or a form, decoded strictly, with no model key at any depth."""
    raw = req.get_content(strict=True)
    if not raw:
        return True
    ctype = req.headers.get("content-type", "").lower()
    text = raw.decode("utf-8")
    if "json" in ctype:
        return not has_model_key(json.loads(text))
    if "x-www-form-urlencoded" in ctype:
        from urllib.parse import parse_qsl
        pairs = parse_qsl(text, strict_parsing=True)
        return not any(k.lower() in MODEL_KEYS or has_model_key(v) for k, v in pairs)
    return False


def verdict(flow):
    """"" to pass, else why the request is refused."""
    req = flow.request
    url = req.method + " " + req.pretty_url
    if STRICT:
        if req.method in ("GET", "HEAD") and not req.raw_content and url in lines(SEEN):
            return ""
        return "strict"
    if req.method + " " + req.pretty_host + " " + norm_path(req.path) not in lines(ALLOW):
        return "not-allowed"
    if not body_ok(req):
        return "body"
    with _lock, open(SEEN, "a") as f:
        f.write(url + "\n")
    return ""


def refuse(flow):
    from mitmproxy import http
    flow.response = http.Response.make(503, b'{"error":"refused by capture gate"}',
                                       {"content-type": "application/json"})


class Recorder:
    def request(self, flow):
        req = flow.request
        rec = {"dir": "req"}
        try:
            rec.update(host=req.pretty_host, method=req.method, path=norm_path(req.path))
            why = verdict(flow)
            if why:
                rec["refused"] = why
                refuse(flow)
            rec.update(query_keys=sorted(req.query.keys()), headers=headers(req.headers, False),
                       body=body_shape(req.get_content(strict=False), req.headers.get("content-type")))
        except Exception as e:
            rec.update(refused="error", error=type(e).__name__)
            refuse(flow)
        flow.metadata["rec"] = rec
        log(rec)

    def response(self, flow):
        if flow.metadata.get("rec", {}).get("refused"):
            return
        r = flow.response
        rec = {"dir": "resp", "host": flow.request.pretty_host, "method": flow.request.method,
               "path": norm_path(flow.request.path), "status": r.status_code}
        try:
            rec.update(headers=headers(r.headers, True),
                       body=body_shape(r.get_content(strict=False), r.headers.get("content-type")))
        except Exception as e:
            rec["error"] = type(e).__name__
        log(rec)

    def websocket_start(self, flow):
        flow.kill()
        log({"dir": "killed", "kind": "websocket", "host": flow.request.pretty_host,
             "path": norm_path(flow.request.path)})

    def tcp_start(self, flow):
        flow.kill()
        log({"dir": "killed", "kind": "tcp", "host": str(flow.server_conn.address)})

    def tcp_message(self, flow):
        # A kill at start does not stop bytes already queued; empty and kill every message too.
        flow.messages[-1].content = b""
        if flow.killable:
            flow.kill()

    def udp_message(self, flow):
        flow.messages[-1].content = b""
        if flow.killable:
            flow.kill()

    def udp_start(self, flow):
        flow.kill()
        log({"dir": "killed", "kind": "udp", "host": str(flow.server_conn.address)})

    def error(self, flow):
        log({"dir": "error", "host": flow.request.pretty_host, "method": flow.request.method,
             "path": norm_path(flow.request.path), "error": str(flow.error)[:120]})

    def tls_failed_client(self, data):
        # The client refused the gate's certificate: it pins or ignores the CA bundle.
        log({"dir": "tls-refused", "sni": data.context.client.sni})

    def http_connect(self, flow):
        log({"dir": "connect", "host": flow.request.pretty_host, "port": flow.request.port})


addons = [Recorder()] if LOG else []
