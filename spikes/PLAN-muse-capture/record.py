"""Shapes-only recorder for the PLAN-muse capture (#1379 slice (b)): a mitmproxy addon that stands
between Muse Code and Meta, as fwd.py did for Codex in #809. It logs hosts, methods, paths, statuses,
header names, quota-like header values and body shapes (key names, kinds, JWT claim names, short
enum values under known-safe keys), never a token, cookie, prompt, reply or account value. Model
calls are refused before they leave the machine unless MUSE_CAP_ALLOW_TURNS grants some, so a run
spends no plan usage by default.

Environment: MUSE_CAP_LOG (JSONL path, required), MUSE_CAP_PHASE (label written on each record),
MUSE_CAP_ALLOW_TURNS (model calls to let through, default 0)."""
import base64, json, os, re, threading, time

LOG = os.environ.get("MUSE_CAP_LOG", "")
PHASE = os.environ.get("MUSE_CAP_PHASE", "")
_lock = threading.Lock()
_turns = [int(os.environ.get("MUSE_CAP_ALLOW_TURNS", "0") or 0)]
# run.sh puts this token in every test prompt. Any request or client websocket message that
# carries it, in any shape or encoding the recorder can decode, is a turn (or a copy of one) and
# is refused unless a turn is granted: this fails closed where the key detector cannot.
CANARY = os.environ.get("MUSE_CAP_CANARY", "").encode()

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
    """True if a model key appears at any depth, including inside strings that parse as JSON
    (GraphQL `variables`, form fields) and inside arrays (batched bodies)."""
    if depth > 32:
        return True
    if isinstance(v, dict):
        return bool(MODEL_KEYS & {str(k).lower() for k in v}) or any(has_model_key(x, depth + 1) for x in v.values())
    if isinstance(v, list):
        return any(has_model_key(x, depth + 1) for x in v)
    if isinstance(v, (str, bytes)) and v[:1] in ("{", "[", b"{", b"["):
        try:
            return has_model_key(json.loads(v), depth + 1)
        except Exception:
            return False
    return False


def body_has_model_key(raw):
    if not raw:
        return False
    if has_model_key(raw.strip()):
        return True
    from urllib.parse import parse_qsl
    try:
        pairs = parse_qsl(raw.decode(errors="replace"))
    except Exception:
        return False
    return any(k.lower() in MODEL_KEYS or has_model_key(v) for k, v in pairs)


def carries_canary(*parts):
    return bool(CANARY) and any(CANARY in p for p in parts if p)


def is_model_call(flow):
    req = flow.request
    raw = req.get_content(strict=False) or b""
    if carries_canary(raw, req.raw_content, req.path.encode(errors="replace"),
                      b"\n".join(v.encode(errors="replace") for v in req.headers.values())):
        return True
    if req.method not in ("POST", "PUT", "PATCH"):
        return False
    return body_has_model_key(raw)


def take_turn():
    if _turns[0] > 0:
        _turns[0] -= 1
        return True
    return False


class Recorder:
    def request(self, flow):
        req = flow.request
        rec = {"dir": "req", "host": req.pretty_host, "method": req.method,
               "path": norm_path(req.path), "query_keys": sorted(req.query.keys()),
               "headers": headers(req.headers, False),
               "body": body_shape(req.get_content(), req.headers.get("content-type"))}
        if is_model_call(flow):
            rec["model_call"] = True
            if not take_turn():
                from mitmproxy import http
                rec["blocked"] = True
                flow.response = http.Response.make(503, b'{"error":"blocked by capture"}',
                                                   {"content-type": "application/json"})
        flow.metadata["rec"] = rec
        log(rec)

    def response(self, flow):
        if flow.metadata.get("rec", {}).get("blocked"):
            return
        r = flow.response
        log({"dir": "resp", "host": flow.request.pretty_host, "method": flow.request.method,
             "path": norm_path(flow.request.path), "status": r.status_code,
             "headers": headers(r.headers, True),
             "body": body_shape(r.get_content(), r.headers.get("content-type"))})

    def websocket_message(self, flow):
        m = flow.websocket.messages[-1]
        try:
            s = shape(json.loads(m.content))
        except Exception:
            s = {"len": len(m.content)}
        rec = {"dir": "ws-" + ("out" if m.from_client else "in"), "host": flow.request.pretty_host,
               "path": norm_path(flow.request.path), "body": s}
        if m.from_client and (carries_canary(m.content) or body_has_model_key(m.content)):
            rec["model_call"] = True
            if not take_turn():
                rec["blocked"] = True
                m.drop()
        log(rec)

    def error(self, flow):
        log({"dir": "error", "host": flow.request.pretty_host, "method": flow.request.method,
             "path": norm_path(flow.request.path), "error": str(flow.error)[:120]})

    def tls_failed_client(self, data):
        # The client refused the recorder's certificate: it pins or ignores the CA bundle.
        log({"dir": "tls-refused", "sni": data.context.client.sni})

    def http_connect(self, flow):
        log({"dir": "connect", "host": flow.request.pretty_host, "port": flow.request.port})


addons = [Recorder()] if LOG else []
