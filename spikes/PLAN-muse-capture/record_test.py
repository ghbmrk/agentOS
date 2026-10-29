"""Tests for record.py: the log holds shapes and never a canary value, and model calls are refused
unless a turn is granted. Run: MUSE_CAP_LOG=x python3 -m pytest record_test.py (run.sh test)."""
import base64, importlib, json, os, sys, tempfile

from mitmproxy.test import tflow, tutils

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def b64(o):
    return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()


# Synthetic canaries only.
JWT = b64({"alg": "RS256", "typ": "JWT"}) + "." + b64({"sub": "CANARYSUB123", "email": "canary@example.invalid", "contributor": True}) + ".c2lnbmF0dXJlQ0FOQVJZc2lnbmF0dXJl"
REFRESH = "mrt_CANARYrefreshTOKENvalue0123456789abcdef"
PROMPT = "CANARY prompt text that must never be logged"


def load(turns="0", canary=""):
    log = tempfile.mktemp()
    os.environ.update(MUSE_CAP_LOG=log, MUSE_CAP_PHASE="test", MUSE_CAP_ALLOW_TURNS=turns, MUSE_CAP_CANARY=canary)
    import record
    importlib.reload(record)
    return record, log


def records(log):
    with open(log) as f:
        return f.read()


def flow(path, body, resp=None, rhdrs=()):
    f = tflow.tflow(req=tutils.treq(method=b"POST", path=path.encode(), content=json.dumps(body).encode(),
                                    headers=((b"content-type", b"application/json"), (b"authorization", ("Bearer " + JWT).encode()))))
    if resp is not None:
        f.response = tutils.tresp(content=json.dumps(resp).encode(),
                                  headers=((b"content-type", b"application/json"),) + tuple(rhdrs))
    return f


def test_token_answer_logs_shapes_not_values():
    rec, log = load()
    f = flow("/oauth/token", {"grant_type": "refresh_token", "refresh_token": REFRESH},
             {"access_token": JWT, "refresh_token": REFRESH, "id_token": JWT, "expires_in": 3600,
              "account_id": 1234567890123, "token_type": "Bearer"},
             ((b"x-ratelimit-remaining", b"42"), (b"set-cookie", b"s=CANARYCOOKIE")))
    r = rec.Recorder()
    r.request(f)
    r.response(f)
    out = records(log)
    for canary in ("CANARYSUB123", "canary@example.invalid", REFRESH, JWT, "CANARYCOOKIE", "1234567890123", "c2lnbmF0dXJl"):
        assert canary not in out
    resp = [json.loads(l) for l in out.splitlines()][1]
    body = resp["body"]["json"]
    assert body["id_token"]["jwt_claims"] == ["contributor", "email", "sub"]
    assert body["refresh_token"]["prefix"] == "mrt_"
    assert body["expires_in"] == 3600 and body["account_id"] == "int"
    assert body["token_type"] == "Bearer"
    assert resp["headers"]["quota"] == {"x-ratelimit-remaining": "42"}


def test_model_call_blocked_by_default():
    rec, log = load()
    f = flow("/v1/turn", {"model": "muse-1", "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": PROMPT}]}]})
    rec.Recorder().request(f)
    assert f.response is not None and f.response.status_code == 503
    out = records(log)
    assert PROMPT not in out
    r = json.loads(out)
    assert r["blocked"] and r["model_call"]
    item = r["body"]["json"]["input"][0]
    assert item["type"] == "message" and item["role"] == "user" and item["content"][0]["type"] == "input_text"


def test_granted_turn_passes_once():
    rec, _ = load("1")
    r = rec.Recorder()
    first, second = (flow("/v1/turn", {"messages": [{"role": "user", "content": PROMPT}]}) for _ in range(2))
    r.request(first)
    r.request(second)
    assert first.response is None
    assert second.response is not None and second.response.status_code == 503


def test_safe_key_value_with_token_run_is_shaped():
    rec, _ = load()
    assert rec.shape("x" * 30, "code") == {"len": 30, "cls": "a"}
    assert rec.shape("invalid_grant", "error") == "invalid_grant"


def test_path_ids_are_replaced():
    rec, _ = load()
    assert rec.norm_path("/v1/users/1234567890/settings?x=1") == "/v1/users/{id}/settings"
    assert rec.norm_path("/a/0f8fad5b-d9cb-469f-a165-70867728950e") == "/a/{id}"


def post(body, ctype):
    return tflow.tflow(req=tutils.treq(method=b"POST", path=b"/api/graphql", content=body,
                                       headers=((b"content-type", ctype),)))


def blocked(rec, f):
    rec.Recorder().request(f)
    return f.response is not None and f.response.status_code == 503


def test_nested_model_bodies_blocked():
    rec, log = load()
    from urllib.parse import urlencode
    shapes = [
        (json.dumps({"doc_id": "1", "variables": {"input": {"message": {"text": PROMPT}}}}), b"application/json"),
        (json.dumps({"doc_id": "1", "variables": json.dumps({"message": {"text": PROMPT}})}), b"application/json"),
        (urlencode({"doc_id": "1", "variables": json.dumps({"message": {"sensitive_string_value": PROMPT}})}), b"application/x-www-form-urlencoded"),
        (urlencode({"doc_id": "1", "prompt": PROMPT}), b"application/x-www-form-urlencoded"),
        (json.dumps([{"messages": [{"role": "user", "content": PROMPT}]}]), b"application/json"),
    ]
    for body, ctype in shapes:
        assert blocked(rec, post(body.encode(), ctype)), body
    assert PROMPT not in records(log)


def test_read_without_model_key_passes():
    rec, _ = load()
    assert not blocked(rec, post(json.dumps({"doc_id": "1", "variables": {"id": "x"}}).encode(), b"application/json"))


def test_websocket_turn_dropped_unless_granted():
    from mitmproxy.websocket import WebSocketMessage
    for turns, dropped in (("0", True), ("1", False)):
        rec, log = load(turns)
        f = tflow.twebsocketflow()
        f.websocket.messages.append(WebSocketMessage(1, True, json.dumps({"type": "turn", "input": [{"text": PROMPT}]}).encode()))
        rec.Recorder().websocket_message(f)
        assert f.websocket.messages[-1].dropped is dropped
        assert PROMPT not in records(log)


def test_mid_length_ids_and_device_codes_are_shaped():
    rec, _ = load()
    assert rec.norm_path("/v1/acct/a1b2c3d4e5f6/x") == "/v1/acct/{id}/x"
    assert rec.norm_path("/v1/graphql") == "/v1/graphql"
    assert rec.shape("ABCD-EFGH", "code") == {"len": 9, "cls": "A-"}
    assert rec.shape("authorization_pending", "code") == "authorization_pending"


CANARY = "mcapcanary0f3a9c1e7b"


def test_canary_blocks_any_shape():
    rec, log = load(canary=CANARY)
    said = "Reply ok. " + CANARY
    for body, ctype in ((b"\x0a\x2d" + said.encode(), b"application/grpc"),
                        (json.dumps({"event": "prompt_submitted", "text": said}).encode(), b"application/json"),
                        (json.dumps({"query": said}).encode(), b"application/json"),
                        (b"--XyZ\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n" + said.encode() + b"\r\n--XyZ--\r\n", b"multipart/form-data; boundary=XyZ")):
        assert blocked(rec, post(body, ctype)), body
    get = tflow.tflow(req=tutils.treq(method=b"GET", path=("/log?q=" + CANARY).encode()))
    assert blocked(rec, get)
    out = records(log)
    assert CANARY not in out and "Reply ok." not in out


def test_canary_websocket_dropped():
    from mitmproxy.websocket import WebSocketMessage
    rec, _ = load(canary=CANARY)
    f = tflow.twebsocketflow()
    f.websocket.messages.append(WebSocketMessage(2, True, b"\x08\x01" + CANARY.encode()))
    rec.Recorder().websocket_message(f)
    assert f.websocket.messages[-1].dropped


def enc_post(body, hdrs):
    return tflow.tflow(req=tutils.treq(method=b"POST", path=b"/x", content=body, headers=hdrs))


def test_uninspectable_bodies_refused_and_logged():
    import gzip
    from urllib.parse import quote
    rec, log = load(canary=CANARY)
    said = "Reply ok. " + CANARY
    cases = [
        (said.encode(), ((b"content-encoding", b"snappy"),)),
        (said.encode(), ((b"content-encoding", b"gzip, br"),)),
        (gzip.compress(said.encode()), ((b"content-type", b"application/octet-stream"),)),
        (b"\x01\x00\x00\x00\x20" + gzip.compress(said.encode()), ((b"content-type", b"application/grpc"), (b"grpc-encoding", b"gzip"))),
        (said.encode("utf-16"), ((b"content-type", b"text/plain"),)),
        (b"\x0a\x03abc", ((b"content-type", b"application/grpc"),)),  # binary, no canary: still refused
    ]
    for body, hdrs in cases:
        assert blocked(rec, enc_post(body, hdrs)), (body[:20], hdrs)
    recs = [json.loads(l) for l in records(log).splitlines()]
    assert len(recs) == len(cases) and all(r["blocked"] for r in recs)


def test_canary_seen_through_text_encodings():
    from urllib.parse import quote
    rec, _ = load(canary=CANARY)
    said = "Reply ok. " + CANARY
    for body in (json.dumps({"p": base64.b64encode(said.encode()).decode()}),
                 json.dumps({"p": said}, ensure_ascii=True).replace(CANARY[:4], "\\u006d\\u0063\\u0061\\u0070"),
                 "q=" + "".join("%%%02X" % c for c in said.encode())):
        assert blocked(rec, post(body.encode(), b"application/json")), body


def test_hook_error_refuses():
    rec, log = load(canary=CANARY)
    f = post(b'{"a":1}', b"application/json")
    orig = rec.body_shape
    rec.body_shape = lambda *a: 1 / 0
    try:
        rec.Recorder().request(f)
    finally:
        rec.body_shape = orig
    assert f.response.status_code == 503
    r = json.loads(records(log))
    assert r["blocked"] and r["error"] == "ZeroDivisionError"


def test_binary_websocket_message_dropped():
    from mitmproxy.websocket import WebSocketMessage
    rec, _ = load(canary=CANARY)
    f = tflow.twebsocketflow()
    f.websocket.messages.append(WebSocketMessage(2, True, b"\xff\x00\x13"))
    rec.Recorder().websocket_message(f)
    assert f.websocket.messages[-1].dropped
