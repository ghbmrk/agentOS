"""Tests for record.py: the gate refuses by default, passes only allowed readable requests (and in
strict phases only bodyless repeats of URLs already seen), kills non-HTTP flows, and the log holds
shapes, never a canary value. Run: run.sh test."""
import base64, gzip, importlib, json, os, sys, tempfile

from mitmproxy.test import tflow, tutils

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def b64(o):
    return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()


# Synthetic canaries only.
JWT = b64({"alg": "RS256", "typ": "JWT"}) + "." + b64({"sub": "CANARYSUB123", "email": "canary@example.invalid", "contributor": True}) + ".c2lnbmF0dXJlQ0FOQVJZc2lnbmF0dXJl"
REFRESH = "mrt_CANARYrefreshTOKENvalue0123456789abcdef"
PROMPT = "CANARY prompt text that must never be logged"


def load(allow=(), strict=False, seen=()):
    d = tempfile.mkdtemp()
    paths = {k: os.path.join(d, k) for k in ("log", "allow", "seen")}
    with open(paths["allow"], "w") as f:
        f.write("".join(a + "\n" for a in allow))
    with open(paths["seen"], "w") as f:
        f.write("".join(u + "\n" for u in seen))
    os.environ.update(MUSE_CAP_LOG=paths["log"], MUSE_CAP_PHASE="test", MUSE_CAP_ALLOW=paths["allow"],
                      MUSE_CAP_SEEN=paths["seen"], MUSE_CAP_STRICT="1" if strict else "")
    import record
    importlib.reload(record)
    return record, paths


def text(path):
    with open(path) as f:
        return f.read()


def recs(paths):
    return [json.loads(l) for l in text(paths["log"]).splitlines()]


def req(method=b"POST", path=b"/oauth/token", body=b"", ctype=b"application/json", extra=()):
    hdrs = ((b"content-type", ctype), (b"authorization", ("Bearer " + JWT).encode())) + tuple(extra)
    return tflow.tflow(req=tutils.treq(method=method, path=path, content=body, headers=hdrs))


def refused(rec, f):
    rec.Recorder().request(f)
    return f.response is not None and f.response.status_code == 503


TOKEN = "POST address:22 /oauth/token"


def test_token_answer_logs_shapes_not_values():
    rec, p = load(allow=[TOKEN])
    f = req(body=json.dumps({"grant_type": "refresh_token", "refresh_token": REFRESH}).encode())
    r = rec.Recorder()
    r.request(f)
    assert f.response is None
    f.response = tutils.tresp(content=json.dumps(
        {"access_token": JWT, "refresh_token": REFRESH, "id_token": JWT, "expires_in": 3600,
         "account_id": 1234567890123, "token_type": "Bearer"}).encode(),
        headers=((b"content-type", b"application/json"), (b"x-ratelimit-remaining", b"42"), (b"set-cookie", b"s=CANARYCOOKIE")))
    r.response(f)
    out = text(p["log"])
    for canary in ("CANARYSUB123", "canary@example.invalid", REFRESH, JWT, "CANARYCOOKIE", "1234567890123", "c2lnbmF0dXJl"):
        assert canary not in out
    body = recs(p)[1]["body"]["json"]
    assert body["id_token"]["jwt_claims"] == ["contributor", "email", "sub"]
    assert body["refresh_token"]["prefix"] == "mrt_"
    assert body["expires_in"] == 3600 and body["account_id"] == "int"
    assert recs(p)[1]["headers"]["quota"] == {"x-ratelimit-remaining": "42"}


def test_default_deny():
    rec, p = load()
    assert refused(rec, req(body=b'{"a":1}'))
    assert refused(rec, req(method=b"GET", path=b"/me"))
    assert recs(p)[0]["refused"] == "not-allowed"


def test_allowed_endpoint_refuses_unreadable_or_model_bodies():
    rec, _ = load(allow=[TOKEN])
    said = PROMPT.encode()
    for body, ctype, extra in (
            (said, b"application/json", ((b"content-encoding", b"snappy"),)),
            (said, b"application/json", ((b"content-encoding", b"gzip, br"),)),
            (gzip.compress(said), b"application/octet-stream", ()),
            (b"\x0a\x03abc", b"application/grpc", ()),
            (PROMPT.encode("utf-16"), b"text/plain", ()),
            (b"--XyZ\r\n\r\n" + said + b"\r\n--XyZ--", b"multipart/form-data; boundary=XyZ", ()),
            (json.dumps({"doc_id": "1", "variables": json.dumps({"message": PROMPT})}).encode(), b"application/json", ()),
            (b"q=" + said, b"text/plain", ())):
        assert refused(rec, req(body=body, ctype=ctype, extra=extra)), body[:20]
    assert not refused(rec, req(body=b"grant_type=device_code&device_code=x", ctype=b"application/x-www-form-urlencoded"))


def test_allowed_request_records_its_url_for_strict_phases():
    rec, p = load(allow=["GET address:22 /v1/me"])
    assert not refused(rec, req(method=b"GET", path=b"/v1/me?fields=a", ctype=b"text/plain"))
    assert "GET http://address:22/v1/me?fields=a" in text(p["seen"])


def test_strict_passes_only_bodyless_repeats_of_seen_urls():
    seen = ["GET http://address:22/v1/me?fields=a"]
    rec, p = load(allow=[TOKEN, "GET address:22 /v1/me"], strict=True, seen=seen)
    assert not refused(rec, req(method=b"GET", path=b"/v1/me?fields=a", ctype=b"text/plain"))
    assert refused(rec, req(method=b"GET", path=b"/v1/me?fields=b", ctype=b"text/plain"))  # new query
    assert refused(rec, req(method=b"GET", path=b"/v1/me?fields=a", body=b"x", ctype=b"text/plain"))
    assert refused(rec, req(body=b'{"grant_type":"x"}'))  # allowed in no-prompt phases, not here
    assert PROMPT not in text(p["log"])


def test_hook_error_refuses():
    rec, p = load(allow=[TOKEN])
    orig = rec.body_shape
    rec.body_shape = lambda *a: 1 / 0
    try:
        f = req(body=b'{"a":1}')
        rec.Recorder().request(f)
    finally:
        rec.body_shape = orig
    assert f.response.status_code == 503
    assert recs(p)[0]["refused"] == "error"


def test_non_http_flows_killed():
    rec, p = load()
    r = rec.Recorder()
    t = tflow.ttcpflow()
    r.tcp_start(t)
    u = tflow.tudpflow()
    r.udp_start(u)
    w = tflow.twebsocketflow()
    r.websocket_start(w)
    assert t.error and u.error and w.error
    assert [x["kind"] for x in recs(p)] == ["tcp", "udp", "websocket"]


def test_path_ids_and_codes_are_shaped():
    rec, _ = load()
    assert rec.norm_path("/v1/users/1234567890/settings?x=1") == "/v1/users/{id}/settings"
    assert rec.norm_path("/a/0f8fad5b-d9cb-469f-a165-70867728950e") == "/a/{id}"
    assert rec.norm_path("/v1/acct/a1b2c3d4e5f6/x") == "/v1/acct/{id}/x"
    assert rec.shape("ABCD-EFGH", "code") == {"len": 9, "cls": "A-"}
    assert rec.shape("authorization_pending", "code") == "authorization_pending"
    assert rec.shape("x" * 30, "code") == {"len": 30, "cls": "a"}


def test_non_http_messages_emptied():
    from mitmproxy.tcp import TCPMessage
    rec, _ = load()
    t = tflow.ttcpflow()
    t.messages.append(TCPMessage(True, b"\x10\x2aMQTT " + PROMPT.encode()))
    rec.Recorder().tcp_message(t)
    assert t.messages[-1].content == b""


def test_allow_matches_the_real_destination_not_the_host_header():
    rec, p = load(allow=["POST allowed.test /v1/usage"])
    f = req(path=b"/v1/usage", body=b'{"a":1}', extra=((b"host", b"allowed.test"),))
    assert f.request.pretty_host == "allowed.test" and f.request.host == "address"
    assert refused(rec, f)
    assert recs(p)[0]["refused"] == "host-mismatch" and recs(p)[0]["host"] == "address:22"
    assert text(p["seen"]) == ""


def test_auth_without_scheme_and_odd_query_keys_are_shaped():
    rec, p = load()
    f = req(method=b"GET", path=b"/x?Reply%20ok%20please=1&fields=a", extra=())
    f.request.headers["authorization"] = "Ab+Cd/Ef12+Gh3=IjKlMn"
    rec.Recorder().request(f)
    r = recs(p)[0]
    assert r["headers"]["auth_scheme"] == "none"
    assert "Ab+Cd" not in text(p["log"]) and "Reply ok" not in text(p["log"])
    assert "fields" in r["query_keys"]
