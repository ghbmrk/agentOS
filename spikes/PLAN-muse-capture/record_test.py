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


def load(turns="0"):
    log = tempfile.mktemp()
    os.environ.update(MUSE_CAP_LOG=log, MUSE_CAP_PHASE="test", MUSE_CAP_ALLOW_TURNS=turns)
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
