"""The plan route's live checks on a `run.sh plan` run (#3110, #3180 item 3, #5089). Usage:
qualify.py printed DIGEST_OUT          < the session's output
qualify.py check DIGEST PLAN_JSONL DECL_JSON

`printed` passes the session's output through to stdout as it comes, so the owner sees the
code, and writes only the digest of the printed code to DIGEST_OUT: the code itself is never
written. It reads the code as broker/clerk/run SignInPrompt.Code does: the first code-shaped
token after the first of CodexSignIn's links, escapes stripped, in the first 64 KiB.

`check` exits 1 on any mismatch, or when the run shows none of what it checks:
1. The printed code equals the user_code the provider answered, exactly: the clerk shows a
   printed code only if it is the one it forwarded (plan.Login UserCode), so a CLI that
   reformats it (case, separators) fails every sign-in as signin-code. Only digests are compared.
2. The CLI's own refresh body carries exactly the declaration's fixed values (Codex Refresh,
   printed by codexdecl.go into DECL_JSON) and refresh_token, so no scope.
3. The CLI's refresh sends each declared refresh header (RefreshHeaders) with its value.
4. The CLI's code exchange sends the refresh's client_id."""
import hashlib, json, os, re, sys

LINKS = ["http://127.0.0.1:18432/codex/device", "https://auth.openai.com/codex/device"]
CODE = re.compile(r"\A[A-Z0-9-]{4,16}\Z")
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
MAX = 64 << 10


def printed_code(text):
    toks = ANSI.sub("", text[:MAX]).split()
    for i, t in enumerate(toks):
        if t in LINKS:
            return next((c for c in toks[i + 1:] if CODE.match(c)), None)
    return None


def printed(out):
    seen = bytearray()
    while True:
        b = os.read(0, 4096)
        if not b:
            break
        os.write(1, b)
        if len(seen) < MAX:
            seen += b[:MAX - len(seen)]
    code = printed_code(seen.decode(errors="replace"))
    with open(out, "w") as f:
        json.dump({"printed_sha256": hashlib.sha256(code.encode()).hexdigest()} if code else {}, f)


def check(digest, log, decl):
    got = json.load(open(digest)).get("printed_sha256")
    recs = [json.loads(line) for line in open(log)]
    d = json.load(open(decl))
    want_body, want_headers = d.get("refresh") or {}, d.get("refresh_headers") or {}
    answered = [r["user_code_sha256"] for r in recs if "user_code_sha256" in r]
    refresh = [r for r in recs if "refresh_fixed" in r]
    codes = [r["code_client_id"] for r in recs if "code_client_id" in r]
    fail = False
    if got is None or not answered:
        print("user_code: FAIL, no printed code or no answered user_code"); fail = True
    elif got != answered[-1]:
        print("user_code: FAIL, the printed code differs from the answered user_code"); fail = True
    else:
        print("user_code: the printed code equals the answered user_code")
    if not want_body or not refresh:
        print("refresh: FAIL, no refresh in the declaration or none in the run"); fail = True
    for r in refresh:
        if r["refresh_fixed"] != want_body:
            print("refresh: FAIL, the CLI sent %s, the declaration pins %s" % (json.dumps(r["refresh_fixed"]), json.dumps(want_body))); fail = True
        else:
            print("refresh: the CLI's body matches the declaration")
        sent = r.get("refresh_headers") or {}
        for k, v in want_headers.items():
            if sent.get(k.lower()) != v:
                print("refresh: FAIL, the CLI sent %s %s, the declaration pins %s" % (k, json.dumps(sent.get(k.lower())), json.dumps(v))); fail = True
        if want_headers and all(sent.get(k.lower()) == v for k, v in want_headers.items()):
            print("refresh: the CLI's refresh headers match the declaration")
    if not codes:
        print("code: FAIL, no code exchange in the run"); fail = True
    for c in codes:
        if c != want_body.get("client_id"):
            print("code: FAIL, the CLI's code exchange sent client_id %s, the declaration pins %s" % (json.dumps(c), json.dumps(want_body.get("client_id")))); fail = True
        else:
            print("code: the CLI's code exchange sends the declared client_id")
    return 1 if fail else 0


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "printed":
        printed(sys.argv[2])
    elif len(sys.argv) == 5 and sys.argv[1] == "check":
        sys.exit(check(*sys.argv[2:5]))
    else:
        sys.exit(__doc__)
