"""The plan route's live checks on a `run.sh plan` run (#3110, #3180 item 3). Usage:
qualify.py SESSION_OUT PLAN_JSONL PLAN_GO

1. The code the CLI printed equals the user_code the provider answered, exactly: the clerk shows
   a printed code only if it is the one it forwarded (broker/clerk/run SignInPrompt.Code, plan.Login
   UserCode), so a CLI that reformats it (case, separators) fails every sign-in as signin-code.
   The printed code is read as SignInPrompt.Code reads it: the first code-shaped token after the
   first of CodexSignIn's links, escapes stripped. Only digests are compared.
2. The CLI's own refresh body carries exactly client_id, grant_type and refresh_token, with the
   client_id the Codex declaration pins (plan.CodexClientID) and no scope.
Exit 1 on any mismatch, or when the run shows neither."""
import hashlib, json, re, sys

LINKS = ["http://127.0.0.1:18432/codex/device", "https://auth.openai.com/codex/device"]
CODE = re.compile(r"\A[A-Z0-9-]{4,16}\Z")
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

out, log, decl = sys.argv[1:4]
toks = ANSI.sub("", open(out, errors="replace").read()[: 64 << 10]).split()
printed = None
for i, t in enumerate(toks):
    if t in LINKS:
        printed = next((c for c in toks[i + 1:] if CODE.match(c)), None)
        break
recs = [json.loads(line) for line in open(log)]
answered = [r["user_code_sha256"] for r in recs if "user_code_sha256" in r]
refresh = [r["refresh_fixed"] for r in recs if "refresh_fixed" in r]
m = re.search(r'(?m)^const CodexClientID = "([^"]+)"$', open(decl).read())
fail = False
if printed is None or not answered:
    print("user_code: FAIL, no printed code or no answered user_code"); fail = True
elif hashlib.sha256(printed.encode()).hexdigest() != answered[-1]:
    print("user_code: FAIL, the printed code differs from the answered user_code"); fail = True
else:
    print("user_code: the printed code equals the answered user_code")
if not m or not refresh:
    print("refresh: FAIL, no CodexClientID in the declaration or no refresh in the run"); fail = True
for body in refresh:
    want = {"client_id": m.group(1) if m else None, "grant_type": "refresh_token"}
    if body != want:
        print("refresh: FAIL, the CLI sent %s, the declaration pins %s" % (json.dumps(body), json.dumps(want))); fail = True
    else:
        print("refresh: the CLI's body matches the declaration")
sys.exit(1 if fail else 0)
