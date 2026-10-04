"""S5 action protocol v0: the closed verb set (CRED-4) and output redaction (CRED-10).

Pure functions only (no browser), so CI can test them without Playwright.

A request is one JSON object: {"v": 0, "verb": <verb>, ...args}. Targets are refs
("e12", "f1e3") taken from the latest snapshot, never CSS/XPath selectors, so the
agent supplies no query language the executor would evaluate.
"""
import math
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

VERSION = 0

REF = re.compile(r"(?:f\d+)?e\d+")
MAX_TEXT = 2000
MAX_SNAPSHOT = 256 * 1024  # characters returned per snapshot

# verb -> {arg: type}. Nothing else exists: no evaluate, no cookies, no storage,
# no headers, no devtools, no tabs.
VERBS = {
    "navigate": {"url": str},
    "click": {"ref": str},
    "type": {"ref": str, "text": str, "submit": bool},
    "select": {"ref": str, "option": str},
    "snapshot": {},
    "screenshot": {},
    "download": {"ref": str},
}
OPTIONAL = {"type": {"submit"}}


class ProtocolError(ValueError):
    pass


def validate(req):
    """Return the request if it is a well-formed v0 request, else raise ProtocolError."""
    if not isinstance(req, dict):
        raise ProtocolError("request must be an object")
    if type(req.get("v")) is not int or req["v"] != VERSION:
        raise ProtocolError(f"unsupported protocol version {req.get('v')!r}")
    verb = req.get("verb")
    if verb not in VERBS:
        raise ProtocolError(f"unknown verb {verb!r}")
    spec = VERBS[verb]
    extra = set(req) - {"v", "verb"} - set(spec)
    if extra:
        raise ProtocolError(f"unknown argument(s) {sorted(extra)} for {verb}")
    for arg, typ in spec.items():
        if arg not in req:
            if arg in OPTIONAL.get(verb, ()):
                continue
            raise ProtocolError(f"{verb} needs {arg}")
        if type(req[arg]) is not typ:
            raise ProtocolError(f"{verb}.{arg} must be {typ.__name__}")
    if "ref" in req and not REF.fullmatch(req["ref"]):
        raise ProtocolError("ref must come from a snapshot (e.g. e12)")
    if verb == "navigate":
        check_url(req["url"])
    if verb == "type" and len(req["text"]) > MAX_TEXT:
        raise ProtocolError("text too long")
    return req


def check_url(url):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ProtocolError("navigate takes an http(s) URL only")
    if parts.username or parts.password:
        raise ProtocolError("URLs with userinfo are refused")
    return url


def origin(url):
    p = urlsplit(url)
    port = p.port or {"http": 80, "https": 443}.get(p.scheme)
    return f"{p.scheme}://{p.hostname}:{port}"


def on_declared_origin(url, declared):
    """CRED-10: is url on one of the account's declared origins?"""
    try:
        o = origin(url)
    except ValueError:
        return False
    return o in {origin(d) for d in declared}


# --- CRED-10 output detector -------------------------------------------------

TOKEN_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),  # JWT
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}"),       # GitHub
    re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}"),                            # API keys
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                                        # AWS
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),                              # Slack
]
SECRET_PARAM = re.compile(r"(token|code|key|sig|auth|session|password|secret)", re.I)
CANDIDATE = re.compile(r"[A-Za-z0-9+_=-]{24,}")  # no "/": path segments are judged one by one
REDACTED = "[REDACTED]"


def entropy(s):
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def high_entropy(s):
    # Mixed classes and >= 4 bits/char: random tokens, not words or paths.
    classes = sum(bool(re.search(p, s)) for p in ("[a-z]", "[A-Z]", "[0-9]"))
    return len(s) >= 24 and classes >= 2 and entropy(s) >= 4.0


def _redact_pairs(s):
    """Redact values of secret-named key=value pairs in a query or fragment string."""
    out, hit = [], False
    for k, v in parse_qsl(s, keep_blank_values=True):
        if v and SECRET_PARAM.search(k):
            out.append((k, REDACTED))
            hit = True
        else:
            out.append((k, v))
    return (urlencode(out, safe="[]") if hit else s), hit


def redact_url(url):
    """Drop values of secret-named query and fragment parameters (REV-5 patterns),
    e.g. OAuth implicit-flow tokens in '#access_token=...'."""
    try:
        p = urlsplit(url)
    except ValueError:
        return url, False
    query, hq = _redact_pairs(p.query) if p.query else (p.query, False)
    frag, hf = _redact_pairs(p.fragment) if "=" in p.fragment else (p.fragment, False)
    if not (hq or hf):
        return url, False
    return urlunsplit(p._replace(query=query, fragment=frag)), True


URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>]+|(?<=/url: )\S+")


def redact_text(text):
    """Return (text, n_matches) with known token formats and high-entropy runs replaced."""
    n = 0

    def sub_url(m):
        nonlocal n
        new, hit = redact_url(m.group(0))
        n += hit
        return new

    text = URL_IN_TEXT.sub(sub_url, text)
    for pat in TOKEN_PATTERNS:
        text, k = pat.subn(REDACTED, text)
        n += k

    def sub_entropy(m):
        nonlocal n
        if high_entropy(m.group(0)):
            n += 1
            return REDACTED
        return m.group(0)

    text = CANDIDATE.sub(sub_entropy, text)
    return text, n


def cap_snapshot(text):
    if len(text) <= MAX_SNAPSHOT:
        return text, False
    return text[:MAX_SNAPSHOT] + "\n[snapshot truncated]", True


# --- password field omission (CRED-4) ----------------------------------------

REF_TOKEN = re.compile(r"\[ref=((?:f\d+)?e\d+)\]")
ATTRS = re.compile(r"^(?: \[[^\]]*\])*")


def omit_values(snapshot, refs):
    """Remove the value text of snapshot nodes whose ref is in refs (password fields).

    The node stays (the agent may need to see a login form exists); only its value goes.
    Works on the YAML-quoted form too ('- 'textbox "Pass:" [ref=e5]': value').
    """
    out = []
    for line in snapshot.splitlines():
        m = REF_TOKEN.search(line)
        if m and m.group(1) in refs:
            attrs = ATTRS.match(line[m.end():]).group(0)
            head = (line[:m.end()] + attrs).replace("- '", "- ", 1)
            rest = line[m.end() + len(attrs):].lstrip("'")
            if rest.startswith(":") and rest[1:].strip():
                line = head + ": [password omitted]"
            elif rest.startswith(":"):
                line = head + ":"
            else:
                line = head
        out.append(line)
    return "\n".join(out)
