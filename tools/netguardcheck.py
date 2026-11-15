#!/usr/bin/env python3
"""Fail when a broker dialer is not hooked into the home-network address guard (DEV-2).

Every non-test Go file under broker/ that opens a network connection (net.Dialer, net.Dial*,
tls.Dial*, smtp.Dial*, an http.Transport, an http.Client or net.Resolver value (a *pointer* type is a reference, not a construction), http.DefaultClient/DefaultTransport, http.Get/Post/Head)
must import broker/netguard (a real import declaration, not the path in a comment or string), or be listed in tools/netguard_allow.txt with a reason. A SIP user agent (sipgo.NewUA) must also hand its transport the guard's dialer (DialerCreate), not
merely import the guard. Unix-socket
dials are exempt, as is testdata/ (guest programs). The allowlist is a debt list: an entry whose
file is gone, now imports the guard, or no longer has an unhooked dial fails the check, so it
cannot go stale. DEV-net-b empties it.

The check is per file, not per call: a file that imports netguard is trusted to use it for every
dial it makes; the netguard tests and review cover that use. Heuristic by design (a regex, not
the Go type checker): it finds the common dial forms and errs toward a flag.

Usage: netguardcheck.py [--root DIR] [--allow FILE]
"""
import argparse
import pathlib
import re
import sys

GUARD = '"github.com/ghbmrk/agentos/broker/netguard"'
DIAL = re.compile(
    r"\bnet\.Dialer\b|\bnet\.Dial(?:Timeout|TCP|UDP|IP)?\(|\btls\.Dial(?:WithDialer)?\(|\bsmtp\.Dial|"
    r"\bhttp\.Transport\b|\bhttp\.Default(?:Client|Transport)\b|\bhttp\.(?:Get|Post|Head|PostForm)\(|"
    r"(?<!\*)\bhttp\.Client\b|(?<!\*)\bnet\.Resolver\b"
)
# A SIP user agent opens its own connections through a transport layer, so importing the guard does
# not hook it: the file must also give the transport the guard's dialer (DialerCreate).
SIP_CLIENT = re.compile(r"\bsipgo\.NewUA\(")
WINDOW = 4  # lines after a match searched for "unix"


def sites(path):
    """Line numbers of dial sites in a Go file that are not Unix-socket dials."""
    lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
    out = []
    for i, line in enumerate(lines):
        if line.lstrip().startswith("//") or not DIAL.search(line):
            continue
        near = lines[i : i + WINDOW + 1]
        if any('"unix"' in l for l in near):
            continue
        # A client that names its Transport is judged by that Transport, which is its own site.
        if re.search(r"\bhttp\.Client\b", line) and not re.search(r"\bhttp\.Client\b\s*\{\s*\}", line) \
                and any(re.search(r"\bTransport\s*:", l) for l in near):
            continue
        out.append(i + 1)
    return out


def strip_comments(text, literals=True):
    """Text with each comment replaced by a space (a newline kept per line comment), or None if a
    comment or literal does not terminate. Interpreted, raw and rune literals are kept verbatim, or
    replaced by `""` when `literals` is false (code identifiers only)."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            out.append(" ")
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                return None
            out.append("\n" if "\n" in text[i:j] else " ")
            i = j + 2
        elif c == "`":
            j = text.find("`", i + 1)
            if j < 0:
                return None
            out.append(text[i:j + 1] if literals else '""')
            i = j + 1
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                if text[j] == "\n":
                    return None
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                return None
            out.append(text[i:j + 1] if literals else '""')
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


_SPEC = r'(?:([A-Za-z_]\w*|\.)\s+)?("(?:[^"\\\n]|\\.)*"|`[^`]*`)'
_HEAD = re.compile(r"\s*package\s+\w+\s*?(?:;|\n|$)")
_DECL = re.compile(r"\s*import\b\s*")


def imports(text):
    """[(name, path)] of a Go file's import declarations, or None if they do not parse. Comments
    are stripped first, so only real declarations count (REV-LOW-tools finding 19)."""
    code = strip_comments(text)
    if code is None:
        return None
    m = _HEAD.match(code)
    if not m:
        return None
    pos, out = m.end(), []
    spec = re.compile(r"\s*" + _SPEC + r"\s*(?:;|\n)?")
    while True:
        d = _DECL.match(code, pos)
        if not d:
            return out
        pos = d.end()
        if code.startswith("(", pos):
            pos += 1
            while True:
                end = re.compile(r"\s*\)\s*(?:;|\n|$)").match(code, pos)
                if end:
                    pos = end.end()
                    break
                s = spec.match(code, pos)
                if not s or s.end() == pos:
                    return None
                out.append((s.group(1) or "", s.group(2)[1:-1]))
                pos = s.end()
        else:
            s = re.compile(r"\s*" + _SPEC + r"[ \t]*(?:;|\n|$)").match(code, pos)
            if not s:
                return None
            out.append((s.group(1) or "", s.group(2)[1:-1]))
            pos = s.end()


def hooked(path):
    """True if the file imports the guard under a usable name (a blank import cannot use it); an
    unparsable file is not hooked, so it fails closed."""
    specs = imports(path.read_text(encoding="utf-8", errors="replace"))
    return bool(specs) and any(p == GUARD.strip('"') and name != "_" for name, p in specs)


def load_allow(path):
    allow = {}
    if path.exists():
        # Bytes, so "\r" is not turned into "\n", and printable ASCII only: a hidden break would
        # add an entry (REV-CHK-crlf, #3902).
        for n, raw in enumerate(path.read_bytes().decode("utf-8", "replace").split("\n"), 1):
            bad = [c for c in raw if not " " <= c <= "~"]
            if bad:
                raise SystemExit(f"{path}:{n}: character {bad[0]!r} outside printable ASCII")
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            rel, _, why = raw.partition(" ")
            if not why.strip():
                raise SystemExit(f"{path}:{n}: {rel} needs a reason")
            allow[rel] = why.strip()
    return allow


def check(root, allow_file):
    root = pathlib.Path(root)
    allow = load_allow(pathlib.Path(allow_file))
    problems, seen = [], set()
    for f in sorted((root / "broker").rglob("*.go")):
        rel = f.relative_to(root).as_posix()
        if "/vendor/" in rel or "/testdata/" in rel or rel.endswith("_test.go") or rel.startswith("broker/netguard/"):
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        if any(SIP_CLIENT.search(l) for l in text.split("\n") if not l.lstrip().startswith("//")) \
                and not (re.search(r"\bDialerCreate\b", strip_comments(text, literals=False) or "") and hooked(f)):
            if rel not in allow:
                problems.append(f"{rel}: SIP client built without a guarded dialer (give the transport layer netguard.Policy's dialer through DialerCreate)")
            seen.add(rel)
            continue
        found = sites(f)
        if not found:
            continue
        if hooked(f):
            if rel in allow:
                problems.append(f"{rel}: imports the guard, remove it from the allowlist")
            continue
        seen.add(rel)
        if rel not in allow:
            problems.append(f"{rel}:{found[0]}: dialer not hooked into broker/netguard (use netguard.Policy.DialContext, or list the file with a reason)")
    for rel in sorted(set(allow) - seen):
        if rel not in {p.split(":")[0] for p in problems}:
            problems.append(f"{rel}: allowlisted but has no unhooked dialer (stale entry)")
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser()
    root = pathlib.Path(__file__).resolve().parent.parent
    ap.add_argument("--root", default=str(root))
    ap.add_argument("--allow", default=str(root / "tools" / "netguard_allow.txt"))
    a = ap.parse_args(argv)
    problems = check(a.root, a.allow)
    for p in problems:
        print("netguardcheck:", p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
