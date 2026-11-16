#!/usr/bin/env python3
"""Fail when a file under broker/ that a build could compile is not plain Go (REV-CHK-src, KRN-2).

The boundary lints under broker/ (the import and launcher gates, the trusted-base checks)
read Go source, and most of them read only the .go files the default build context picks.
Code they do not parse passes them: an assembly file that opens a socket (#3356), a cgo
preamble (#3818), a `//go:linkname` pull of an unexported function, or a file behind a
build tag the lint's context does not set (#3754, #3043). This check makes those shapes
fail in one place, so each boundary lint holds for the files it parses.

It fails on every file under broker/ outside vendor/, third_party/ and any testdata/
directory, apart from _test.go files and names starting with `_` or `.` (go/build ignores
those), that is:
  - a non-Go source the go tool compiles or links (.s, .S, .sx, .c, .h, .cc, .cpp, .m,
    .f, .swig, .syso and the rest of go/build's list), in any letter case;
  - a .go file that imports "C" (in any spelling of the literal), has `#cgo` in any comment,
    or has `go:linkname` or a `go:cgo_` directive in any comment;
  - a .go file that imports a package under a testdata/ directory: go builds one when it is
    named, though ./... leaves it out, and this check skips testdata/;
  - a .go file whose build constraint (`//go:build` or `// +build` before the package
    clause) or file-name suffix (_GOOS, _GOARCH) names a tag outside the build set;
  - a .go file it cannot read: not UTF-8, or an unterminated comment or literal.
  - a symlink, to a file or a directory, under any name: the walk does not follow one.
The build set is read from the builds, not a hand list: every `-tags` value, `-race`,
`GOOS`/`GOARCH` and `CGO_ENABLED=1` in .github/workflows/ and in the non-Markdown files
under image/, plus linux and amd64 for each `runs-on: ubuntu` runner (arm64 for an -arm
one). Always admitted: `gc`, release tags `goN.M`, `unix` with linux, and `ignore` (the
convention for a file no build selects). Whole-line `#` comments are not read.

Each exception is a line in tools/srclint_allow.txt: the path, the kinds of finding it
excuses (comma-separated, from KINDS), then the reason, separated by spaces. A finding of
another kind in that file still fails, and so does a line naming a kind the file no longer
has, or a file that is gone (stale entry).

Wipe lint (CRED-1, MUT-wipe-lint #5865): in the non-test .go files of each WIPE_DIRS package,
a local assigned from `hkdf(...)`, `random(...)` or a `decrypt` call must be passed to `wipe(name)`
(or `defer wipe(name)`) later in the same function, or be returned as a bare operand (`return v, nil`; the caller then owns
it). Mutation testing cannot see a dropped wipe (#5857). A site that cannot be wiped there is an
allow line whose kind is `wipe:FUNC:VAR` (FUNC is the function's name, VAR the local), with the reason.
Bound: a buffer held in a field, a composite literal or a call argument is not seen; nor is a wipe
of the wrong buffer or one behind a branch.

Bound: reflection, `unsafe` and raw syscalls in plain Go stay held by review (childproc
r8 l1, l2), as do what an allowed file does, the skipped vendor/ and third_party/ code, and
code reached from outside broker/ by a go.mod `replace` or a go.work `use`.

Usage: srclint.py [--root DIR] [--allow FILE]
"""
import argparse
import pathlib
import re
import sys

# go/build's knownExt, less .go: every other file the go tool compiles, assembles or links.
NON_GO = frozenset({
    ".c", ".cc", ".cpp", ".cxx", ".m", ".h", ".hh", ".hpp", ".hxx", ".f", ".f90", ".for",
    ".s", ".sx", ".swig", ".swigcxx", ".syso",
})
# go/build's knownOS and knownArch (go1.26), for file-name constraints.
GOOS = frozenset(
    "aix android darwin dragonfly freebsd hurd illumos ios js linux nacl netbsd openbsd plan9 "
    "solaris wasip1 windows zos".split())
GOARCH = frozenset(
    "386 amd64 amd64p32 arm armbe arm64 arm64be loong64 mips mipsle mips64 mips64le mips64p32 "
    "mips64p32le ppc ppc64 ppc64le riscv riscv64 s390 s390x sparc sparc64 wasm".split())
ALWAYS = frozenset({"gc", "ignore"})
# Finding kinds, as an allow line names them.
KINDS = frozenset({"nongo", "cgo", "linkname", "tag", "parse", "symlink", "testdata"})
RELEASE = re.compile(r"go1\.\d+\Z")
# Vault-side packages whose derived and decrypted key buffers must be wiped.
WIPE_DIRS = ("broker/recovery/",)
WIPE_SOURCES = frozenset({"hkdf", "random"})
GO_KEYWORDS = frozenset("break case chan const continue default defer else fallthrough for func go goto if "
                        "import interface map package range return select struct switch type var".split())
# What may come just before the first word of an assignment's left-hand side.
LHS_AFTER = frozenset({("nl", "\n"), ("punct", "{"), ("punct", "}"), ("punct", ";"),
                       ("word", "if"), ("word", "for"), ("word", "switch"), ("word", "var")})
SKIP_TOP = ("broker/vendor/", "broker/third_party/")

TAGS = re.compile(r"""(?<![\w-])-tags(?:=|\s+)(?:"([^"]*)"|'([^']*)'|([^\s"']+))""")
# A shell word that may stand before a command: an env assignment or a wrapper (`jail` is
# image/camdecode.sh's chroot wrapper). An unknown wrapper fails closed: its tags are not counted.
ASSIGN = r"""[A-Za-z_]\w*=(?:"[^"]*"|'[^']*'|[^\s"';&|()`]*)"""
WRAPPER = r"(?:env|exec|command|time|nice|nohup|sudo|jail|export|if|then|do|else|elif|while|until|!|\{)"
# A command segment that builds: optional YAML `- ` / `run:`, assignments and wrappers, then a go
# verb, or a GOFLAGS assignment.
GO_CMD = re.compile(rf"""\s*(?:-\s+)?(?:run:\s*)?(?:(?:{ASSIGN}|{WRAPPER})\s+)*"""
                    rf"""(?:go\s+(?:build|test|vet|run|install|list|generate)\b|GOFLAGS=)""")
# A segment that only assigns variables, whose `-tags` values a later build may expand.
ASSIGN_ONLY = re.compile(rf"""\s*(?:export\s+)?((?:{ASSIGN}\s*)+)\Z""")
ASSIGN_ONE = re.compile(rf"""([A-Za-z_]\w*)=("[^"]*"|'[^']*'|[^\s"';&|()`]*)""")
# Unquoted shell separators; a quoted string is skipped whole.
SEP = re.compile(r"""("(?:[^"\\]|\\.)*"|'[^']*')|(&&|\|\||\$\(|[;|()`])""")
VAR = re.compile(r"\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))")
RACE = re.compile(r"(?<![\w-])-race\b")
GOENV = re.compile(r"""\b(GOOS|GOARCH)\s*[=:]\s*["']?([A-Za-z0-9_]+)""")
CGO_ON = re.compile(r"""\bCGO_ENABLED\s*[=:]\s*["']?1\b""")
RUNS_ON = re.compile(r"""\bruns-on\s*:\s*["']?([^\s"'#]+)""")
TAG = re.compile(r"[A-Za-z0-9_.]+\Z")

CGO_DIRECTIVE = re.compile(r"#\s*cgo\b")
LINK_DIRECTIVE = re.compile(r"go:(linkname|cgo_\w*)")
GO_BUILD = re.compile(r"//go:build(?:[ \t](.*))?\Z")
PLUS_BUILD = re.compile(r"//\s*\+build(?:[ \t](.*))?\Z")


def build_tags(root):
    """The tags some repo build sets, read from the workflows and image/."""
    root = pathlib.Path(root)
    files = sorted((root / ".github" / "workflows").glob("*.y*ml"))
    files += sorted(p for p in (root / "image").rglob("*") if p.is_file() and p.suffix != ".md")
    tags = set(ALWAYS)
    for f in files:
        try:
            text = f.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            continue  # a binary under image/ names no build
        held = {}  # variable -> value holding `-tags`, for a later build's `$NAME`
        for line in _logical_lines(text):
            if line.lstrip().startswith("#"):
                continue
            # `-tags` counts only inside a command segment that runs go or sets GOFLAGS: a stale
            # string in an echo, a message or a doc is not a build.
            for seg in _segments(line):
                a = ASSIGN_ONLY.match(seg)
                if a and not GO_CMD.match(seg):
                    for name, val in ASSIGN_ONE.findall(a.group(1)):
                        if TAGS.search(val.strip("\"'")):
                            held[name] = val.strip("\"'")
                    continue
                if not GO_CMD.match(seg):
                    continue
                seg = VAR.sub(lambda v: held.get(v.group(1) or v.group(2), v.group(0)), seg)
                for m in TAGS.finditer(seg):
                    for t in re.split(r"[,\s]+", next(g for g in m.groups() if g is not None)):
                        if TAG.match(t):
                            tags.add(t)
            if RACE.search(line):
                tags.add("race")
            if CGO_ON.search(line):
                tags.add("cgo")
            for _, val in GOENV.findall(line):
                tags.add(val)
            for runner in RUNS_ON.findall(line):
                if runner.startswith("ubuntu"):
                    tags.update({"linux", "arm64" if "arm" in runner else "amd64"})
    if "linux" in tags:
        tags.add("unix")
    return tags


def _logical_lines(text):
    """Physical lines with backslash continuations joined; a comment line is never continued."""
    out, cur = [], ""
    for line in text.split("\n"):
        if not cur and line.lstrip().startswith("#"):
            out.append(line)
            continue
        if line.endswith("\\"):
            cur += line[:-1] + " "
            continue
        out.append(cur + line)
        cur = ""
    if cur:
        out.append(cur)
    return out


def _segments(line):
    """The command segments of a shell line, split at unquoted separators."""
    segs, start = [], 0
    for m in SEP.finditer(line):
        if m.group(2):
            segs.append(line[start:m.start()])
            start = m.end()
    segs.append(line[start:])
    return segs


class Unreadable(Exception):
    pass


ESC = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v",
       "\\": "\\", "'": "'", '"': '"'}


def _unquote(body):
    """The value of a Go interpreted string literal's body."""
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        e = body[i + 1:i + 2]
        if e in ESC:
            out.append(ESC[e])
            i += 2
        elif e in ("x", "u", "U"):
            n = {"x": 2, "u": 4, "U": 8}[e]
            out.append(chr(int(body[i + 2:i + 2 + n], 16)))
            i += 2 + n
        elif e.isdigit():
            out.append(chr(int(body[i + 1:i + 4], 8)))
            i += 4
        else:
            raise Unreadable(f"bad escape \\{e}")
    return "".join(out)


def tokens(src, newlines=False):
    """Go tokens: ("comment", text), ("string", value), ("word", text) or ("punct", char), and
    ("nl", "\n") for each line break when newlines is set."""
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "\n" and newlines:
            yield "nl", c
            i += 1
        elif c in " \t\r\n":
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            yield "comment", src[i:j]
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            if j < 0:
                raise Unreadable("unterminated comment")
            yield "comment", src[i:j + 2]
            i = j + 2
        elif c == "`":
            j = src.find("`", i + 1)
            if j < 0:
                raise Unreadable("unterminated raw string")
            yield "string", src[i + 1:j].replace("\r", "")
            i = j + 1
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c:
                if src[j] == "\n":
                    raise Unreadable("newline in a literal")
                j += 2 if src[j] == "\\" else 1
            if j >= n:
                raise Unreadable("unterminated literal")
            try:
                value = _unquote(src[i + 1:j])
            except (ValueError, IndexError) as e:
                raise Unreadable(f"bad literal: {e}") from None
            yield ("string" if c == '"' else "rune"), value
            i = j + 1
        elif c.isalnum() or c == "_" or ord(c) > 127:
            j = i
            while j < n and (src[j].isalnum() or src[j] in "_." or ord(src[j]) > 127):
                j += 1
            yield "word", src[i:j]
            i = j
        else:
            yield "punct", c
            i += 1


def _header_and_imports(toks):
    """(comments before the package clause, import paths)."""
    header, it = [], iter(toks)
    for kind, val in it:
        if kind == "comment":
            header.append(val)
            continue
        break
    else:
        return header, []
    if val != "package":
        raise Unreadable("no package clause")
    code = (t for t in it if t[0] != "comment")
    next(code, None)  # the package name
    paths = []
    for kind, val in code:
        if kind == "punct" and val == ";":
            continue
        if val != "import":
            break
        kind, val = next(code, ("", ""))
        if val == "(":
            for kind, val in code:
                if kind == "string":
                    paths.append(val)
                elif val == ")":
                    break
        else:
            if kind != "string":
                kind, val = next(code, ("", ""))  # the import name
            if kind == "string":
                paths.append(val)
    return header, paths


def _constraint_tags(header):
    tags = set()
    for c in header:
        m = GO_BUILD.match(c) or PLUS_BUILD.match(c)
        if m:
            tags.update(t for t in re.split(r"[^A-Za-z0-9_.]+", m.group(1) or "") if t)
    return tags


def _name_tags(name):
    """GOOS/GOARCH a file name's suffix constrains it to (go/build's goodOSArchFile; _test.go
    files are skipped before this)."""
    stem = name.rsplit(".", 1)[0]
    if "_" not in stem:
        return set()
    parts = stem[stem.index("_"):].split("_")
    if len(parts) >= 2 and parts[-2] in GOOS and parts[-1] in GOARCH:
        return {parts[-2], parts[-1]}
    if parts[-1] in GOOS or parts[-1] in GOARCH:
        return {parts[-1]}
    return set()


def go_problems(text, name, tags):
    """(kind, message) for what makes one .go file's source not plain Go, or unreadable."""
    try:
        toks = list(tokens(text))
        header, imports = _header_and_imports(toks)
    except Unreadable as e:
        return [("parse", f"cannot parse ({e})")]
    out = []
    if "C" in imports:
        out.append(("cgo", 'imports "C" (cgo)'))
    for path in sorted({i for i in imports if "testdata" in i.split("/")}):
        out.append(("testdata", f"imports {path}, which is under a testdata/ directory this check skips"))
    comments = [v for k, v in toks if k == "comment"]
    if any(CGO_DIRECTIVE.search(c) for c in comments):
        out.append(("cgo", "has a #cgo line in a comment"))
    for d in sorted({m.group(0) for c in comments for m in LINK_DIRECTIVE.finditer(c)}):
        out.append(("linkname", f"has a {d} directive"))
    named = _constraint_tags(header) | _name_tags(name)
    unknown = sorted(t for t in named if t not in tags and not RELEASE.match(t))
    if unknown:
        out.append(("tag", f"build constraint names {', '.join(unknown)}, which no workflow or image build sets"))
    return out


def wipe_problems(text):
    """[("wipe:FUNC:VAR", message)] for each local from hkdf/random/decrypt with no later wipe(VAR) or
    return of VAR in its function. Unreadable source is left to go_problems."""
    try:
        toks = [t for t in tokens(text, newlines=True) if t[0] != "comment"]
    except Unreadable:
        return []
    out, i, n = [], 0, len(toks)
    while i < n:
        if toks[i] != ("word", "func"):
            i += 1
            continue
        j, name = i + 1, "?"
        while j < n and toks[j] != ("punct", "{"):
            if toks[j][0] == "word" and name == "?" and toks[j - 1] in (("word", "func"), ("punct", ")")):
                name = toks[j][1]
            j += 1
        depth, k = 0, j
        while k < n:
            if toks[k] == ("punct", "{"):
                depth += 1
            elif toks[k] == ("punct", "}"):
                depth -= 1
                if depth == 0:
                    break
            k += 1
        body = toks[j:k]
        for a in range(len(body)):
            # LHS words from a statement start (a line, `{`, `}`, `;` or a keyword that opens a
            # simple statement), then `:=` or `=`, then the call's name and `(`.
            if (body[a][0] != "word" or body[a][1] in GO_KEYWORDS
                    or (a and body[a - 1] not in LHS_AFTER)
                    or (a > 1 and body[a - 1][0] == "nl" and body[a - 2] == ("punct", ","))):
                continue
            b = a
            while b < len(body) and (body[b][0] == "word" or body[b] == ("punct", ",")
                                     or (body[b][0] == "nl" and body[b - 1] == ("punct", ","))):
                b += 1
            if body[b:b + 2] == [("punct", ":"), ("punct", "=")]:
                b += 2
            elif body[b:b + 1] == [("punct", "=")] and body[b + 1:b + 2] != [("punct", "=")]:
                b += 1
            else:
                continue
            if b + 1 >= len(body) or body[b][0] != "word" or body[b + 1] != ("punct", "("):
                continue
            callee = body[b][1].rsplit(".", 1)[-1]
            if callee not in WIPE_SOURCES and "decrypt" not in callee.lower():
                continue
            rest = body[b:]
            for v in [w for kind, w in body[a:b] if kind == "word" and w not in ("_", "err", "var")]:
                wiped = any(rest[x:x + 3] == [("word", "wipe"), ("punct", "("), ("word", v)]
                            for x in range(len(rest)))
                returned = False
                for x in range(len(rest)):
                    if rest[x] == ("word", "return"):
                        y = x + 1
                        while y < len(rest) and (rest[y][0] == "word" or rest[y] == ("punct", ",")
                                                 or (rest[y][0] == "nl" and rest[y - 1] == ("punct", ","))):
                            returned = returned or rest[y] == ("word", v)
                            y += 1
                if not (wiped or returned):
                    out.append((f"wipe:{name}:{v}", f"{name}: {v} comes from {callee}(...) and is never "
                                f"passed to wipe({v}) or returned"))
        i = k + 1
    return out


def _skipped(rel):
    parts = rel.split("/")
    return (rel.startswith(SKIP_TOP) or "testdata" in parts
            or parts[-1].startswith(("_", ".")) or parts[-1].endswith("_test.go"))


def scan(root, tags):
    """{repo-relative path: [(kind, message), ...]} for every file under broker/ that is not plain Go."""
    root = pathlib.Path(root)
    found = {}
    for f in sorted((root / "broker").rglob("*")):
        rel = f.relative_to(root).as_posix()
        if f.is_symlink() and not rel.startswith(SKIP_TOP) and "testdata" not in rel.split("/"):
            # rglob does not descend into a linked directory, but the go tool builds through one.
            found[rel] = [("symlink", "is a symlink: the go tool follows it and this check does not")]
            continue
        if not f.is_file() or _skipped(rel):
            continue
        ext = f.suffix.lower()
        if ext in NON_GO:
            found[rel] = [("nongo", f"is a {f.suffix} file the go tool compiles or links, not Go")]
        elif ext == ".go":
            try:
                text = f.read_bytes().decode("utf-8")
            except UnicodeDecodeError:
                found[rel] = [("parse", "cannot parse (not UTF-8)")]
                continue
            p = go_problems(text, f.name, tags)
            if rel.startswith(WIPE_DIRS):
                p += wipe_problems(text)
            if p:
                found[rel] = p
    return found


def load_allow(path):
    """{path: kinds}. A line is `path kind[,kind...] reason`; blank lines and `#` lines are skipped. A
    control character, a line break other than LF or a byte that is not UTF-8 fails: a line must mean what it shows."""
    allow = {}
    path = pathlib.Path(path)
    if not path.exists():
        return allow
    text = path.read_bytes().decode("utf-8", "replace")  # a byte that is not UTF-8 reads as U+FFFD, refused on its line
    for n, raw in enumerate(text.split("\n"), 1):
        bad = [c for c in raw if (ord(c) < 32 and c != "\t") or 0x7F <= ord(c) <= 0x9F
               or c in "  \ufffd"]
        if bad:
            raise SystemExit(f"srclint: {path}:{n}: control or line-break character {bad[0]!r}")
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rel, kinds, why = (line.split(None, 2) + ["", ""])[:3]
        kinds = frozenset(kinds.split(","))
        if not {k for k in kinds if not k.startswith("wipe:")} <= KINDS:
            raise SystemExit(f"srclint: {path}:{n}: {rel}: kinds must be from {', '.join(sorted(KINDS))}")
        if not why.strip():
            raise SystemExit(f"srclint: {path}:{n}: {rel} needs a reason")
        if rel in allow:
            raise SystemExit(f"srclint: {path}:{n}: {rel} listed twice")
        allow[rel] = kinds
    return allow


def check(root, allow_file):
    root = pathlib.Path(root)
    allow = load_allow(allow_file)
    found = scan(root, build_tags(root))
    problems = [f"{rel}: {msg}" for rel, ps in found.items() for kind, msg in ps
                if kind not in allow.get(rel, ())]
    for rel, kinds in sorted(allow.items()):
        for kind in sorted(kinds - {k for k, _ in found.get(rel, ())}):
            problems.append(f"{rel}: allow-listed for {kind} but has none (stale entry)")
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser()
    root = pathlib.Path(__file__).resolve().parent.parent
    ap.add_argument("--root", default=str(root))
    ap.add_argument("--allow", default=str(root / "tools" / "srclint_allow.txt"))
    a = ap.parse_args(argv)
    problems = check(a.root, a.allow)
    for p in problems:
        print("srclint:", p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
