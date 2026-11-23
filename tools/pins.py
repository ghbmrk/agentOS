#!/usr/bin/env python3
"""The one reader for pinned external downloads (CI-pin-liveness, #6424).

A pin file (`*.pins`, tracked) holds one pin per line, three fields split by spaces:

  <sha256, 64 lowercase hex>  <name>  <source>

A source is an https URL, or `<name>:<member>`, a member of the zip an earlier line of the same
file names. A name may repeat on consecutive lines with the same hash: those URLs are alternative
sources, tried in order. Lines starting with `#` and blank lines are skipped; any other line is an
error naming file:line. The sha256 is the only authority: no source, retry or repin makes bytes that
miss it pass, and `fetch` writes DEST only after they match.

  pins.py fetch FILE NAME DEST   download NAME from its first source that serves the pinned bytes
  pins.py verify FILE NAME PATH  exit 1 unless PATH hashes to NAME's pin
  pins.py get FILE NAME          print NAME's sha256
  pins.py live [FILE ...]        download every source of every pin (default: every tracked pin
                                 file but those in NOT_YET); exit 1 naming each one that fails
"""
import ast
import hashlib
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
HEX = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
URL = re.compile(r"https://[A-Za-z0-9.-]+(?::443)?/[!#$%&'()*+,./0-9:;=?@A-Z_a-z~-]*")
# curl reads no .curlrc (-q), follows redirects only to https, and fails on an HTTP error.
CURL = ["curl", "-q", "--proto", "=https", "--proto-redir", "=https", "-fsSL", "--retry", "3",
        "--retry-delay", "5", "--retry-connrefused", "--connect-timeout", "30", "--max-time", "1800"]

# Pin files not yet in this format, and direct downloads not yet through this reader. Each entry is
# owed by the release row it names; tests/test_pins.py fails on an entry that no longer exists or
# that main's copy of this file lacks (`grown`), so this list only shrinks. A pin here is not checked by `live`.
NOT_YET = {
    "broker/cmd/agentos-infer/llama.pins": "#6515",
    "broker/cmd/agentos-vision/faces.pins": "#6515",
    "broker/cmd/agentos-vision/plates.pins": "#6515",
    "broker/cmd/agentos-vision/scenes.pins": "#6515",
    "broker/cmd/agentos-vision/sounds.pins": "#6515",
    "broker/drone/sitl/ardupilot.pin": "#6515",
    "broker/enforcer/radio/thread/openthread.pin": "#6515",
}


# Files that fetch over the network directly instead of through this reader, with how many fetch
# sites `fetch_sites` finds in each (tests/test_pins.py requires that exact count, so a new fetch in a
# listed file fails too). Owed by the row named; shrink-only like NOT_YET.
FETCH_NOT_YET = {
    ".github/workflows/ci.yml": ("#6515", 3),
    ".github/workflows/infer-real.yml": ("#6515", 1),
    ".github/workflows/vision-real.yml": ("#6515", 6),
    "guest/codex/build-rootfs.sh": ("#6515", 3),
    "guest/openclaw/build-rootfs.sh": ("#6515", 2),
    "image/build.sh": ("#6515", 1),
    "image/camnode/build.sh": ("#6515", 1),
    "image/infer.sh": ("#6515", 1),
    "image/libavcodec.sh": ("#6515", 2),
    "image/llamaserver.sh": ("#6515", 2),
}
# Files whose fetch sites are not pinned downloads: the count, and why.
FETCH_EXEMPT = {
    "broker/drone/sitl/build.sh": (1, "a pip install pinned by version only; hashes owed by #6588"),
    "image/security-snapshot.sh": (5, "probes which debian-security snapshot run is served; apt's signed "
                                      "InRelease is the authority for what it then installs"),
    "spikes/S4-openclaw-guest/run_gateway.sh": (2, "talks to a gateway on 127.0.0.1; downloads nothing"),
    "spikes/PLAN-muse-capture/run.sh": (2, "probes a gate on 127.0.0.1 through bash's /dev/tcp, and a "
                                           "manual spike's unhashed venv; not run by CI"),
    "spikes/S8-live/fwd.py": (1, "a measurement relay spike; downloads nothing it keeps"),
    "tests/test_ci_scope.py": (6, "ci.yml download steps as fixture text it checks"),
    "tests/test_close_guard_hook.py": (1, "a curl command line fed to the close-guard hook, never run"),
    "tests/test_hostcheck.py": (30, "fetch lines as fixture text, and `curl --version` to check -q skips "
                                    ".curlrc; downloads nothing"),
    "tests/test_image_wifidel_nm.py": (1, "names curl as a package the image must not ship"),
    "tests/test_image.py": (1, "a busybox wget shebang as fixture text"),
    "tests/test_pins.py": (99, "this reader's test cases"),
    "tests/test_py_names.py": (1, "an import line as fixture text"),
    "tests/test_s4_stub_broker.py": (1, "talks to its stub broker on 127.0.0.1"),
    "tools/board.py": (2, "GitHub API calls (its docstring is read as data, so counted); downloads nothing it runs"),
    "tools/metrics.py": (1, "GitHub API calls; downloads nothing it runs"),
    "tests/test_workflows.py": (1, "`pip install` as a pattern a workflow must not hold"),
    "tests/test_vulncheck.py": (8, "names curl as a package in OSV fixtures"),
    "tools/vulncheck.py": (3, "names curl as its canary's package; OSV and GitHub API queries, release "
                              "notes read as text, and npm tarballs checked against the lockfile's sha512"),
}

# What `fetch_sites` counts. A word is split at shell quoting and punctuation and read by its basename,
# so `/usr/bin/curl`, `x=curl; $x`, `"curl"` and a `curl\` continuation are each a curl.
FETCHERS = frozenset(["curl", "wget", "aria2c"])
WORDS = re.compile(r"[\s'\"`$(){}\[\];|&<>=\\,]+")
NET_TEXT = re.compile(r"\burllib\.request\b|\burlopen\b|\bhttp\.client\b|\burllib3\b|\bhttpx\b|\baiohttp\b|"
                      r"\bftplib\b|\bxmlrpc\.client\b|\b(?:import|from)\s+requests\b|\brelease\s+download\b|/dev/(?:tcp|udp)/")
NET_MODULES = ("urllib.request", "urllib3", "requests", "http.client", "httpx", "aiohttp", "ftplib", "xmlrpc.client")
# Package-manager fetches their own check does not cover (CI-pin-liveness-fu2-2): pip without
# --require-hashes, an npm/yarn/pnpm verb that resolves outside the lockfile, npx as a command, and a
# Go setting that turns off the checksum database. `npm ci`, hashed pip and `go install x@v` are not sites.
PIP = re.compile(r"pip(?:3(?:\.[0-9]+)?)?")
JS_VERBS = {"npm": {"install", "i", "add", "exec", "x"}, "yarn": {"add", "dlx", "install"},
            "pnpm": {"add", "dlx", "install", "i"}}
FROZEN = frozenset(["--frozen-lockfile", "--immutable"])  # a yarn/pnpm install then holds to the lockfile
WRAPPERS = frozenset(["sudo", "env", "exec", "retry", "command", "nice", "time", "timeout", "nohup", "xargs",
                      "stdbuf", "setsid"])
WRAPPER_ARG = re.compile(r"-.*|[0-9.]+[smhd]?")  # a wrapper's flag or duration (`timeout 60`, `nice -n 5`)
GO_UNCHECKED = re.compile(r"\bGOSUMDB=off\b|\bGONOSUMDB\b|\bGONOSUMCHECK\b|\bGOINSECURE\b|\bGOPRIVATE\b|"
                          r"\bGOFLAGS=\S*-insecure")


def tool_sites(line):
    """Package-manager fetch sites in one shell line (quotes already removed), per command."""
    n = len(GO_UNCHECKED.findall(line))
    for cmd in re.split(r"[;|&(){}`<>]", line):
        w = [x.rsplit("/", 1)[-1] for x in cmd.split() if x not in ("\\",)]
        w = w[:next((i for i, x in enumerate(w) if x.startswith("#")), len(w))]  # a trailing comment runs nothing
        lead = next((x for x in w if "=" not in x and x not in WRAPPERS and not WRAPPER_ARG.fullmatch(x)), None)
        n += lead in ("npx", "pnpx")
        for i, x in enumerate(w):
            if PIP.fullmatch(x) and {"install", "download"} & set(w[i + 1:]) and "--require-hashes" not in w:
                n += 1
            elif x in JS_VERBS and JS_VERBS[x] & set(w[i + 1:]):
                # Only yarn and pnpm read FROZEN (npm ignores it), and only for a plain install.
                n += not (x != "npm" and JS_VERBS[x] & set(w[i + 1:]) <= {"install", "i"} and FROZEN & set(w))
    return n


def text_sites(text):
    """Fetch sites in shell-like text: a word naming a fetcher, a Python network module or a
    `release download` or a bash `/dev/tcp` path. A comment line is read too (it may sit in a quoted
    string or heredoc) but never continues to the next line, as in shell; other continuations are
    joined. Quotes and backslashes are removed, not split at, so `cu""rl` and `c\\url` read as curl."""
    n, joined, prev = 0, [], ""
    for line in text.split("\n"):
        if prev.endswith("\\") and not prev.lstrip().startswith("#"):
            joined[-1] = joined[-1][:-1] + line  # shell removes backslash-newline outright
        else:
            joined.append(line)
        prev = joined[-1]
    for line in joined:
        line = re.sub(r"[\"'\\]", "", line)
        n += sum(1 for w in WORDS.split(line) if w.rsplit("/", 1)[-1] in FETCHERS)
        n += len(NET_TEXT.findall(line)) + tool_sites(line)
    return n


def yaml_sites(text):
    """Fetch sites in every scalar of a YAML file (run, with, env and keys alike), read from the
    composed node tree, so escapes are decoded and a duplicate key cannot hide a value. A scalar
    alias counts each place it is used, from a per-node memo, so nested aliases cost linear time."""
    import yaml  # only the repository test needs it; `live` runs without PyYAML
    memo = {}

    def count(node):
        if id(node) not in memo:
            if isinstance(node, yaml.ScalarNode):
                memo[id(node)] = text_sites(node.value)
            else:
                kids = node.value if isinstance(node, yaml.SequenceNode) else [x for kv in node.value for x in kv]
                memo[id(node)] = sum(count(k) for k in kids)
        return memo[id(node)]
    return sum(count(d) for d in yaml.compose_all(text, Loader=yaml.SafeLoader))


def _str(c):
    """A str or bytes constant's text (subprocess takes bytes on POSIX), else None."""
    if isinstance(c, ast.Constant) and isinstance(c.value, (str, bytes)):
        return c.value if isinstance(c.value, str) else c.value.decode("latin-1")
    return None


def _exact(c):
    return _str(c) is not None and _str(c).rsplit("/", 1)[-1] in FETCHERS


DYN_IMPORTS = frozenset(["import_module", "__import__"])


def _net(dotted):
    """The NET_MODULES entry a dotted name is or lies under, else None."""
    return next((m for m in NET_MODULES if dotted == m or dotted.startswith(m + ".")), None)


def py_sites(text):
    """Fetch sites in Python: each import of a network module, each module reached by attribute
    (`import urllib` then `urllib.request.urlopen`) and not imported by name, once per file per module,
    each string that is a fetcher's name (so `c = "curl"` counts where bound), each
    `import_module`/`__import__` of a network module named by a constant, and each other fetch site in any string but a
    docstring, wherever it is passed (an aliased runner or a command held in a variable hides none)."""
    tree = ast.parse(text)
    docs = {id(d.body[0].value) for d in ast.walk(tree)
            if isinstance(d, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and d.body
            and isinstance(d.body[0], ast.Expr) and isinstance(d.body[0].value, ast.Constant)}
    if any(isinstance(x, ast.Name) and x.id == "__doc__" or isinstance(x, ast.Attribute) and x.attr == "__doc__"
           for x in ast.walk(tree)):
        docs = set()  # a file that reads a docstring as data has its docstrings counted
    bound = {}  # every name an import binds, from a first walk, so a use visited before its import resolves
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                bound[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            for a in node.names:
                bound[a.asname or a.name] = (node.module or "") + "." + a.name
    n, imported, reached = 0, set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if _net(a.name):
                    n += 1
                    imported.add(_net(a.name))
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            mod = node.module or ""
            if _net(mod):
                n += 1
                imported.add(_net(mod))
            else:  # `from http import client`, `from urllib import request`
                hit = {mod + "." + a.name for a in node.names} & set(NET_MODULES)
                n += len(hit)
                imported |= hit
        elif isinstance(node, ast.Attribute):
            chain, x = [], node
            while isinstance(x, ast.Attribute):
                chain.append(x.attr)
                x = x.value
            if isinstance(x, ast.Name) and x.id in bound and _net(".".join([bound[x.id]] + chain[::-1])):
                reached.add(_net(".".join([bound[x.id]] + chain[::-1])))
        elif _exact(node):
            n += 1
        elif _str(node) is not None and id(node) not in docs:
            n += text_sites(_str(node))
        if isinstance(node, ast.Call) and (isinstance(node.func, ast.Name) and bound.get(node.func.id, node.func.id)
                                           .rsplit(".", 1)[-1] in DYN_IMPORTS
                                           or isinstance(node.func, ast.Attribute) and node.func.attr in DYN_IMPORTS) \
                and node.args and _str(node.args[0]) is not None and _net(_str(node.args[0])):
            n += not text_sites(_str(node.args[0]))  # `import_module("requests")`; "urllib.request" counts as text
    return n + len(reached - imported)


def scanned():
    """{repo-relative path: kind} for every file fetch_sites reads: each tracked workflow and action
    (`.github/**.yml`, `.yaml`), Python file and script (by extension or `#!` line), bar vendored code
    and this reader."""
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], check=True, stdout=subprocess.PIPE).stdout
    kinds = {}
    for n in (x.decode("utf-8") for x in out.split(b"\0") if x):
        if "/vendor/" in n or n == "tools/pins.py":
            continue
        if n.startswith(".github/") and n.endswith((".yml", ".yaml")):
            kinds[n] = "yaml"
        elif n.endswith(".py"):
            kinds[n] = "python"
        elif n.endswith((".sh", ".bash", ".mk")) or n.rsplit("/", 1)[-1] == "Makefile":
            kinds[n] = "text"
        else:
            try:
                with open(ROOT / n, "rb") as f:
                    head = f.read(128)
            except OSError:
                continue
            if head.startswith(b"#!"):
                kinds[n] = "python" if b"python" in head.split(b"\n", 1)[0] else "text"
    return kinds


def fetch_sites(path, kind):
    """How many direct network fetches the file at path holds; a file that does not parse raises."""
    text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    return {"yaml": yaml_sites, "python": py_sites, "text": text_sites}[kind](text)


def owed(text):
    """{list name: {file: count or None}} for NOT_YET and FETCH_NOT_YET in a copy of this file's text,
    read as literals (never run); a count is None where that copy records none."""
    out = {}
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign) and [getattr(t, "id", None) for t in node.targets] in (["NOT_YET"], ["FETCH_NOT_YET"]):
            v = ast.literal_eval(node.value)
            out[node.targets[0].id] = {f: (row[1] if isinstance(row, tuple) else None) for f, row in v.items()}
    if sorted(out) != ["FETCH_NOT_YET", "NOT_YET"]:
        raise PinError("NOT_YET or FETCH_NOT_YET is not a literal assignment")
    return out


def grown(base, head):
    """Entries of the owed lists in head's text that base's lacks, or whose count rose."""
    b, h = owed(base), owed(head)
    out = []
    for name in sorted(h):
        for f, n in sorted(h[name].items()):
            if f not in b[name]:
                out.append("%s adds %s" % (name, f))
            elif n is not None and b[name][f] is not None and n > b[name][f]:
                out.append("%s raises %s from %d to %d" % (name, f, b[name][f], n))
    return out


class PinError(Exception):
    pass


class Pin:
    def __init__(self, path, line, sha, name, source):
        self.path, self.line, self.sha, self.name, self.source = path, line, sha, name, source

    def where(self):
        return "%s:%d" % (self.path, self.line)


def parse(path, text):
    """Every pin in a pin file's text, in order; PinError naming file:line on any other line."""
    pins, last = [], None
    for n, raw in enumerate(text.split("\n"), 1):
        if raw == "" or raw.startswith("#"):
            last = None if raw == "" else last
            continue
        f = raw.split(" ")
        f = [x for x in f if x != ""]
        if len(f) != 3 or not HEX.fullmatch(f[0]) or not NAME.fullmatch(f[1]):
            raise PinError("%s:%d: not `<sha256> <name> <source>`" % (path, n))
        sha, name, source = f
        if URL.fullmatch(source):
            pass
        elif ":" in source and NAME.fullmatch(source.split(":", 1)[0]):
            parent = [p for p in pins if p.name == source.split(":", 1)[0]]
            if not parent or not URL.fullmatch(parent[0].source):
                raise PinError("%s:%d: %s is not a member of an earlier downloaded pin" % (path, n, source))
        else:
            raise PinError("%s:%d: the source is neither an https URL nor <name>:<member>" % (path, n))
        same = [p for p in pins if p.name == name]
        if same and (last is None or last.name != name or same[0].sha != sha or not URL.fullmatch(source)):
            raise PinError("%s:%d: %s is pinned again; alternatives sit on consecutive lines with one "
                           "hash" % (path, n, name))
        last = Pin(path, n, sha, name, source)
        pins.append(last)
    return pins


def load(path):
    return parse(path, pathlib.Path(path).read_text(encoding="utf-8"))


def sources(path, name):
    found = [p for p in load(path) if p.name == name]
    if not found:
        raise PinError("%s: no pin named %s" % (path, name))
    return found


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def download(url, dest):
    """True when curl wrote url's bytes to dest."""
    return subprocess.run(CURL + ["-o", dest, url], stdin=subprocess.DEVNULL).returncode == 0


def fetch(path, name, dest):
    """Writes the pinned bytes of name to dest from its first source that serves them."""
    pins = sources(path, name)
    if not URL.fullmatch(pins[0].source):
        raise PinError("%s: %s is a member, not a download; verify it after extracting" % (pins[0].where(), name))
    d = os.path.dirname(os.path.abspath(dest))
    for p in pins:
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".pin-")
        os.close(fd)
        try:
            if not download(p.source, tmp):
                print("%s: %s did not download from %s" % (p.where(), name, p.source), file=sys.stderr)
                continue
            got = sha256(tmp)
            if got != p.sha:
                # Bytes that miss the pin end the fetch: another source is not asked to outvote them.
                raise PinError("%s: %s from %s hashes to %s, pinned %s" % (p.where(), name, p.source, got, p.sha))
            os.replace(tmp, dest)
            print("%s: sha256 %s from %s" % (name, got, p.source))
            return
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    raise PinError("%s: %s did not download from any of its %d sources" % (pins[0].where(), name, len(pins)))


def verify(path, name, file):
    want = sources(path, name)[0].sha
    got = sha256(file)
    if got != want:
        raise PinError("%s: %s hashes to %s, pinned %s" % (sources(path, name)[0].where(), file, got, want))
    print("%s: sha256 %s (pinned)" % (name, got))


def tracked():
    """Every tracked pin file (*.pins, *.pin), repo-relative, from git's NUL-separated listing."""
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z", "--", "*.pins", "*.pin"],
                         check=True, stdout=subprocess.PIPE).stdout
    return sorted(n.decode("utf-8") for n in out.split(b"\0") if n)


MEMBER_MAX = 1 << 30  # bytes `live` reads of one zip member


def member_sha256(zpath, member):
    """sha256 of a zip member, read in blocks; PinError past MEMBER_MAX, whatever the header says."""
    h, n = hashlib.sha256(), 0
    with zipfile.ZipFile(zpath) as z, z.open(member) as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            n += len(block)
            if n > MEMBER_MAX:
                raise PinError("%s is over %d bytes" % (member, MEMBER_MAX))
            h.update(block)
    return h.hexdigest()


def live(paths, fetcher=download):
    """Problems, one per source that no longer serves its pinned bytes; empty when all do."""
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        for path in paths:
            try:
                pins = load(path)
            except (PinError, OSError, UnicodeDecodeError) as e:
                problems.append("%s: unreadable: %s" % (path, e))
                continue
            got = {}  # name -> the downloaded file whose bytes matched its pin
            for i, p in enumerate(pins):
                f = os.path.join(tmp, "%d" % i)
                if URL.fullmatch(p.source):
                    if not fetcher(p.source, f):
                        problems.append("%s: %s no longer downloads from %s" % (p.where(), p.name, p.source))
                        continue
                    h = sha256(f)
                    if h == p.sha:
                        got.setdefault(p.name, f)
                else:
                    parent, member = p.source.split(":", 1)
                    if parent not in got:
                        # A zip that did not download or missed its pin is never opened.
                        problems.append("%s: %s: its zip %s did not download with its pinned bytes" % (p.where(), p.name, parent))
                        continue
                    try:
                        h = member_sha256(got[parent], member)
                    except (zipfile.BadZipFile, KeyError, PinError) as e:
                        problems.append("%s: %s: %s" % (p.where(), p.name, e))
                        continue
                if h != p.sha:
                    problems.append("%s: %s from %s now hashes to %s, pinned %s" % (p.where(), p.name, p.source, h, p.sha))
                else:
                    print("ok %s %s %s" % (p.where(), p.name, p.source))
    return problems


def main(argv):
    try:
        if len(argv) == 4 and argv[0] == "fetch":
            fetch(argv[1], argv[2], argv[3])
        elif len(argv) == 4 and argv[0] == "verify":
            verify(argv[1], argv[2], argv[3])
        elif len(argv) == 3 and argv[0] == "get":
            print(sources(argv[1], argv[2])[0].sha)
        elif argv[:1] == ["live"]:
            if not argv[1:]:
                os.chdir(ROOT)  # names in the report are repo-relative
            paths = argv[1:] or [p for p in tracked() if p not in NOT_YET]
            problems = live(paths)
            for p in problems:
                print("::error::pin no longer live: " + p)
            return 1 if problems else 0
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except PinError as e:
        print("::error::" + str(e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
