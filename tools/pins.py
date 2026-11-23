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
# owed by the release row it names; tests/test_pins.py fails on an entry that no longer exists, so
# this list only shrinks. A pin here is not checked by `live`.
NOT_YET = {
    "broker/cmd/agentos-infer/llama.pins": "#6515",
    "broker/cmd/agentos-vision/faces.pins": "#6515",
    "broker/cmd/agentos-vision/plates.pins": "#6515",
    "broker/cmd/agentos-vision/scenes.pins": "#6515",
    "broker/cmd/agentos-vision/sounds.pins": "#6515",
    "broker/drone/sitl/ardupilot.pin": "#6515",
    "broker/enforcer/radio/thread/openthread.pin": "#6515",
}


# Files that download with curl or wget directly instead of through this reader (tests/test_pins.py
# reads every tracked workflow and shell script). Owed by the row named; shrink-only like NOT_YET.
FETCH_NOT_YET = {
    ".github/workflows/ci.yml": "#6515",
    ".github/workflows/infer-real.yml": "#6515",
    ".github/workflows/vision-real.yml": "#6515",
    "guest/codex/build-rootfs.sh": "#6515",
    "guest/openclaw/build-rootfs.sh": "#6515",
    "image/build.sh": "#6515",
    "image/camnode/build.sh": "#6515",
    "image/infer.sh": "#6515",
    "image/libavcodec.sh": "#6515",
    "image/llamaserver.sh": "#6515",
}
# Files whose curl is not a pinned download, and why.
FETCH_EXEMPT = {
    "image/security-snapshot.sh": "probes which debian-security snapshot run is served; apt's signed "
                                  "InRelease is the authority for what it then installs",
    "spikes/S4-openclaw-guest/run_gateway.sh": "talks to a gateway on 127.0.0.1; downloads nothing",
}


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
            got = {}
            for i, p in enumerate(pins):
                f = os.path.join(tmp, "%d" % i)
                if URL.fullmatch(p.source):
                    if not fetcher(p.source, f):
                        problems.append("%s: %s no longer downloads from %s" % (p.where(), p.name, p.source))
                        continue
                    got.setdefault(p.name, f)
                    h = sha256(f)
                else:
                    parent, member = p.source.split(":", 1)
                    if parent not in got:
                        problems.append("%s: %s: its zip %s did not download" % (p.where(), p.name, parent))
                        continue
                    try:
                        with zipfile.ZipFile(got[parent]) as z:
                            h = hashlib.sha256(z.read(member)).hexdigest()
                    except (zipfile.BadZipFile, KeyError) as e:
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
