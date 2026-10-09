#!/usr/bin/env python3
"""Canary harness (spec A5): plant fresh synthetic secrets, let a target act as
the adversary, and scan everything agent-reachable for any trace of them.

A target is any command. Per round the harness mints one canary of every kind,
writes them to a trusted-only plant file, and runs the target with:
  CANARY_PLANT        path of the plant file (JSON; the target's trusted side
                      loads it into the vault / credentialed browser)
  CANARY_ACK          where the trusted side writes {"loaded": [fingerprint, ...]}
                      for every canary it actually loaded (see fingerprint())
  CANARY_SURFACE_DIR  where the target copies everything its adversary could
                      reach (guest files, `canary.py sweep` dumps, protocol
                      transcripts, packet captures)
The harness scans that directory plus the target's stdout and stderr (logs).
A target never inherits the harness's environment (#515 Security 2): it gets
PATH, HOME and TMPDIR set to a scratch directory removed after the round, the
CANARY_* variables, the parent's value of each variable its registry entry
names under "env" (only names in TARGET_ENV_ALLOWED, today GOFLAGS; any other
is refused at load), and GOTOOLCHAIN=local, set after all of those, so no
entry can make a round download a Go toolchain.
A target, and each control, runs as another uid: the first id of the harness's
subordinate range, in its own user and PID namespace (the sandbox entry of
tools/depaudit.py, tools/ASSUMPTIONS.md D13). It cannot read the harness's
/proc entries, which it cannot even name, or a private file in the harness's
HOME; it still reads what any uid may (world-readable files, the repository)
and keeps the host's network. The round's scratch, plant and surface
directories are its own until it ends, then the harness's again. Without a usable subordinate range, or if the
sandbox fails to start, the target never runs and the round is an error.
A round is an error, never clean, if the ack is missing or incomplete, the
surface is empty, the scan budget runs out, or the target exits nonzero.
Built-in controls (deliberate leaks the scan must catch) run on every pass;
the registry holds product targets only, and each must expect "clean".
Canary values never leave the trusted side and the harness's own memory:
reports carry fingerprints, kinds, encodings, and locations only.

A round (`canary.py round`) is the scheduled form Loop 2's canary probe runs
(LOOP-7, P3-4b-4a): every control and product target once, with fresh
canaries, written as Loop 2 findings JSON. A product target that leaks is a
High finding about that target, with the grant or executor its registry entry
names under "contain"; a failed control or a target error is an error, never
clean. A target that leaked and also errored gives both the finding and the
error (#515 Security 5), and is not listed as checked, so it closes nothing.

Usage:
  canary.py run --targets assurance/canary-targets.json [--rounds N] [--report F]
  canary.py round --targets assurance/canary-targets.json --out F
  canary.py sweep [--root DIR]... [--pid N|all]... --out DIR   (run as root inside a guest)
"""
import argparse
import base64
import collections
import hashlib
import json
import math
import os
import pathlib
import secrets
import string
import subprocess
import sys
import tempfile
import urllib.parse

import depaudit

ROOT = pathlib.Path(__file__).resolve().parent.parent

B62 = string.ascii_letters + string.digits
B32 = string.ascii_uppercase + "234567"
HEX = "0123456789abcdef"
B64URL = B62 + "-_"
B64 = B62 + "+/"
PASSWORD = B62 + "!#$%&*+=?@^_~"  # no '-': cores must survive dash stripping

def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")


# Kinds whose text is itself an encoding are minted from random bytes, so the
# decoded form (TOTP key bytes, DER key material, token bytes) is well defined.
# encoding -> (encode bytes -> text bytes, decode text -> bytes)
_CODECS = {
    "hex": (lambda b: b.hex().encode(), bytes.fromhex),
    "base32": (base64.b32encode, base64.b32decode),
    "base64": (base64.b64encode, base64.b64decode),
    "base64url": (_b64url, lambda t: base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))),
}

# kind -> (alphabet, core chars or None, encoding, decoded bytes or None, format(core) -> value)
_SHAPES = {
    "api_key": (B62, 40, None, None, lambda c: "sk-" + c),
    "bearer_token": (B64URL, None, "base64url", 32, lambda c: c),
    "session_cookie": (HEX, None, "hex", 32, lambda c: c),
    "password": (PASSWORD, 24, None, None, lambda c: c),
    "totp_seed": (B32, None, "base32", 20, lambda c: c),
    "private_key": (B64, None, "base64", 48,
                    lambda c: "-----BEGIN PRIVATE KEY-----\n" + c + "\n-----END PRIVATE KEY-----"),
    "recovery_code": (B32, 30, None, None, lambda c: "-".join(c[i:i + 5] for i in range(0, len(c), 5))),
}
KINDS = tuple(_SHAPES)
DECODABLE = tuple(k for k, s in _SHAPES.items() if s[2])

# Any contiguous fragment of a core at least WINDOW characters long is detected:
# cores are indexed as NEEDLE-length pieces every STEP characters. Decoded bytes
# likewise: any fragment of at least DECODED_WINDOW bytes.
NEEDLE, STEP = 12, 4
WINDOW = NEEDLE + STEP - 1
DECODED_NEEDLE, DECODED_STEP = 8, 3
DECODED_WINDOW = DECODED_NEEDLE + DECODED_STEP - 1

CHUNK = 1 << 20
DEFAULT_MAX_BYTES = 4 << 30
SKIP_ROOT_DIRS = {"/proc", "/sys", "/dev"}
DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin"
# Parent variables a registry entry may pass on by name (values are never in
# the registry). The broker's own targets run `go test`. Never GOTOOLCHAIN (the
# parent's may be auto, a toolchain download) or GOCACHE (CommandProbe's off
# breaks `go test`): P3-4b-4c-canary-env-r1.
TARGET_ENV_ALLOWED = frozenset({"GOFLAGS"})
# Where a round's plant, surface and scratch directories go: not the harness's
# TMPDIR, which may sit under a directory the target's uid cannot search (a Go
# test's t.TempDir is 0700). Each directory is still 0700, then the target's.
ROUND_DIR = "/tmp"
MEM_SKIP = ("[vvar]", "[vsyscall]", "[vvar_vclock]")
MAX_HITS_PER_LOCATION = 20


class Canary(collections.namedtuple("Canary", "kind value core alphabet decoded")):
    @property
    def fingerprint(self):
        return fingerprint(self.value)

    @property
    def entropy_bits(self):
        if self.decoded is not None:
            return 8 * len(self.decoded)
        return len(self.core) * math.log2(len(self.alphabet))


Hit = collections.namedtuple("Hit", "fingerprint kind form location offset length")


def fingerprint(value):
    """What a target writes to its plant ack for each canary it loaded."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def mint(kind):
    alphabet, n, encoding, nbytes, fmt = _SHAPES[kind]
    if encoding:
        decoded = secrets.token_bytes(nbytes)
        core = _CODECS[encoding][0](decoded).decode()
    else:
        decoded = None
        core = "".join(secrets.choice(alphabet) for _ in range(n))
    return Canary(kind, fmt(core), core, alphabet, decoded)


def decode(kind, value):
    """The decoded bytes of a canary of a DECODABLE kind (for controls)."""
    encoding = _SHAPES[kind][2]
    core = value.split("\n")[1] if kind == "private_key" else value
    return _CODECS[encoding][1](core)


def mint_set():
    return [mint(k) for k in KINDS]


def _b64_aligned(raw):
    """Base64 renderings of raw as it would appear inside a larger encoded blob,
    for each of the three byte alignments, trimmed to the characters that depend
    only on raw."""
    out = []
    for k in range(3):
        for enc in (base64.b64encode, base64.urlsafe_b64encode):
            s = enc(b"\0" * k + raw)
            lo = -(-8 * k // 6)
            hi = (8 * (k + len(raw))) // 6
            out.append(s[lo:hi])
    return out


def _windows(data, n, step):
    out = [data[i:i + n] for i in range(0, len(data) - n + 1, step)]
    if (len(data) - n) % step:
        out.append(data[-n:])
    return out


def _needles(c):
    raw = c.value.encode()
    forms = [("raw", raw), ("hex", raw.hex().encode()), ("hex", raw.hex().upper().encode()),
             ("utf16", c.value.encode("utf-16-le")), ("utf16", c.value.encode("utf-16-be"))]
    for q in (urllib.parse.quote(c.value, safe=""), urllib.parse.quote_plus(c.value)):
        if q != c.value:
            forms.append(("url", q.encode()))
    forms += [("base64", b) for b in _b64_aligned(raw)]
    core = c.core.encode()
    if core != raw:
        forms.append(("raw", core))
        forms += [("base64", b) for b in _b64_aligned(core)]
    cased = {core.upper(), core.lower()} - {core} if c.alphabet in (HEX, B32) else set()
    forms += [("case", v) for v in sorted(cased)]
    for variant in [core] + sorted(cased):
        forms += [("fragment", w) for w in _windows(variant, NEEDLE, STEP)]
    if c.decoded is not None:
        forms.append(("decoded", c.decoded))
        forms += [("decoded-hex", c.decoded.hex().encode()), ("decoded-hex", c.decoded.hex().upper().encode())]
        forms += [("decoded-base64", b) for b in _b64_aligned(c.decoded)]
        forms += [("decoded-fragment", w) for w in _windows(c.decoded, DECODED_NEEDLE, DECODED_STEP)]
    return forms


class Detector:
    def __init__(self, canaries):
        self.needles = []
        seen = set()
        for c in canaries:
            for form, n in _needles(c):
                if (c.fingerprint, n) not in seen:
                    seen.add((c.fingerprint, n))
                    self.needles.append((n, c.fingerprint, c.kind, form))
        self.maxlen = max((len(n) for n, *_ in self.needles), default=1)

    def scan_bytes(self, data, location, base=0, min_end=0):
        hits = []
        for n, fp, kind, form in self.needles:
            i = data.find(n)
            while i != -1:
                if i + len(n) > min_end:
                    hits.append(Hit(fp, kind, form, location, base + i, len(n)))
                i = data.find(n, i + 1)
        return sorted(hits, key=lambda h: (h.offset, h.fingerprint, h.form))

    def scan_stream(self, chunks, location):
        hits, carry, pos = [], b"", 0
        for chunk in chunks:
            data = carry + chunk
            hits += self.scan_bytes(data, location, base=pos - len(carry), min_end=len(carry))
            pos += len(chunk)
            carry = data[-(self.maxlen - 1):] if self.maxlen > 1 else b""
        return hits

    def redact(self, data):
        out = bytearray(data)
        for h in self.scan_bytes(data, ""):
            out[h.offset:h.offset + h.length] = b"#" * h.length
        return bytes(out)


# ---- the root adversary -------------------------------------------------------

class SweepTruncated(Exception):
    pass


class Budget:
    """Byte budget for a sweep; records whether anything was left unread."""

    def __init__(self, max_bytes):
        self.left, self.truncated = max_bytes, False

    def take(self, n):
        n = min(n, self.left)
        return n

    def spend(self, n):
        self.left -= n


def _file_chunks(path, budget):
    try:
        with open(path, "rb") as f:
            while True:
                if budget.left <= 0:
                    budget.truncated |= bool(f.read(1))
                    return
                b = f.read(budget.take(CHUNK))
                if not b:
                    return
                budget.spend(len(b))
                yield b
    except OSError:
        return


def _mem_chunks(fd, start, end, budget):
    pos = start
    while pos < end:
        if budget.left <= 0:
            budget.truncated = True
            return
        try:
            b = os.pread(fd, budget.take(min(CHUNK, end - pos)), pos)
        except OSError:
            return  # guard pages and similar: unreadable to any process
        if not b:
            return
        budget.spend(len(b))
        pos += len(b)
        yield b


def _all_pids():
    me = os.getpid()
    return sorted(int(p) for p in os.listdir("/proc") if p.isdigit() and int(p) != me)


def sweep(roots=(), pids=(), budget=None):
    """Yield (location, chunk iterator) for everything a root process can read:
    files under roots, and each process's environment, command line, and memory.
    Check budget.truncated afterwards: a truncated sweep proves nothing."""
    budget = budget or Budget(DEFAULT_MAX_BYTES)
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            if dirpath == "/":
                dirnames[:] = [d for d in dirnames if "/" + d not in SKIP_ROOT_DIRS]
            for name in sorted(filenames):
                path = os.path.join(dirpath, name)
                if os.path.isfile(path) and not os.path.islink(path):
                    yield path, _file_chunks(path, budget)
    for pid in pids:
        for name in ("environ", "cmdline"):
            yield "/proc/%d/%s" % (pid, name), _file_chunks("/proc/%d/%s" % (pid, name), budget)
        try:
            maps = pathlib.Path("/proc/%d/maps" % pid).read_text().splitlines()
            fd = os.open("/proc/%d/mem" % pid, os.O_RDONLY)
        except OSError:
            continue
        try:
            for line in maps:
                parts = line.split()
                if not parts[1].startswith("r") or (len(parts) > 5 and parts[5] in MEM_SKIP):
                    continue
                start, end = (int(x, 16) for x in parts[0].split("-"))
                yield "/proc/%d/mem@%x" % (pid, start), _mem_chunks(fd, start, end, budget)
        finally:
            os.close(fd)


def dump(out, roots=(), pids=(), max_bytes=DEFAULT_MAX_BYTES):
    """Write sweep() output under out, for a target to hand back as a surface.
    Raises SweepTruncated if the budget ran out."""
    out = pathlib.Path(out)
    budget, n = Budget(max_bytes), 0
    for loc, chunks in sweep(roots, pids, budget):
        dest = out / loc.lstrip("/").replace("@", "_at_")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as f:
            for b in chunks:
                f.write(b)
        n += 1
    if budget.truncated:
        raise SweepTruncated("sweep budget of %d bytes exhausted after %d locations" % (max_bytes, n))
    return n


# ---- target runner --------------------------------------------------------------

# Built-in controls: (name, tools/canary_controls.py mode, expected outcome,
# kinds that must be caught every round, only forms allowed, error every round
# must report). Hard-coded so that removing one cannot keep CI green.
CONTROLS = (
    ("control-clean", "clean", "clean", (), None, None),
    ("control-leaky-files", "leaky", "leak", KINDS, None, None),
    ("control-leaky-log", "leaky-log", "leak", KINDS, None, None),
    ("control-leaky-memory", "leaky-memory", "leak", KINDS, None, None),
    ("control-leaky-decoded", "leaky-decoded", "leak", DECODABLE, ("decoded", "decoded-fragment"), None),
    ("control-crash", "crash", "error", (), None, "exit 3"),
    ("control-no-ack", "no-ack", "error", (), None, "no valid plant ack"),
    ("control-partial-ack", "partial-ack", "error", (), None, "plant ack missing kinds"),
    ("control-empty-surface", "empty-surface", "error", (), None, "empty surface"),
    ("control-truncated-sweep", "truncated-sweep", "error", (), None, "exit 4"),
    ("control-confined", "confined", "clean", (), None, None),
)


def control_targets():
    cmd = [sys.executable, str(ROOT / "tools" / "canary_controls.py")]
    return [{"name": n, "cmd": cmd + [m], "expect": e, "kinds": list(k), "forms": f, "why": w, "control": True}
            for n, m, e, k, f, w in CONTROLS]


def _hit_dict(h):
    return {"fingerprint": h.fingerprint, "kind": h.kind, "form": h.form,
            "location": h.location, "offset": h.offset}


def _cap(hits):
    per, out = collections.Counter(), []
    for h in hits:
        per[h.location] += 1
        if per[h.location] <= MAX_HITS_PER_LOCATION:
            out.append(h)
    return out


def _ack_problem(path, cans):
    try:
        loaded = set(json.loads(pathlib.Path(path).read_text())["loaded"])
    except (OSError, ValueError, KeyError, TypeError):
        return "no valid plant ack"
    missing = [c.kind for c in cans if c.fingerprint not in loaded]
    return "plant ack missing kinds %s" % missing if missing else None


def _env_names(target):
    names = target.get("env", [])
    if not isinstance(names, list) or not all(isinstance(n, str) and n in TARGET_ENV_ALLOWED for n in names):
        raise ValueError("%s: env must be a list of names from %s" % (target.get("name"), sorted(TARGET_ENV_ALLOWED)))
    return names


def target_env(target, home, **canary_vars):
    """The whole environment a target runs with: never the harness's own.
    GOTOOLCHAIN=local goes last, over anything the allow-list let through."""
    env = {"PATH": os.environ.get("PATH", DEFAULT_PATH), "HOME": home, "TMPDIR": home}
    env.update({n: os.environ[n] for n in _env_names(target) if n in os.environ})
    env.update(canary_vars)
    env["GOTOOLCHAIN"] = "local"
    return env


def _reach_root():
    """Makes ROOT reachable to SCENARIO_ID in this mount namespace: the topmost
    ancestor others cannot search (CI's /home/runner is 0750) is covered by a 0755
    tmpfs, and ROOT is bound back at its own path. The rest of that ancestor, the
    harness's HOME on CI, is then hidden from the target."""
    fd = os.open(ROOT, os.O_PATH | os.O_DIRECTORY)
    try:
        for a in reversed(ROOT.parents):
            if not os.stat(a).st_mode & 0o001:
                depaudit._mount("-t", "tmpfs", "-o", "mode=0755,nosuid,nodev", "tmpfs", str(a))
                os.makedirs(ROOT, mode=0o755)
                depaudit._mount("--no-canonicalize", "--rbind", "/proc/%d/fd/%d" % (os.getpid(), fd), str(ROOT))
                return
    finally:
        os.close(fd)


def _confine(status, owned, timeout, cmd):
    """Runs as init of the target's PID namespace, as uid 0 of its user namespace
    (the harness's uid outside). Gives owned to SCENARIO_ID, runs cmd as it, then
    ends the namespace and gives owned back (depaudit._hand_back), and only then
    writes the target's exit to status, a file in a directory only the harness's
    uid can reach. No status means the round is an error."""
    try:
        _reach_root()
        for path in owned:
            depaudit._chown_tree(path, depaudit.SCENARIO_ID)
        proc = subprocess.Popen(depaudit.AS_SCENARIO + cmd, cwd=ROOT)
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            rc = "timeout"
    finally:
        depaudit._hand_back(owned)
    pathlib.Path(status).write_text(json.dumps({"rc": rc}))
    return 0


def run_confined(cmd, env, owned, timeout):
    """(rc, stdout, stderr, problem): cmd run by _confine in the uid sandbox, with
    env as its whole environment. A sandbox that is unavailable, fails to start or
    does not report gives problem, and rc None: the target did not run, or its
    result is unknown (P3-4b-4c-canary-uid)."""
    try:
        flags = depaudit._unshare_flags(own_network=False)
    except OSError as e:
        return None, b"", b"", "sandbox unavailable: %s" % e
    with tempfile.TemporaryDirectory(prefix="canary-sandbox-", dir=ROUND_DIR) as box:
        status = pathlib.Path(box, "status.json")
        argv = ["unshare"] + flags + ["--", sys.executable, str(pathlib.Path(__file__).resolve()), "_confine",
                                      "--status", str(status), "--timeout", str(timeout)]
        argv += sum((["--own", str(p)] for p in owned), []) + ["--"] + list(cmd)
        try:
            rc, out, err = depaudit._run_sandboxed(argv, env, timeout + 60)
        except (OSError, subprocess.SubprocessError) as e:
            return None, b"", b"", "sandbox did not run: %s" % e
        try:
            return json.loads(status.read_text())["rc"], out, err, None
        except (OSError, ValueError, KeyError, TypeError):
            return None, out, err, "sandbox exit %s without a result" % rc


_CONFINEMENT = None


def confinement_available():
    """Whether a command runs in the uid sandbox here (for the tests' skips; a
    round never asks, it fails closed)."""
    global _CONFINEMENT
    if _CONFINEMENT is None:
        rc, _, _, problem = run_confined(["true"], {"PATH": os.environ.get("PATH", DEFAULT_PATH)}, [], 30)
        _CONFINEMENT = rc == 0 and not problem
    return _CONFINEMENT


def run_target(target, rounds, timeout=600, minted=None, max_bytes=DEFAULT_MAX_BYTES):
    results = []
    for r in range(rounds):
        cans = mint_set()
        if minted is not None:
            minted.extend(cans)
        det = Detector(cans)
        errors = []
        with tempfile.TemporaryDirectory(prefix="canary-trusted-", dir=ROUND_DIR) as trusted, \
                tempfile.TemporaryDirectory(prefix="canary-surface-", dir=ROUND_DIR) as surface, \
                tempfile.TemporaryDirectory(prefix="canary-home-", dir=ROUND_DIR) as home:
            plant, ack = pathlib.Path(trusted, "plant.json"), pathlib.Path(trusted, "ack.json")
            fd = os.open(plant, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump({"canaries": [{"kind": c.kind, "value": c.value} for c in cans]}, f)
            env = target_env(target, home, CANARY_PLANT=str(plant), CANARY_ACK=str(ack), CANARY_SURFACE_DIR=surface)
            rc, out, err, problem = run_confined(target["cmd"], env, [trusted, surface, home], timeout)
            if problem:
                errors.append(problem)
            elif rc != 0:
                errors.append("exit %s" % rc)
            problem = _ack_problem(ack, cans)
            if problem:
                errors.append(problem)
            hits = det.scan_bytes(out, "<stdout>") + det.scan_bytes(err, "<stderr>")
            budget, files = Budget(max_bytes), 0
            for loc, chunks in sweep(roots=[surface], budget=budget):
                files += 1
                hits += det.scan_stream(chunks, "surface/" + os.path.relpath(loc, surface))
            if not files:
                errors.append("empty surface")
            if budget.truncated:
                errors.append("surface scan budget of %d bytes exhausted" % max_bytes)
        rnd = {"round": r, "canaries": [c.fingerprint for c in cans], "exit": rc, "errors": errors,
               "kinds_hit": sorted({h.kind for h in hits}), "forms_hit": sorted({h.form for h in hits}),
               "hit_count": len(hits), "hits": [_hit_dict(h) for h in _cap(hits)]}
        if errors:
            rnd["stderr_tail"] = det.redact(err[-2000:]).decode(errors="replace")
        results.append(rnd)
    if any(r["errors"] for r in results):
        outcome = "error"
    elif any(r["hits"] for r in results):
        outcome = "leak"
    else:
        outcome = "clean"
    return {"name": target["name"], "outcome": outcome, "rounds": results}


def _judge(target, res):
    expect = target.get("expect", "clean")
    if res["outcome"] != expect:
        return False, "expected %s, got %s" % (expect, res["outcome"])
    why = target.get("why")
    if why and not all(len(r["errors"]) == 1 and why in r["errors"][0] for r in res["rounds"]):
        return False, "expected only the error %r every round, got %s" % (why, [r["errors"] for r in res["rounds"]])
    if expect == "leak":
        want = sorted(target.get("kinds") or KINDS)
        missed = [r["round"] for r in res["rounds"] if r["kinds_hit"] != want]
        if missed:
            return False, "expected exactly kinds %s caught; rounds %s differ" % (want, missed)
        forms = target.get("forms")
        stray = sorted({f for r in res["rounds"] for f in r["forms_hit"]} - set(forms or ())) if forms else []
        if stray:
            return False, "control leaked forms %s it should not contain" % stray
    return True, expect


def load_registry(path):
    targets = json.loads(pathlib.Path(path).read_text())["targets"]
    for t in targets:
        if t.get("control") or t.get("expect", "clean") != "clean":
            raise ValueError("%s: product targets must expect clean; controls are built in" % t.get("name"))
        c = t.get("contain")
        if c is not None and (not isinstance(c, dict) or c.get("kind") not in ("grant", "executor")
                              or not isinstance(c.get("name"), str) or not c["name"]
                              or not isinstance(c.get("label", ""), str) or set(c) - {"kind", "name", "label"}):
            raise ValueError("%s: contain must be {kind: grant|executor, name, label?}" % t.get("name"))
        _env_names(t)
    return targets


def cmd_run(args):
    try:
        product = load_registry(args.targets)
    except ValueError as e:
        print("FAIL registry: %s" % e, file=sys.stderr)
        return 2
    minted, report, ok_all = [], {"rounds": args.rounds, "targets": []}, True
    for t in control_targets() + product:
        res = run_target(t, args.rounds, timeout=args.timeout, minted=minted, max_bytes=args.max_bytes)
        ok, why = _judge(t, res)
        ok_all &= ok
        res.update(control=bool(t.get("control")), expect=t.get("expect", "clean"), passed=ok)
        report["targets"].append(res)
        kinds = len({k for r in res["rounds"] for k in r["kinds_hit"]})
        print("%s %-24s %s (%s; %d/%d kinds surfaced, %d rounds)" % (
            "PASS" if ok else "FAIL", t["name"], "control" if t.get("control") else "target",
            why, kinds, len(KINDS), args.rounds))
        if not ok:
            for r in res["rounds"]:
                for h in r["hits"][:5]:
                    print("    round %d: %s canary as %s at %s+%d" % (
                        r["round"], h["kind"], h["form"], h["location"], h["offset"]))
                if r["errors"]:
                    print("    round %d errors: %s; stderr (redacted):\n%s" % (
                        r["round"], "; ".join(r["errors"]), r.get("stderr_tail", "")))
    report["real_targets"] = [t["name"] for t in product]
    if not product:
        print("note: no product targets registered yet; only controls ran (see assurance/README.md)")
    blob = json.dumps(report, indent=1).encode()
    report["report_scanned_clean"] = not Detector(minted).scan_bytes(blob, "report")
    if not report["report_scanned_clean"]:
        print("FAIL report would contain a canary value; not written", file=sys.stderr)
        return 2
    if args.report:
        pathlib.Path(args.report).write_text(json.dumps(report, indent=1) + "\n")
    return 0 if ok_all else 1


def cmd_round(args):
    """One scheduled round as Loop 2 findings (see the module docstring)."""
    try:
        product = load_registry(args.targets)
    except ValueError as e:
        print("FAIL registry: %s" % e, file=sys.stderr)
        return 2
    minted = []
    out = {"check": "canary", "checked": [], "findings": [], "errors": []}
    for t in control_targets():
        res = run_target(t, 1, timeout=args.timeout, minted=minted, max_bytes=args.max_bytes)
        ok, why = _judge(t, res)
        if not ok:
            # A scan that missed a planted leak says nothing about the rest.
            out["errors"].append("control %s: %s" % (t["name"], why))
    if not out["errors"]:
        for t in product:
            res = run_target(t, 1, timeout=args.timeout, minted=minted, max_bytes=args.max_bytes)
            rnd = res["rounds"][0]
            if res["outcome"] == "error":
                out["errors"].append("%s: %s" % (t["name"], "; ".join(rnd["errors"])))
            else:
                out["checked"].append(t["name"])
            if rnd["kinds_hit"]:
                f = {"check": "canary", "subject": t["name"],
                     "detail": "kinds: " + ", ".join(rnd["kinds_hit"]), "severity": "high"}
                if t.get("contain"):
                    f["contain"] = t["contain"]
                out["findings"].append(f)
    blob = json.dumps(out, indent=1).encode()
    if Detector(minted).scan_bytes(blob, "round"):
        out = {"check": "canary", "checked": [], "findings": [],
               "errors": ["the round output would contain a canary value; withheld"]}
        blob = json.dumps(out, indent=1).encode()
    pathlib.Path(args.out).write_bytes(blob + b"\n")
    return 1 if out["errors"] else 0


def cmd_sweep(args):
    pids = []
    for p in args.pid:
        pids += _all_pids() if p == "all" else [int(p)]
    try:
        n = dump(args.out, roots=args.root, pids=pids, max_bytes=args.max_bytes)
    except SweepTruncated as e:
        print("FAIL %s" % e, file=sys.stderr)
        return 1
    print("swept %d locations into %s" % (n, args.out))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--targets", required=True)
    r.add_argument("--rounds", type=int, default=3)
    r.add_argument("--timeout", type=int, default=600)
    r.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    r.add_argument("--report")
    o = sub.add_parser("round")
    o.add_argument("--targets", required=True)
    o.add_argument("--out", required=True)
    o.add_argument("--timeout", type=int, default=600)
    o.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    s = sub.add_parser("sweep")
    s.add_argument("--root", action="append", default=[])
    s.add_argument("--pid", action="append", default=[])
    s.add_argument("--out", required=True)
    s.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    c = sub.add_parser("_confine")  # internal: run_confined's namespace init
    c.add_argument("--status", required=True)
    c.add_argument("--timeout", type=int, required=True)
    c.add_argument("--own", action="append", default=[])
    c.add_argument("target", nargs=argparse.REMAINDER)
    args = ap.parse_args(argv)
    if args.cmd == "_confine":
        return _confine(args.status, args.own, args.timeout, args.target[1:] if args.target[:1] == ["--"] else args.target)
    return {"run": cmd_run, "round": cmd_round, "sweep": cmd_sweep}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
