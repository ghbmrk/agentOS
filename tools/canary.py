#!/usr/bin/env python3
"""Canary harness (spec A5): plant fresh synthetic secrets, let a target act as
the adversary, and scan everything agent-reachable for any trace of them.

A target is any command. Per round the harness mints one canary of every kind,
writes them to a trusted-only plant file, and runs the target with:
  CANARY_PLANT        path of the plant file (JSON; the target's trusted side
                      loads it into the vault / credentialed browser)
  CANARY_SURFACE_DIR  where the target copies everything its adversary could
                      reach (guest files, `canary.py sweep` dumps, protocol
                      transcripts, packet captures)
The harness scans that directory plus the target's stdout and stderr (logs).
Canary values never leave the trusted side and the harness's own memory:
reports carry fingerprints, kinds, encodings, and locations only.

Usage:
  canary.py run --targets assurance/canary-targets.json [--rounds N] [--report F]
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

ROOT = pathlib.Path(__file__).resolve().parent.parent

B62 = string.ascii_letters + string.digits
B32 = string.ascii_uppercase + "234567"
HEX = "0123456789abcdef"
B64URL = B62 + "-_"
B64 = B62 + "+/"
PASSWORD = B62 + "!#$%&*+=?@^_~"  # no '-': cores must survive dash stripping

# kind -> (alphabet, core length, format(core) -> value)
_SHAPES = {
    "api_key": (B62, 40, lambda c: "sk-" + c),
    "bearer_token": (B64URL, 43, lambda c: c),
    "session_cookie": (HEX, 64, lambda c: c),
    "password": (PASSWORD, 24, lambda c: c),
    "totp_seed": (B32, 32, lambda c: c),
    "private_key": (B64, 64, lambda c: "-----BEGIN PRIVATE KEY-----\n" + c + "\n-----END PRIVATE KEY-----"),
    "recovery_code": (B32, 30, lambda c: "-".join(c[i:i + 5] for i in range(0, len(c), 5))),
}
KINDS = tuple(_SHAPES)

# Any contiguous fragment of a core at least WINDOW characters long is detected:
# cores are indexed as NEEDLE-length pieces every STEP characters.
NEEDLE, STEP = 12, 4
WINDOW = NEEDLE + STEP - 1

CHUNK = 1 << 20
DEFAULT_MAX_BYTES = 4 << 30
SKIP_ROOT_DIRS = {"/proc", "/sys", "/dev"}
MEM_SKIP = ("[vvar]", "[vsyscall]", "[vvar_vclock]")
MAX_HITS_PER_LOCATION = 20


class Canary(collections.namedtuple("Canary", "kind value core alphabet")):
    @property
    def fingerprint(self):
        return hashlib.sha256(self.value.encode()).hexdigest()[:16]

    @property
    def entropy_bits(self):
        return len(self.core) * math.log2(len(self.alphabet))


Hit = collections.namedtuple("Hit", "fingerprint kind form location offset length")


def mint(kind):
    alphabet, n, fmt = _SHAPES[kind]
    core = "".join(secrets.choice(alphabet) for _ in range(n))
    return Canary(kind, fmt(core), core, alphabet)


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
    for i in range(0, len(core) - NEEDLE + 1, STEP):
        forms.append(("fragment", core[i:i + NEEDLE]))
    if (len(core) - NEEDLE) % STEP:
        forms.append(("fragment", core[-NEEDLE:]))
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

def _file_chunks(path, budget):
    try:
        with open(path, "rb") as f:
            while budget[0] > 0:
                b = f.read(min(CHUNK, budget[0]))
                if not b:
                    return
                budget[0] -= len(b)
                yield b
    except OSError:
        return


def _mem_chunks(fd, start, end, budget):
    pos = start
    while pos < end and budget[0] > 0:
        try:
            b = os.pread(fd, min(CHUNK, end - pos, budget[0]), pos)
        except OSError:
            return
        if not b:
            return
        budget[0] -= len(b)
        pos += len(b)
        yield b


def _all_pids():
    me = os.getpid()
    return sorted(int(p) for p in os.listdir("/proc") if p.isdigit() and int(p) != me)


def sweep(roots=(), pids=(), max_bytes=DEFAULT_MAX_BYTES):
    """Yield (location, chunk iterator) for everything a root process can read:
    files under roots, and each process's environment, command line, and memory."""
    budget = [max_bytes]
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
    """Write sweep() output under out, for a target to hand back as a surface."""
    out = pathlib.Path(out)
    n = 0
    for loc, chunks in sweep(roots, pids, max_bytes):
        dest = out / loc.lstrip("/").replace("@", "_at_")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as f:
            for b in chunks:
                f.write(b)
        n += 1
    return n


# ---- target runner --------------------------------------------------------------

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


def run_target(target, rounds, timeout=600, minted=None):
    results = []
    for r in range(rounds):
        cans = mint_set()
        if minted is not None:
            minted.extend(cans)
        det = Detector(cans)
        with tempfile.TemporaryDirectory(prefix="canary-trusted-") as trusted, \
                tempfile.TemporaryDirectory(prefix="canary-surface-") as surface:
            plant = pathlib.Path(trusted, "plant.json")
            fd = os.open(plant, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump({"canaries": [{"kind": c.kind, "value": c.value} for c in cans]}, f)
            env = dict(os.environ, CANARY_PLANT=str(plant), CANARY_SURFACE_DIR=surface)
            try:
                p = subprocess.run(target["cmd"], env=env, cwd=ROOT, capture_output=True, timeout=timeout)
                rc, out, err = p.returncode, p.stdout, p.stderr
            except subprocess.TimeoutExpired as e:
                rc, out, err = "timeout", e.stdout or b"", e.stderr or b""
            hits = det.scan_bytes(out, "<stdout>") + det.scan_bytes(err, "<stderr>")
            for loc, chunks in sweep(roots=[surface]):
                hits += det.scan_stream(chunks, "surface/" + os.path.relpath(loc, surface))
        rnd = {"round": r, "canaries": [c.fingerprint for c in cans], "exit": rc,
               "kinds_hit": sorted({h.kind for h in hits}), "hit_count": len(hits),
               "hits": [_hit_dict(h) for h in _cap(hits)]}
        if rc != 0:
            rnd["stderr_tail"] = det.redact(err[-2000:]).decode(errors="replace")
        results.append(rnd)
    if any(r["exit"] != 0 for r in results):
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
    if expect == "leak":
        missed = [r["round"] for r in res["rounds"] if r["kinds_hit"] != sorted(KINDS)]
        if missed:
            return False, "detector missed kinds in rounds %s" % missed
    return True, expect


def cmd_run(args):
    targets = json.loads(pathlib.Path(args.targets).read_text())["targets"]
    minted, report, ok_all = [], {"rounds": args.rounds, "targets": []}, True
    for t in targets:
        res = run_target(t, args.rounds, timeout=args.timeout, minted=minted)
        ok, why = _judge(t, res)
        ok_all &= ok
        res.update(control=bool(t.get("control")), expect=t.get("expect", "clean"), passed=ok)
        report["targets"].append(res)
        kinds = len({k for r in res["rounds"] for k in r["kinds_hit"]})
        print("%s %-22s %s (%s; %d/%d kinds surfaced, %d rounds)" % (
            "PASS" if ok else "FAIL", t["name"], "control" if t.get("control") else "target",
            why, kinds, len(KINDS), args.rounds))
        if not ok:
            for r in res["rounds"]:
                for h in r["hits"][:5]:
                    print("    round %d: %s canary as %s at %s+%d" % (
                        r["round"], h["kind"], h["form"], h["location"], h["offset"]))
                if "stderr_tail" in r:
                    print("    round %d exit %s; stderr (redacted):\n%s" % (r["round"], r["exit"], r["stderr_tail"]))
    real = [t["name"] for t in targets if not t.get("control")]
    report["real_targets"] = real
    if not real:
        print("note: no product targets registered yet; only controls ran (see assurance/README.md)")
    blob = json.dumps(report, indent=1).encode()
    report["report_scanned_clean"] = not Detector(minted).scan_bytes(blob, "report")
    if not report["report_scanned_clean"]:
        print("FAIL report would contain a canary value; not written", file=sys.stderr)
        return 2
    if args.report:
        pathlib.Path(args.report).write_text(json.dumps(report, indent=1) + "\n")
    return 0 if ok_all else 1


def cmd_sweep(args):
    pids = []
    for p in args.pid:
        pids += _all_pids() if p == "all" else [int(p)]
    n = dump(args.out, roots=args.root, pids=pids, max_bytes=args.max_bytes)
    print("swept %d locations into %s" % (n, args.out))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--targets", required=True)
    r.add_argument("--rounds", type=int, default=3)
    r.add_argument("--timeout", type=int, default=600)
    r.add_argument("--report")
    s = sub.add_parser("sweep")
    s.add_argument("--root", action="append", default=[])
    s.add_argument("--pid", action="append", default=[])
    s.add_argument("--out", required=True)
    s.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    args = ap.parse_args(argv)
    return cmd_run(args) if args.cmd == "run" else cmd_sweep(args)


if __name__ == "__main__":
    sys.exit(main())
