#!/usr/bin/env python3
"""Model-check formal/*.tla with TLC and cut test vectors from the states it finds (FRM-key).

TLC explores every reachable state of KeyVerdict.tla and HoldRule.tla, checks
their invariants and properties, and dumps the states. Each KeyVerdict state is
a key, a check context and the model's verdict for every step; each HoldRule
scenario's earliest dispatch is the hold rule's answer. The Go tests replay
them through broker/kernel/key (formal_test.go) and the kernel itself
(formal_hold_test.go), so the model and the code cannot drift apart unseen.

Usage:
  broker/kernel/formal/vectors.py --jar tla2tools.jar           check, then rewrite the committed vectors
  broker/kernel/formal/vectors.py --jar tla2tools.jar --check   check, and exit 1 if the committed vectors differ
  ... --full DIR                                  also write every state's vector to DIR

The committed key vectors are a fixed sample (every chain once in a plain
context, then every SAMPLE-th state); --full writes all of them, which CI runs.
TLC runs with one worker, so its dump, and so the sample, is the same on every run.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile

FORMAL = pathlib.Path(__file__).resolve().parent
ROOT = FORMAL.parent.parent.parent
KEY_OUT = ROOT / "broker" / "kernel" / "key" / "testdata" / "formal" / "key.json"
HOLD_OUT = ROOT / "broker" / "kernel" / "testdata" / "formal" / "hold.json"
# tla2tools.jar from https://github.com/tlaplus/tlaplus/releases/tag/v1.7.4
JAR_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
SAMPLE = 499

TOKEN = re.compile(r'\s*(<<|>>|\|->|:>|@@|[\[\]{}(),]|"(?:[^"\\]|\\.)*"|-?\d+|[A-Za-z_]\w*)')


def tokens(text):
    pos, out = 0, []
    text = text.rstrip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m:
            raise ValueError(f"unreadable TLA+ value at {text[pos:pos + 40]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


def parse(text):
    """Parse one TLA+ value as TLC prints it: integers, strings, booleans,
    sequences, sets, records and (a :> b @@ ...) functions."""
    ts, i = tokens(text), 0

    def value():
        nonlocal i
        t = ts[i]
        i += 1
        if t == "<<":
            return tuple(items(">>"))
        if t == "{":
            return frozenset(items("}"))
        if t == "[":
            rec = {}
            while ts[i] != "]":
                name = ts[i]
                if ts[i + 1] != "|->":
                    raise ValueError("record field without |->")
                i += 2
                rec[name] = value()
                if ts[i] == ",":
                    i += 1
            i += 1
            return rec
        if t == "(":
            fn = {}
            while True:
                k = value()
                if ts[i] != ":>":
                    raise ValueError("function pair without :>")
                i += 1
                fn[freeze(k)] = value()
                t = ts[i]
                i += 1
                if t == ")":
                    return fn
                if t != "@@":
                    raise ValueError("function pairs not joined by @@")
        if t in ("TRUE", "FALSE"):
            return t == "TRUE"
        if t.startswith('"'):
            return json.loads(t)
        if re.fullmatch(r"-?\d+", t):
            return int(t)
        raise ValueError(f"unexpected token {t!r}")

    def items(close):
        nonlocal i
        out = []
        while ts[i] != close:
            out.append(value())
            if ts[i] == ",":
                i += 1
        i += 1
        return out

    v = value()
    if i != len(ts):
        raise ValueError("trailing tokens after a value")
    return v


def freeze(v):
    if isinstance(v, dict):
        return tuple(sorted((k, freeze(x)) for k, x in v.items()))
    return v


def states(dump):
    """Yield each state of a TLC dump as {variable: value}, in dump order."""
    for block in re.split(r"\n\s*\n", dump):
        block = block.strip()
        if not block:
            continue
        head, _, body = block.partition("\n")
        if not re.fullmatch(r"State \d+:", head):
            raise ValueError(f"unexpected dump block {head!r}")
        st = {}
        for part in re.split(r"^/\\ ", body, flags=re.M):
            if part.strip():
                name, _, val = part.partition(" = ")
                st[name.strip()] = parse(val)
        yield st


def tlc(jar, spec, out):
    """Model-check spec; exit on any violation. Returns the state dump."""
    dump = out / f"{spec}.dump"
    r = subprocess.run(["java", "-XX:+UseParallelGC", "-cp", str(jar), "tlc2.TLC", "-workers", "1",
                        "-deadlock", "-cleanup", "-metadir", str(out / f"{spec}.meta"), "-dump", str(dump),
                        "-config", f"{spec}.cfg", f"{spec}.tla"],
                       cwd=FORMAL, capture_output=True, text=True)
    if r.returncode != 0 or "Model checking completed. No error has been found." not in r.stdout:
        sys.stdout.write(r.stdout + r.stderr)
        sys.exit(f"formal: TLC found a violation in {spec} (or did not finish)")
    found = re.findall(r"([\d,]+) distinct states found", r.stdout)[-1]
    print(f"formal: {spec}: TLC checked {found} distinct states, no violation")
    return dump.read_text()


def step_list():
    """KeyVerdict's StepList, read from the spec so the order cannot differ."""
    src = (FORMAL / "KeyVerdict.tla").read_text()
    m = re.search(r"^StepList == (.*?)^StepIx", src, flags=re.S | re.M)
    return [{"verb": s["verb"], "labels": sorted(s["labels"])} for s in parse(m.group(1))]


def key_vectors(dump):
    steps = step_list()
    every, sample, seen = [], [], set()
    for n, st in enumerate(states(dump)):
        chain = [[lk["sig"], lk["cav"]["k"], sorted(lk["cav"]["s"]), lk["cav"]["n"], lk["cav"]["m"]]
                 for lk in st["chain"]]
        v = {"root": st["rootOK"], "chain": chain, "now": st["now"], "used": st["used"],
             "cut": [st["cut"]["k"], st["cut"]["i"]], "verdict": list(st["verdict"]),
             "window": list(st["window"])}
        if len(v["verdict"]) != len(steps):
            sys.exit("formal: a verdict table does not match StepList")
        every.append(v)
        plain = v["now"] == 0 and v["used"] == 0 and v["cut"] == ["none", 0]
        ident = json.dumps([v["root"], chain])
        if (plain and ident not in seen) or n % SAMPLE == 0:
            seen.add(ident)
            sample.append(v)
    return ({"steps": steps, "states": every}, {"steps": steps, "states": sample})


def hold_vectors(dump):
    """The earliest dispatch the model allows for each scenario: the hold, the
    verb, whether the shape was seen before the hold, and whether one of the
    same shape completed during it. Scenarios with no dispatch are left out."""
    best = {}
    for st in states(dump):
        if st["phase"] != "sent":
            continue
        held = st["heldAt"] >= 0
        seen = (not st["novel"]) if held else st["seen"]
        k = (tuple(st["hold"]), st["verb"], seen, st["midHold"])
        best[k] = min(best.get(k, st["sentAt"]), st["sentAt"])
    return {"unit": "hour", "scenarios": [
        {"hold": list(h), "verb": verb, "seen": seen, "mid_hold": mid, "sent_at": at}
        for (h, verb, seen, mid), at in sorted(best.items())]}


def dumps(v):
    # One state per line keeps the committed files diffable.
    if "states" in v:
        lines = ",\n".join(json.dumps(s, separators=(",", ":")) for s in v["states"])
        return '{"steps":' + json.dumps(v["steps"], separators=(",", ":")) + ',"states":[\n' + lines + "\n]}\n"
    lines = ",\n".join(json.dumps(s, separators=(",", ":")) for s in v["scenarios"])
    return '{"unit":"hour","scenarios":[\n' + lines + "\n]}\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--jar", required=True, help="tla2tools.jar, v1.7.4")
    ap.add_argument("--check", action="store_true", help="exit 1 if the committed vectors differ")
    ap.add_argument("--full", help="also write every state's vectors to this directory")
    a = ap.parse_args()
    if hashlib.sha256(pathlib.Path(a.jar).read_bytes()).hexdigest() != JAR_SHA256:
        sys.exit("formal: tla2tools.jar is not the pinned v1.7.4 build")
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        full_key, key = key_vectors(tlc(a.jar, "KeyVerdict", tmp))
        hold = hold_vectors(tlc(a.jar, "HoldRule", tmp))
    if a.full:
        d = pathlib.Path(a.full)
        d.mkdir(parents=True, exist_ok=True)
        (d / "key.json").write_text(dumps(full_key))
        (d / "hold.json").write_text(dumps(hold))
        print(f"formal: wrote {len(full_key['states'])} key states to {d}")
    want = {KEY_OUT: dumps(key), HOLD_OUT: dumps(hold)}
    if a.check:
        stale = [str(p.relative_to(ROOT)) for p, text in want.items()
                 if not p.exists() or p.read_text() != text]
        if stale:
            sys.exit("formal: committed vectors differ from the model; run broker/kernel/formal/vectors.py: " + ", ".join(stale))
        print("formal: committed vectors match the model")
        return
    for p, text in want.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    print(f"formal: wrote {len(key['states'])} key states and {len(hold['scenarios'])} hold scenarios")


if __name__ == "__main__":
    main()
