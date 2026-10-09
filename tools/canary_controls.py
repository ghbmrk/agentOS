#!/usr/bin/env python3
"""Control targets for the canary harness. A scan that finds nothing means
something only if the same scan catches deliberate leaks, so CI runs these on
every pass alongside the real targets.

  clean         trusted side holds the canaries; surface gets unrelated data
  leaky         every canary leaks into surface files, each in a different disguise
  leaky-log     every canary leaks to stderr only, base64 inside a log line
  leaky-memory  every canary lives only in a child's memory; the root sweeper dumps it
  leaky-decoded only the decoded bytes of hex/base32/base64 canaries, in a child's memory
  crash         exits nonzero (a crashed target must never count as clean)
  no-ack        never loads the plant: must be an error, not clean
  partial-ack   acks only some canaries: must be an error
  empty-surface hands back nothing: must be an error
  truncated-sweep  its sweep runs out of budget: must be an error
  leaky-crash   leaks like leaky, then exits nonzero: the leak must still be reported
  env-dump PATH clean, and writes the environment it was given to PATH (outside
                the surface), so a test can check what a target inherits
"""
import base64
import json
import os
import pathlib
import subprocess
import sys
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import canary  # noqa: E402


def _fragment(v, n=canary.WINDOW + 5):
    line = max(v.split("\n"), key=len)
    return line[len(line) // 2 - n // 2:][:n]


DISGUISES = [
    lambda v: json.dumps({"config": {"token": v}}).encode(),
    lambda v: v.encode().hex().upper().encode(),
    lambda v: base64.b64encode(b"Authorization: Bearer " + v.encode() + b"\r\n"),
    lambda v: ("https://h.example/cb?code=" + urllib.parse.quote(v, safe="")).encode(),
    lambda v: v.encode("utf-16-le"),
    lambda v: b"log: " + _fragment(v).encode(),
    lambda v: v.encode(),
]


def ack(cans, n=None):
    fps = [canary.fingerprint(c["value"]) for c in cans][:n]
    pathlib.Path(os.environ["CANARY_ACK"]).write_text(json.dumps({"loaded": fps}))


def hold_in_child(payload, surface, max_bytes=canary.DEFAULT_MAX_BYTES):
    """Start a child that holds payload (bytes) only in memory, then sweep it."""
    child = subprocess.Popen(
        [sys.executable, "-c",
         "import sys,time; n=int(sys.stdin.buffer.readline()); held=sys.stdin.buffer.read(n); "
         "print('ready', flush=True); time.sleep(60)"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        child.stdin.write(b"%d\n" % len(payload) + payload)
        child.stdin.close()
        assert child.stdout.readline().strip() == b"ready"
        canary.dump(surface / "sweep", pids=[child.pid], max_bytes=max_bytes)
    finally:
        child.kill()
        child.wait()
        child.stdout.close()


def main(mode, arg=None):
    cans = json.loads(pathlib.Path(os.environ["CANARY_PLANT"]).read_text())["canaries"]
    surface = pathlib.Path(os.environ["CANARY_SURFACE_DIR"])
    if mode not in ("no-ack", "partial-ack"):
        ack(cans)
    if mode in ("clean", "no-ack", "partial-ack", "leaky-log", "crash", "env-dump"):
        (surface / "workspace").mkdir()
        (surface / "workspace" / "notes.txt").write_bytes(os.urandom(4096).hex().encode())
    if mode == "clean":
        print("held %d canaries on the trusted side" % len(cans))
    elif mode == "partial-ack":
        ack(cans, n=len(cans) - 1)
    elif mode in ("leaky", "leaky-crash"):
        for i, c in enumerate(cans):
            d = surface / "guest" / ("d%d" % i)
            d.mkdir(parents=True)
            (d / "blob").write_bytes(os.urandom(13) + DISGUISES[i % len(DISGUISES)](c["value"]))
        if mode == "leaky-crash":
            sys.exit(3)
    elif mode == "leaky-log":
        for c in cans:
            line = json.dumps({"k": c["kind"], "v": c["value"]}).encode()
            sys.stderr.write("debug: %s\n" % base64.b64encode(os.urandom(2) + line).decode())
    elif mode == "leaky-memory":
        hold_in_child("".join(json.dumps(c["value"]) + "\n" for c in cans).encode(), surface)
    elif mode == "leaky-decoded":
        hold_in_child(b"".join(os.urandom(5) + canary.decode(c["kind"], c["value"])
                               for c in cans if c["kind"] in canary.DECODABLE), surface)
    elif mode == "truncated-sweep":
        try:
            hold_in_child(os.urandom(64), surface, max_bytes=1 << 16)
        except canary.SweepTruncated:
            sys.exit(4)
    elif mode == "env-dump":
        pathlib.Path(arg).write_text(json.dumps(dict(os.environ)))
    elif mode == "crash":
        sys.exit(3)
    elif mode not in ("no-ack", "empty-surface"):
        sys.exit("unknown mode " + mode)


if __name__ == "__main__":
    main(*sys.argv[1:3])
