#!/usr/bin/env python3
"""Control targets for the canary harness. A scan that finds nothing means
something only if the same scan catches deliberate leaks, so CI runs these on
every pass alongside the real targets.

  clean         trusted side holds the canaries; surface gets unrelated data
  leaky         every canary leaks into surface files, each in a different disguise
  leaky-log     every canary leaks to stderr only, base64 inside a log line
  leaky-memory  every canary lives only in a child's memory; the root sweeper dumps it
  crash         exits nonzero (a crashed target must never count as clean)
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


def main(mode):
    cans = json.loads(pathlib.Path(os.environ["CANARY_PLANT"]).read_text())["canaries"]
    surface = pathlib.Path(os.environ["CANARY_SURFACE_DIR"])
    if mode == "clean":
        (surface / "workspace").mkdir()
        (surface / "workspace" / "notes.txt").write_bytes(os.urandom(4096).hex().encode())
        print("held %d canaries on the trusted side" % len(cans))
    elif mode == "leaky":
        for i, c in enumerate(cans):
            d = surface / "guest" / ("d%d" % i)
            d.mkdir(parents=True)
            (d / "blob").write_bytes(os.urandom(13) + DISGUISES[i % len(DISGUISES)](c["value"]))
    elif mode == "leaky-log":
        for c in cans:
            line = json.dumps({"k": c["kind"], "v": c["value"]}).encode()
            sys.stderr.write("debug: %s\n" % base64.b64encode(os.urandom(2) + line).decode())
    elif mode == "leaky-memory":
        child = subprocess.Popen(
            [sys.executable, "-c",
             "import sys,time; held=[l.strip() for l in sys.stdin]; "
             "print('ready', flush=True); time.sleep(60)"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            child.stdin.write("".join(json.dumps(c["value"]) + "\n" for c in cans))
            child.stdin.close()
            assert child.stdout.readline().strip() == "ready"
            canary.dump(surface / "sweep", pids=[child.pid])
        finally:
            child.kill()
            child.wait()
    elif mode == "crash":
        sys.exit(3)
    else:
        sys.exit("unknown mode " + mode)


if __name__ == "__main__":
    main(sys.argv[1])
