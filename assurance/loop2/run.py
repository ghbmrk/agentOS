#!/usr/bin/env python3
"""Build and run the A11 loop 2 qualification harness (P3-4b-2).

The harness's Go sources live in assurance/loop2/ so the broker tree never
holds them; this script overlays them into the broker module as package
zz_a11harness for the build, so they compile against the real loops and
change packages. Arguments pass through to the harness; see main.go.
`run.py --go-test` runs the harness's own unit tests instead.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
SRC = ROOT / "assurance" / "loop2"
BROKER = ROOT / "broker"
PKG = "zz_a11harness"


def main(argv):
    args = list(argv)
    for flag in ("--catalog", "--report"):
        if flag in args:
            i = args.index(flag) + 1
            if i < len(args):
                args[i] = str(pathlib.Path(args[i]).resolve())
    with tempfile.TemporaryDirectory() as d:
        overlay = {"Replace": {str(BROKER / PKG / f.name): str(f) for f in sorted(SRC.glob("*.go"))}}
        ovl = pathlib.Path(d) / "overlay.json"
        ovl.write_text(json.dumps(overlay))
        env = dict(os.environ)
        env.setdefault("GOTOOLCHAIN", "local")
        if args != ["--go-test"]:
            return subprocess.run(["go", "run", "-overlay", str(ovl), "./" + PKG, *args],
                                  cwd=BROKER, env=env).returncode
        # The package directory exists only in the overlay, so `go test`
        # cannot run the binary there: build it, then run it from here.
        exe = pathlib.Path(d) / "harness.test"
        rc = subprocess.run(["go", "test", "-vet=off", "-c", "-o", str(exe), "-overlay", str(ovl), "./" + PKG],
                            cwd=BROKER, env=env).returncode
        if rc != 0:
            return rc
        env["A11_CATALOG"] = str(ROOT / "assurance" / "loop2-seeds")
        return subprocess.run([str(exe), "-test.v", "-test.count=1"], cwd=d, env=env).returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
