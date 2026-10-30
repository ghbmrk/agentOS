#!/usr/bin/env python3
"""Mutation testing on the tier-A broker packages (MUT-tierA, #1814).

Runs gremlins (github.com/go-gremlins/gremlins, an existing Go mutation tool) per package,
reports the surviving mutants, and fails a PR that claims coverage of code where a mutant
survives.

  tools/mutgate.py packages                  list the tier-A broker packages
  tools/mutgate.py claimed --git BASE [HEAD] [--json]
                                             the tier-A packages where the diff BASE...HEAD adds a
                                             REQ marker: the only ones the gate can fail, so the
                                             only ones CI runs gremlins on (REV-CHK-mut, #3899)
  tools/mutgate.py run [PKG...] [--out DIR] [--git BASE]
                                             run gremlins per package (default: all tier A),
                                             one JSON file per package in DIR (default mutants/);
                                             with --git, only on lines the diff BASE...HEAD adds
  tools/mutgate.py report DIR                survivors per package, from the JSON in DIR
  tools/mutgate.py gate DIR --git BASE [HEAD]
                                             exit 1 if the diff BASE...HEAD adds a REQ marker
                                             to a package and adds a line carrying a LIVED mutant

The gate's claim: a diff that adds `REQ: ID` to a file under broker/<pkg>/ says the package's
tests cover ID. A LIVED mutant on a line that diff added to a non-test .go file in the same
package is code those tests run (gremlins mutates only covered code) but do not check. Not
covered mutants are not failures here; gremlins' coverage run is the only judge of "covered".
The gate reads no other line, and gremlins tests each mutant alone, so `run --git` mutates only
added lines (60-minute timeouts on #4014) and the gate decides the same; `run` fails if gremlins skipped a
mutant on an added line, so a diff gremlins reads differently cannot pass the gate empty.
Install: go install github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0
"""
import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import risk_tier  # noqa: E402

BROKER = ROOT / "broker"
MARKER = re.compile(r"\+.*REQ:\s*[A-Z]{2,4}-\d+")
HUNK = re.compile(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@")


# A package name that reaches the workflow's matrix: path segments of plain characters only.
PKG_NAME = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")


def tier_a_packages(broker=BROKER):
    """Package paths under broker/ that hold Go source with a file risk_tier.tier_of puts in tier A, sorted.

    Every .go file is classed by tier_of, so packages under a prefix line (kernel/privfile,
    clerk/inbox/imapsmtp) and unlisted ones count, as risk_tier counts them (#3948). A tier-A
    package whose path PKG_NAME refuses raises, rather than dropping out of the gate unseen.
    """
    files = {}
    for f in broker.rglob("*.go"):
        rel = f.parent.relative_to(broker).as_posix()
        if rel != "." and not {"vendor", "testdata"} & set(rel.split("/")):
            files.setdefault(rel, []).append(f"broker/{rel}/{f.name}")
    out = sorted(rel for rel, fs in files.items() if any(risk_tier.tier_of(p)[0] == "A" for p in fs))
    bad = [rel for rel in out if not PKG_NAME.fullmatch(rel)]
    if bad:
        raise ValueError(f"mutgate: tier-A package path(s) outside {PKG_NAME.pattern}: {bad}")
    return out


def survivors(results_dir):
    """{package: [(file, line, type)]} of LIVED mutants in the per-package JSON files."""
    out = {}
    for f in sorted(pathlib.Path(results_dir).glob("*.json")):
        pkg = f.stem.replace("__", "/")
        data = json.loads(f.read_text())
        live = [
            (m_file["file_name"], m["line"], m["type"])
            for m_file in data.get("files") or []
            for m in m_file.get("mutations") or []
            if m.get("status") == "LIVED"
        ]
        out[pkg] = sorted(live)
    return out


_ESC = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def _unquote(name):
    """Git's C-style quoted file name (`"b/h\\303\\251.go"`) as text."""
    out, i = bytearray(), 1
    while i < len(name) - 1:
        c = name[i]
        if c != "\\":
            out += c.encode()
        elif name[i + 1] in _ESC:
            out.append(_ESC[name[i + 1]])
            i += 1
        else:
            out.append(int(name[i + 1:i + 4], 8))
            i += 3
        i += 1
    return out.decode("utf-8", "replace")


def _header_path(raw):
    """The repo path a `+++ ` header names, or None for /dev/null or a non-b/ name (#4105)."""
    name = raw[4:].rstrip("\t")  # git appends a TAB after a name that holds a space
    if name.startswith('"'):
        name = _unquote(name)
    return name[2:] if name.startswith("b/") else None


def added_lines(diff_text):
    """({path: set(line)} of added lines, set of paths whose added lines carry a REQ marker)."""
    added, marked, path, line, in_hunk = {}, set(), None, 0, False
    # split("\n"), not splitlines(): that also breaks on \r, \x0b, \x0c, \x1c-\x1e, \x85, U+2028 and
    # U+2029, which a Go comment can carry, and every later added line would be numbered one low (#4028).
    for raw in diff_text.split("\n"):
        # Every line inside a hunk starts with space, + , - or \, so `diff ` can only be a file
        # header and a `+++ ` line is a header only before the first @@ (an added `++ x` is not one).
        if raw.startswith("diff "):
            in_hunk, path = False, None
            continue
        m = HUNK.match(raw)
        if m:
            in_hunk, line = True, int(m.group(1))
            continue
        if not in_hunk:
            if raw.startswith("+++ "):
                path = _header_path(raw)
            continue
        if path is None or raw.startswith("\\"):  # "\ No newline at end of file" is no line (#4103)
            continue
        if raw.startswith("+"):
            added.setdefault(path, set()).add(line)
            if MARKER.match(raw):
                marked.add(path)
            line += 1
        elif not raw.startswith("-"):
            line += 1
    return added, marked


def package_of(path):
    """The broker/ package directory of a repo path, as survivors() names it, or None."""
    parts = path.split("/")
    if parts[0] != "broker" or len(parts) < 3:
        return None
    return "/".join(parts[1:-1])


def claimed(diff_text, tier_a=None):
    """Tier-A packages where the diff adds a REQ marker, sorted. violations() reads no other."""
    _, marked = added_lines(diff_text)
    pkgs = {package_of(p) for p in marked} - {None}
    return sorted(pkgs & set(tier_a_packages() if tier_a is None else tier_a))


def violations(diff_text, live):
    """Lines the diff adds where a mutant lived, in packages the diff claims coverage of."""
    added, marked = added_lines(diff_text)
    claimed = {package_of(p) for p in marked} - {None}
    found = []
    for pkg in sorted(claimed):
        for fname, line, kind in live.get(pkg, []):
            path = f"broker/{pkg}/{fname}"
            if fname.endswith("_test.go"):
                continue
            if line in added.get(path, ()):
                found.append((pkg, path, line, kind))
    return found


# gremlins -D runs `git diff --merge-base BASE` in its own cwd and matches the file names to
# mutant paths relative to the package directory, one range per hunk from its first added line.
# Run from the package directory, relative names and no context lines make both exact.
DIFF_GIT_CONFIG = {"GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "diff.relative", "GIT_CONFIG_VALUE_0": "true",
                   "GIT_CONFIG_KEY_1": "diff.context", "GIT_CONFIG_VALUE_1": "0"}


def skipped_added(data, pkg, added):
    """Added lines of non-test files directly in broker/<pkg>/ where gremlins skipped a mutant, sorted."""
    return sorted(
        (f["file_name"], m["line"])
        for f in data["files"] if not f["file_name"].endswith("_test.go")
        for m in f.get("mutations") or []
        if m["status"] == "SKIPPED" and m["line"] in added.get(f"broker/{pkg}/{f['file_name']}", ())
    )


def cmd_run(args):
    pkgs = args.pkg or tier_a_packages()
    # Absolute: gremlins runs in broker/, so a relative -o would name a directory there (#3947).
    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    added = added_lines(broker_diff(args.git, "HEAD"))[0] if args.git else None
    bad = 0
    # Gremlins reads .gremlins.yaml from broker/ and the package directory, and GREMLINS_* from the
    # environment: a PR-added file with `dry-run: true` would leave no LIVED mutant. An explicit
    # --config file is the only one it reads, and the environment is cleared of GREMLINS_* (#4027).
    env = {k: v for k, v in os.environ.items() if not k.startswith("GREMLINS_")}
    cfgdir = tempfile.TemporaryDirectory()
    cfg = pathlib.Path(cfgdir.name) / "gremlins.yaml"
    cfg.write_text("{}\n")
    for pkg in pkgs:
        dest = out / (pkg.replace("/", "__") + ".json")
        if args.git:
            r = subprocess.run(["gremlins", "unleash", str(BROKER / pkg), "-D", args.git, "--config", str(cfg),
                                "-o", str(dest)], cwd=BROKER / pkg, env={**env, **DIFF_GIT_CONFIG})
        else:
            r = subprocess.run(["gremlins", "unleash", f"./{pkg}", "--config", str(cfg), "-o", str(dest)],
                               cwd=BROKER, env=env)
        if r.returncode != 0 or not dest.exists():
            print(f"mutgate: gremlins failed on {pkg} (exit {r.returncode})", file=sys.stderr)
            bad += 1
        elif not shape_ok(json.loads(dest.read_text())):
            # survivors() would read nothing from another shape and the gate would pass (ASSUMPTIONS D33).
            print(f"mutgate: {dest} is not gremlins' files[].mutations[] shape", file=sys.stderr)
            bad += 1
        elif dry := dry_run(json.loads(dest.read_text())):
            # RUNNABLE is a mutant gremlins found and did not run: no verdict, so no LIVED either (#4027).
            print(f"mutgate: {dest} holds {dry} mutants gremlins did not run (dry-run?)", file=sys.stderr)
            bad += 1
        elif unknown := foreign_names(json.loads(dest.read_text()), BROKER / pkg):
            # violations() joins broker/<pkg>/<file_name>; another name format would match no line (#3956).
            print(f"mutgate: {dest} names LIVED mutants in {unknown}, not files in broker/{pkg}/", file=sys.stderr)
            bad += 1
        elif added is not None and (skipped := skipped_added(json.loads(dest.read_text()), pkg, added)):
            # The gate reads these lines; a skip there means gremlins' diff is not this one.
            print(f"mutgate: gremlins skipped mutants on lines this diff adds in broker/{pkg}/: {skipped}",
                  file=sys.stderr)
            bad += 1
    cfgdir.cleanup()
    return 1 if bad else 0


def dry_run(data):
    """How many mutants gremlins left RUNNABLE, which it does only when it ran none of them."""
    return sum(m["status"] == "RUNNABLE" for f in data["files"] for m in f.get("mutations") or [])


def foreign_names(data, pkg_dir):
    """file_names carrying a LIVED mutant that are not a file directly in pkg_dir, sorted."""
    names = {f["file_name"] for f in data["files"]
             if any(m["status"] == "LIVED" for m in f.get("mutations") or [])}
    return sorted(n for n in names if "/" in n or "\\" in n or not (pkg_dir / n).is_file())


def shape_ok(data):
    """True when gremlins' JSON has the fields survivors() reads, for every mutation it counts."""
    if not isinstance(data, dict) or not isinstance(data.get("files"), list):
        return False
    muts = [m for f in data["files"] for m in (f.get("mutations") or [])]
    if not all(isinstance(f.get("file_name"), str) for f in data["files"]):
        return False
    if not all(isinstance(m.get("status"), str) and isinstance(m.get("line"), int) for m in muts):
        return False
    # gremlins' own LIVED count must match what survivors() reads, so a renamed status fails too.
    return data.get("mutants_lived") == sum(m["status"] == "LIVED" for m in muts)


def cmd_report(args):
    live = survivors(args.dir)
    for pkg, items in live.items():
        print(f"{pkg}: {len(items)} surviving")
        for fname, line, kind in items:
            print(f"  {fname}:{line} {kind}")
    return 0


def broker_diff(base, head):
    return subprocess.run(
        # --text: a `-diff` .gitattributes line would otherwise hide a file's lines as binary.
        ["git", "-c", "core.quotepath=off", "diff", "-U0", "--text", f"{base}...{head}", "--", "broker"],
        # errors="replace" below: with --text a binary file's bytes are diff lines, and need not be UTF-8.
        cwd=ROOT, capture_output=True, check=True,
    # Bytes decoded here: text=True would turn a lone \r into \n and number the lines wrongly (#4028).
    ).stdout.decode("utf-8", errors="replace")


def cmd_claimed(args):
    pkgs = claimed(broker_diff(args.git, args.head))
    print(json.dumps(pkgs) if args.json else "\n".join(pkgs))
    return 0


def cmd_gate(args):
    found = violations(broker_diff(args.git, args.head), survivors(args.dir))
    for pkg, path, line, kind in found:
        print(f"mutgate: {path}:{line} {kind} survives, in package {pkg} where this PR claims REQ coverage")
    if found:
        print("mutgate: add a test that fails when the line changes, or drop the REQ claim")
    return 1 if found else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("packages")
    p = sub.add_parser("claimed")
    p.add_argument("--git", required=True, metavar="BASE")
    p.add_argument("head", nargs="?", default="HEAD")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("run")
    p.add_argument("pkg", nargs="*")
    p.add_argument("--out", default="mutants")
    p.add_argument("--git", metavar="BASE")
    p = sub.add_parser("report")
    p.add_argument("dir")
    p = sub.add_parser("gate")
    p.add_argument("dir")
    p.add_argument("--git", required=True, metavar="BASE")
    p.add_argument("head", nargs="?", default="HEAD")
    args = ap.parse_args(argv)
    if args.cmd == "packages":
        print("\n".join(tier_a_packages()))
        return 0
    return {"claimed": cmd_claimed, "run": cmd_run, "report": cmd_report, "gate": cmd_gate}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
