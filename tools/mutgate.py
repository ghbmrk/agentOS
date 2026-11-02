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
  tools/mutgate.py delete PKG... [--out DIR] --git BASE
                                             delete each statement that starts on a line the diff
                                             BASE...HEAD adds in the package, one at a time, run
                                             its tests, and add the verdicts to `run`'s JSON in DIR
                                             (MUTGATE-stmt-delete, #4573)
  tools/mutgate.py report DIR                survivors per package, from the JSON in DIR
  tools/mutgate.py gate DIR --git BASE [HEAD]
                                             exit 1 if the diff BASE...HEAD adds a REQ marker
                                             to a package and adds a line carrying a LIVED mutant
  tools/mutgate.py verify DIR --git BASE [HEAD]
                                             `gate`, after checking that DIR/*/ holds exactly
                                             one readable result for every package `claimed`
                                             names, as `run` and `delete` check it: CI's trusted
                                             job (#4106)

The gate's claim: a diff that adds `REQ: ID` to a file under broker/<pkg>/ says the package's
tests cover ID. A LIVED mutant on a line that diff added to a non-test .go file in the same
package is code those tests run (gremlins mutates only covered code) but do not check. Not
covered mutants are not failures here; gremlins' coverage run is the only judge of "covered".
The gate reads no other line, and gremlins tests each mutant alone, so `run --git` mutates only
added lines (60-minute timeouts on #4014) and the gate decides the same; `run` fails if gremlins skipped a
mutant on an added line, so a diff gremlins reads differently cannot pass the gate empty.
Gremlins v0.6.0 has no mutator that deletes a statement, and the survivors that broke a bound on
#4525 and #4560 were deleted statements (a state reset, a ctx check), so `delete` adds that one
mutant kind itself: each statement in a covered statement list that starts on an added line is
deleted alone, the package's tests run, and the verdict joins gremlins' JSON as a
STATEMENT_DELETION mutant, which the gate reads as it reads gremlins' own (#4573).
CI runs the PR's tests in the `mutants` jobs, and a test can write anything there, so those jobs
only hand their JSON on as data; the `mutgate` job, which runs no PR code, takes this file from the
base commit and decides with `verify` (#4106).
Install: go install github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0
"""
import argparse
import glob
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile
import time

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


def result_name(pkg):
    """The JSON file name of a package's result: `/` as `+`, which PKG_NAME never holds, so no two
    packages share one (`a/b` and `a__b` did, and one's result stood in for the other's, #4106)."""
    return pkg.replace("/", "+") + ".json"


def survivors(results_dir):
    """{package: [(file, line, type)]} of LIVED mutants in the per-package JSON files."""
    out = {}
    for f in sorted(pathlib.Path(results_dir).glob("*.json")):
        pkg = f.stem.replace("+", "/")
        out[pkg] = survivors_of(json.loads(f.read_text()))
    return out


def survivors_of(data):
    """[(file, line, type)] of LIVED mutants in one package's gremlins JSON, sorted."""
    return sorted(
        (m_file["file_name"], m["line"], m["type"])
        for m_file in data.get("files") or []
        for m in m_file.get("mutations") or []
        if m.get("status") == "LIVED"
    )


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
# diff.renames=false: broker_diff passes --no-renames, so a moved file's lines are added lines there,
# and gremlins must mutate them too or `run` fails on its skips (#4147).
DIFF_GIT_CONFIG = {"GIT_CONFIG_COUNT": "3", "GIT_CONFIG_KEY_0": "diff.relative", "GIT_CONFIG_VALUE_0": "true",
                   "GIT_CONFIG_KEY_1": "diff.context", "GIT_CONFIG_VALUE_1": "0",
                   "GIT_CONFIG_KEY_2": "diff.renames", "GIT_CONFIG_VALUE_2": "false"}

# gremlins walks every directory below the one it is given and names a mutant by its path from
# there, so a subpackage's file carries a `/`. The gate joins bare names only (foreign_names), and a
# subpackage is its own package with its own claim: `run` mutates only the package's own files (#4025).
SUBDIRS = ["--exclude-files", "/"]


def skipped_added(data, pkg, added):
    """Added lines of non-test files directly in broker/<pkg>/ where gremlins skipped a mutant, sorted."""
    return sorted(
        (f["file_name"], m["line"])
        for f in data["files"] if not f["file_name"].endswith("_test.go")
        for m in f.get("mutations") or []
        if m["status"] == "SKIPPED" and m["line"] in added.get(f"broker/{pkg}/{f['file_name']}", ())
    )


def result_problem(data, pkg, pkg_dir, added, deletions=False):
    """Why gremlins' JSON for pkg cannot be read as its verdicts, or None. `run` and `verify` both ask;
    verify (deletions=True) also needs `delete`'s mutants in it."""
    if not shape_ok(data):
        # survivors() would read nothing from another shape and the gate would pass (ASSUMPTIONS D33).
        return "is not gremlins' files[].mutations[] shape"
    if deletions and (type(data.get("statement_deletions")) is not int or data["statement_deletions"] != sum(
            m.get("type") == DELETION for f in data["files"] for m in f.get("mutations") or [])):
        # Without the pass, a deleted statement on a claimed line would pass unseen (#4573).
        return "holds no statement-deletion pass (`mutgate.py delete`), or a count that is not its mutants'"
    if dry := dry_run(data):
        # RUNNABLE is a mutant gremlins found and did not run: no verdict, so no LIVED either (#4027).
        return f"holds {dry} mutants gremlins did not run (dry-run?)"
    if unknown := foreign_names(data, pkg_dir):
        # violations() joins broker/<pkg>/<file_name>; another name format would match no line (#3956).
        return f"names LIVED mutants in {unknown}, not files in broker/{pkg}/"
    if added is not None and (skipped := skipped_added(data, pkg, added)):
        # The gate reads these lines; a skip there means gremlins' diff is not this one.
        return f"gremlins skipped mutants on lines this diff adds in broker/{pkg}/: {skipped}"
    return None


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
        dest = out / result_name(pkg)
        if args.git:
            r = subprocess.run(["gremlins", "unleash", str(BROKER / pkg), "-D", args.git, "--config", str(cfg),
                                *SUBDIRS, "-o", str(dest)], cwd=BROKER / pkg, env={**env, **DIFF_GIT_CONFIG})
        else:
            r = subprocess.run(["gremlins", "unleash", f"./{pkg}", "--config", str(cfg), *SUBDIRS, "-o", str(dest)],
                               cwd=BROKER, env=env)
        if r.returncode != 0 or not dest.exists():
            print(f"mutgate: gremlins failed on {pkg} (exit {r.returncode})", file=sys.stderr)
            bad += 1
        elif problem := result_problem(json.loads(dest.read_text()), pkg, BROKER / pkg, added):
            print(f"mutgate: {dest} {problem}", file=sys.stderr)
            bad += 1
    cfgdir.cleanup()
    return 1 if bad else 0


# MUTGATE-stmt-delete (#4573): the mutant kind gremlins v0.6.0 lacks. mutgate_stmts.go lists the
# statements (go/parser, data only); each one starting on an added line is replaced by its own line
# breaks (so no other line moves) through `go test -overlay`, which leaves the tree untouched.
DELETION = "STATEMENT_DELETION"
STMTS = pathlib.Path(__file__).resolve().parent / "mutgate_stmts.go"
COVER = re.compile(r"^(.+):(\d+)\.(\d+),(\d+)\.(\d+) \d+ (\d+)$")
# Gremlins' own report fields for each status (internal/report, v0.6.0), kept equal so its totals stay true.
COUNTERS = {"LIVED": "mutants_lived", "KILLED": "mutants_killed", "NOT VIABLE": "mutants_not_viable",
            "NOT COVERED": "mutants_not_covered"}


def covered_blocks(profile):
    """{file base name: [((line, col), (line, col))]} of the blocks a `-coverprofile` ran."""
    out = {}
    for row in profile.split("\n")[1:]:
        m = COVER.match(row)
        if m and int(m.group(6)) > 0:
            out.setdefault(m.group(1).rsplit("/", 1)[-1], []).append(
                ((int(m.group(2)), int(m.group(3))), (int(m.group(4)), int(m.group(5)))))
    return out


def is_covered(blocks, site):
    pos = (site["line"], site["col"])
    return any(start <= pos < end for start, end in blocks.get(site["file"], ()))


def deleted(src, site):
    """src (bytes) with the statement at site removed, its line breaks kept."""
    return src[:site["start"]] + b"\n" * src.count(b"\n", site["start"], site["end"]) + src[site["end"]:]


def run_tests(binary, cwd, timeout):
    """'KILLED', 'LIVED' or 'TIMED OUT' for one run of a compiled test binary; its process group
    is killed at the timeout, so a test's child cannot outlive the verdict."""
    p = subprocess.Popen([str(binary), "-test.failfast", f"-test.timeout={timeout + 2}s"], cwd=cwd,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        return "LIVED" if p.wait(timeout=timeout) == 0 else "KILLED"
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait()
        return "TIMED OUT"


def deletion_mutants(pkg, added, tmp, lister):
    """([mutation dict], None) for each statement starting on a line the diff adds in a non-test .go
    file directly in broker/<pkg>/, or (None, problem)."""
    pkg_dir = BROKER / pkg
    files = sorted(p for p in pkg_dir.glob("*.go")
                   if p.is_file() and not p.name.endswith("_test.go") and added.get(f"broker/{pkg}/{p.name}"))
    if not files:
        return [], None
    r = subprocess.run([str(lister), *map(str, files)], capture_output=True)
    if r.returncode != 0:
        return None, f"cannot list the statements of broker/{pkg}/: {r.stderr.decode(errors='replace')}"
    sites = [s for s in json.loads(r.stdout) if s["line"] in added[f"broker/{pkg}/{s['file']}"]]
    if not sites:
        return [], None
    # One coverage-instrumented build and run: the coverage judge (as gremlins' own coverage run is)
    # and the time a passing run takes, three times which (gremlins' coefficient) times a mutant out.
    base, profile = tmp / "base.test", tmp / "cover.out"
    if subprocess.run(["go", "test", "-c", "-cover", "-covermode=set", "-o", str(base), "."], cwd=pkg_dir).returncode:
        return None, f"broker/{pkg}/ does not build its tests"
    if not base.exists():  # `go test -c` writes nothing for a package with no test files: none covered
        return [{"file": s["file"], "type": DELETION, "status": "NOT COVERED", "line": s["line"], "column": s["col"]}
                for s in sites], None
    began = time.monotonic()
    r = subprocess.run([str(base), "-test.failfast", f"-test.coverprofile={profile}"], cwd=pkg_dir)
    if r.returncode != 0 or not profile.exists():
        return None, f"broker/{pkg}/'s tests fail before any statement is deleted"
    timeout = 3 * (time.monotonic() - began) + 10
    blocks = covered_blocks(profile.read_text())
    out = []
    for site in sites:
        if not is_covered(blocks, site):
            status = "NOT COVERED"
        else:
            src_path = pkg_dir / site["file"]
            mutant, overlay, binary = tmp / "mutant.go", tmp / "overlay.json", tmp / "mutant.test"
            mutant.write_bytes(deleted(src_path.read_bytes(), site))
            overlay.write_text(json.dumps({"Replace": {str(src_path): str(mutant)}}))
            built = subprocess.run(["go", "test", "-c", "-overlay", str(overlay), "-o", str(binary), "."],
                                   cwd=pkg_dir, capture_output=True)
            status = "NOT VIABLE" if built.returncode else run_tests(binary, pkg_dir, timeout)
        out.append({"file": site["file"], "type": DELETION, "status": status, "line": site["line"],
                    "column": site["col"]})
    return out, None


def add_mutants(data, mutants):
    """Gremlins' JSON with the deletion mutants joined to its files and totals, and their count."""
    files = {f["file_name"]: f for f in data["files"]}
    for m in mutants:
        f = files.get(m["file"])
        if f is None:
            f = files[m["file"]] = {"file_name": m["file"], "mutations": []}
            data["files"].append(f)
        f["mutations"] = (f.get("mutations") or []) + [{k: v for k, v in m.items() if k != "file"}]
        for key in ("mutants_total", COUNTERS.get(m["status"])):
            if key:
                data[key] = data.get(key, 0) + 1
    data["statement_deletions"] = len(mutants)
    return data


def cmd_delete(args):
    out = pathlib.Path(args.out).resolve()
    added = added_lines(broker_diff(args.git, "HEAD"))[0]
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        lister = tmp / "stmts"
        # Built outside any module (cwd tmp, GOFLAGS cleared): the standard library only.
        if subprocess.run(["go", "build", "-o", str(lister), str(STMTS)], cwd=tmp,
                          env={**os.environ, "GOFLAGS": "", "GOWORK": "off"}).returncode:
            print("mutgate: cannot build tools/mutgate_stmts.go", file=sys.stderr)
            return 1
        for pkg in args.pkg:
            dest = out / result_name(pkg)
            try:
                data = json.loads(dest.read_text())
            except (OSError, ValueError) as e:
                print(f"mutgate: no gremlins result for {pkg} to add to ({dest}: {e}); `run` first", file=sys.stderr)
                bad += 1
                continue
            if not shape_ok(data) or "statement_deletions" in data:
                print(f"mutgate: {dest} is not one gremlins result without deletions", file=sys.stderr)
                bad += 1
                continue
            mutants, problem = deletion_mutants(pkg, added, tmp, lister)
            if problem:
                print(f"mutgate: {problem}", file=sys.stderr)
                bad += 1
                continue
            dest.write_text(json.dumps(add_mutants(data, mutants)))
    return 1 if bad else 0


def cmd_verify(args):
    """The gate on JSON that PR code wrote (#4106): every claimed package has a readable result, then gate."""
    diff = broker_diff(args.git, args.head)
    added = added_lines(diff)[0]
    live, bad = {}, 0
    for pkg in claimed(diff):
        # Each mutants job's artifact is its own directory, so a result named twice (a job writing
        # another package's) is refused rather than one copy picked.
        found = sorted(pathlib.Path(args.dir).glob(f"*/{glob.escape(result_name(pkg))}"))
        if len(found) != 1:
            print(f"mutgate: {len(found)} results for {pkg} in {args.dir}, not one: {found}", file=sys.stderr)
            bad += 1
            continue
        f = found[0]
        try:
            data = json.loads(f.read_text())
        except (OSError, ValueError) as e:
            print(f"mutgate: no readable result for {pkg} ({f}: {e})", file=sys.stderr)
            bad += 1
            continue
        if problem := result_problem(data, pkg, BROKER / pkg, added, deletions=True):
            print(f"mutgate: {f} {problem}", file=sys.stderr)
            bad += 1
            continue
        live[pkg] = survivors_of(data)
    if bad:
        return 1
    return report_violations(violations(diff, live))


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
        # The prefix, colour, external-diff, textconv and rename options pin the format: git config such as diff.noprefix,
        # color.ui=always, diff.external a diff.<driver>.textconv or diff.renames=copies would otherwise hide added lines (#4115).
        ["git", "-c", "core.quotepath=off", "diff", "-U0", "--text", "--src-prefix=a/", "--dst-prefix=b/",
         "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", f"{base}...{head}", "--", "broker"],
        # errors="replace" below: with --text a binary file's bytes are diff lines, and need not be UTF-8.
        cwd=ROOT, capture_output=True, check=True,
    # Bytes decoded here: text=True would turn a lone \r into \n and number the lines wrongly (#4028).
    ).stdout.decode("utf-8", errors="replace")


def cmd_claimed(args):
    pkgs = claimed(broker_diff(args.git, args.head))
    print(json.dumps(pkgs) if args.json else "\n".join(pkgs))
    return 0


def cmd_gate(args):
    return report_violations(violations(broker_diff(args.git, args.head), survivors(args.dir)))


def report_violations(found):
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
    p = sub.add_parser("delete")
    p.add_argument("pkg", nargs="+")
    p.add_argument("--out", default="mutants")
    p.add_argument("--git", required=True, metavar="BASE")
    p = sub.add_parser("report")
    p.add_argument("dir")
    p = sub.add_parser("gate")
    p.add_argument("dir")
    p.add_argument("--git", required=True, metavar="BASE")
    p.add_argument("head", nargs="?", default="HEAD")
    p = sub.add_parser("verify")
    p.add_argument("dir")
    p.add_argument("--git", required=True, metavar="BASE")
    p.add_argument("head", nargs="?", default="HEAD")
    args = ap.parse_args(argv)
    if args.cmd == "packages":
        print("\n".join(tier_a_packages()))
        return 0
    return {"claimed": cmd_claimed, "run": cmd_run, "delete": cmd_delete, "report": cmd_report, "gate": cmd_gate,
            "verify": cmd_verify}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
