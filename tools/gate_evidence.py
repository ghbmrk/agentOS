#!/usr/bin/env python3
"""Check named execution evidence separately from TRACE's marker claims.

Reports evidence completeness, never gate qualification. Case mappings,
environment assertions and artifact provenance require independent review.
No commands in a manifest or record are executed.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import sys

from review_context import definition_ids

ROOT = pathlib.Path(__file__).resolve().parent.parent
LIMIT = 32 * 1024 * 1024


def read(bundle, name):
    rel = pathlib.PurePosixPath(name)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("artifact path must stay inside bundle")
    p = (bundle / name).resolve()
    if not p.is_relative_to(bundle.resolve()) or not p.is_file() or p.stat().st_size > LIMIT:
        raise ValueError("artifact missing, outside bundle, or too large")
    return p.read_bytes()


def case_result(bundle, manifest, case):
    try:
        record = json.loads(read(bundle, case["record"]))
        if record.get("schema") != 1:
            raise ValueError("unsupported record schema")
        if record["revision"] != manifest["revision"] or record["profile"] != manifest["profile"]:
            raise ValueError("revision/profile differs from frozen manifest")
        if type(record["exit_code"]) is not int or record["exit_code"] != 0:
            raise ValueError("test command failed")
        cmd = record["command"]
        if not isinstance(cmd, list) or len(cmd) < 2 or pathlib.Path(cmd[0]).name != "go" or cmd[1] != "test" \
                or "-json" not in cmd or [a for a in cmd if a.startswith("-count")] != ["-count=1"]:
            raise ValueError("record needs an uncached go test -json command")
        options = cmd[:cmd.index("-args")] if "-args" in cmd else cmd
        options = options[:options.index("--")] if "--" in options else options
        if "-json" not in options or "-count=1" not in options:
            raise ValueError("test flags must precede the argument separator")
        if not record["started_at"] or not record["finished_at"]:
            raise ValueError("run timestamps missing")
        start = datetime.datetime.fromisoformat(record["started_at"].replace("Z", "+00:00"))
        finish = datetime.datetime.fromisoformat(record["finished_at"].replace("Z", "+00:00"))
        if start.tzinfo is None or finish.tzinfo is None or finish < start:
            raise ValueError("run timestamps need timezones and chronological order")
        raw = read(bundle, record["artifact"])
        if hashlib.sha256(raw).hexdigest() != record["sha256"]:
            raise ValueError("artifact hash mismatch")
        actions, package_actions, descendants = [], [], {}
        for line in raw.splitlines():
            event = json.loads(line)
            if event.get("Package") != case["package"]:
                continue
            action = event.get("Action")
            if event.get("Test") == case["test"]:
                actions.append(action)
            elif event.get("Test", "").startswith(case["test"] + "/"):
                descendants.setdefault(event["Test"], []).append(action)
            elif not event.get("Test"):
                package_actions.append(action)
        if "fail" in package_actions or not package_actions or package_actions[-1] != "pass":
            raise ValueError("package has no final passing result")
        if "fail" in actions or "skip" in actions or not actions or actions[-1] != "pass" \
                or actions.count("run") != actions.count("pass") or "run" not in actions:
            raise ValueError("named test is absent, skipped, failed, or incomplete")
        for child in descendants.values():
            if "fail" in child or "skip" in child or child[-1] != "pass" \
                    or child.count("run") != child.count("pass") or "run" not in child:
                raise ValueError("named test has skipped, failed, or incomplete subtests")
        return {"id": case["id"], "status": "pass", "requirements": case["requirements"],
                "record": case["record"], "artifact_sha256": record["sha256"]}
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
        return {"id": case.get("id", "?"), "status": "incomplete", "reason": str(exc),
                "requirements": case.get("requirements", [])}


def assess(bundle, manifest, known_ids):
    if manifest.get("schema") != 1 or not re.fullmatch(r"[0-9a-f]{40}", manifest.get("revision", "")):
        raise ValueError("manifest needs schema 1 and a full revision SHA")
    if not manifest.get("gate") or not manifest.get("profile") or not manifest.get("required"):
        raise ValueError("freeze gate, profile, and required IDs first")
    required = set(manifest["required"])
    if required - known_ids:
        raise ValueError("unknown required IDs: " + ", ".join(sorted(required - known_ids)))
    cases, seen = [], set()
    for case in manifest["cases"]:
        if not case.get("id") or case["id"] in seen:
            raise ValueError("missing or duplicate case ID")
        seen.add(case["id"])
        if not case.get("requirements") or set(case["requirements"]) - required:
            raise ValueError("case requirements must be in frozen required IDs")
        cases.append(case_result(bundle, manifest, case))
    # Every mapped case must pass: another passing case cannot hide a failure.
    missing = sorted(required - {r for c in cases for r in c["requirements"]})
    return {"schema": 1, "gate": manifest["gate"], "revision": manifest["revision"],
            "profile": manifest["profile"], "evidence_complete": not missing and
            all(c["status"] == "pass" for c in cases), "missing_requirements": missing,
            "cases": cases, "external_review_required": True,
            "limitations": "Checks recorded test outcomes and artifact integrity only. "
                           "It does not authenticate the producer, prove the mapping covers every normative clause, "
                           "verify hardware/profile assertions, or approve a gate. Manual checks remain outside this tool."}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=pathlib.Path, default=ROOT)
    ap.add_argument("--bundle", required=True, type=pathlib.Path)
    ap.add_argument("--manifest", required=True, type=pathlib.Path)
    ap.add_argument("--output", type=pathlib.Path)
    args = ap.parse_args(argv)
    try:
        manifest = json.loads(args.manifest.read_text())
        head = subprocess.check_output(["git", "-C", str(args.root), "rev-parse", "HEAD"], text=True).strip()
        if head != manifest["revision"]:
            raise ValueError("manifest revision differs from repository HEAD")
        # Changed source would make a HEAD-only label misleading.
        dirty = subprocess.check_output(["git", "-C", str(args.root), "status", "--porcelain"], text=True)
        if dirty:
            raise ValueError("recorded evidence needs a clean source checkout")
        spec = (args.root / "SPEC.md").read_text()
        known = definition_ids(spec)
        report = assess(args.bundle, manifest, known)
        text = json.dumps(report, indent=2) + "\n"
        if args.output:
            args.output.write_text(text)
        else:
            print(text, end="")
        return 0 if report["evidence_complete"] else 1
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        print("evidence refused: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
