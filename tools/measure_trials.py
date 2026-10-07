#!/usr/bin/env python3
"""Validate independent A10 trial measurements; no executor/model calls."""
import argparse, datetime as dt, hashlib, json, math, pathlib, statistics

ARMS = {"agentos", "openclaw", "provider-cli"}


def stamp(value):
    t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if t.tzinfo is None:
        raise ValueError("timestamp needs timezone")
    return t


def number(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("metric must be finite nonnegative number, not a boolean")
    return value


def validate(root, trial):
    if trial.get("schema") != 1 or trial.get("arm") not in ARMS:
        raise ValueError("unknown schema/arm")
    for field in [
        "run_id",
        "task_id",
        "workload_sha256",
        "profile_id",
        "start_state_sha256",
        "versions",
        "route_id",
        "repetition",
        "phase",
        "judgment",
        "judgment_source",
        "evidence",
    ]:
        if field not in trial or trial[field] is None:
            raise ValueError("missing " + field)
    for field in ["workload_sha256", "start_state_sha256"]:
        if len(trial[field]) != 64 or any(
            (c not in "0123456789abcdef" for c in trial[field])
        ):
            raise ValueError("need full sha256")
    if (
        type(trial["repetition"]) is not int
        or trial["repetition"] < 1
        or trial["phase"] not in ("first-use", "repeat-use")
    ):
        raise ValueError("invalid repetition/phase")
    if trial["judgment"] not in ("accepted", "rejected", "pending"):
        raise ValueError("unknown judgment")
    if trial["judgment"] != "pending" and trial["judgment_source"] not in (
        "owner",
        "external-reviewer",
    ):
        raise ValueError("goal judgment needs independent source")
    elapsed = (stamp(trial["finished_at"]) - stamp(trial["started_at"])).total_seconds()
    if elapsed < 0 or number(trial["owner_active_seconds"]) > elapsed:
        raise ValueError("invalid elapsed/owner effort")
    for field in [
        "necessary_approvals",
        "avoidable_approvals",
        "failures",
        "fallbacks",
    ]:
        if type(trial[field]) is not int or trial[field] < 0:
            raise ValueError("invalid count")
    units = {
        "calls": "calls",
        "tokens": "tokens",
        "cached_tokens": "tokens",
        "plan_runs": "runs",
        "plan_quota": "declared-pool-units",
        "api_cost": "USD",
    }
    for key, metric in trial.get("resources", {}).items():
        if key not in units or metric.get("unit") != units[key]:
            raise ValueError("resource unit mismatch")
        number(metric["value"])
        if key == "plan_quota" and (not metric.get("pool_unit_definition")):
            raise ValueError("quota unit definition missing")
    if not trial["evidence"]:
        raise ValueError("evidence required")
    root = root.resolve()
    for item in trial["evidence"]:
        rel = pathlib.PurePosixPath(item["path"])
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError("evidence escape")
        p = (root / item["path"]).resolve()
        if (
            not p.is_relative_to(root)
            or not p.is_file()
            or p.stat().st_size > 32 * 1024 * 1024
        ):
            raise ValueError("missing/oversized/escaping evidence")
        if hashlib.sha256(p.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("evidence hash mismatch")
    return dict(trial, elapsed_seconds=elapsed)


def summarize(root, trials):
    records = [validate(root, t) for t in trials]
    seen = set()
    pairs = {}
    for t in records:
        if t["run_id"] in seen:
            raise ValueError("duplicate run ID")
        seen.add(t["run_id"])
        key = tuple(
            (
                t[k]
                for k in [
                    "task_id",
                    "workload_sha256",
                    "profile_id",
                    "start_state_sha256",
                    "repetition",
                    "phase",
                ]
            )
        )
        bucket = pairs.setdefault(key, {})
        if t["arm"] in bucket:
            raise ValueError("duplicate arm in matched trial")
        bucket[t["arm"]] = t
    ready = bool(pairs) and all(
        (
            set(p) == ARMS and all((t["judgment"] != "pending" for t in p.values()))
            for p in pairs.values()
        )
    )
    report = {
        "schema": 1,
        "status": "descriptive-evidence-only",
        "matched_three_arm_complete": ready,
        "trial_count": len(records),
        "matched_sets": len(pairs),
        "arms": {},
        "limitations": [
            "No producer authentication or independent audit of goal judgments",
            "No gate qualification, resource conversion or model-tier recommendation",
            "Constructed fixtures are not measured product benefit",
        ],
    }
    for arm in sorted(ARMS):
        rows = [r for r in records if r["arm"] == arm]
        accepted = [r for r in rows if r["judgment"] == "accepted"]
        total = sum((r["owner_active_seconds"] for r in rows))
        report["arms"][arm] = {
            "attempts": len(rows),
            "accepted": len(accepted),
            "pending": sum((r["judgment"] == "pending" for r in rows)),
            "owner_active_seconds_all_attempts": total,
            "owner_minutes_per_accepted_task": (
                total / 60 / len(accepted) if accepted else None
            ),
            "accepted_latency_seconds_median": (
                statistics.median((r["elapsed_seconds"] for r in accepted))
                if accepted
                else None
            ),
            "accepted_latency_seconds_range": (
                [
                    min((r["elapsed_seconds"] for r in accepted)),
                    max((r["elapsed_seconds"] for r in accepted)),
                ]
                if accepted
                else None
            ),
            "resource_observations": [
                {"run_id": r["run_id"], "resources": r.get("resources", {})}
                for r in rows
            ],
            "necessary_approvals": sum((r["necessary_approvals"] for r in rows)),
            "avoidable_approvals": sum((r["avoidable_approvals"] for r in rows)),
        }
    if ready:
        report["paired_owner_seconds_differences_both_accepted"] = {
            other: [
                p[other]["owner_active_seconds"] - p["agentos"]["owner_active_seconds"]
                for p in pairs.values()
                if p[other]["judgment"] == "accepted"
                and p["agentos"]["judgment"] == "accepted"
            ]
            for other in ["openclaw", "provider-cli"]
        }
        report["phases"] = (
            {
                phase: summarize(root, [t for t in trials if t["phase"] == phase])
                for phase in sorted({t["phase"] for t in trials})
            }
            if len({t["phase"] for t in trials}) > 1
            else {}
        )
        report["note"] = (
            "Positive effort differences are descriptive only; accepted goal counts, failures and frozen margins must also be reviewed."
        )
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=pathlib.Path, required=True)
    ap.add_argument("--trials", type=pathlib.Path, required=True)
    ap.add_argument("--output", type=pathlib.Path, required=True)
    a = ap.parse_args()
    trials = [json.loads(l) for l in a.trials.read_text().splitlines() if l.strip()]
    a.output.write_text(json.dumps(summarize(a.root, trials), indent=2) + "\n")


if __name__ == "__main__":
    main()
