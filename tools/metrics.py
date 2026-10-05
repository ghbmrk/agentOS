#!/usr/bin/env python3
"""L4 metrics: writes METRICS.md, one row per plan week (PLAN.md §2 L4, §5).

Sources, all re-read in full on every run so METRICS.md is regenerated, never appended:
  git, first-parent history of --ref   TRACE.md covered count; BOARD.md package states
  LEDGER.md                            usage readings (weekly %, all models and Fable only); phase table
  GitHub API                           PRs: L3 verdicts in reviews, `Defect: <ID>` lines in bodies;
                                       Actions runs and their attempts (CI flakes)
GitHub drops Actions runs after its retention window; a value already in METRICS.md is kept
when the source no longer has data for that week.

Usage:
  tools/metrics.py [--repo owner/name] [--raw-out FILE]   collect (needs GITHUB_TOKEN), write METRICS.md
  tools/metrics.py --raw FILE                             recompute offline from saved raw data
Stdlib only, like the other harness tools.
"""
import argparse
import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
# Plan weeks reset Sunday 06:00 Mark's local time (LEDGER.md). Commit timestamps put that at
# UTC-4; DST shifts the boundary by an hour, which no weekly figure here is sensitive to.
TZ_HOURS = -4
STATES = ("queued", "building", "in review", "merged", "escalated", "dropped")
REACHED_REVIEW = {"in review", "merged", "escalated"}
VERDICTS = r"(accept|fix-list|reject)"
VERDICT_LINE = re.compile(r"verdict\W{0,4}" + VERDICTS + r"\b", re.I)
DEFECT = re.compile(r"^Defect:\s*([A-Z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*(?:\s*,\s*[A-Z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)*)\s*$", re.M)
COVERED = re.compile(r"^Covered: (\d+) / \d+", re.M)
NONE = "—"


# ---------- parsing ----------

def verdict(body):
    """The L3 verdict a review states: a `Verdict: X` line, else the first line's X."""
    if not body:
        return None
    m = VERDICT_LINE.search(body)
    if m:
        return m.group(1).lower()
    first = next((l for l in body.splitlines() if l.strip()), "")
    m = re.search(r"\b" + VERDICTS + r"\b", first, re.I)
    return m.group(1).lower() if m else None


def is_l3(body):
    """Only L3 reviews carry the verdict; lens, correction or bot reviews do not count."""
    return bool(body) and re.search(r"\bL3\b", body) is not None


def defects(body):
    """Package IDs named on `Defect:` lines: a fix to code that was already merged."""
    out = []
    for m in DEFECT.finditer(body or ""):
        out += [x.strip() for x in m.group(1).split(",")]
    return out


def _rows(text, header_has):
    """Yield cell lists of markdown tables whose header row contains header_has."""
    in_table = False
    for line in text.splitlines():
        if not line.startswith("|"):
            in_table = False
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not in_table:
            in_table = header_has in line
            continue
        if set("".join(cells)) <= set("-: "):
            continue
        yield cells


def board_states(text):
    out = {}
    for cells in _rows(text, "| State |"):
        state = cells[-1].lower()
        out[cells[0]] = next((s for s in STATES if state.startswith(s)), "other")
    return out


def _pct(cell):
    m = re.match(r"\s*(\d+(?:\.\d+)?)\s*%", cell)
    return float(m.group(1)) if m else None


def ledger_readings(text):
    out = []
    for cells in _rows(text, "Weekly, all models"):
        try:
            when = dt.datetime.strptime(cells[0], "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        out.append({"at": when.strftime("%Y-%m-%dT%H:%M"), "all": _pct(cells[2]), "fable": _pct(cells[3])})
    return out


def ledger_phases(text):
    return [cells[:3] for cells in _rows(text, "| Phase | Share | Spent |")]


def trace_covered(text):
    m = COVERED.search(text)
    return int(m.group(1)) if m else None


# ---------- collection ----------

def _git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout


def git_history(root, ref):
    """TRACE.md covered counts and BOARD.md states at each first-parent commit that changed them."""
    def series(path, parse):
        out = []
        log = _git(root, "log", "--first-parent", "--reverse", "--format=%H %cI", ref, "--", path)
        for line in log.splitlines():
            sha, when = line.split()
            try:
                value = parse(_git(root, "show", f"{sha}:{path}"))
            except subprocess.CalledProcessError:  # file deleted in this commit
                continue
            if value is not None:
                out.append((when, value))
        return out
    trace = [{"at": w, "covered": v} for w, v in series("TRACE.md", trace_covered)]
    board = [{"at": w, "states": v} for w, v in series("BOARD.md", board_states)]
    return trace, board


def _api(repo, path, token):
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/{path}",
        headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                 **({"Authorization": f"Bearer {token}"} if token else {})})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code not in (403, 429) and e.code < 500 or attempt == 3:
                raise
        except urllib.error.URLError:
            if attempt == 3:
                raise
        time.sleep(2 ** attempt * 5)


def _since(previous_md, tz):
    """UTC start of the week after the last closed week METRICS.md already records."""
    closed = [k for k, cells in _previous(previous_md).items() if "(to date)" not in cells[0]]
    if not closed:
        return None
    start = dt.datetime.strptime(max(closed), "%Y-%m-%d").replace(hour=6, tzinfo=tz) + dt.timedelta(days=7)
    return start.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pages(repo, path, token, key=None):
    sep = "&" if "?" in path else "?"
    page = 1
    while True:
        data = _api(repo, f"{path}{sep}per_page=100&page={page}", token)
        items = data[key] if key else data
        yield from items
        if len(items) < 100:
            return
        page += 1


def collect_github(repo, token, since=None):
    """PRs and Actions runs. With `since` (an ISO time), skip what only frozen weeks use:
    reviews of PRs merged earlier (verdicts None = not collected) and older runs. That keeps
    the call count inside GITHUB_TOKEN's hourly limit as history grows."""
    pulls = []
    for p in _pages(repo, "pulls?state=all", token):
        verdicts = None
        if p.get("merged_at") and (since is None or p["merged_at"] >= since):
            reviews = list(_pages(repo, f"pulls/{p['number']}/reviews", token))
            reviews.sort(key=lambda r: r.get("submitted_at") or "")
            verdicts = [v for v in (verdict(r.get("body")) for r in reviews if is_l3(r.get("body"))) if v]
        pulls.append({"number": p["number"], "merged_at": p.get("merged_at"),
                      "body": p.get("body") or "", "verdicts": verdicts})
    runs = []
    # No query filter: GitHub caps any filtered runs listing (status, created, ...) at 1,000
    # results, which this repo passes in days. The listing is newest first, so paging stops
    # at `since`; unfinished runs are skipped here.
    for r in _pages(repo, "actions/runs", token, "workflow_runs"):
        if since is not None and r["created_at"] < since:
            break
        if r.get("status") != "completed":
            continue
        conclusions = [r["conclusion"]]
        for n in range(1, r.get("run_attempt", 1)):
            conclusions.insert(n - 1, _api(repo, f"actions/runs/{r['id']}/attempts/{n}", token)["conclusion"])
        runs.append({"workflow": r["name"], "sha": r["head_sha"], "at": r["created_at"], "conclusions": conclusions})
    pulls.sort(key=lambda p: p["number"])
    runs.sort(key=lambda r: (r["at"], r["workflow"], r["sha"]))
    return pulls, runs


# ---------- computation ----------

def _when(s, tz):
    t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    return t.replace(tzinfo=tz) if t.tzinfo is None else t


def week_start(t, tz):
    local = t.astimezone(tz)
    start = local.replace(hour=6, minute=0, second=0, microsecond=0)
    start -= dt.timedelta(days=(start.weekday() + 1) % 7)  # back to Sunday
    if start > local:
        start -= dt.timedelta(days=7)
    return start


def compute(raw):
    tz = dt.timezone(dt.timedelta(hours=raw.get("tz_hours", TZ_HOURS)))
    wk = lambda s: week_start(_when(s, tz), tz)
    weeks = set()
    for key in ("trace", "board", "readings", "runs"):
        weeks |= {wk(x["at"]) for x in raw[key]}
    weeks |= {wk(p["merged_at"]) for p in raw["pulls"] if p.get("merged_at")}

    out = []
    for start in sorted(weeks):
        end = start + dt.timedelta(days=7)
        inside = lambda s: start <= _when(s, tz) < end
        before = lambda s: _when(s, tz) < start
        upto = lambda s: _when(s, tz) < end

        covered_end = max((x for x in raw["trace"] if upto(x["at"])), key=lambda x: _when(x["at"], tz), default=None)
        covered_start = max((x for x in raw["trace"] if before(x["at"])), key=lambda x: _when(x["at"], tz), default=None)
        reqs = (covered_end["covered"] if covered_end else 0) - (covered_start["covered"] if covered_start else 0)

        readings = [x for x in raw["readings"] if inside(x["at"])]
        last = max(readings, key=lambda x: (x["all"] or 0, x["at"]), default=None)
        usage_all = last["all"] if last else None
        pace = None
        if last:
            pace = 100 * (_when(last["at"], tz) - start).total_seconds() / (7 * 86400)

        merged = [p for p in raw["pulls"] if p.get("merged_at") and inside(p["merged_at"])]
        judged = [p for p in merged if p["verdicts"]]  # None: not collected (frozen week)

        ever_esc, ever_rev = set(), set()
        for snap in raw["board"]:
            if upto(snap["at"]):
                ever_esc |= {k for k, v in snap["states"].items() if v == "escalated"}
                ever_rev |= {k for k, v in snap["states"].items() if v in REACHED_REVIEW}

        groups = {}
        for r in raw["runs"]:
            groups.setdefault((r["workflow"], r["sha"]), []).append(r)
        flaky = n_runs = 0
        for runs in groups.values():
            if not inside(min(r["at"] for r in runs)):
                continue
            seen = {c for r in runs for c in r["conclusions"]} & {"success", "failure"}
            if seen:
                n_runs += 1
                flaky += seen == {"success", "failure"}

        out.append({
            "week": start.strftime("%Y-%m-%d"),
            "current": start <= _when(raw["now"], tz) < end,
            "reqs": reqs,
            "usage_all": usage_all,
            "usage_fable": last["fable"] if last else None,
            "pace": pace,
            "usage_per_req": usage_all / reqs if usage_all is not None and reqs > 0 else None,
            "first_pass_ok": sum(p["verdicts"][0] == "accept" for p in judged),
            "first_pass_n": len(judged),
            "no_verdict": [p["number"] for p in merged if p["verdicts"] == []],
            "merged": len(merged),
            "escalated": len(ever_esc),
            "reviewed": len(ever_rev),
            "defects": sorted(d for p in merged for d in defects(p["body"])),
            "flaky": flaky,
            "runs": n_runs,
        })
    return out


# ---------- rendering ----------

# Columns sourced from the GitHub API: frozen once a closed week has been recorded, so
# later edits, deleted reviews or expired runs cannot rewrite a finished week.
FROZEN = (5, 7, 8)
COLUMNS = [
    "Week starting", "Usage all / Fable", "On-pace mark", "Reqs newly covered", "Usage per req",
    "First-pass L3 accept", "Escalation rate (cum.)", "Defects after merge", "CI flake rate",
]


def _ratio(k, n):
    return f"{round(100 * k / n)}% ({k}/{n})" if n else NONE


def _cells(w):
    return [
        w["week"] + (" (to date)" if w["current"] else ""),
        f"{w['usage_all']:g}% / {w['usage_fable']:g}%" if w["usage_all"] is not None else NONE,
        f"{w['pace']:.0f}%" if w["pace"] is not None else NONE,
        str(w["reqs"]),
        f"{w['usage_per_req']:.2f} pts" if w["usage_per_req"] is not None else NONE,
        _ratio(w["first_pass_ok"], w["first_pass_n"]),
        _ratio(w["escalated"], w["reviewed"]),
        f"{len(w['defects'])} ({', '.join(w['defects'])})" if w["defects"] else ("0" if w["merged"] else NONE),
        _ratio(w["flaky"], w["runs"]),
    ]


def _previous(text):
    rows = {}
    for cells in _rows(text or "", "| Week starting |"):
        rows[cells[0].split()[0]] = cells
    return rows


def render(weeks, raw, previous_md=None):
    old = _previous(previous_md)
    lines = [
        "# METRICS (generated by tools/metrics.py; do not edit)",
        "",
        "Inputs for the L4 meta loop (PLAN.md §2). Regenerated weekly by `.github/workflows/metrics.yml`, "
        f"or on demand. Data as of {raw['now'][:16].replace('T', ' ')} UTC.",
        "",
        "## Weekly",
        "",
        "| " + " | ".join(COLUMNS) + " |",
        "|" + "---|" * len(COLUMNS),
    ]
    for w in weeks:
        cells = _cells(w)
        prev = old.get(w["week"])
        if prev and len(prev) == len(cells):
            closed = not w["current"] and "(to date)" not in prev[0]
            cells = [o if (c == NONE and o != NONE) or (closed and i in FROZEN) else c
                     for i, (c, o) in enumerate(zip(cells, prev))]
        lines.append("| " + " | ".join(cells) + " |")
    unjudged = sorted(n for w in weeks for n in w["no_verdict"])
    lines += [
        "",
        "## Definitions",
        "",
        "- **Week**: a plan week, Sunday 06:00 to Sunday 06:00 Mark's local time (UTC-4 assumed).",
        "- **Usage**: the highest weekly-limit reading in LEDGER.md that week, all models / Fable only. "
        "Model usage is not metered per package; Mark's usage screen is the source (LEDGER B-6). "
        "Spend by model tier is approximated by this all-models / Fable-only split.",
        "- **On-pace mark**: the share of the week elapsed at that reading. Usage at the mark is on pace for ~100% at reset.",
        "- **Reqs newly covered**: growth of TRACE.md's covered count on main that week.",
        "- **Usage per req**: weekly-limit points per newly covered requirement ID. "
        "Stands in for tokens per merged requirement until tokens are metered.",
        "- **First-pass L3 accept**: PRs merged that week whose first review with a verdict "
        "(an L3 review stating `Verdict: accept|fix-list|reject`, or the verdict on its first line) was accept.",
        "- **Escalation rate**: packages ever `escalated` on BOARD.md over packages that ever reached "
        "`in review`, `merged` or `escalated`, up to that week.",
        "- **Defects after merge**: `Defect: <package ID>` lines in the bodies of PRs merged that week "
        "(a fix to code already merged; see the PR template).",
        "- **CI flake rate**: commits that, within one workflow, had both a failed and a passed run or "
        "attempt, over commits with any finished run; counted in the week of the first run.",
        "- **Closed weeks**: once a finished week is recorded, its L3, defect and flake cells are kept as "
        "recorded; the other columns are recomputed from git and LEDGER.md each run.",
        "",
        "## Spend by phase (copied from LEDGER.md)",
        "",
        "| Phase | Share | Spent |",
        "|---|---|---|",
    ]
    lines += ["| " + " | ".join(p) + " |" for p in raw["phases"]]
    lines += [
        "",
        "## Data gaps",
        "",
        "- Merged PRs with no parseable L3 verdict (left out of first-pass acceptance): "
        + (", ".join(f"#{n}" for n in unjudged) if unjudged else "none") + ".",
    ]
    return "\n".join(lines) + "\n"


# ---------- main ----------

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--ref", default="HEAD")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "ghbmrk/agentos"))
    ap.add_argument("--raw", help="compute from this saved raw JSON instead of collecting")
    ap.add_argument("--raw-out", help="save the collected raw JSON here")
    ap.add_argument("--now", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    root = pathlib.Path(args.root)

    out = root / "METRICS.md"
    previous = out.read_text() if out.exists() else None
    if args.raw:
        raw = json.loads(pathlib.Path(args.raw).read_text())
    else:
        trace, board = git_history(root, args.ref)
        ledger = (root / "LEDGER.md").read_text()
        tz = dt.timezone(dt.timedelta(hours=TZ_HOURS))
        pulls, runs = collect_github(args.repo, os.environ.get("GITHUB_TOKEN"), _since(previous, tz))
        raw = {
            "now": args.now or dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "tz_hours": TZ_HOURS, "trace": trace, "board": board,
            "readings": ledger_readings(ledger), "phases": ledger_phases(ledger),
            "pulls": pulls, "runs": runs,
        }
        if args.raw_out:
            pathlib.Path(args.raw_out).write_text(json.dumps(raw, indent=1, sort_keys=True))

    out.write_text(render(compute(raw), raw, previous))
    return 0


if __name__ == "__main__":
    sys.exit(main())
