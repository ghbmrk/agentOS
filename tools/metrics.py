#!/usr/bin/env python3
"""L4 metrics: writes METRICS.md, one row per plan week (PLAN.md §2 L4, §5).

Sources, all re-read in full on every run so METRICS.md is regenerated, never appended:
  git, first-parent history of --ref   TRACE.md covered count; BOARD.md package states
  LEDGER.md                            usage readings (weekly %, all models and Fable only); phase table
  GitHub API                           PRs: L3 verdicts in collaborators' reviews, `Defect: <ID>`
                                       lines in bodies; this repository's own Actions runs and
                                       their attempts (CI flakes)
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
NA = "n/a"  # a column that cannot be computed from the data at hand (never printed as 0)
OPEN_STATES = ("queued", "building", "in review", "escalated")
# D-085 convergence measures (CONV-0). The guard compares weeks starting after DECISION with the
# mean of the two 7-day windows that end at DECISION 00:00 local time.
DECISION = dt.date(2026, 10, 9)
STALE_HOURS = 48
LEDGER_STALE_HOURS = 36
FOLLOWUP_ID = re.compile(r"-[frl]\d+$")
CITES_REVIEW = re.compile(r"\b(?:L3|Security|UX\d*|Potency|lens|review)\b")
CITES_LATER = re.compile(r"\bLATER(?:\.md)?\s+(?:line\s+)?[A-Z][A-Za-z0-9]*-[\w-]*")


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


CAUSES = ("spec-gap", "brief-gap", "defect", "scope")
CAUSE_LINE = re.compile(r"^\W*cause\W{0,4}(" + "|".join(CAUSES) + r")\b", re.I | re.M)


def cause(body):
    """The rework cause a non-accept L3 verdict names on its `Cause: X` line (OPERATING §4)."""
    m = CAUSE_LINE.search(body or "")
    return m.group(1).lower() if m else None


def is_l3(body):
    """Only L3 reviews carry the verdict; lens, correction or bot reviews do not count."""
    return bool(body) and re.search(r"\bL3\b", body) is not None


# Security review 2, finding 8: the repository is public, so anyone can post a review or
# run a fork's CI. Only collaborators' reviews and this repository's own runs count.
TRUSTED = {"OWNER", "MEMBER", "COLLABORATOR"}


def trusted_review(r):
    return r.get("author_association") in TRUSTED


def own_run(r, repo):
    head = r.get("head_repository") or {}
    return (head.get("full_name") or "").lower() == repo.lower()


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


def board_flags(text):
    """{row ID: flags} for rows that are review follow-ups ("f": an ID ending -f<N>, -r<N> or -l<N>,
    or a `(release` row citing a review) or promotions from LATER.md ("p": its text cites a LATER line)."""
    out = {}
    for cells in _rows(text, "| State |"):
        body = " ".join(cells[1:])
        flags = ("f" if FOLLOWUP_ID.search(cells[0]) or ("(release" in body and CITES_REVIEW.search(body)) else "") \
            + ("p" if CITES_LATER.search(body) else "")
        if flags:
            out[cells[0]] = flags
    return out


def held_drafts(text):
    """PR numbers in the Draft column of briefs/CODEX-1.md's "Held" table."""
    section = text.split("\n## Held", 1)[-1].split("\n## ", 1)[0] if "\n## Held" in text else ""
    return sorted({int(n) for cells in _rows(section, "| Item |") if len(cells) > 1
                   for n in re.findall(r"#(\d+)", cells[1])})


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
    board = [{"at": w, "states": v[0], "flags": v[1]}
             for w, v in series("BOARD.md", lambda t: (board_states(t), board_flags(t)))]
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
        verdicts = causes = None
        if p.get("merged_at") and (since is None or p["merged_at"] >= since):
            reviews = list(_pages(repo, f"pulls/{p['number']}/reviews", token))
            reviews.sort(key=lambda r: r.get("submitted_at") or "")
            l3 = [r.get("body") for r in reviews if trusted_review(r) and is_l3(r.get("body"))]
            verdicts = [v for v in map(verdict, l3) if v]
            # A non-accept verdict without a Cause line counts as "none" so the gap shows.
            causes = [cause(b) or "none" for b in l3 if verdict(b) in ("fix-list", "reject")]
        pulls.append({"number": p["number"], "merged_at": p.get("merged_at"),
                      "state": p.get("state"), "draft": bool(p.get("draft")), "updated_at": p.get("updated_at"),
                      "body": p.get("body") or "", "verdicts": verdicts,
                      "causes": causes})
    runs = []
    # No query filter: GitHub caps any filtered runs listing (status, created, ...) at 1,000
    # results, which this repo passes in days. The listing is newest first, so paging stops
    # at `since`; unfinished runs are skipped here.
    for r in _pages(repo, "actions/runs", token, "workflow_runs"):
        if since is not None and r["created_at"] < since:
            break
        if r.get("status") != "completed" or not own_run(r, repo):
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


def convergence(raw, tz, a, b):
    """D-085 measures for the window [a, b): open rows at b, follow-up rows and promotions first seen
    in the window, PRs merged and `Defect:` lines. None where the raw data cannot say."""
    snaps = sorted(raw["board"], key=lambda x: _when(x["at"], tz))
    upto = [x for x in snaps if _when(x["at"], tz) < b]
    first = {}
    for x in snaps:
        for k in x["states"]:
            first.setdefault(k, _when(x["at"], tz))
    new = {k for k, t in first.items() if a <= t < b}
    # Before the first BOARD.md commit nothing was open or added; with no history at all, unknown.
    out = {"open_rows": (sum(v in OPEN_STATES for v in upto[-1]["states"].values()) if upto else 0) if snaps else None,
           "followups": None, "promotions": None}
    if snaps and all("flags" in x for x in snaps):
        flags = upto[-1]["flags"] if upto else {}
        out["followups"] = sum("f" in flags.get(k, "") for k in new)
        out["promotions"] = sum("p" in flags.get(k, "") for k in new)
    merged = [p for p in raw["pulls"] if p.get("merged_at") and a <= _when(p["merged_at"], tz) < b]
    out["merged"] = len(merged)
    out["defects"] = sorted(d for p in merged for d in defects(p["body"]))
    out["followups_per_pr"] = out["followups"] / len(merged) if merged and out["followups"] is not None else None
    return out


def stale_prs(raw, tz):
    """Open PRs untouched for STALE_HOURS at run time, minus drafts held in briefs/CODEX-1.md."""
    if raw.get("held") is None or not any(p.get("state") for p in raw["pulls"]):
        return None
    cutoff = _when(raw["now"], tz) - dt.timedelta(hours=STALE_HOURS)
    held = set(raw["held"])
    return sorted(p["number"] for p in raw["pulls"]
                  if p.get("state") == "open" and p.get("updated_at") and _when(p["updated_at"], tz) < cutoff
                  and not (p.get("draft") and p["number"] in held))


def baseline(raw):
    """Mean of the two 7-day windows before DECISION, per D-085 measure (None where unknown)."""
    tz = dt.timezone(dt.timedelta(hours=raw.get("tz_hours", TZ_HOURS)))
    end = dt.datetime.combine(DECISION, dt.time(), tzinfo=tz)
    wins = [convergence(raw, tz, end - dt.timedelta(days=14), end - dt.timedelta(days=7)),
            convergence(raw, tz, end - dt.timedelta(days=7), end)]
    wins = [dict(w, defects=len(w["defects"])) for w in wins]
    mean = lambda k: None if any(w[k] is None for w in wins) else sum(w[k] for w in wins) / 2
    out = {k: mean(k) for k in ("open_rows", "followups", "followups_per_pr", "promotions", "defects")}
    out["stale"] = None  # open PRs are known only at run time; no history to average
    return out


def compute(raw):
    tz = dt.timezone(dt.timedelta(hours=raw.get("tz_hours", TZ_HOURS)))
    wk = lambda s: week_start(_when(s, tz), tz)
    weeks = set()
    for key in ("trace", "board", "readings", "runs"):
        weeks |= {wk(x["at"]) for x in raw[key]}
    weeks |= {wk(p["merged_at"]) for p in raw["pulls"] if p.get("merged_at")}

    out = []
    base = baseline(raw)
    stale_now = stale_prs(raw, tz)
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
            "rounds": sum(len(p["verdicts"]) for p in judged),
            # Pulls collected before causes were parsed have no "causes" key.
            "causes": sorted(c for p in judged for c in (p.get("causes") or [])),
            "no_verdict": [p["number"] for p in merged if p["verdicts"] == []],
            "merged": len(merged),
            "escalated": len(ever_esc),
            "reviewed": len(ever_rev),
            "defects": sorted(d for p in merged for d in defects(p["body"])),
            "flaky": flaky,
            "runs": n_runs,
        })
        conv = convergence(raw, tz, start, end)
        judged_week = start.date() > DECISION  # the decision's own week is half baseline
        out[-1].update({
            "open_rows": conv["open_rows"], "followups": conv["followups"],
            "followups_per_pr": conv["followups_per_pr"], "promotions": conv["promotions"],
            "stale": stale_now if out[-1]["current"] else None,
            "red": {k for k, v in (("promotions", conv["promotions"]), ("defects", len(conv["defects"])))
                    if judged_week and v is not None and base[k] is not None and v > base[k]},
        })
    return out


# ---------- rendering ----------

# Columns sourced from the GitHub API: frozen once a closed week has been recorded, so
# later edits, deleted reviews or expired runs cannot rewrite a finished week.
FROZEN = (5, 7, 8, 9, 11, 16)
COLUMNS = [
    "Week starting", "Usage all / Fable", "On-pace mark", "Reqs newly covered", "Usage per req",
    "First-pass L3 accept", "Escalation rate (cum.)", "Defects after merge", "CI flake rate",
    "L3 rounds per merged PR", "Usage per merged PR", "L3 causes",
    "Open BOARD rows", "Follow-up rows added", "Follow-ups per merged PR", "Promotions later to release",
    "Stale PRs (48 h)",
]


def _ratio(k, n):
    return f"{round(100 * k / n)}% ({k}/{n})" if n else NONE


def _cells(w):
    red = lambda key: " red" if key in w["red"] else ""
    n = lambda v: NA if v is None else str(v)
    return [
        w["week"] + (" (to date)" if w["current"] else ""),
        f"{w['usage_all']:g}% / {w['usage_fable']:g}%" if w["usage_all"] is not None else NONE,
        f"{w['pace']:.0f}%" if w["pace"] is not None else NONE,
        str(w["reqs"]),
        f"{w['usage_per_req']:.2f} pts" if w["usage_per_req"] is not None else NONE,
        _ratio(w["first_pass_ok"], w["first_pass_n"]),
        _ratio(w["escalated"], w["reviewed"]),
        (f"{len(w['defects'])} ({', '.join(w['defects'])})" if w["defects"] else ("0" if w["merged"] else NONE))
        + red("defects"),
        _ratio(w["flaky"], w["runs"]),
        f"{w['rounds'] / w['first_pass_n']:.1f}" if w["first_pass_n"] else NONE,
        f"{w['usage_all'] / w['merged']:.2f} pts" if w["usage_all"] is not None and w["merged"] else NONE,
        ", ".join(f"{c} {w['causes'].count(c)}" for c in sorted(set(w["causes"]))) if w["causes"]
        else ("0" if w["first_pass_n"] else NONE),
        n(w["open_rows"]), n(w["followups"]),
        NA if w["followups_per_pr"] is None else f"{w['followups_per_pr']:.1f}",
        n(w["promotions"]) + red("promotions") if w["promotions"] is not None else NA,
        NA if w["stale"] is None else str(len(w["stale"])),
    ]


def _previous(text):
    rows = {}
    for cells in _rows(text or "", "| Week starting |"):
        rows[cells[0].split()[0]] = cells
    return rows


def _ledger_stale(raw):
    """First line of METRICS.md when LEDGER.md's newest reading is over LEDGER_STALE_HOURS old (D-085)."""
    tz = dt.timezone(dt.timedelta(hours=raw.get("tz_hours", TZ_HOURS)))
    newest = max((r["at"] for r in raw["readings"]), default=None)
    if newest is None:
        return ["**LEDGER.md has no reading; take one (D-085).**", ""]
    if _when(raw["now"], tz) - _when(newest, tz) <= dt.timedelta(hours=LEDGER_STALE_HOURS):
        return []
    return [f"**LEDGER.md is stale: its newest reading, {newest.replace('T', ' ')} (local), is over "
            f"{LEDGER_STALE_HOURS} hours old; take a reading (D-085).**", ""]


def render(weeks, raw, previous_md=None):
    old = _previous(previous_md)
    lines = [
        *_ledger_stale(raw),
        "# METRICS (generated by tools/metrics.py; do not edit)",
        "",
        "Inputs for the L4 meta loop (PLAN.md §2). Regenerated daily by `.github/workflows/metrics.yml`, "
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
        if prev and len(prev) < len(cells):
            prev = prev + [NONE] * (len(cells) - len(prev))  # recorded before later columns were appended
        if prev and len(prev) == len(cells):
            closed = not w["current"] and "(to date)" not in prev[0]
            cells = [o if (c in (NONE, NA) and o not in (NONE, NA)) or (closed and i in FROZEN) else c
                     for i, (c, o) in enumerate(zip(cells, prev))]
        lines.append("| " + " | ".join(cells) + " |")
    base = baseline(raw)
    lines += ["", "## Baseline (D-085)", "",
              "Mean of the two 7-day windows before 2026-10-09 (2026-09-25 to 2026-10-09, UTC-4). "
              "A week starting after 2026-10-09 is marked `red` when its promotions or `Defect:` lines exceed it.",
              "", "| Column | Baseline |", "|---|---|"]
    for key, name in (("open_rows", "Open BOARD rows"), ("followups", "Follow-up rows added"),
                      ("followups_per_pr", "Follow-ups per merged PR"), ("promotions", "Promotions later to release"),
                      ("defects", "Defects after merge"), ("stale", "Stale PRs (48 h)")):
        lines.append(f"| {name} | {NA if base[key] is None else format(base[key], 'g')} |")
    for key, name in (("promotions", "promotions"), ("defects", "`Defect:` lines")):
        if any(a["red"] >= {key} and b["red"] >= {key} and
               (dt.date.fromisoformat(b["week"]) - dt.date.fromisoformat(a["week"])).days == 7
               for a, b in zip(weeks, weeks[1:])):
            lines += ["", "D-085 guard tripped: revert the release-class rule (decisions/D-085.md)",
                      f"(two weeks in a row above baseline: {name})"]
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
        "- **L3 rounds per merged PR**: L3 reviews with a verdict, averaged over the PRs merged that week "
        "that had one. 1.0 means every PR was accepted on its first review (COST-1: rework is the main cost).",
        "- **Usage per merged PR**: weekly-limit points per PR merged that week; the cost-per-package "
        "figure the operating model steers by (docs/OPERATING.md §6).",
        "- **L3 causes**: the `Cause:` lines of fix-list and reject L3 reviews on PRs merged that week, "
        "by code (spec-gap, brief-gap, defect, scope; docs/OPERATING.md §4). `none` is a non-accept "
        "verdict without a Cause line.",
        "- **Open BOARD rows**: rows queued, building, in review or escalated in the last BOARD.md of the week.",
        "- **Follow-up rows added**: rows first seen on BOARD.md that week whose ID ends `-f<N>`, `-r<N>` or `-l<N>`, "
        "or whose package text says `(release` and cites a review. **Per merged PR**: that count over PRs merged that week.",
        "- **Promotions later to release**: rows first seen that week whose text cites a LATER.md line (`LATER <ID>`).",
        "- **Stale PRs (48 h)**: open PRs with no update for 48 hours at run time, leaving out draft PRs listed under "
        "Held in briefs/CODEX-1.md; counted for the current week only.",
        "- **red** / **n/a**: red marks a week above the D-085 baseline; `n/a` means the data to compute a column is "
        "absent (never printed as 0).",
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
        codex = root / "briefs" / "CODEX-1.md"
        ledger = (root / "LEDGER.md").read_text()
        tz = dt.timezone(dt.timedelta(hours=TZ_HOURS))
        pulls, runs = collect_github(args.repo, os.environ.get("GITHUB_TOKEN"), _since(previous, tz))
        raw = {
            "now": args.now or dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "tz_hours": TZ_HOURS, "trace": trace, "board": board,
            "readings": ledger_readings(ledger), "phases": ledger_phases(ledger),
            "pulls": pulls, "runs": runs,
            "held": held_drafts(codex.read_text()) if codex.is_file() else None,
        }
        if args.raw_out:
            pathlib.Path(args.raw_out).write_text(json.dumps(raw, indent=1, sort_keys=True))

    out.write_text(render(compute(raw), raw, previous))
    return 0


if __name__ == "__main__":
    sys.exit(main())
