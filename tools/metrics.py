#!/usr/bin/env python3
"""L4 metrics: writes METRICS.md, one row per plan week (PLAN.md §2 L4, §5).

Sources, all re-read in full on every run so METRICS.md is regenerated, never appended:
  git, first-parent history of --ref   TRACE.md covered count; BOARD.md package states (the
                                       hand-kept board up to SIM-repo-2b, the generated one since)
  LEDGER.md                            usage readings (weekly %, all models and Fable only); phase table
  working tree                         SPEC.md and process-doc word counts (tools/word_budget.py, D-152)
  GitHub API                           PRs: L3 verdicts in collaborators' reviews, `Defect: <ID>`
                                       lines in bodies; this repository's own Actions runs and
                                       their attempts (CI flakes); `state:` labels added to
                                       work-item issues (package states between board renders)
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

import word_budget  # tools/, beside this file

ROOT = pathlib.Path(__file__).resolve().parent.parent
# Plan weeks reset Sunday 06:00 Mark's local time (LEDGER.md). Commit timestamps put that at
# UTC-4; DST shifts the boundary by an hour, which no weekly figure here is sensitive to.
TZ_HOURS = -4
STATES = ("queued", "building", "in review", "merged", "escalated", "dropped")
REACHED_REVIEW = {"in review", "merged", "escalated"}
VERDICTS = r"(accept|fix-list|reject)"
VERDICT_LINE = re.compile(r"verdict\W{0,4}" + VERDICTS + r"\b", re.I)
# A comment counts only with the OPERATING §4 form: a line that starts with `Verdict:`.
COMMENT_VERDICT = re.compile(r"^[ \t*_]*verdict:[ \t*_]*" + VERDICTS + r"\b", re.I | re.M)
DEFECT = re.compile(r"^Defect:\s*([A-Z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*(?:\s*,\s*[A-Z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)*)\s*$", re.M)
COVERED = re.compile(r"^Covered: (\d+) / \d+", re.M)
NONE = "—"
NA = "n/a"  # a column that cannot be computed from the data at hand (never printed as 0)
OPEN_STATES = ("queued", "building", "in review", "escalated")
# D-086 convergence measures (CONV-0). The guard compares the two latest full weeks with the
# two 7-day windows that end at DECISION 00:00 local time.
DECISION = dt.date(2026, 10, 9)
STALE_HOURS = 48
LEDGER_STALE_HOURS = 36
LANE_CAP = 10
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


RECORD_HEAD = re.compile(r"^[ \t>*_-]*Record:.*?\bhead\W{0,3}([0-9a-f]{7,40})\b", re.I | re.M)
HEAD_SHA = re.compile(r"\bhead\W{0,3}([0-9a-f]{7,40})\b", re.I)


def review_head(body):
    """The head SHA a verdict's `Record: ... head <SHA>` line names (OPERATING §4); a verdict with no
    Record line falls back to the first `head <SHA>` in its text, else None."""
    m = RECORD_HEAD.search(body or "") or HEAD_SHA.search(body or "")
    return m.group(1).lower() if m else None


def count_rounds(bodies):
    """OPERATING §4 round = one reviewed head. Verdicts naming the same head (a Security, lens or
    repeat accept) are one round; short SHAs match by prefix; a verdict naming no head counts alone."""
    heads, n = [], 0
    for b in bodies:
        h = review_head(b)
        if h is None:
            n += 1
        elif not any(x.startswith(h) or h.startswith(x) for x in heads):
            heads.append(h)
    return n + len(heads)


NOISE_CLASSES = ("fixed", "wrong", "intentional", "didn't-matter")
FINDING_CLASSES = ("blocker", "release", "later")
# One line per finding in a builder reply or verdict: `Finding blocker: fixed`, any text after.
NOISE_LINE = re.compile(r"^[ \t*_>-]*finding[ \t]+(" + "|".join(FINDING_CLASSES) + r")[ \t]*:[ \t*_]*(fixed|wrong|intentional|didn['\u2019]?t[- ]matter)\b",
                        re.I | re.M)


def noise(bodies):
    """(finding class, resolution) for each `Finding <class>: <resolution>` line."""
    out = []
    for b in bodies:
        for m in NOISE_LINE.finditer(b or ""):
            out.append((m.group(1).lower(), "didn't-matter" if m.group(2).lower().startswith("didn") else m.group(2).lower()))
    return out


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


WORK_ITEM_TITLE = re.compile(r"([A-Z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*(?: [a-z][A-Za-z0-9]*)*): ")


def collect_states(repo, token):
    """[{at, id, state}] for every `state:` label added to a work-item issue (tools/board.py).
    The generated BOARD.md only shows a package while it is open, and a state held between two
    board renders never reaches its history, so escalations and reviews are also counted here."""
    out = []
    for e in _pages(repo, "issues/events", token):
        issue, label = e.get("issue") or {}, (e.get("label") or {}).get("name", "")
        names = {x["name"] for x in issue.get("labels", [])}
        m = WORK_ITEM_TITLE.match(issue.get("title", ""))
        if e.get("event") == "labeled" and label.startswith("state:") and "work-item" in names and m \
                and "pull_request" not in issue:
            out.append({"at": e["created_at"], "id": m.group(1), "state": label[len("state:"):]})
    out.sort(key=lambda x: (x["at"], x["id"]))
    return out


def _open_week(cell):
    """A recorded week label still open: "(current, ...)", or "(to date)" as recorded before MET-1."""
    return "(current" in cell or "(to date)" in cell


def _since(previous_md, tz):
    """UTC start of the week after the last closed week METRICS.md already records."""
    closed = [k for k, cells in _previous(previous_md).items() if not _open_week(cells[0])]
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
        verdicts = causes = rounds = notes_noise = None
        if p.get("merged_at") and (since is None or p["merged_at"] >= since):
            reviews = list(_pages(repo, f"pulls/{p['number']}/reviews", token))
            # A verdict posted as a conversation comment counts too, but only with a
            # `Verdict:` line, so an incidental "L3" mention is not read as one.
            notes = [{"submitted_at": c.get("created_at"), "body": c.get("body"),
                      "author_association": c.get("author_association"), "comment": True}
                     for c in _pages(repo, f"issues/{p['number']}/comments", token)
                     if COMMENT_VERDICT.search(c.get("body") or "") or NOISE_LINE.search(c.get("body") or "")]
            reviews = sorted(reviews + notes, key=lambda r: r.get("submitted_at") or "")
            l3, seen, from_comments = [], set(), set()
            for r in reviews:
                b = r.get("body")
                # A builder reply that only carries `Finding` lines is no verdict.
                if not (trusted_review(r) and is_l3(b)) or (r.get("comment") and not COMMENT_VERDICT.search(b)):
                    continue
                # A verdict bears the head SHA, so separate rounds differ; a review and a
                # comment with the same body (either order), or two comments, are one round.
                key = b.strip()
                if key in seen and (r.get("comment") or key in from_comments):
                    continue
                seen.add(key)
                if r.get("comment"):
                    from_comments.add(key)
                l3.append(b)
            verdicts = [v for v in map(verdict, l3) if v]
            rounds = count_rounds([b for b in l3 if verdict(b)])
            notes_noise = noise([r.get("body") for r in reviews if trusted_review(r)])
            # A non-accept verdict without a Cause line counts as "none" so the gap shows.
            causes = [cause(b) or "none" for b in l3 if verdict(b) in ("fix-list", "reject")]
        pulls.append({"number": p["number"], "merged_at": p.get("merged_at"),
                      "state": p.get("state"), "draft": bool(p.get("draft")), "updated_at": p.get("updated_at"),
                      "body": p.get("body") or "", "verdicts": verdicts,
                      "labels": [l["name"] for l in p.get("labels") or []],
                      "causes": causes, "rounds": rounds, "noise": notes_noise})
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
    """D-086 measures for the window [a, b): open rows at b, follow-up rows and promotions first seen
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
    out["defects_per_pr"] = len(out["defects"]) / len(merged) if merged else None
    out["followups_per_pr"] = out["followups"] / len(merged) if merged and out["followups"] is not None else None
    return out


def stale_prs(raw, tz):
    """Open PRs untouched for STALE_HOURS at run time; held drafts count like any other (D-098)."""
    if not any(p.get("state") for p in raw["pulls"]):
        return None
    cutoff = _when(raw["now"], tz) - dt.timedelta(hours=STALE_HOURS)
    return sorted(p["number"] for p in raw["pulls"]
                  if p.get("state") == "open" and p.get("updated_at") and _when(p["updated_at"], tz) < cutoff)


def open_by_lane(raw):
    """{lane: open PR count} from each PR's `lane:<name>` label (docs/LANES.md); no label is the peers' lane."""
    if not any(p.get("state") for p in raw["pulls"]):
        return None
    out = {}
    for p in raw["pulls"]:
        if p.get("state") == "open":
            lane = next((l[5:] for l in p.get("labels", []) if l.startswith("lane:")), "peers")
            out[lane] = out.get(lane, 0) + 1
    return out


def baseline(raw):
    """Mean of the two 7-day windows before DECISION, per D-086 measure (None where unknown).
    Defects per merged PR pools the two windows: all their `Defect:` lines over all their merges."""
    tz = dt.timezone(dt.timedelta(hours=raw.get("tz_hours", TZ_HOURS)))
    end = dt.datetime.combine(DECISION, dt.time(), tzinfo=tz)
    wins = [convergence(raw, tz, end - dt.timedelta(days=14), end - dt.timedelta(days=7)),
            convergence(raw, tz, end - dt.timedelta(days=7), end)]
    wins = [dict(w, defects=len(w["defects"])) for w in wins]
    mean = lambda k: None if any(w[k] is None for w in wins) else sum(w[k] for w in wins) / 2
    out = {k: mean(k) for k in ("open_rows", "followups", "followups_per_pr", "promotions", "defects")}
    n = sum(w["merged"] for w in wins)
    out["defects_per_pr"] = sum(w["defects"] for w in wins) / n if n else None
    out["stale"] = None  # open PRs are known only at run time; no history to average
    return out


def compute(raw):
    tz = dt.timezone(dt.timedelta(hours=raw.get("tz_hours", TZ_HOURS)))
    wk = lambda s: week_start(_when(s, tz), tz)
    weeks = set()
    for key in ("trace", "board", "readings", "runs"):
        weeks |= {wk(x["at"]) for x in raw[key]}
    weeks |= {wk(p["merged_at"]) for p in raw["pulls"] if p.get("merged_at")}
    weeks |= {wk(x["at"]) for x in raw.get("states", [])}

    out = []
    base = baseline(raw)
    stale_now = stale_prs(raw, tz)
    lanes_now = open_by_lane(raw)
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
        # MET-1a: requirements are counted at the reading's own time, not at the week's end.
        at_reading = max((x for x in raw["trace"] if _when(x["at"], tz) <= _when(last["at"], tz)),
                         key=lambda x: _when(x["at"], tz), default=None) if last else None
        reqs_at_reading = ((at_reading["covered"] if at_reading else 0)
                           - (covered_start["covered"] if covered_start else 0)) if last else None
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
        for x in raw.get("states", []):  # raw data saved before SIM-repo-2b has none
            if upto(x["at"]):
                ever_esc |= {x["id"]} if x["state"] == "escalated" else set()
                ever_rev |= {x["id"]} if x["state"] in REACHED_REVIEW else set()

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
            "reading_at": last["at"] if last else None,
            "reqs_at_reading": reqs_at_reading,
            "usage_per_req": usage_all / reqs_at_reading if usage_all is not None and reqs_at_reading > 0 else None,
            # MET-1b: the newest input of any kind, to show how old the row's data is.
            "newest_input": max((x["at"] for k in ("trace", "board", "readings") for x in raw[k]
                                 if upto(x["at"]) and _when(x["at"], tz) <= _when(raw["now"], tz)),
                                key=lambda s: _when(s, tz), default=None),
            "age_hours": None,
            "first_pass_ok": sum(p["verdicts"][0] == "accept" for p in judged),
            "first_pass_n": len(judged),
            "rounds": sum(p["rounds"] if p.get("rounds") is not None else len(p["verdicts"]) for p in judged),
            # Pulls collected before noise was parsed have no "noise" key.
            "noise": [x for p in merged for x in (p.get("noise") or [])],
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
        if out[-1]["current"] and out[-1]["newest_input"]:
            out[-1]["age_hours"] = (_when(raw["now"], tz) - _when(out[-1]["newest_input"], tz)).total_seconds() / 3600
        conv = convergence(raw, tz, start, end)
        judged_week = start.date() > DECISION  # the decision's own week is half baseline
        out[-1].update({
            "open_rows": conv["open_rows"], "followups": conv["followups"],
            "followups_per_pr": conv["followups_per_pr"], "promotions": conv["promotions"],
            "stale": stale_now if out[-1]["current"] else None,
            "lanes": lanes_now if out[-1]["current"] else None,
            "defects_per_pr": conv["defects_per_pr"],
            # D-086 guard (amended 2026-10-23): promotions per week, `Defect:` lines per merged PR.
            "red": {k for k, v in (("promotions", conv["promotions"]), ("defects_per_pr", conv["defects_per_pr"]))
                    if judged_week and v is not None and base[k] is not None and v > base[k]},
        })
    return out


# ---------- rendering ----------

# Columns sourced from the GitHub API: frozen once a closed week has been recorded, so
# later edits, deleted reviews or expired runs cannot rewrite a finished week.
FROZEN = (5, 7, 8, 9, 11, 16, 17)
COLUMNS = [
    "Week starting", "Usage all / Fable", "On-pace mark", "Reqs newly covered", "Usage per req",
    "First-pass L3 accept", "Escalation rate (cum.)", "Defects after merge", "CI flake rate",
    "L3 rounds per merged PR", "Usage per merged PR", "L3 causes",
    "Open BOARD rows", "Follow-up rows added", "Follow-ups per merged PR", "Promotions later to release",
    "Stale PRs (48 h)", "Open PRs by lane", "Defects per merged PR",
]


def _ratio(k, n):
    return f"{round(100 * k / n)}% ({k}/{n})" if n else NONE


def _week_label(w):
    """Closed weeks print the date; the current week names its reading and, past 36 h, the age of its newest input."""
    if not w["current"]:
        return w["week"]
    note = f"reading {w['reading_at'].replace('T', ' ')}" if w["reading_at"] else "no reading"
    if w["age_hours"] is not None and w["age_hours"] > LEDGER_STALE_HOURS:
        note += f"; newest input {int(w['age_hours'])} h old"
    return f"{w['week']} (current, {note})"


def _cells(w):
    red = lambda key: " red" if key in w["red"] else ""
    n = lambda v: NA if v is None else str(v)
    return [
        _week_label(w),
        f"{w['usage_all']:g}% / {w['usage_fable']:g}%" if w["usage_all"] is not None else NONE,
        f"{w['pace']:.0f}%" if w["pace"] is not None else NONE,
        str(w["reqs"]),
        f"{w['usage_per_req']:.2f} pts (reading {w['reading_at'].replace('T', ' ')})" if w["usage_per_req"] is not None else NONE,
        _ratio(w["first_pass_ok"], w["first_pass_n"]),
        _ratio(w["escalated"], w["reviewed"]),
        f"{len(w['defects'])} ({', '.join(w['defects'])})" if w["defects"] else ("0" if w["merged"] else NONE),
        _ratio(w["flaky"], w["runs"]),
        f"{w['rounds'] / w['first_pass_n']:.1f}" if w["first_pass_n"] else NONE,
        f"{w['usage_all'] / w['merged']:.2f} pts" if w["usage_all"] is not None and w["merged"] else NONE,
        ", ".join(f"{c} {w['causes'].count(c)}" for c in sorted(set(w["causes"]))) if w["causes"]
        else ("0" if w["first_pass_n"] else NONE),
        n(w["open_rows"]), n(w["followups"]),
        NA if w["followups_per_pr"] is None else f"{w['followups_per_pr']:.1f}",
        n(w["promotions"]) + red("promotions") if w["promotions"] is not None else NA,
        NA if w["stale"] is None else str(len(w["stale"])),
        NA if w["lanes"] is None else
        ", ".join(f"{k} {v}" for k, v in sorted(w["lanes"].items())) + f" (cap about {LANE_CAP})",
        NONE if w["defects_per_pr"] is None else
        f"{w['defects_per_pr']:.2f} ({len(w['defects'])}/{w['merged']})" + red("defects_per_pr"),
    ]


def _previous(text):
    rows = {}
    for cells in _rows(text or "", "| Week starting |"):
        rows[cells[0].split()[0]] = cells
    return rows


def _ledger_stale(raw):
    """First line of METRICS.md when LEDGER.md's newest reading is over LEDGER_STALE_HOURS old (D-086)."""
    tz = dt.timezone(dt.timedelta(hours=raw.get("tz_hours", TZ_HOURS)))
    newest = max((r["at"] for r in raw["readings"]), default=None)
    if newest is None:
        return ["**LEDGER.md has no reading; take one (D-086).**", ""]
    if _when(raw["now"], tz) - _when(newest, tz) <= dt.timedelta(hours=LEDGER_STALE_HOURS):
        return []
    return [f"**LEDGER.md is stale: its newest reading, {newest.replace('T', ' ')} (local), is over "
            f"{LEDGER_STALE_HOURS} hours old; take a reading (D-086).**", ""]


def guard(weeks):
    """D-086 guard lines. Only the two latest full weeks are judged, so the guard clears once
    either of them is back at or under baseline; the current, partial week never counts."""
    full = [w for w in weeks if not w["current"]][-2:]
    if len(full) < 2 or (dt.date.fromisoformat(full[1]["week"]) - dt.date.fromisoformat(full[0]["week"])).days != 7:
        return ["", "D-086 guard: not judged (needs two consecutive full weeks)."]
    span = f"weeks starting {full[0]['week']} and {full[1]['week']}"
    tripped = [name for key, name in (("promotions", "promotions"), ("defects_per_pr", "`Defect:` lines per merged PR"))
               if all(key in w["red"] for w in full)]
    if not tripped:
        return ["", f"D-086 guard clear: the {span} are not both above baseline."]
    return ["", "D-086 guard tripped: items 2 to 4 are reverted by a new decision row (decisions/D-086.md)",
            f"(both of the {span} above baseline: {', '.join(tripped)})"]


def _repair_share(cells):
    """`Defect:` lines per reviewed merge, from a rendered row's defect and first-pass cells."""
    defects = re.match(r"\d+", cells[COLUMNS.index("Defects after merge")])
    judged = re.search(r"/(\d+)\)", cells[COLUMNS.index("First-pass L3 accept")])
    if not defects or not judged:
        return NONE
    d, n = int(defects.group()), int(judged.group(1))
    return f"{d / n:.2f} ({d}/{n})"


def _lead(rows, words):
    """D-152: the repair share leads, with the spec and process word counts beside it."""
    size = (f"SPEC.md {words['spec']:,} words; process docs {words['process']:,} words "
            "(both shrink-only on main, `tools/word_budget.py`)." if words else f"Word counts: {NA}.")
    return ["## Repair share (D-152)", "", "`Defect:` lines per reviewed merge, by week:", "",
            *[f"- {cells[0]}: {_repair_share(cells)}" for cells in rows], "", size, ""]


def render(weeks, raw, previous_md=None):
    old = _previous(previous_md)
    lines = [
        *_ledger_stale(raw),
        "# METRICS (generated by tools/metrics.py; do not edit)",
        "",
        "Inputs for the L4 meta loop (PLAN.md §2). Regenerated daily by `.github/workflows/metrics.yml`, "
        f"or on demand. Data as of {raw['now'][:16].replace('T', ' ')} UTC.",
        "",
    ]
    rows = []
    for w in weeks:
        cells = _cells(w)
        prev = old.get(w["week"])
        if prev and len(prev) < len(cells):
            prev = prev + [NONE] * (len(cells) - len(prev))  # recorded before later columns were appended
        if prev and len(prev) == len(cells):
            closed = not w["current"] and not _open_week(prev[0])
            cells = [o if (c in (NONE, NA) and o not in (NONE, NA)) or (closed and i in FROZEN) else c
                     for i, (c, o) in enumerate(zip(cells, prev))]
            # Before the 2026-10-23 guard change the frozen defect count carried the red mark.
            i = COLUMNS.index("Defects after merge")
            cells[i] = cells[i].removesuffix(" red")
        rows.append(cells)
    lines += _lead(rows, raw.get("words"))
    lines += ["## Weekly", "", "| " + " | ".join(COLUMNS) + " |", "|" + "---|" * len(COLUMNS)]
    lines += ["| " + " | ".join(cells) + " |" for cells in rows]
    base = baseline(raw)
    lines += ["", "## Baseline (D-086)", "",
              "Mean of the two 7-day windows before 2026-10-09 (2026-09-25 to 2026-10-09, UTC-4); defects per merged PR "
              "pools both windows. A week starting after 2026-10-09 is marked `red` when its promotions or its "
              "`Defect:` lines per merged PR exceed it.",
              "", "| Column | Baseline |", "|---|---|"]
    for key, name in (("open_rows", "Open BOARD rows"), ("followups", "Follow-up rows added"),
                      ("followups_per_pr", "Follow-ups per merged PR"), ("promotions", "Promotions later to release"),
                      ("defects", "Defects after merge"), ("stale", "Stale PRs (48 h)")):
        lines.append(f"| {name} | {NA if base[key] is None else format(base[key], 'g')} |")
    lines.append(f"| Defects per merged PR | "
                 f"{NA if base['defects_per_pr'] is None else format(base['defects_per_pr'], '.2f')} |")
    lines += guard(weeks)
    noise_all = [x for w in weeks for x in w["noise"]]
    blockers = [r for c, r in noise_all if c == "blocker"]
    lines += ["", "Blockers not fixed (review noise, `wrong`, `intentional` or `didn't-matter`): "
              + (_ratio(sum(r != "fixed" for r in blockers), len(blockers)) if blockers else NONE)
              + ", from `Finding <blocker|release|later>: <fixed|wrong|intentional|didn't-matter>` lines "
              "in reviews and builder replies."]
    unjudged = sorted(n for w in weeks for n in w["no_verdict"])
    lines += [
        "",
        "## Definitions",
        "",
        "- **Repair share**: `Defect:` lines (Defects after merge) over the merged PRs with an L3 verdict "
        "(the First-pass L3 accept denominator) that week; word counts as `tools/word_budget.py` counts them (D-152).",
        "- **Week**: a plan week, Sunday 06:00 to Sunday 06:00 Mark's local time (UTC-4 assumed).",
        "- **Usage**: the highest weekly-limit reading in LEDGER.md that week, all models / Fable only. "
        "Model usage is not metered per package; Mark's usage screen is the source (LEDGER B-6). "
        "Spend by model tier is approximated by this all-models / Fable-only split.",
        "- **On-pace mark**: the share of the week elapsed at that reading. Usage at the mark is on pace for ~100% at reset.",
        "- **Reqs newly covered**: growth of TRACE.md's covered count on main that week.",
        "- **Usage per req**: weekly-limit points per requirement ID covered at the time of the reading "
        "(TRACE.md's last snapshot at or before the reading, minus the count before the week); the reading's time is shown "
        "beside it. Stands in for tokens per merged requirement until tokens are metered.",
        "- **Current week label**: the time of the week's highest usage reading; past 36 hours it adds the age of the "
        "newest input (reading, TRACE.md or BOARD.md snapshot) relative to \"Data as of\".",
        "- **First-pass L3 accept**: PRs merged that week whose first review with a verdict "
        "(an L3 review stating `Verdict: accept|fix-list|reject`, or the verdict on its first line) was accept.",
        "- **Escalation rate**: packages ever `escalated` on BOARD.md or by a work-item issue's state label over packages that ever reached "
        "`in review`, `merged` or `escalated`, up to that week.",
        "- **Defects after merge**: `Defect: <package ID>` lines in the bodies of PRs merged that week "
        "(a fix to code already merged; see the PR template).",
        "- **Defects per merged PR**: those lines over all PRs merged that week; the D-086 guard's defect measure.",
        "- **CI flake rate**: commits that, within one workflow, had both a failed and a passed run or "
        "attempt, over commits with any finished run; counted in the week of the first run.",
        "- **L3 rounds per merged PR**: distinct reviewed heads with an L3 verdict (OPERATING §4; a verdict "
        "naming no head counts alone), averaged over the PRs merged that week that had one. 1.0 means every PR was accepted on its first review (COST-1: rework is the main cost).",
        "- **Usage per merged PR**: weekly-limit points per PR merged that week; the cost-per-package "
        "figure the operating model steers by (docs/OPERATING.md §6).",
        "- **L3 causes**: the `Cause:` lines of fix-list and reject L3 reviews on PRs merged that week, "
        "by code (spec-gap, brief-gap, defect, scope; docs/OPERATING.md §4). `none` is a non-accept "
        "verdict without a Cause line.",
        "- **Open BOARD rows**: rows queued, building, in review or escalated in the last BOARD.md of the week.",
        "- **Follow-up rows added**: rows first seen on BOARD.md that week whose ID ends `-f<N>`, `-r<N>` or `-l<N>`, "
        "or whose package text says `(release` and cites a review. **Per merged PR**: that count over PRs merged that week.",
        "- **Promotions later to release**: rows first seen that week whose text cites a LATER.md line (`LATER <ID>`).",
        "- **Stale PRs (48 h)**: open PRs, held drafts included (D-098), with no update for 48 hours at run time; "
        "counted for the current week only.",
        "- **Open PRs by lane**: open PRs per lane (a `lane:<name>` label, docs/LANES.md; no label is the peers) "
        "against a cap of about 10; current week only.",
        "- **red** / **n/a**: red marks a week above the D-086 baseline; `n/a` means the data to compute a column is "
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
        ledger = (root / "LEDGER.md").read_text()
        tz = dt.timezone(dt.timedelta(hours=TZ_HOURS))
        pulls, runs = collect_github(args.repo, os.environ.get("GITHUB_TOKEN"), _since(previous, tz))
        raw = {
            "now": args.now or dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "tz_hours": TZ_HOURS, "trace": trace, "board": board,
            "readings": ledger_readings(ledger), "phases": ledger_phases(ledger),
            "pulls": pulls, "runs": runs, "words": word_budget.tree_counts(root),
            "states": collect_states(args.repo, os.environ.get("GITHUB_TOKEN")),
        }
        if args.raw_out:
            pathlib.Path(args.raw_out).write_text(json.dumps(raw, indent=1, sort_keys=True))

    out.write_text(render(compute(raw), raw, previous))
    return 0


if __name__ == "__main__":
    sys.exit(main())
