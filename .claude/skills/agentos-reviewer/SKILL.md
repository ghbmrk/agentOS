---
name: agentos-reviewer
description: agentOS reviewer (L3 and lens) rules. Load before posting any review, verdict, re-review or arm/merge step on a PR.
---

# Reviewer (L3) rules

Also load the agentos-budget skill.

- Review in a fresh context, from the diff plus the cited requirement IDs. Don't rely on the builder's reasoning. Start once every required check is green on the head; mutgate may still run (OPERATING §7). Defer a review requested on a red or pending head without starting a session.
- **Verify, then hunt.** First read the builder's proof (tests per brief ID; corpus or differential tests for a parser or allowlist) and check each new `MUTANTS-EQUIVALENT` entry's reason. Re-run 2 or 3 mutants of the most security-relevant guards to check the proof is honest; don't sweep mutants mutgate reports killed. Spend the rest on what proofs can't show: concurrency and lock splits, invariants, replay and freshness, fail-open paths, spec, brief and decision-record fidelity, owner-facing truth.
- First line `Verdict: accept|fix-list|reject`; any verdict but accept adds `Cause: spec-gap|brief-gap|defect|scope`. Each point cites a requirement ID or a concrete defect and carries its class (OPERATING §4). Last line: the PR's next step and the reviews still owed.
- A point outside the cited IDs, or only on lines the diff doesn't change (`tools/difflines.py`), is a `release` work item, never a blocker. The release findings from one PR's reviews make one follow-up brief.
- Each blocker names its in-diff `path:line`, a `Repro:` the reviewer ran and one tag of `mutation|ci|claim|corpus|judgment`; with no repro, a fresh verifier checks it first (OPERATING §4 "Blocker evidence"). A lens's first review reads the whole PR; its re-review reads only the delta since its own last reviewed head and never repeats a posted finding. A missed in-diff finding outside the delta is `release` at least, or a blocker when it is an exploit path, a false pass or tier-A security; each blocker names its bug class and the builder fixes every instance. After three fix-list rounds (reviewed heads), the next review posts `Verdict: reject` with `Next: step back` and escalates (OPERATING §4).
- Review depth follows the risk tier `python3 tools/risk_tier.py --git origin/main HEAD` prints; the stages each tier needs are in OPERATING §3–4. Tier A needs the strongest model and an explicit threat check.
- **The verdict comment is the record** (#2172). Post each L3 and lens verdict as a PR comment in the shape OPERATING §4 "Verdict comment shape" shows: `Verdict:` (and `Cause:`) first, then `Record: PR #N · package <ID> · head <SHA>`, then one `<!-- record: <lens> -->` per lens (`l3`, `security`, `potency`, `ux`, `combined`); the required `premerge` check reads those lines. Answer each finding with a `Finding <class>: <outcome>` line in a PR conversation comment, not an inline thread reply (OPERATING §4). After an accept, push to the PR only to fix another review's finding: push without disarming (OPERATING §7), then get a delta review (one line for a comment-only or test-only delta, OPERATING §4 "One-line delta").
- Each PR gets one new L3 session, which spawns a fresh-context UX and Potency subagent on its model, blind to its reasoning; Security gets its own fresh session (D-246). No reviewer session stands; lens memory lives in DECISIONS.md and `reviews/<lens>/README.md`.
- A kind of finding seen on a second PR becomes a lint rule, test or CI check in that same follow-up PR, named on its Findings line and listed in the lens README (OPERATING §4, FIRST-PASS).
