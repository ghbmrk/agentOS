# CHG-adoption-journal-sec: no stray proposal bytes after a forget, and a saved proposal is bound to its intent

Board row: issue #1965. Source: the two release findings of PR #1964's Security review. Class: release. Tier: A (`broker/change/`). Builder: strongest model. Usage estimate: 80k tokens, checkpoint at 60k.

**Why (facts, verified at main 9b26cb9).**

1. *Stray bytes (CAP-3, C23).* `dropLocked` deletes `proposal/<id>` and only logs a failed delete. If that delete fails, or the process stops before it runs, Content keeps the candidate tree, which may hold what was learned from goal G. Replay restores only proposals whose adopt intent is still Pending or Authorized, `forgetAdoptionsLocked` walks only `p.props`, and `reforgetLocked` reaches only restored proposals. So no later forget of G removes those bytes.
2. *Unbound candidate (CHG-2).* After a restart, `loadProposalLocked` trusts whatever `proposal/<id>` holds. If Content is rewritten between submit and approve, the owner's approval of intent `chg:<id>:adopt` adopts a tree the evaluation never saw.

## Requirement (from SPEC.md)

- **CAP-3** Deletion requests propagate: content stores named only by erased records are deleted, so no store has its own forget path. With **C23** (ForgetGoal removes what was learned from the goal, candidate bytes included).
- **CHG-2** Changing suites, graders, or adoption policy is an owner-approved intent and cannot be validated by the change itself.

Package IDs:

- **AJS-1** After an adopt intent settles (adopted, denied or failed), no `proposal/<id>` bytes outlive it past the next start or the next `ForgetGoal`. This holds even when the delete failed at settle, and whether or not the process restarted in between.
- **AJS-2** A proposal read back from Content is used only when it carries a keyed MAC, under the pipeline's secret key, over its own id and its exact bytes. A rewritten, misfiled, or unauthenticated blob leaves its intent with nothing to adopt: Check refuses, and Active is unchanged.
- **AJS-3** Check refuses an adopt intent whose `to`/`from` params are missing, or are unredacted hashes that differ from the candidate's tree hash or base.

## Acceptance tests

**Acceptance tests:** AJS-1: `TestForgetRemovesStrayProposal`, `TestForgetAfterRestartRemovesStrayProposal`, `TestReplayRemovesSettledProposal`, `TestForgetRemovesUnsealedWaitingProposal`; AJS-2: `TestRewrittenProposalIsRefused`, `TestUnauthenticatedProposalIsRefused`, `TestMisfiledProposalIsRefused`, `TestAuthenticProposalLoads`; AJS-3: `TestAdoptParamsBindCandidate`.

All are in the new `broker/change/adoption_journal_sec_test.go`. Each test carries `REQ: CAP-3, C23, CHG-2` and its ID.

- **AJS-1.** Content's Delete fails, and a goal-learned proposal waiting for the owner is denied. Three cases follow:
  - Heal the delete and forget the goal: no Content key holds the goal's bytes.
  - Restart with the delete still failing, heal it, then forget: no Content key holds the goal's bytes.
  - Heal the delete and restart without a forget: the bytes are gone.
- **AJS-2.** A proposal waits for the owner and the pipeline restarts. Three blobs are tried:
  - a blob whose `next` is rewritten under the old MAC;
  - a plain blob without a MAC, as an attacker or an earlier build writes it;
  - another proposal's authentic blob filed under this id.

  Each time the owner approves, the adopt is refused, and Active is unchanged.
- **AJS-3.** Check is called directly with the following params, and refuses each:
  - `to` set to a different hash;
  - `from` set to a different hash;
  - `to` missing.

  Redacted params pass to the other rules.

## Design (recommendation)

**AJS-2: deviation from the issue's suggested fix.** The issue suggests that Check compare `params.to`/`params.from` with the candidate. That binding does not hold in production:
- The daemon's journal scrubber is `redactAll` (`broker/daemon/daemon.go:260`), so Check sees `Redacted` in every param.
- `pipeline.go:190` says decisions are read from the intent ID and grant reference, never from params.

The binding therefore lives in the blob:
- `putProposalLocked` writes `{"body": <savedProposal JSON>, "mac": hex(HMAC-SHA256(k, id ‖ 0 ‖ body))}`. The key `k` is derived from the pipeline's secret split key (`p.key`, saved in the state, not in Content) with a separate label.
- `loadProposalLocked` returns nil unless the MAC verifies. An attacker who can rewrite Content but not the state cannot forge a blob, and a blob copied to another id fails.
- A blob from an earlier build has no MAC and fails closed. The owner proposes again, as after any lost proposal (ASSUMPTIONS).

AJS-3 is the issue's check, kept as defence in depth. It applies where params are not redacted (tests, and any future scrubber that keeps hashes). A missing param fails closed.

**AJS-1.**
- `replayLocked` deletes `proposal/<id>` for every adopt intent that is no longer Pending or Authorized. This is idempotent: Delete of a missing key is nil.
- `dropLocked` and replay add each id whose delete failed to `p.stray`.
- `forgetGoal` retries those deletes before it returns, including when the goal changed nothing. A failure stays stray and is logged.

## Scope

`broker/change/adoption_journal.go`, `broker/change/effect.go`, `broker/change/suite.go`, `broker/change/pipeline.go`, `broker/change/adoption_journal_sec_test.go` (new), `broker/change/ASSUMPTIONS.md`, `briefs/CHG-adoption-journal-sec.md`. **Guard files:** none.

## Out of scope

Follow-ups #1995 and #1996 of PR #1990. Garbage-collecting orphan adoption bodies (C37). An attacker who can write the state file as well as Content (the key lives there).

## Done

CI green; AJS-1..3 covered by passing tests carrying `REQ: CAP-3, C23, CHG-2` and their ID.
