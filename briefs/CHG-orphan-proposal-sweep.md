# CHG-orphan-proposal-sweep: a proposal blob with no adopt intent is deleted at start (CAP-3, C23)

Board row: issue #1999. Source: release finding from the Security (point 3) and L3 reviews of PR #1998. Class: release. Tier: A (`broker/change/`). Rows #2012, #2000, #2013 are separate; not built here. Builder: strongest model. Usage estimate: 60k tokens, checkpoint at 45k.

**Why (facts, verified at main f96c6dc).** `Propose` mints `c<Seq>`, saves the state, then `putProposalLocked` writes `proposal/<id>` before `chg:<id>:adopt` is submitted. A stop between the put and the submit leaves a blob no intent names. Replay only deletes blobs of intents it sees, and `ForgetGoal` only reaches `props` and `stray`, so that goal's candidate bytes stay in Content after the goal is forgotten. `DirContent` names files by the hash of their key, so Content cannot list keys to find them.

## Requirement (from SPEC.md)

- **CAP-3** / **C23**: forgetting a goal leaves none of its learned bytes in storage.
- **OP-11** "No component keeps its own durable lifecycle, receipts or recovery rule beside the journal."

Package IDs:
- **OPS-1** At start, every proposal ID the pipeline minted that no waiting intent holds has its blob deleted; a waiting proposal is kept and still settles.
- **OPS-2** A sweep delete that fails is retried by the next `ForgetGoal` (via `stray`) and by the next start.
- **OPS-3** Each minted ID is swept once across starts (a saved watermark); a state saved before the watermark existed is swept from `c1`.

**Acceptance tests** (`broker/change/orphan_proposal_test.go`): OPS-1: `TestOrphanProposalIsSweptAtStart`, `TestOrphanSweepKeepsWaitingProposal`. OPS-2: `TestOrphanSweepFailureIsRetried`. OPS-3: `TestOrphanSweepCoversEachIDOnce`.

## Design

A saved watermark `state.Swept`. At the end of replay, `sweepOrphansLocked` deletes `proposal/c<n>` for each n in (Swept, Seq] that `props` does not hold, then saves `Swept`. A failed delete goes to `stray` and holds the mark below it. No change to the Content interface.

## Scope

`broker/change/adoption_journal.go`, `broker/change/pipeline.go`, `broker/change/orphan_proposal_test.go` (new), `broker/change/ASSUMPTIONS.md`, `briefs/CHG-orphan-proposal-sweep.md`. **Guard files:** none.

## Out of scope

Rows #2012, #2000, #2013. A key listing on Content.

## Done

CI green; OPS-1..3 covered by passing tests; tier A reviews accepted.
