# CHG-adoption-body-trust: replay takes no lifecycle from an adoption body (OP-11, C23)

Board row: issue #2012. Source: release finding on CHG-legacy-revert-journal (#1995). Class: release. Tier: A (`broker/change/`). Builder: strongest model. Usage estimate: 60k tokens, checkpoint at 50k.

**Why (facts, verified at main 19b69cc).** Adoption bodies live in Content under `adoption/<id>`, and unlike proposals (AJS-2) they carry no seal. On every start, replay (`replayLocked`) reads two lifecycles from the body: a top-level `reverted` (the #1990 migration) and the `legacy` lifecycle that `migrateLocked` wrote for a pre-journal state. Anyone who can write Content but not the state file can put `"legacy":{"reverted":"forgotten"}` (or a top-level `"reverted":"forgotten"`) on an active adoption's body. At the next start, replay journals a revert that never happened. A later `ForgetGoal` then skips the adoption as already reverted, so the goal's bytes stay active. Any forged `legacy` field also changes the adoption's lifecycle (for example `"reverted":"dropped"`, `"staged":true`).

Sealing the bodies alone does not fix this: an unsealed body would read as a pre-seal one. The fix needs a trusted mark in the state that says the bodies were already migrated.

## Requirement (from SPEC.md)

- **C23**: forgetting a goal removes the bytes it brought.
- **CAP-3**: delete means gone.
- **OP-11** "No component keeps its own durable lifecycle, receipts or recovery rule beside the journal."
- **SM-AD-2** (audit): replay reads none of the lifecycle from the body.

Package IDs:
- **ABT-1** Once a state carries the mark, a body's top-level lifecycle fields and its `legacy` are ignored at `Attach`. A forged forget, settings or other revert, or a forged legacy lifecycle, on an active adoption journals nothing and changes nothing. A later `ForgetGoal` removes the goal's bytes and journals one forget revert. The forged fields are put away at that start.
- **ABT-2** The first start that finds the mark unset (the first start of this build on a state an earlier build saved) still trusts the bodies once, as before. It owes the forget and settings reverts they hold (FRJ-3, LRJ-1), moves each legacy lifecycle into the state, and sets the mark. From then on the legacy lifecycle comes from the state. A pre-journal state's migration (`migrateLocked`) puts the lifecycle and the mark in the state directly.
- **ABT-3** That first start saves the debt, the legacy lifecycles and the mark before any body is put again without its lifecycle. A failed save leaves the bodies as they were and the mark unset, so the next start migrates again.

**Acceptance tests**:
- `broker/change/adoption_body_trust_test.go`:
  - ABT-1: `TestForgedBodyLifecycleIsIgnored`
  - ABT-2: `TestEarlierBuildLegacyMovesToTheState`, `TestPreJournalLegacyIsInTheState`
  - ABT-3: `TestBodyTrustMarkSavedBeforeBodiesStrip`
- The LRJ and FRJ tests that forge a body after the start now first turn the saved state back into an earlier build's state (`e.asEarlierBuild()`).

## Design

Two fields go on `state` (pipeline.go), next to `Swept`: `Legacy map[string]*lifecycle` and `LegacyInState bool`.

In replay, when the mark is unset:
- Read the bodies as now.
- Copy each loaded `legacy`, with any owed revert cleared, into `p.st.Legacy`.
- Set the mark, and save. Bodies are put first in each save, but each is unchanged against `lastBody`, so this save writes only the state.
- Then put every body that held a lifecycle again without it, and save a second time.

When the mark is set:
- Replay ignores the body's lifecycle and takes the legacy lifecycle from `p.st.Legacy`.
- A body that holds lifecycle fields anyway is put again without them.

`encodeBodyLocked` writes no `legacy`. The pipeline's `legacy` map is replaced by `p.st.Legacy`, so `reloadLocked`, which replaces `p.st` from disk, keeps it.

**Assumptions.** These go here and not in `broker/change/ASSUMPTIONS.md`, because #2087 is changing that file (D-111).
- An attacker can write Content but not the state file. Anyone who can write the state already controls the adoptions.
- A body forged before the first start of this build is trusted once, as every earlier build trusted it. This build cannot tell that body from a real earlier-build body.
- A state file that is lost or deleted also loses the legacy lifecycles and the mark. That start trusts the bodies once more. Losing the state already loses the active tree, so this adds no new kind of loss.

## Scope

- `broker/change/adoption_journal.go`
- `broker/change/pipeline.go`: only the two `state` fields and the removal of the `legacy` field and its initialisation. #2087 also changes this file, so the build starts only after #2087 merges (D-111).
- `broker/change/adoption_body_trust_test.go` (new)
- `broker/change/legacy_revert_journal_test.go`
- `broker/change/forget_revert_journal_test.go`
- `briefs/CHG-adoption-body-trust.md`

**Guard files:** none.

## Out of scope

- Sealing adoption bodies. The mark already makes body lifecycle untrusted, so a seal would add nothing for this finding.
- A deleted or unreadable body. That already breaks replay, so it is a denial of service and not a false pass.
- `broker/change/ASSUMPTIONS.md` and #2049's files (D-111).

## Done

CI green, and ABT-1..3 covered by tests that carry `REQ: CAP-3, OP-11, SM-AD-2` and their ID (C23 named in the test).
