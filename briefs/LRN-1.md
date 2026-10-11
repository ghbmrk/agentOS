# LRN-1: No adoption bonus without a measured gain

Board section: Owner-benefit review (2026-10-09).

**Goal.** The scheduler funds loops by measured return (LOOP-3). `value()` in `broker/loops/loop1.go` gave every adopted change its gain plus 0.25, so an adoption with zero gain over the baseline still read as value: loop 1 never went dry while it only changed the system without improving it (external review point 2, Mark 2026-10-10, project message cmsg_01R91wiieBzMSvPKFsAJVvuKX1u4keGveWMXoXRmodJt1h).

**Change.** No-regression adoption stays allowed (the change still takes effect); the 0.25 bonus applies only when the measured gain is positive. An adoption with no gain is worth 0, so `DryRuns` such runs park the loop. Waiting-on-owner (half the gain) and rejected (0) are unchanged.

**Requirement IDs.** LOOP-3. Assumption L14 in `broker/loops/ASSUMPTIONS.md` is updated.

**Scope.** `broker/loops/loop1.go` (`value`), `broker/loops/loop1_test.go`, `broker/loops/ASSUMPTIONS.md`, this brief, its BOARD row.

**Acceptance.** `TestAdoptionBonusNeedsMeasuredGain`: adopted at equal-to-baseline, at nothing passed either side, and with an explicit gain cancelled by an implicit loss is worth 0; adopted with an explicit or implicit-only gain gets gain + 0.25; waiting-on-owner and rejected rows unchanged. Revert mutant (Potency recurring kind): returning `gain + 0.25` for every adoption fails the zero-gain rows.

**Out of scope (sibling packages from the same review).** Independent task episodes in the evidence threshold, owner-verdict revisions invalidating adoptions, and requiring a declared useful improvement before adoption (review point 2); DEL-1; notification ordering; fuzz evidence.

**Usage estimate.** Small: under 60k tokens. Tier A (`broker/loops`).
