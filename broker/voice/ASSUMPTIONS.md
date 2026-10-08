# Voice lint: assumptions

Built for CH-21a (BOARD.md) against SPEC CH-21 and D-042. Covers `broker/voice`.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| V1 | **What counts as owner text.** Every Go string literal in a non-test file under `broker/` (vendor, testdata and this package excluded) is checked, not only literals that reach the owner channel. Comments are not checked. A literal can be exempt only by its top-level directory being in `pending`; there is no per-string escape, so a legitimate third-person use (third-party texts use the box's name, not these phrases) would need a new rule here. | CH-21 | Add a per-string marker if a real third-person literal turns up. |
| V2 | **The phrase set.** "the box", "this box", "the agent" and "agent:" (case-insensitive, word-bounded). It misses other third-person forms ("it", "AgentOS"), which a regex cannot judge; the sweep and the L3 review cover those. | CH-21 | Extend `thirdPerson` and its self-check test. |
| V3 | **The pending list only shrinks.** `pending` names the directories not yet swept and the part that sweeps them (CH-21c, CH-21d). A stale entry (directory already clean) fails the test, so each part must delete its entries. | OPERATING §4 (a finding becomes a check) | — |
| V4 | **Agent-facing literals follow the same rule.** A reason shown to the agent machine (a `guesterr` text) also avoids "the agent"; it is reworded to say what is refused, not who. | CH-21 | — |
| V5 | **Wording of the swept texts.** "I"/"my" replaces the box; "box page" becomes "my Wi-Fi page" (the CH-12s name). The Owner Card and the other tier-A packages are CH-21c/CH-21d. | CH-21, CH-12s | — |
