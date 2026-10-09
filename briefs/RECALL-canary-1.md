# RECALL-canary-1: a digit-free recovery code stored as a fact object

Board section: Phase 3: compounding.

**Requirement IDs:** CRED-1 (no recovery codes in storage or the recall index), CAP-3 (the recall index).

**Defect.** On #617's CI (head ebd1beeb, no change to `broker/recall`), `TestCredentialsNeverStored` failed with `round 17: canaries stored: [recovery_code]`. Recaptured locally by looping the full ingest path against a directory store: `JMNOX-CPMGJ-JYTLJ-OOYJG-PXOYY-JDNTG` (synthetic). In the mail text it sits after `recovery code:` and `secretKV` removes it. As the fact object `{"account","recovery",…}` it is scrubbed alone: `groupedCode` removed only codes mixing letters and digits, and `randomLooking` needs entropy ≥ 3.5 for a digit-free token; this one has 3.48. About 1 in 1.5 million random 6×5 base32 codes has no digit and entropy under 3.5, which is why 200k-sample probes saw none. Introduced by P3-3 (`4ba91d5a`).

**Scope:** `broker/recall` (scrubber, its tests, `ASSUMPTIONS.md`), BOARD.md, this brief.

**Build.**
1. The canary generator is seeded (`RECALL_CANARY_SEED` replays a run) and logs its seed on failure; `TestCredentialsNeverStored` keeps minting random canaries.
2. A deterministic regression test with the captured value as a fact object and in bare text, on disk and through `Get`.
3. A property test over grouped codes: 3–8 groups of one length 4–8, alphabets from full base32 to a few repeated letters, letters only, digits only. Plus a guard that hyphenated words and dates are kept.
4. Fix: a grouped code is removed when it mixes letters and digits or its groups all have one length. Mutants of the length check must fail a test.

**Usage estimate:** 120k tokens (tier A, the session's model).

## RECALL-canary-2

Release, tier A, from RECALL-canary-1's root cause. Two neighbouring gaps, not widened into canary-1:
- `randomLooking` keeps a random letters-only token with no grouping and no key beside it when it is under 20 characters, or 20–24 with entropy under 3.5: measured, 16% of random 20-letter uppercase tokens and 3% of 24-letter ones. Context-free paths (fact objects, event summaries) reach it. Decide a length-aware floor (expected entropy of a random string of that length) against over-scrubbing words, with a corpus test.
- A fact whose predicate names credential material (`password`, `recovery`, `api_key`, `seed`) is scrubbed on its object alone, so the predicate's context is lost. Remove the object when the predicate names a credential, with a test per predicate.
