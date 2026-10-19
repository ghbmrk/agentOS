# RECALL-bare-codes: bare two-group codes with a letters-only group are scrubbed

Board section: Backlog refill (2026-10-05). Work item: #2232. Follow-up of PR #2228 (RECALL-canary-3) combined review. **Tier A** (`broker/recall`).

**Why.** Serves CRED-1. `codeLike` (`n == 2`) requires a digit in each group, so a bare GitHub-style hex recovery code with a letters-only group (`abcde-12345`, synthetic) is stored unchanged: 490 of 20,000 sampled hex `xxxxx-xxxxx` codes (2.45%) are kept, so a bare list of 16 codes leaks at least one about a third of the time. Keyed lists (`recovery codes:`) are covered.

**Requirements:**
- CRED-1-B1: for two dash-joined even groups of 5+, a code is accepted when the joined run mixes letters and digits and its letters lie in a hex or base32 alphabet.
- CRED-1-B2: a corpus test keeps hyphenated words, product numbers and postal numbers unchanged.

**Acceptance tests in `broker/recall/` (REQ: CRED-1-B1, CRED-1-B2):**
- `codes_bare_test.go::TestBareHexTwoGroupCodesAreScrubbed` (B1; synthetic codes only, including letters-only first group; mutant: restore the digit-per-group rule).
- `::TestHyphenatedWordsAndNumbersAreKept` (B2; corpus).
- `::TestBareCodeLeakRateIsZeroOnSampledHexCodes` (seeded sample of 20,000 synthetic hex codes, none kept).

**Out of scope.** Other code shapes; the keyed-list rule.

**Scope:** `broker/recall/codes.go`, tests, the R-row in `broker/recall/ASSUMPTIONS.md` that describes `codeLike`, this brief.

**Usage estimate:** 50k tokens. Do not run beside RECALL-longs (both edit `codes.go`, D-111).
