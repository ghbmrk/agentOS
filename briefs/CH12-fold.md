# CH12-fold: the CH-12 fold, iterated to a fixed point, with a full code-point scan

Board section: Human-native texting (spec #2157, D-127). Work item: #2162.

**Goal.** CH-12 defines the fold the CH-19 and CH-21 checks run on, in UTS #39 skeleton order: NFKD and case folding; the confusables.txt prototype then NFD; NFKD and case folding again; marks dropped; Default_Ignorable_Code_Point dropped (one reading) or read as a space (the other); everything that is not a letter, a digit or printable ASCII read as a space; space runs collapsed. It must be idempotent and case-blind for every code point and every text, checked by a test that scans every code point. One pass is not idempotent (U+13B7 `Ꮇ` folds to `m`, which folds to `rn`, so `ᎷORE A7` and `MORE A7` differ after one pass), so the pass repeats until the text stops changing.

Build:
1. `broker/owner/gen_skelfold.go` (`//go:build ignore`, stdlib only): reads UnicodeData, CaseFolding, confusables and DerivedCoreProperties 15.0.0, checks their SHA-256, and writes `skelfold_tables.go` (per-code-point NFKD+casefold and prototype+NFD maps, the DICP ranges).
2. `broker/owner/skelfold.go`: `SkeletonFold(s, ignorableAsSpace)` and `SkeletonFolds(s)` (both readings), iterating the pass to a fixed point under a cap the scan shows is never reached. Stdlib only (ARC-2, DEP-1).

**Requirement IDs:** CH-12.

**Acceptance tests** (`broker/owner/skelfold_test.go`): `TestCH12FoldTablesMatchGoUnicode`, `TestCH12FoldEveryCodePoint` (both readings: fold(fold(x)), fold(upper(x)), fold(lower(x)), fold(title(x)) all equal fold(x), and the pass depth at most half the cap), `TestCH12FoldReviewCases` (the code points named on #2162), `TestCH12FoldMultiCharacter` (`ᎷORE A7`, `ᎩᎬᏚ A7`, `YES ⍶7`, `YES⠀A7`, `Y̲ES`, ZWJ in a code word, fullwidth, line breaks), `TestCH12FoldTextsIdempotentAndCaseBlind` (seeded random texts).

**Scope:** `broker/owner/gen_skelfold.go`, `broker/owner/skelfold.go`, `broker/owner/skelfold_tables.go`, `broker/owner/skelfold_test.go` (all new), `broker/owner/ASSUMPTIONS.md`, this brief. Calling the fold from the CH-19 and CH-21 checks (`broker/voice`, outside the G1 list) is a follow-up.

**Dependencies:** none. **Usage estimate:** small (one generator, one function, five tests).
