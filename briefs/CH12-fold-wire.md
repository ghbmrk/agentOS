# CH12-fold-wire: run the CH-19 and CH-21 checks on the CH-12 skeleton folds

Board section: Human-native texting (spec #2157, D-127). Work item: #2181 (release findings from the reviews of #2180).

**Goal.** CH12-fold (#2162, #2180) built `owner.SkeletonFolds`, but no check calls it: `voice.WouldHold` (CH-21) and `owner.SecretShaped` (CH-19) still run on the raw text and the older small `fold`, so `ᎷORE A7` and `YES⠀A7` are not held. Wire the folds into both checks and close the two gaps the #2180 reviews found in the fold itself:
- **Marks that survive.** Case folding runs before the mark drop, so 17 combining marks fold to letters (U+0345 folds to ι, so `YͅES A7` folds to `yies a7`). Also check the text with every combining mark dropped first.
- **Capital homoglyphs.** Case folding runs before the prototype, so a capital loses its shape first: 380 of the confusables pairs fold apart (`ΥΕЅ Α7` folds to `uꞓs a7`, `ΝΟ Α7` to `vo a7`). Also check a fold whose pass runs the prototype before case folding.
- **Input cap.** A fold can grow its text about tenfold. Fold a long text in bounded, overlapping windows.

Build:
1. `broker/owner/skelfold.go`: `CheckFolds(s)`, every fold the checks run on besides the raw text (both readings × marks kept or dropped first × prototype after or before case folding, per window), and `FoldPattern(lit)`, a regular expression matching any fold of a literal in any case. `SkeletonFold` and `SkeletonFolds` are unchanged.
2. `broker/voice/voice.go`: `WouldHold` also holds when the vocabulary, the reply grammar or the footer, each built with `FoldPattern`, matches any of `CheckFolds`.
3. `broker/owner/disclose.go`: `SecretShaped` also runs its code-word check on each of `CheckFolds`, with the code words built with `FoldPattern` and a code needing an ASCII digit in the folded token.

**Requirement IDs:** CH-12, CH-19, CH-21.

**Acceptance tests:** `broker/owner/checkfolds_test.go`: `TestCH12CheckFoldsMarksAndCapitals`, `TestCH12CapitalHomoglyphsCaught` (the 380 pairs), `TestCH12MixedHomoglyphWordsCaught`, `TestCH12CheckFoldsWindowed`; `broker/owner/disclose_fold_test.go`: `TestCH19SecretShapedOnTheFolds`, `TestCH19FoldsKeepOrdinaryText`; `broker/voice/fold_test.go`: `TestCH21HoldsOnTheFolds`, `TestCH21FoldsKeepOrdinaryText`.

**Scope:** `broker/owner/skelfold.go`, `broker/owner/disclose.go`, `broker/owner/checkfolds_test.go`, `broker/owner/disclose_fold_test.go`, `broker/owner/ASSUMPTIONS.md`, `broker/voice/voice.go`, `broker/voice/fold_test.go`, `broker/voice/ASSUMPTIONS.md`, this brief. SPEC CH-12 states only the two readings; stating the marks-first and prototype-first folds needs a one-line L1 spec-diff, raised as a finding, not made here.

**Dependencies:** CH12-fold (merged). CH21-no-prefix (#2189) waits on this one. **Usage estimate:** small (two functions, two call sites, three test files).
