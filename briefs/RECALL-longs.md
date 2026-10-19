# RECALL-longs: a credential key spelled with long s or Kelvin sign is scrubbed

Board section: Mark's review findings. Work item: #2357. Found on main c1a37df. **Tier A** (`broker/recall`, credential package). A security finding on a tier-A path, so never `later` (OPERATING §2).

**Why.** Serves CRED-1 and Invariant C. `Scrub("ſecret: hunter2")`, `Scrub("ſession=abc123")`, `Scrub("paſſ: hunter2")` and `ScrubFact(Fact{"me","ſecret","hunter2"})` keep the value: `(?i)` makes `s` match U+017F, but `\b` is ASCII-only, `fold` does not map ſ to `s`, and `credWords` drops non-ASCII runes. Failure path: a converter or crafted note writes `ſecret: <password>`; it renders as "secret" and the password lands in the recall index and storage. The Kelvin sign U+212A (`k`) is the only other rune whose fold orbit holds an ASCII letter; the same fix covers it.

**Requirements:**
- CRED-1-L1: `fold` (`broker/recall/codes.go`) maps U+017F to `s` and U+212A to `k`, so the folded pass sees ASCII keys, `\b` holds and `credWords(fold(...))` sees `secret`.
- CRED-1-L2: every `secretKV` key and `credPredicate` word, with ſ/K substitutions at its first and last letter, at the start of the text and after a space, has its value or object removed.
- CRED-1-L3: `codeKey` and `codeKeyTail` (`backup codeſ:`) get the same check.

**Acceptance tests in `broker/recall/` (REQ: CRED-1-L1..L3):**
- `scrub_longs_test.go::TestLongSAndKelvinKeysAreScrubbed` (L1, L2; table crosses every key and predicate word; mutant: drop the U+017F mapping, drop the U+212A mapping).
- `::TestLongSCodeKeysAreScrubbed` (L3).
- `::TestAsciiKeysStillScrubbed` and a benign-text check that ordinary prose with ſ is not over-scrubbed beyond the value.

**Out of scope.** Other Unicode confusables (a new row if the builder finds one).

**Scope:** `broker/recall/codes.go` (`fold`/`foldRune`), `scrub.go` if needed, tests, row R12 of `broker/recall/ASSUMPTIONS.md`, this brief.

**Usage estimate:** 50k tokens.
