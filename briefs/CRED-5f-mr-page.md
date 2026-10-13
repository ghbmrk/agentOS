# CRED-5f-mr-page: one name for the box's page in C2's locked line

Board section: Phase 0: harness and risk spikes. Source: UX lens on #566 (release, row #813). Tier B, one string and its tests; expect well under the checkpoint.

**Why.** `modelLocked` (broker/cmd/agentosd/capoff.go:52) ends "unlock it on the local page." Every other owner-facing line says "my Wi-Fi page" (broker/maintain, broker/loops), and SPEC names it so: "Open my Wi-Fi page" (CH, first-person rule) and "the Wi-Fi page" throughout. "The local page" is the developer's name for it (SPEC OWN-12 uses it as prose, not as owner text). The owner sees two names for one page.

**Requirements:** OP-9 (C2 line), CH-8 (the box speaks in the first person; owner lines name the Wi-Fi page).

**Change.**
- `modelLocked` becomes `Model: the vault is locked, so your agent cannot think or learn; unlock it on my Wi-Fi page.` Keep it inside `ownerWorded` (no apostrophes).
- Sweep the other owner-facing strings in `broker/cmd/agentosd` (`capoff.go` constants, `digest*.go` status lines) for "local page" and fix any found; code comments and log lines keep the developer name. `grep -n 'local page' broker/cmd/agentosd/*.go` finds them; on main only capoff.go:52 is an owner line (main.go:704 is a log line, leave it).
- Optional, same lines (LATER CRED-5f-mr-wording): `modelNoGrant` ends "a later box version adds this." Change it to use `fixUpdate` ("nothing to do; a later box version adds it") only if `TestModelNoGrantNamesAServedStep` and the wording test stay green without edits to their intent. If not trivial, leave it and say so in Findings.

**Tests first.**
1. In `capoff_test.go` add a table test over `capLineTexts()` (and the digest status constants it lists): no owner line contains "local page" (case-insensitive), and every line that tells the owner to act on a page says "my Wi-Fi page". Show it failing on main at `modelLocked`, then passing.
2. Existing `ownerWorded` checks (capoff_test.go:307, 457, 568) and the "granted, locked" steps (624, 632) stay green; update their expected string only through the constant.

**Acceptance.** `go test ./broker/cmd/agentosd/...` green; `python3 tools/trace.py` shows OP-9 still covered; marker `REQ: OP-9` in the new test.

**Out of scope.** CRED-5f-mr-key, -cache and -bound (LATER-HISTORY); any change to `modelLine` logic or the cache.

**Scope:** `broker/cmd/agentosd/capoff.go`, `broker/cmd/agentosd/capoff_test.go`, and `broker/cmd/agentosd/ASSUMPTIONS.md` only if a line there quotes the old string.

**Usage estimate:** 30k tokens. Builder model: Sonnet-class (tier B).
