# DIG-1: The daily digest reads every `Digest()` source (CH-15, OP-9)

Board section: Phase 3 (row DIG-1); brief written 2026-10-09 by the coordinator after the owner-benefit review (point 3). It replaces the pointer to `briefs/OP9-status.md#split`, whose constraints it carries over (OP9-status l.57, 69, 135).

**Tier:** A (`broker/cmd`). Strongest model. About 90k tokens. If the adapter for consuming sources (DIG-1c) runs over, split it out as DIG-1b and ship DIG-1a/b/d first.

**Needs:** W5 and W5-Db (merged), OP9-status-a (merged), W5-Dc (#592). Check #592's state first. If it has not merged, build on its branch only with the coordinator's say-so; otherwise wait.

## Today (broker/cmd/agentosd at 9b4bf8a)

- The digest queue, collector, sender and transport exist:
  - `digestqueue.Source` has `Peek(ctx) (*Snapshot, error)`, which is non-consuming and returns nil when nothing is pending, and `Ack(ctx, Snapshot)`, which is durable and idempotent per generation and hash (`digestqueue/collector.go:20`).
  - `digestConfig.Sources` is a `map[string]digestqueue.Source` ("Sources are DIG-1's", `digest.go:88`), cloned into the collector in `openLocked` (:216) beside the day and status sources.
  - `MaxSources` is 16.
  - The transport is wired at `main.go:628` (`newDigestTransport`, which uses `SendReceipt`).
- **But nothing is fed in.** `main.go:576` calls `newDigestBox(digestConfig{Queue: queue, State: state})` with no Sources. The owner-facing sources exist only as `newDigestSources(capLines, lp, line)` (`capoff.go:335`): "capabilities" (`capLines.Digest`), "loops" (`lp.sched.Digest`, which fans out to every enabled `loops.Digester` including Loop 1 sleep and Loop 7 fuzz) and "second line". They are built at `main.go:855` only to log their count. They are `func() []string`, not `digestqueue.Source`, and they are built after the box.
- `Digest()` implementers not reachable from either list: `maintain.Loop3` (not constructed until W5b), `change.Pipeline.Digest` (consuming: "marks them listed"), `apply.Applier.Digest` (consuming: "once"). There are also take-style feeds: `question.Book.TakeDigest`, `events.Attention.TakeDigest`, `owner.Channel.TakeDigestNotes`.
- The test `capoff_test.go:493-505` pins the names of `newDigestSources`.

## Requirements (local IDs)

- **DIG-1a, level sources adapted.** A `digestqueue.Source` adapter over a level-style `func() []string`:
  - Peek returns a snapshot of the current lines, with a generation that changes only when the lines change, and nil when there are none.
  - Ack records the generation in the box's state store.
  - A level line repeats daily while it holds. **OP-9 lines are never deduplicated across days** (OP9-status risk row 1), with a test.
  - Lines with no owner step are paced per Mark's ruling with Q1 (LATER `OP9-status-a l5`). Until he rules, repeat them, which is the provisional choice; record it in ASSUMPTIONS.
- **DIG-1b, wired in production.** `main.go` builds the sources before `newDigestBox` (or registers them on the box before `open`) and passes them as `Sources`. The `main.go:855` log line goes away.
- **DIG-1c, consuming sources adapted.** For `change.Pipeline`, `apply.Applier` and the take-style feeds the coordinator lists as in scope (start with Pipeline and Applier; the others are `release` rows if they need owner wording), Peek must not consume. Either the source gains a peek-and-mark-on-ack form, or the adapter persists taken lines in the state store until Ack. A crash between take and Ack must not lose a line (test).
- **DIG-1d, the wiring test.** This is the point of the review finding: a structural test (go/ast or go/types over the module, in the style of `digestgate_test.go`) lists every type with a `Digest() []string` or `TakeDigest` method and fails unless each is either registered in the production source list or named on an explicit `unwired` list with a reason and a BOARD ID (for example `maintain.Loop3`, W5b). A new `Digest()` method cannot silently go nowhere again.
- **DIG-1e, the existing gates hold.** The W5-Dc structural gates (`digestgate_test.go`, and W5-Dc-r11's tightening if merged) pass unchanged. Source-side forget (W5-Dc-r5) is shared: implement the Ack and generation half here, and note in the PR what r5 still owns.

## Tests (written first)

- Each adapter: Peek is non-consuming (twice gives the same snapshot), Ack is idempotent, the generation changes on a line change, and nil when empty.
- The OP-9 line repeats on day 2 and day 3.
- A consuming source: crash after take and before Ack, reopen, and the line is still sent once.
- The production wiring: a test builds the box the way `main.go` does (factor the construction into one function both use) and asserts the collector's source names.
- DIG-1d's structural test, including a seeded failure (a test-only type with `Digest()` that is unlisted makes it fail).

## Scope

`broker/cmd/agentosd/` (`digest*.go`, `capoff.go`, `main.go`, new `digestsrc.go`, tests, ASSUMPTIONS.md), plus `broker/change`, `broker/apply` and `broker/loops` only for a non-consuming peek form if DIG-1c needs one (say so in the PR).

## Not in scope

Quiet hours and pacing (W5-Dc-r1), the digest time setting (W5-Dc-r2), owner wording of new lines beyond the existing wording check.
