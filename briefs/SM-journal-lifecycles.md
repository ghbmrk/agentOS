# SM-journal-lifecycles: New lifecycles are journal intent kinds; a guard fails any that keep their own store

Board section: State-machine audit follow-ups (2026-10-16). Source: `audits/2026-10-16-state-machines.md` R4 (sections 2.3, 2.8). Class: release (OP-11 invariant: no new durable lifecycle beside the journal). Tier: A (`broker/journal`, `broker/durable` are tier A; `python3 tools/risk_tier.py` prints A). Builder: strongest model. Usage estimate: 90k tokens, checkpoint at 75k.

**Why (facts).** Device actuation (SPEC 10B, DEV-*) is not built: there is no `actuate` verb (`broker/verb/verb.go:12-21`) and TRACE lists DEV-5 as uncovered. The CRED-11 hand-off verbs are not built either (`broker/browser/protocol.go:38-46` has no copy, paste or hand-off verb; TRACE lists CRED-11 uncovered). Building them is the cheapest moment to keep them off a private store; the audit found nine lifecycles that already did the opposite. Non-test code in 23 broker packages writes files through `durable.WriteFile`/`durable.Rename` today (`apnet change checker clock cmd/agentos-egress cmd/agentos-guest-bridge cmd/agentosd follow guest journal localsrv localui meter owner pubid pubsend question recall recovery update vault vm vm/gvisor`, counted at HEAD e57ac41c). `TestNoBareRename` (`broker/durable/norename_test.go:23`) already walks `broker/` for a rule of this shape, so the guard follows its pattern.

## Requirements (from SPEC.md)

- **OP-11** "The journal is the only durable source of truth for broker state. Every other broker store is one of three kinds: a **projection** ... a **content store** ... or an **external-session store** ... No component keeps its own durable lifecycle, receipts or recovery rule beside the journal."
- **DEV-5** "`actuate` is reversible, as `organize` is (ADP-2): an operation maps to it only if its adapter declares the inverse, the broker journals the prior state with each effect, and the target value lies inside bounds the owner confirmed at connection ... Effects are bounded (an owner-set daily count per device, default 50), counted in the digest, and undone by `UNDO <id>` (CH-16), which restores a device only if its state still matches what the agent set."
- **CRED-11** "Every hand-off is journaled with source, destination, size, and content hash. Items expire when the task ends."
- Package IDs: **SM-JL-1** a lifecycle declaration names its intent kind, inverse, prior-state field, bounds and daily cap, and an incomplete one is rejected. **SM-JL-2** the daily count is a pure function of journal records. **SM-JL-3** an undo plan is produced only while the device's current state still equals the journaled effect (DEV-5). **SM-JL-4** a package under `broker/` that persists files and is not listed in the store manifest fails CI. **SM-JL-5** a manifest entry that no longer matches code fails CI.

## Design rule (the part later briefs copy)

A domain lifecycle (device actuation, credential hand-off) is a set of **intent kinds** submitted to `journal.Engine`, never a store of its own. Mapping: the effect is an intent (`Account` = device or executor, `Action` = `actuate.<op>` or `handoff.<verb>`); the **inverse** is a second intent named in the first's declaration (UNDO submits it); the **prior state** and **bounds** ride in `Params` as non-secret scalars (the journal scrubs params, `journal/redact.go`, so the builder checks what survives scrubbing and puts any larger value in a content store named by hash, OP-11); the **daily count** is counted from records, not kept in a counter; state such as "stopped" is a record, rebuilt by replay as a projection (`broker/projection`). Nothing here writes a file.

## Scope of this package

Rule, guard, and registration hook only. The actuation build (adapters, `actuate` verb, DEV-1..DEV-10 wiring) and the CRED-11 verbs are follow-ups that must cite this rule.

1. `broker/journal/lifecycle.go` (new): `type Lifecycle` (kind prefix, inverse action or `Irreversible`, prior-state param key, bound param keys, default daily cap), `Register(Lifecycle) error` with a duplicate and an incomplete-declaration check, `(Lifecycle).Check(Intent) error` that callers run before `Submit`, `DailyCount(records []Record, account string, day time.Time) int`, and `UndoPlan(records []Record, effectID string, current map[string]any) (Intent, error)`. It reads records only; it does not edit `engine.go`, `validate` or the record types.
2. `broker/durable/stores.txt` (new manifest, one line per package directory: `<dir> <kind> [debt:<ref>]`, kind one of `projection`, `content`, `external-session`, `config`, `debt`) and `broker/durable/lifecycle_guard_test.go` (new): walks non-test, non-vendor, non-testdata Go files under `broker/`, finds calls to `durable.WriteFile` and `durable.Rename` with `go/parser`, and fails if the file's package directory is not in the manifest (SM-JL-4) or a manifest directory has no such call (SM-JL-5). The builder seeds the manifest from the 23 packages above, classing each by reading it; any that keeps a lifecycle beside the journal is `debt` with the audit section as its ref (for example `change debt:audit-2.5`, `owner debt:audit-2.2`). A line may be exempted in code with `lifecycle:exempt <reason>`, as `durable:exempt` is.
3. A short section in `broker/journal/doc.go` stating the rule.

## Acceptance tests

**Acceptance tests:** `broker/journal/lifecycle_test.go` (SM-JL-1 to SM-JL-3) and `broker/durable/lifecycle_guard_test.go` (SM-JL-4, SM-JL-5), as listed below.

- SM-JL-1: `broker/journal/lifecycle_test.go::TestRegisterRejectsIncompleteLifecycle` and `TestCheckRejectsIntentMissingPriorState` (catch: an actuation intent journaled without its prior state, which makes UNDO impossible).
- SM-JL-2: `TestDailyCountFromRecords` (replay across a midnight and a restart gives the same count; catch: a counter held in memory).
- SM-JL-3: `TestUndoPlanOnlyWhileStateMatches` (catch: restoring a device someone else has since changed).
- SM-JL-4: `broker/durable/lifecycle_guard_test.go::TestUnlistedPersistingPackageFails` (a temp tree with an unlisted package calling `durable.WriteFile` fails) and `TestBrokerPackagesAreListed` (the real tree passes).
- SM-JL-5: `TestStaleManifestEntryFails`.

## Scope (files)

`broker/journal/lifecycle.go`, `broker/journal/lifecycle_test.go`, `broker/journal/doc.go`, `broker/journal/ASSUMPTIONS.md`, `broker/durable/stores.txt`, `broker/durable/lifecycle_guard_test.go`, `broker/durable/ASSUMPTIONS.md`, `briefs/SM-journal-lifecycles.md`. **Guard files:** none (no new package; `broker/journal` and `broker/durable` are already classed).

**Scope overlap.** `broker/journal/engine.go` is not touched, so #1927 (validate guards for `cancel_requested`/`quality`) does not conflict; a new file in `broker/journal/` still counts as a touched package for the tier. No overlap with #1923, #1924. If the builder finds a hook cannot be built without editing `engine.go`, stop and escalate: that overlaps #1927.

## Follow-ups (not in this package)

The `actuate` verb and DEV adapters; the CRED-11 `copy`/`paste`/`hand-off` verbs and their journaled records; moving each `debt` entry off its own store (R3 and R6 cover owner/grants and change). Each is its own brief and must cite SM-JL-1..3.

## Done

CI green; SM-JL-1..5 covered by tests carrying `REQ: OP-11, DEV-5, CRED-11` and the SM-JL ID; the manifest has no unclassed package.
