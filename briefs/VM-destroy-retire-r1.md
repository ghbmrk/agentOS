# VM-destroy-retire r1: pin stampLegacy's write-error abort

Board section: Security and architecture review (2026-10-08). Source: work item #1659, from the #1575 delta review 3 (Potency P-R1, `reviews/potency/2026-10-14-pr1575.md`). Tier A (broker/vm).

**Why.** `stampLegacy` (`broker/vm/vm.go`) gives each snapshot recorded before Instance one at load, and aborts the load when the stamp's write fails. No test pins that abort: the mutant that ignores the write error survives. With it, a failed stamp lives only in memory; after the machine is destroyed, a same-lineage successor created and the broker reopened, the next load decides afresh and can stamp the snapshot with the successor's Instance, so the successor reaches its predecessor's snapshot (S-N1 under a write fault).

**Requirements:** RES-2, A2.

**Change.** Test only; vm.go is unchanged. Adopt the drafted probe `TestProbeD3StampCrashMidway` under a permanent name. The review scratch file is not in the repository, so the test is rewritten from its description: one of two stamp writes fails and Open fails; a reopen stamps both with the machine's Instance on disk; after a destroy, a same-lineage recreate and a reopen, the successor's rollback to either gets `ErrLineage`.

**Acceptance tests:** RES-2, A2: `broker/vm/stampfault_test.go::TestStampLegacyWriteFault` (new). It fails on the `stamp-write-error-ignored` mutant (`return err` → `_ = err` in stampLegacy) with "Open succeeded although a stamp write failed".

**Guard files:** none.

**Out of scope.** `broker/vm/forget.go` (#1660); any change to stampLegacy itself.

**Scope:** `broker/vm/stampfault_test.go` (new), `briefs/VM-destroy-retire-r1.md`.

**Usage estimate:** 60k tokens.
