# W3-forget-reach-r5: test the `OnTakenBack` wiring through `NewService` (mutants W1, W2)

Board row: W3-forget-reach-r5. Source: Lens R4 on #569. Class: release. Tier: A. Builder: strongest model. Estimate: 45k tokens, checkpoint 35k.

**Why (facts, verified at main 8676ac9).** `broker/recalltool/service.go:118` copies `cfg.OnTakenBack` into `Reach`, and `broker/cmd/agentosd/main.go:897` sets `recallCfg.OnTakenBack`. The hook is tested only on a hand-built `Reach` (`takeback_test.go:543`, `:600`), never through `NewService`, so dropping the field copy (W1) or the main.go assignment (W2) survives.

**Requirement:** RCH-3 / CAP-3. Package ID **W3-forget-reach-r5-1**: a `ServiceConfig.OnTakenBack` set by the caller fires from a `Retry` pass of a service built with `NewService`, and agentosd builds its `ServiceConfig` through one helper the test also uses.

**Acceptance tests:**
- W3-forget-reach-r5-1: `broker/recalltool/service_test.go::TestServiceRetryReportsATakeBackToOnTakenBack` (new or existing file): build with `NewService`, owe a take-back, run `Retry`, assert the hook fires once and `TakenBack` is not sent. Mutant W1: drop the `OnTakenBack: cfg.OnTakenBack` copy.
- W3-forget-reach-r5-2: `broker/cmd/agentosd/forget_owed_test.go::TestAgentosdRecallConfigWiresOnTakenBack`: the helper agentosd's `main.go` uses to set `OnTakenBack` is called by the test; fails if main.go stops using it (W2).

**Scope:** `broker/recalltool/service.go` (helper only if needed), `broker/recalltool/service_test.go`, `broker/cmd/agentosd/main.go` (extract the one-line assignment into a helper), `broker/cmd/agentosd/forget_owed_test.go`, this brief.
**Dependencies:** none; order after r1 and r3 in the same session (shared test file).
**Done:** CI green; both mutants fail a test.
