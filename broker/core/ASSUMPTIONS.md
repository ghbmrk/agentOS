# Trusted core list: assumptions

Built for SIM-core (briefs/SIM.md, ARC-1). Each row is a reading of the brief, or a gap left for a later package, that a reviewer may want to change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| CO1 | The check is a Go test (`broker/core/core_test.go`), so CI's existing `go test ./...` in broker runs it; no workflow change. It type-checks each non-core package against the compiler's export data from `go list -export -compiled -deps`, using only the standard library (no x/tools in the module), so calls through embedded fields, method values and generic instantiations resolve to the core symbol they reach. | ARC-1 | Move to a vet analyzer if x/tools is vendored. |
| CO2 | "Write path" fails closed: every core function or method is one unless core.txt marks it `open` (the journal's Submit, reads, pure helpers, the sanctioned childproc, guesterr, verb and meter interfaces) or `allow`s one named caller with a reason. Types, constants and fields are not checked: reading a core type or building a value of it writes nothing. | ARC-1 | Add a line kind if a field write must be caught. |
| CO3 | `grants.Gate.Submit` counts as the journal's Submit: it is the same call behind the gate's refusal of broker-reserved intent IDs. | ARC-1 | Route callers to `journal.Engine.Submit` and drop the open line. |
| CO4 | Wiring packages (`daemon`, `cmd/agentosd`, `cmd/agentos-egress`, `cmd/agentos-a8scan`) build and connect the core, so they may call any write path and are rated A with the core. | ARC-1 | Shrink wiring as SIM-bound moves code out. |
| CO5 | **Known gap (later):** a write path reached through a non-core interface, or through a func value that wiring hands a non-core package, is not caught; only static references to core symbols are. Wiring is tier A, so each such hand-off is reviewed at A. | ARC-1 | A dynamic check, or a lint on func-valued Config fields. |
| CO6 | `tools/risk_tier.py` reads core.txt: a file under a core or wiring package is A, as is the list and its check (`broker/core`). The existing tier A package list stays; the core list adds to it and lowers nothing, so a non-core broker package outside that list (say `broker/attention`) stays B. | ARC-1 | Drop TIER_A_BROKER entries the core list covers, as a separate decision. |
