# VM-create-unreserve-order: pin the order of create's failure tail

Board section: Security and architecture review (2026-10-08). Issue #1712 (later; from #1575 Potency P3).

On a failed create, `Manager.create` (broker/vm/vm.go) returns the machine's admission (`release`) and then takes it out of the table (`unreserve`). No test fails if the two are swapped together with a raw `Admit.Release`. The window is a destroy and same-ID create that run between the two steps.

**Requirement:** RES-2. A same-ID successor made between the two steps of a failed create's tail keeps its admission and its table entry.

**Scope:** broker/vm/vm.go (a test seam between the two steps, no behaviour change), broker/vm/destroy_test.go.

**Acceptance tests:** RES-2: `TestRES2CreateFailureTailLeavesASameIDSuccessorAlone` (broker/vm/destroy_test.go). The seam destroys the failing machine and creates a successor under its ID; the test asserts the successor is listed, running and admitted. Swapping the two steps fails it.

**Gate:** tier A (broker/vm): L3 with an explicit threat check.
