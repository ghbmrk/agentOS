# Potency review probes — 2026-10-08

These small programs call the unchanged public APIs at main
7b753eb87f606ea2268ca536d429d47989dba196. They illustrate current behavior; they
are not implementation regressions, a full replay run, security qualification,
or a product-benefit benchmark.

From the repository root, with the Go toolchain named in broker/go.mod installed:

```sh
cd broker
GOTOOLCHAIN=local go run -mod=vendor ../reviews/potency/evidence/2026-10-08/attention_cohorts.go
GOTOOLCHAIN=local go run -mod=vendor ../reviews/potency/evidence/2026-10-08/replay_grader.go
```

Run the files separately: each is its own standalone main program. The programs
use in-memory synthetic fixtures. They do not access accounts, perform effects,
create grants, or call models/networks.

## Approval cohorts

The probe uses the default ADP-9 Threshold=10 and ReplyThreshold=20 (the latter
is unused). UserContent is false for the synthetic service. All observations
are verified, unedited send decisions on one synthetic account/action/recipient,
with different record IDs, either a monthly or quarterly fixed template,
six hours apart. Existing grants are not exercised.

Observed output:

```text
one-template: approvals=20 suggestions=1 counted_necessary=10 counted_avoidable=10
alternating-templates: approvals=40 suggestions=0 counted_necessary=40 counted_avoidable=0
one-outlier-then-100-identical: approvals=111 suggestions=0 counted_necessary=110 counted_avoidable=1
```

This demonstrates broad-class template suppression. It does not establish how
much owner time a cohort design saves. The single outlier counted avoidable is
a secondary classification issue: the current counter checks the prior earned
state before updating its template match. It is not an unauthorized effect.

## Replay grader

The probe calls change.DefaultGrader with representative effect-parameter JSON
as the expectation and a natural-language completion as the output. The source
trace in the review establishes that the production harvesting and replay paths
supply these different representations.

Observed output:

```text
outcome=accepted natural_reply=false exact_params_json=true
outcome=rejected natural_reply=true exact_params_json=false
```

No actual effect or replay guest is executed. This proves the grader's boundary
behavior, not end-to-end adoption, task correctness or a security bypass. An
implementation must add the assembled test described under P3.

## Other checks

Existing attention, route, change, recall and events package tests passed on
macOS using Go 1.26.8. The compile package failed to build because its VM overlay
dependencies use Linux-only system calls/types. No modifications or compatibility
stubs were used to make that package pass. Linux/image/floor-host and owner
workload qualification remain separate.
