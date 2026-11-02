# MIG-4-plan-pins: pin the Codex body to its CLI, and client_metadata to its keys

Work items #2115 and #2117 (raised against `broker/egress`, retargeted to `broker/clerk/plan`, which replaced it). Tier A.

**#2115.** (1) The undeclared-namespace case of the body check must be pinned by a test. In `clerk/plan` it already is: `TestPlanModelBodyHeldToDeclaredShape` "undeclared namespace" sends an undeclared namespace with an empty `tools` list, the one shape that reaches `!b.namespace(name)`, and fails when that check is removed (checked by hand). (2) The Codex body (keys, tools) is measured on CLI 0.162.1, pinned as `CODEX_VERSION` in `guest/codex/build-rootfs.sh`, and nothing ties the two. A test now requires the declaration's `Version` to be `codex-<CODEX_VERSION>-<n>`, so a CLI bump fails until the same change requalifies the declaration.

**#2117.** `client_metadata` was any object of strings. `Body.Meta` now declares each key the CLI sets with a byte cap on its value; any other key, a longer value or a non-string is refused (`plan-body meta`) before anything is sent. `New` refuses a body that declares `client_metadata` without keys, keys without `client_metadata`, or a key with no cap. The Codex keys are read from the CLI 0.162.1 source (codex-rs `core/src/responses_metadata.rs`, `client_metadata`).

**Requirement IDs:** PLN-5, CLK-7.

**Scope:** `broker/clerk/plan/` (`body.go`, `plan.go`, `body_test.go`, `ASSUMPTIONS.md`), this brief.

**Guard files:** none (`broker/clerk/plan` is outside the trusted core).

**Acceptance tests:** all in `broker/clerk/plan/body_test.go`:
- `TestPlanClientMetadataHeldToItsKeys` (PLN-5, CLK-7): every declared key at its cap passes; an unknown key, a key in another case, a value one byte over its cap, or an object value is refused with nothing sent.
- `TestCodexBodyIsMeasuredOnThePinnedCLI` (PLN-5): the Codex declaration's `Version` names the pinned `CODEX_VERSION`.
- `TestPlanDeclarationRefusesAHostedBody` (CLK-7), extended: `New` refuses metadata keys without `client_metadata`, the reverse, and a key with no cap or no name.
