# MIG-4-plan-pins-2: hold the Codex turn metadata blob to its shape

Work item #4580 (release findings of #4556's L3 and Security reviews; Scout's claim adds the main item). Tier A.

**Defect.** `x-codex-turn-metadata` inside `client_metadata` is checked for size only, so a guest can set provider-read flags such as `history_ingest_requested` for the owner's plan.

**Fix.** `Body.Meta` declares each key's value shape (`Value`: text, int, bool, off, object, map, JSON text). The Codex blob is a JSON text held to CLI 0.162.1's `CodexTurnMetadataPayload`; history ingest and analytics may only be false; a tool source may only be `harness`; the clerk sends its own encoding of the checked blob. Also: the 128-byte id cap is described as the clerk's own (L3 1), every declared key is tested at its cap and one byte over, in ASCII and in two-byte characters (L3 2, Security 1). The live measurement of the 16 KiB cap (L3 3) waits on the capture behind #809/#3133 and stays on ASSUMPTIONS MIG-4-plan-pins-1/2.

**Requirement IDs:** PLN-5, CLK-7.

**Scope:** `broker/clerk/plan/` (`body.go`, `plan.go`, `body_test.go`, `ASSUMPTIONS.md`), this brief.

**Guard files:** none (`broker/clerk/plan` is outside the trusted core).

**Acceptance tests:** all in `broker/clerk/plan/body_test.go`:
- `TestPlanClientMetadataHeldToItsKeys` (PLN-5, CLK-7): generated from the declaration, every declared key and limit: at cap taken; one byte over (ASCII and two-byte) refused; wrong kind, unknown key, other case, null, an off flag turned on, an undeclared word, and a JSON text that does not parse or trails data are refused with nothing sent.
- `TestPlanTurnMetadataIsSentAsChecked` (CLK-7): a repeated flag is sent once, as checked.
- `TestPlanTurnMetadataCapHoldsAfterEncoding` (CLK-7): a blob the clerk's encoding grows past its cap is refused.
- `TestPlanDeclarationRefusesAHostedBody` (CLK-7), extended: `New` refuses a malformed shape.
