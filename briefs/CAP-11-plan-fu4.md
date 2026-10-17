# CAP-11-plan-fu4: per-declaration credential formats scrubbed from a provider run's result

Board row: issue #1879. Source: PR #1864 delta review R4 (Security #7). Class: release. Tier: A (`broker/provagent`, `broker/vault`). Builder: strongest model. Usage estimate: 60k tokens, checkpoint at 45k.

**Why (verified at main).** `Runner.Run` withholds a result when `Scan` reports a credential (`broker/provagent/run.go:336-342`); the default `LooksLikeCredential` knows one fixed set of shapes. The vault redactor (`broker/vault/redact.go`, `redactValues`) matches stored values and, for a plan login, each string in its token set, so it catches the login the vault holds but not a fresh token the provider mints during a run (a refreshed access token in another format). A declaration states its endpoints and placeholder, but not what its credentials look like. Failure path: a new provider's token format the default scan misses is echoed by the CLI into the result file and reaches the guest.

## Requirements

- **CRED-7** (SPEC.md) credential-shaped content is redacted from anything leaving the broker; ARC-2 keeps `provagent` free of a `vault` import (provagent `ASSUMPTIONS.md` P9).
- **FMT-1** `Declaration` gains `CredFormats []string`, regular expressions for that provider's credential shapes (access token, refresh token, API key), and `Validate` requires at least one, each compiling and each not matching the empty string. The built-in Codex declaration states its formats.
- **FMT-2** A run's result is scanned with the declaration's formats as well as `LooksLikeCredential`: a canary in any declared format makes the run end `result-withheld`, and no part of the canary appears in the reply, the journal event or the log.
- **FMT-3** agentosd passes the same formats to the vault redactor, which scrubs a match from anything the vault process returns about that provider (`vault.Redactor` gains a format-based pattern next to its value patterns). A canary in each format is redacted whole, including when split across writes (the `Writer` path).
- **FMT-4** A declaration whose formats are missing or malformed refuses to load, so no provider runs with the default scan alone.

**Acceptance tests** (each carries `REQ: CRED-7`):
- FMT-1, FMT-4: `TestDeclarationNeedsCredentialFormats` (`broker/provagent/declare_test.go`; missing, empty-matching and non-compiling formats each refuse).
- FMT-2: `TestResultWithADeclaredFormatCanaryIsWithheld` (`broker/provagent/run_test.go`; one canary per built-in format, asserting the canary is absent from the reply, event and log).
- FMT-3: `TestRedactorScrubsDeclaredFormats` and `TestRedactorScrubsDeclaredFormatSplitAcrossWrites` (`broker/vault/redact_test.go`).

**Revert mutants:** scan only the default shapes; compile the formats case-sensitively when the provider's are not; let the redactor skip a match that straddles a `Write` boundary.

## Design (recommendation)

Formats stay strings in `Declaration`, so `provagent` imports no `vault` (P9). agentosd builds `Runner.Scan` as `LooksLikeCredential` OR the declaration's compiled formats, and hands the same list to `vault.NewRedactor` through a new `WithFormats(...string)` option. Reuse `MaxLen` logic in `Writer` with a per-format cap so a streamed match is held back until it ends.

## Assumptions

Codex's token shapes are those #809 measures with the pinned CLI; until then the built-in lists the shapes the spike recorded (`spikes/S8-provider-workers/RESULT.md`) and the Codex route stays disabled through the qualification record, so a wrong shape cannot leak a live login before #809 corrects it.

## Out of scope

Result-channel encodings the scan misses (the scan is a tripwire: the worker holds only placeholders), Claude/Grok/Muse declarations, redaction of non-provider vault kinds.

## Scope

`broker/provagent/declare.go`, `broker/provagent/declare_test.go`, `broker/provagent/run.go`, `broker/provagent/run_test.go`, `broker/vault/redact.go`, `broker/vault/redact_test.go`, `broker/cmd/agentosd/main.go` (the `Scan` wiring), `broker/provagent/ASSUMPTIONS.md`, `briefs/CAP-11-plan-fu4.md`.

## Done

CI green; FMT-1 to FMT-4 covered by the acceptance tests.
