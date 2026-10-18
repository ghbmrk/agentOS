# CAP-11-plan-fu4-shapes: procedure to measure the Codex credential shapes

Board row: issue #2313. Source: CAP-11-plan-fu4 (ASSUMPTIONS P17: the Codex `CredFormats` are the public shapes, not measured). Class: release. Tier: C (`spikes/`, `briefs/`). Usage estimate: 60k tokens, checkpoint at 45k.

**Why.** The Codex declaration's `CredFormats` (`broker/provagent/declare.go`) back the result scan and the vault redactor (FMT-2, FMT-3). They were written from public token shapes. If a real sign-in issues tokens in another shape, a fresh token echoed by the CLI escapes both. Failure path: an access token whose shape no declared format matches reaches the guest in a result file.

## Requirements

- **SHP-1** `spikes/S8-live/SHAPES.md` states the host, the owner's sign-in steps (device code), what leaves the machine and where the result is recorded.
- **SHP-2** `spikes/S8-live/shapes/` reads the pinned CLI's `auth.json` and prints only shapes: length, a public or generic prefix, character classes, dot-segment lengths, JWT `alg`/`typ` from an allowlist and header and claim names, and for each declared Codex format `full`, `partial` or `none`. No value, or any 6-byte window of one past its public prefix, appears in the output.
- **SHP-3** The extractor's formats are the declaration's verbatim, so a change to `declare.go` fails the spike's test.
- **SHP-4** `run.sh shapes` runs the sign-in in a gVisor machine with no network but loopback, through `fwd.py` in relay mode (model calls refused), writes only `shapes.json` to the work volume, and logs out and removes `auth.json` before the machine exits.

**Acceptance tests** (each carries `REQ: CRED-7`), in `spikes/S8-live/shapes/main_test.go`:
- SHP-2: `TestOutputHoldsNoValue`, `TestShapes`.
- SHP-3: `TestFormatsMatchDeclaration`.
- SHP-1, SHP-4: reviewed from the procedure and `run.sh`; the live run is recorded in RESULTS.md.

## Out of scope

Changing `CredFormats` or P17 (a tier-A follow-up once the shapes are recorded); exercising a token refresh; the API-key route.

## Scope

`spikes/S8-live/run.sh`, `spikes/S8-live/shapes/*`, `spikes/S8-live/SHAPES.md`, `spikes/S8-live/RESULTS.md`, `briefs/CAP-11-plan-fu4-shapes.md`.

## Done

CI green; the three tests pass; after the owner's sign-in, the shapes are in RESULTS.md and on #2313.
