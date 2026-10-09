# P3-4b-3r-env-r1: the child-environment check catches the shapes it still passes

Board section: Phase 3: the agentic loops. Part of P3-4b ([P3-4b.md](P3-4b.md)); SPEC CRED-1, ARC-1, LOOP-7. Written 2026-10-09 from the #587 (P3-4b-3r-env) review records.

**Package:** P3-4b-3r-env-r1 alone. It is one test-only check in one file. The BOARD row already folds the former LATER line P3-4b-3r-env-l1, which is no longer in LATER.md.

**Tier A** (`broker/daemon` holds the check that guards every tier-A child): strongest model, L3 with a threat check, UX and Potency lenses, a separate Security section. Runs on CI.

**Dependencies, all merged:** P3-4b-3r-env (#587, 6473ce9).

**Parallel work.** Low-conflict overlaps only: P3-4b-3r-told edits a different row of `reviews/security/README.md`, and P3-4b-3r-confine-r2, -r3 and -r6 edit agentosd `ASSUMPTIONS.md` (L7-6 and L7-3; this package edits L7-2). Whoever merges second rebases.

## Goal

No non-test broker code can start a child process that inherits agentosd's environment without the check failing. The shapes the AST check still passes are each caught or narrowed, and the residue is named as procedural.

## IDs

CRED-1 (no reusable authentication material in I/O readable by a model-directed process; an inherited agentosd environment is such I/O) and ARC-1 (only the broker holds credentials). Tests carry `REQ: CRED-1`. ARC-2 is the inference ban and does not state this property; do not tag it.

## Sources

- #587 Security 4a point 1 and L3 point 3 (the former LATER P3-4b-3r-env-l1).
- Runtime-nil `Env`: Security, comment 6079549676.
- Typed-nil conversion: L3, comment 6079546431.
- The check is `childEnvCheck` in `broker/daemon/inference_test.go`. Its rules are in the doc comment above it, and it is held by `TestEveryChildGetsAnExplicitEnvironment` and `TestEnvCheckCatchesAnInheritedEnvironment`.
- agentosd ASSUMPTIONS L7-2, and the Security README row "A broker child process inherits the daemon's whole environment".

None of these shapes is in the tree today. This package closes the check's gaps before one arrives.

## Requirements (each with a failing test first)

For each shape, add a planted fixture to `TestEnvCheckCatchesAnInheritedEnvironment`, or a new table test beside it. Each fixture must fail against today's check, and the tree must still pass.

1. **Commands made without a constructor.**
   - `var c exec.Cmd` and `c := new(exec.Cmd)` with `Path` and `Args` assigned, then `.Run()`, `.Start()` or `.Output()`, and no `Env`: flagged.
   - The same with `c.Env` set to an explicit list: passes.
2. **Constructors not called in place.**
   - `exec.Command` or `exec.CommandContext` used as a function value (`f := exec.Command`, or passed as an argument): flagged wherever the reference appears, since the call cannot be followed.
   - Called in a package-level `var` initializer, or inside a func literal: the initializer or literal is checked as a function of its own. One flagged, one passing fixture each.
3. **`Env` tracked per command, not per function.** Today `setsEnv` is per function, so one `.Env =` anywhere covers every child in it, even an `Env` on an unrelated struct.
   - Key the set to the receiver: the identifier, or the selector chain, of the `exec.Cmd` or `ProcAttr` value.
   - Fixtures: two commands in one function where only one sets `Env` (flagged); an unrelated struct's `.Env =` beside a command without one (flagged); a command whose `Env` is set through the same variable it runs (passes).
4. **`Environ` through a helper.** An `Env` assigned from a call to a same-package function whose return expression contains an `Environ` selector, or calls another such function, followed up to a fixed depth (suggested 3): flagged. A helper that returns an explicit list passes.
5. **`Env` that is nil at run time.**
   - Flagged:
     - `c.Env = e`, where `e` is a local declared `var e []string` with no assignment before the start;
     - an identifier bound to a package-level `var` with no initializer;
     - a call to a same-file function whose only return is `return nil`;
     - the typed-nil conversion `c.Env = []string(nil)`.
   - Package-level env vars with an initializer pass. `alsaEnv` and `runscEnv` already exist in the tree and must still pass.
   - A value the check cannot classify (a parameter, a field of another struct, a map lookup) stays procedural. Do not flag it. List it in the check's doc comment as covered by review, and keep the Security README row's "Check" cell honest about that.
6. **Type information where AST guessing fails, if needed.** If requirements 1 to 3 cannot be done reliably by names alone (for example, telling an `exec.Cmd` variable from another type with an `Env` field), type-check the file. Stdlib `go/types` with `importer.ForCompiler(fset, "source", nil)` works without adding `golang.org/x/tools` to `go.mod`, which would be a tier-A supply-chain change. Keep the run time of `TestEveryChildGetsAnExplicitEnvironment` under about 20 s on CI, and note the figure in the PR.
7. **Records.**
   - The check's doc comment lists what it catches and what stays procedural.
   - The Security README row's "Check" cell is updated, and its owner column points at this package.
   - agentosd ASSUMPTIONS L7-2 gets one clause.

## Threat check

- A refactor that starts a child with an inherited environment by a route the check misses, reaching the owner's number (`AGENTOS_OWNER`) or a credential (requirements 1 to 5).
- A check so broad it fails on the tree and gets an exemption added (the tree must pass with no new `envExempt` entry, and `TestEnvExemptionsAreTestFixturesOnly` stays green).
- A slow check that someone later skips (requirement 6's bound).

## Scope

`broker/daemon/inference_test.go` (`childEnvCheck`, its fixtures and tests, and new fixture files under `broker/daemon/testdata/` if they read better than inline sources); `reviews/security/README.md` (one row); `broker/cmd/agentosd/ASSUMPTIONS.md` (L7-2).

**Not here:** LATER P3-4b-3r-env l3 and l4 (later rows; do not start them, though a rewrite that removes l3's dead clause in passing is fine). Also not here: any production call site. None needs a change today; if one does, it is a finding for the PR's Findings line.

**Estimate:** ~80k. Checkpoint at 45k: requirements 1 to 3 green.
