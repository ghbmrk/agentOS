# Security review loop

A recurring adversarial review of the spec, spike results, and (once it exists) the code. Advisory: findings become proposals here, and spec changes go through an L1 spec-diff PR that Mark merges.

It is one of three lenses (security, potency, UX). An arbitrator loop weighs their proposals against each other, so **every proposal states its cost to UX and to potency**.

**Method:** a fixed threat model (assets and adversaries, see run 1) applied to each change: follow every path from each adversary to each asset, and record whether a requirement stops it structurally, only procedurally, or not at all. Security-critical code paths (broker, vault, executors, clean room, update signing) get an explicit threat check (CLAUDE.md).

**Output of a spec-wide run** (only when Mark or L1 asks for one): `YYYY-MM-DD-security-review.md` with findings (severity, adversary, proposal, UX cost, potency cost), a decisions list, and, when warranted, SPEC.md edits in the same PR.

## In the lens screen

Tier A PRs get a Security section in its own fresh session on the strongest model; tier B PRs get Security as part of the combined pass. Each run applies the method below to the PR's diff, not to all of `main`. Verdicts go to `reviews/security/YYYY-MM-DD-pr<N>.md` (combined passes to `reviews/combined/`), in the L3 format of docs/OPERATING.md §4. A later delta on a signed tier-A PR needs a re-sign by the mechanical rule in OPERATING §3.

## Checks that replaced findings

Finding kinds CI now catches; the screen no longer looks for them by hand (OPERATING §4).

| Finding kind | Check | Since |
|---|---|---|
| — | none recorded yet | — |

## Spec-wide runs

Weekly runs over all of `main` until 2026-10-07, when the batched lens screen replaced them (DECISIONS D-048).

| Run | main at | Review |
|---|---|---|
| 1 | e841b78 | [2026-10-04](2026-10-04-security-review.md) |
| 2 | 76ac0b9 | [2026-10-05](2026-10-05-security-review.md) |

## Records

Per-PR and per-bundle records are the files `YYYY-MM-DD-*.md` in this directory (tier-B combined passes are in `../combined/`), in filename order, so there is no run number to pick. Each opens with a `Record:` line giving PR, package and head SHA; `tools/doclint.py` checks it on files dated 2026-10-09 or later. No run rows are appended to this README, so open PRs do not conflict on it; recurring kinds and the checks that replaced them still are (DOC-4, docs/OPERATING.md §4).

## Recurring kinds (to become checks)

| Kind | Seen on | Check to add | Owner package |
|---|---|---|---|
| A broker child process inherits the daemon's whole environment | #523 (f3), #515 (f2) | `daemon` `TestEveryChildGetsAnExplicitEnvironment` (beside the ARC-2 AST walk, `daemon/inference_test.go`; rules in `childEnvCheck`'s doc comment): in any file that imports a launcher package, non-test broker code fails when it starts a child without an explicit environment through `exec.Cmd` (constructor, literal, `new` or `var`; `exec.Cmd` as any other type, an alias, field or element, fails outright), `os.StartProcess` (a nil `ProcAttr` or one without `Env`), `syscall.ForkExec`, `syscall.StartProcess`, `syscall.Exec` or `unix.Exec`, under any import name; when a launcher is used as a function value; when no `Env` is set on the variable that holds the command between storing it and the variable's next store; when the `Env` is nil at run time (literal or typed `nil`, a `var` declared with no value or a nil one and not yet assigned, a package `var` of the file never assigned, a helper that returns only `nil` or a nil local); or when any `Environ` selector reaches an `Env` value, directly, through a package helper's return up to three calls deep, or through a package-level `var` of the same file (no exemption). Package-level `var` and `type` specs and func literals are checked too. Procedural, held by review: an `Env` from a value the check cannot classify (a parameter, another struct's field, a map lookup, a declaration in another file); an `Env` set after the start or only under a condition; a nil the check does not trace (from a method or func literal, a slice or append of nil, a slice appended to only on some paths, a nil `Env` on a copy, parameter or promoted field) and a command copied by dereference; a command given its `Env` in another function; an `Environ` helper behind a func value, an interface or another package, and `Environ` itself as a func value; files that import no launcher package; reflection, `unsafe`, raw syscalls and `/proc/self/environ`. `envExempt` holds only test fixtures that no `cmd/` binary links | P3-4b-3r-env-r1 |
| A guard fails open on a missing, invalid or out-of-range value: nil `Env` read as explicit, a digest error read as "changed", a wrapped CPU count, a negative counter, a free `Script` or `Rise` knob that makes a control vacuous | #587 (nil `Env`), #584 (control digest error), #599 (`cpuCount` wrap, negative `cgroupCounter`, free `Script`; also trivial or overhead-sized activity satisfying a rise check, #548 and #599) | a table-driven test beside each parser or guard feeding nil, negative, wrapping and under-minimum inputs and asserting the round fails closed. Exists for the `loops` exhaustion round (`TestEachExhaustionParserAndGuardFailsClosed`: the configuration guard, `cpusEffective` and `cpuCount`, `cgroupCounter`, `usage`'s disk counter, `cgroupInt` and `limited`) and for `machprobe` (`TestPressRefusesWhatItCannotPress`: `Press` and `fill`), P3-4b-4c-bounds; still owed for the tamper side (`TamperProbe.Run`, `targetDigest`, `treeDigest`) | P3-4b-4c-nofollow, then the next package touching `loops` or `machprobe` |
| A "Cleared" or return text disagrees with the finding's state: Cleared while a same-name finding is open, a return texted "back" though Cleared was suppressed, a silent return after Cleared | #585 (L3 and Security blockers, `ToldCleared`), #586 (L3 blocker, `CloseTarget`) | a flap-sequence test helper (alert, cleared, return, move between details, restart) run by every path that closes findings (`Pass`, `Resolve`, `runProbe`, `CloseTarget`) | P3-4b-3r-told |
| A root-side or host-side file operation follows a link the guest or the fuzz uid planted | #584 (P3-4b-4c-nofollow, P3-4b-4c-symlink), #588 (F16, P3-4b-3r-confine-r5) | a test per operation that plants a link out of the tree and asserts the outside file is neither read nor replaced, run against the reverted path-based call | the next package that touches `machprobe` or `loop7` |
| Code that decides finding closure or containment is not tier A | #523 (f5), #515 (f4) | `loops`, `probecmd`, `corpus`, `loop7` in `TIER_A_BROKER`, pinned in `tests/test_risk_tier.py` | P3-4b-4b (done: enforced by `tools/risk_tier.py` since #548; loop7 tier A added at the Security 4a blocker) |
