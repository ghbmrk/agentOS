# P3-4b-3r-env-r8: child environments fail closed at run time (`childproc`)

Board section: Phase 3: the agentic loops. Part of P3-4b ([P3-4b.md](P3-4b.md)); SPEC CRED-1, ARC-1, LOOP-7. Written 2026-10-09 from the #621 delta reviews (Security 4a, comments 6085089719, 6085443650, 6085554043).

**Package:** split for size into **r8a** and **r8b** (below). The parent row P3-4b-3r-env-r8 is not startable itself. Moving all eleven launchers and their tests onto the wrapper, together with the wrapper, the gate and the gate's tests, would not finish under 150k. r8a builds the wrapper, the gate and its tests, and moves the first callers (the two LOOP-7 runners and `machprobe`). r8b moves the rest. Both are **tier A** (`broker/childproc` and the daemon check guard every tier-A child): strongest model, L3 with a threat check, UX and Potency lenses, a separate Security section.

**Dependencies, all merged:** P3-4b-3r-env-r1 (#621, ffe1a159). r8b needs r8a.

## Goal

`childEnvCheck` is an AST check, and #621's delta review showed that it can be bypassed: `fresh(a.New()).Run()`, in a file that does not import `os/exec`, started a child that saw `AGENTOS_OWNER` (Security 6). This package makes the environment a run-time property that one package enforces, so the AST check becomes defence in depth rather than the boundary.

1. One package, `broker/childproc`, is the only code in the module that can start a process. It hands out an opaque handle and checks the environment immediately before every start.
2. An import gate on the dependency graph keeps every other package away from the launchers.

## IDs

- **LOOP-7**: the runners that start fuzz and probe children (`loop7`, `probecmd`).
- **CRED-1**: no reusable authentication material in I/O that a model-directed process can read. An inherited agentosd environment is such I/O.
- **ARC-1**: only the broker holds credentials.

Tests carry `REQ: LOOP-7, CRED-1, ARC-1` as fits. Each requirement below names its IDs. Every ID gets a failing test first.

## Binding definitions

These are part of the requirements. A reviewer holds the diff to them word for word.

**D1. Opaque.** `childproc` exports no `*exec.Cmd` and no other `os/exec` type. Specifically:
- No exported type embeds one.
- No exported struct field, function result or method result has an `os/exec` type, or a type built from one (pointer, slice, map, chan, func signature, or struct field reached through an exported type).
- No exported accessor yields one. That rules out results of type `any`, an empty interface, an interface any `os/exec` type satisfies through methods the package defines, `reflect.Value`, and `unsafe.Pointer`.
- The handle's own fields are unexported.
- Exit status is reported through a `childproc` type (for example `*childproc.ExitError` with `ExitCode()`), never `*exec.ExitError`.
- `LookPath` returns a `string`.

**D2. Deny-by-default environment.** The run-time check allows only an explicit allowlist, applied at two levels:
- **The caller's values.** A child's environment is exactly the `KEY=value` pairs that the caller passed to `childproc.NewEnv`. `NewEnv` copies them, so later changes to the caller's slice change nothing. Nothing else in the API sets the environment.
- **Global keys.** Every key must appear in `childproc`'s one key allowlist, and each entry there carries its reason.
- **Refused:**
  - a key not on the allowlist;
  - any `AGENTOS_*` key;
  - a malformed entry: no `=`, an empty key, a NUL byte, or a duplicate key;
  - a value equal to the process's own non-empty value of an `AGENTOS_*` key, or of any key on `childproc`'s credential denylist. This stops the owner's number from being smuggled under an allowed key such as `HOME`. A secret of 6 bytes or more is also looked for inside a value. A value that is an absolute path is configuration, not a secret, and is not matched, because a child's `HOME` may lie under a configured directory.
- **Not enough:** comparing the environment against `os.Environ()`. A filtered copy of `os.Environ` passes an equality test.
- **The zero value fails closed.** A zero `childproc.Env` (one not built by `NewEnv`) is refused at start with an error. A nil `context.Context` panics, as `exec.CommandContext` does.
- **No `ProcAttr` entry point in r8a.** `childproc` exports none, and `machprobe` moves to `Command`. Any later entry point that takes a `ProcAttr`-like value must panic or error on a nil one. The API-surface test (requirement 1) pins the exported set, so adding one is a reviewed change.

**D3. The gate is on the dependency graph.** Direct imports are not enough: `net/http/cgi` and `go/build`, for example, start children without the importer naming `os/exec`. The gate runs `go list -deps` (non-test build graph) over `./...` in `broker/`.
- **Graph rule.** With the `childproc` node removed, plus the nodes on the exemption list below, no package in the graph may reach `os/exec`. A stdlib package such as `go/build`, `go/importer`, `net/http/cgi` or `net/http/fcgi` therefore counts because it reaches `os/exec`, not because it is on a name list. A test pins those four as "child-starting" against the current toolchain, so a change to the toolchain's graph is seen.
- **Source rule.** No non-test file of a non-stdlib package in the graph (module or vendor) may name a launcher selector, called or used as a value. The launcher selectors are `os.StartProcess`; `syscall.ForkExec`, `syscall.StartProcess`, `syscall.Exec`; and `golang.org/x/sys/unix.Exec`, plus any `ForkExec`/`StartProcess` in `unix`. The selector is resolved by import path, so a renamed import is still caught.
- **One exemption list.** `childproc` itself is the only permanent entry. All exemptions are listed in one place, the gate's `exempt` map, each with its reason.
  - Every exemption must still be needed: if a listed package no longer reaches `os/exec` or names a selector, the test fails and says to drop it.
  - r8a lists the not-yet-moved r8b packages there, each with the reason "moves in P3-4b-3r-env-r8b", and `golang.org/x/sys/unix`'s own `Exec` definition, which calls `syscall.Exec`.
  - Test files and the test-only graph are out of scope, because they are not linked into a shipped binary. That is stated once beside the map.

**D4. Nil `Env` anywhere.** `childEnvCheck` flags any assignment `X.Env = <nil>` and any keyed literal `Env: <nil>`, whatever the type or receiver.
- `<nil>` means the literal `nil`, the conversion `[]string(nil)`, and r1's run-time-nil shapes: a package-level `var` with no initializer, a same-file func whose only return is `return nil`, and a local `var e []string` never assigned before use.
- No struct in the tree has an `Env` field that should be nil, so the rule costs nothing. A future one that needs it gets an exemption by review.

## The complete set of process starters

This is a `grep` of non-test, non-vendor Go for `"os/exec"`, `StartProcess`, `ForkExec` and `syscall.Exec` on ffe1a159. `assurance/` and `reviews/` hold no `os/exec` user. `loop7/testdata/*` are separate test modules with none either.

| Package / file | Starts | Uses beyond `Env` | Moves in |
|---|---|---|---|
| `loop7/loop7.go` (`Source.run`) | release-listed fuzz binaries | `Dir`, `SysProcAttr` (pgid, jail credential, CgroupFD), `Cancel` killing the group, `WaitDelay`, `Stdout`/`Stderr`, start on a locked no_new_privs thread, `*exec.ExitError` (`exited`) | r8a |
| `probecmd/command.go` (`CommandProbe.Run`) | release-listed probe harnesses | `SysProcAttr` (pgid), group-kill `Cancel`, `WaitDelay`, `Run` | r8a |
| `machprobe/machprobe.go` (pressure `processes`) | idle child via `os.StartProcess`, empty env | `Kill`, `Wait` | r8a |
| `vm/gvisor/gvisor.go` (`Runtime.cmd`, `exec`) | runsc | `Stdin`, `Stdout`, `Stderr`, `ExtraFiles`, CgroupFD `SysProcAttr`, `Cancel`, `WaitDelay`, `*exec.ExitError`, `ErrWaitDelay` | r8b |
| `modem/at/audio.go` | arecord, aplay | `StdoutPipe`/`StdinPipe`, `Process.Kill`, `Wait` | r8b |
| `browser/gate.go` | the browser driver | `Dir`, pgid, `StdinPipe`/`StdoutPipe`, group kill by pid, configured extra env (`cfg.Env`) | r8b |
| `clock/chrony.go` (`chronycCmd`) | chronyc | `Output`; tests read the returned `*exec.Cmd` | r8b |
| `cmd/agentos-guest-bridge/main.go` | the guest runtime | `Process.Signal`, pid for reaping, a token and `runtimeVars` copied from its own (guest) environment by design | r8b |
| `quota/quotatest/quotatest.go` | mkfs, mount, umount (test helper package) | `CombinedOutput` | r8b |
| `tpmseal/swtpm/swtpm.go` | swtpm | `LookPath`, `Process.Signal`/`Kill`, `Wait` | r8b |

Test files that use `os/exec` (33 on ffe1a159, for example `loop7/*_test.go` building fuzz binaries, and the daemon's `go list` calls) stay as they are, per D3.

## Requirements: r8a

Each requirement starts with a failing test.

1. **`childproc` exists and is opaque** (CRED-1, ARC-1).
   - Package `broker/childproc` provides:
     - `NewEnv(kv ...string) Env`;
     - `Command(ctx, env Env, name string, args ...string) *Cmd`, with options for `Dir`, `Stdin`/`Stdout`/`Stderr`, `SysProcAttr`, `ExtraFiles`, `WaitDelay`, and killing the whole process group on cancel;
     - `Start`, `Wait`, `Run`, `Output`/`CombinedOutput`, `StdinPipe`/`StdoutPipe`, `Pid`, `Signal`, `Kill`;
     - `ExitError`, `ExitCode`, `LookPath`.

     The exact surface is the builder's, within D1.
   - **API-surface test.** Type-check `childproc` with stdlib `go/types` and `importer.ForCompiler(fset, "source", nil)` (no new module). Walk every exported identifier's type transitively and fail on any `os/exec` type, any embedded one, `any`/empty interface, `reflect.Value` or `unsafe.Pointer` results. Pin the exported names, so a new entry point is a reviewed change.
   - A planted fixture (an exported method returning `*exec.Cmd`, an embedded `exec.Cmd`, an `any` accessor) fails the walk.
2. **Run-time environment check** (CRED-1).
   - Table tests for each refusal in D2: zero `Env`, a key not allowlisted, `AGENTOS_OWNER=…`, `HOME=<the process's own AGENTOS_OWNER value>`, no `=`, NUL, a duplicate key.
   - A copy test: mutate the caller's slice after `NewEnv` and see no change.
   - An end-to-end canary test:
     - `t.Setenv("AGENTOS_OWNER", <synthetic canary>)` plus a synthetic credential-shaped variable;
     - start a real child (`/usr/bin/env`, or the test binary re-run as a helper) through `childproc`;
     - assert that its environment is exactly the built pairs and holds no canary.
   - Synthetic values only (CLAUDE.md).
   - The key allowlist and credential denylist live in one place in `childproc`, each key with its reason. r8a holds only the keys its callers need: `PATH`, `HOME`, `TMPDIR`, `GOCACHE` and `GOFLAGS`.
3. **The gate** (CRED-1, ARC-1).
   - `broker/childproc/gate_test.go` implements D3 over the real module, with the exemption map, and the tree passes.
   - Fixtures, each a temporary module the gate runs on:
     - **Security 6 repro.** Package `a` imports `os/exec` and exports `New() *exec.Cmd`. Package `b` has no `os/exec` import and calls `fresh(a.New()).Run()`, where `fresh` is a local helper. Both `a` and `b` are flagged. This is the #621 delta Security 6 shape. In the real tree that code now fails the gate, and it cannot be written against `childproc`, because `childproc` yields no `*exec.Cmd` (requirement 1).
     - A package importing `net/http/cgi` is flagged.
     - A file using `os.StartProcess` as a value, and one using `syscall.ForkExec` through a renamed import (`sc "syscall"`), are each flagged.
     - A stale exemption fails.
     - A package that starts children only through the fixture's `childproc` passes.
   - The gate test runs in under ~20 s on CI. Note the figure in the PR.
4. **The two LOOP-7 runners and `machprobe` move** (LOOP-7, CRED-1).
   - `loop7.Source.run`, `probecmd.CommandProbe.Run` and `machprobe` start children only through `childproc`. None of them imports `os/exec` or names a launcher selector, so the gate lists none of them.
   - Behaviour is kept:
     - group kill on cancel, and `WaitDelay`;
     - loop7's jail `SysProcAttr`, and its start on the locked no_new_privs thread (`startNoNewPrivs` takes the start func);
     - the `exited` classification, through `childproc.ExitError`.
   - The existing loop7, probecmd and machprobe tests stay green unchanged, except where they named `exec` types in package code.
   - New failing-first tests: the runners' child environment (via the canary helper of requirement 2) holds no `AGENTOS_OWNER`. For loop7, give that test a fuzz binary or helper whose run the test can observe, as the current tests do.
5. **Nil `Env` outright** (CRED-1). D4 in `childEnvCheck` (`broker/daemon/inference_test.go`). Fixtures:
   - `type T struct{ Env []string }; t.Env = nil` is flagged.
   - `T{Env: []string(nil)}` is flagged.
   - `T{Env: unsetPkgVar}` is flagged.
   - `T{Env: []string{}}` passes.

   The tree must still pass.
6. **`childEnvCheck` scope follows `childproc`** (CRED-1).
   - A file that imports `childproc` is in the check's scope, so its `Env`-value rules (nil, `Environ`) run there.
   - Add one rule: `childproc.NewEnv` given an `Environ` value (direct, spread, or through a helper, as for `Env` today) is flagged. Fixture first.
7. **Records.**
   - The daemon's `escapeOK` drops `loop7` and `probecmd` `os/exec` and adds `childproc`, and `TestEscapeOKNamesTheLoopRunners` is updated to name the new owner.
   - The `arc2_test.go` and `netOK` allowlists take `childproc` wherever the moved packages now import it.
   - The Security README row "A broker child process inherits the daemon's whole environment" names `childproc` and the gate as the boundary, and `childEnvCheck` as defence in depth.
   - agentosd ASSUMPTIONS L7-2 gets one clause.
   - `broker/childproc/ASSUMPTIONS.md` records what `childproc` rests on: Linux, the stdlib `os/exec` semantics it wraps, and the later items below.
   - LATER.md gets the two lines under "Later".

## Requirements: r8b (its own session, after r8a merges)

Move `vm/gvisor`, `modem/at`, `browser`, `clock`, `cmd/agentos-guest-bridge`, `quota/quotatest` and `tpmseal/swtpm` onto `childproc`, and drop each one's gate exemption. Each move carries a failing-first test that its child's environment is exactly the built pairs. Widen the key allowlist only by a reviewed entry with a reason.

- The browser's configured `cfg.Env` keys must each be allowlisted. Otherwise the configuration is refused at load.
- The guest bridge's `OPENCLAW_GATEWAY_TOKEN` and `runtimeVars` run in the guest, where no `AGENTOS_*` key exists. Give them an allowlist entry with that reason. Do not add a way around `NewEnv`.

After r8b, the exemption map holds only `childproc` and the `unix` definition.

## Threat check

- **An escape from the handle** to the `*exec.Cmd` inside, so its `Env` can be set after the check: D1 and requirement 1's walk. Reflection plus `unsafe` remains possible (later).
- **A child started off the graph**:
  - a new launcher route through a stdlib or vendored package (D3 graph rule);
  - a raw `SYS_EXECVE`/`SYS_EXECVEAT` via `syscall.Syscall`, which is later. Today the daemon's `rawOK` already limits raw syscall numbers for agentosd's graph.
- **A filtered or smuggled copy of the daemon's environment**: D2's key allowlist and value denial.
- **An exemption that outlives its reason**: the stale-exemption check.
- **A gate so slow it gets skipped**: the ~20 s bound.

## Later (LATER.md lines; do not build)

- `P3-4b-3r-env-r8 l1`: reflection plus `unsafe` can reach `childproc.Cmd`'s unexported `*exec.Cmd` and change its `Env` after the check. The daemon's import check already gates `unsafe`, through `escapes` and `escapeOK`, for agentosd's graph. Extend that to the whole module, or re-check `Env` inside `Start` against a sealed copy.
- `P3-4b-3r-env-r8 l2`: a raw `SYS_EXECVE`/`SYS_EXECVEAT` (or `clone` plus exec) through `syscall.Syscall`/`RawSyscall` or `unix.Syscall` starts a child outside `childproc`. The gate does not follow syscall numbers. `rawOK` covers agentosd's graph only. Extend it to the module.

## Scope

**r8a:**
- `broker/childproc/` (new: package, tests, `ASSUMPTIONS.md`);
- `broker/loop7/loop7.go`, `broker/probecmd/command.go`, `broker/machprobe/machprobe.go` and their tests where they name `exec` types;
- `broker/daemon/inference_test.go` (`childEnvCheck`, `escapeOK`, fixtures) and `broker/daemon/arc2_test.go` (allowlists only);
- `reviews/security/README.md` (one row);
- `broker/cmd/agentosd/ASSUMPTIONS.md` (L7-2);
- `LATER.md` (two lines);
- `BOARD.md` (these rows).

**r8b:** the seven packages listed above, their tests, and the gate's exemption map.

**Not here:**
- r7's type-based detection;
- r2 to r6 (separate rows; a rewrite that removes one in passing is a finding to note, not a goal);
- the later lines above.

**Estimate:**
- r8a ~130k. Checkpoint at 70k: requirements 1 to 3 green.
- r8b ~100k.
