# P3-4b-4c-canary-uid: a canary target cannot read the harness's secrets or fetch a toolchain

Board section: Phase 3: the agentic loops. Part of P3-4b-4c ([P3-4b-4c.md](P3-4b-4c.md#p3-4b-4c-canary)); SPEC LOOP-7. Written 2026-10-09 from the #583 (P3-4b-4c-canary) and #607 review records.

**Package:** P3-4b-4c-canary-uid, carrying P3-4b-4c-canary-env-r1 and one docstring point from the #607 Security review. All three are in how `tools/canary.py` starts a target. They edit `target_env`, `run_target`, the module docstring and loops S52 together.

**Tier A** (`tools/canary`, `assurance/`, `broker/loops/ASSUMPTIONS.md`): strongest model, L3 with a threat check, UX and Potency lenses, a separate Security section. CI runs the canary rounds in `assurance.yml`'s `canary` job, as the unprivileged `runner` user, and `tests/test_canary.py` in the `dependency-audit` job.

**Dependencies, all merged:** P3-4b-4c-canary (#583, bc0cea9).

## Goal

A canary target holds none of the harness's authority. It cannot read the harness's environment or real `HOME`, and it never gets a toolchain download through a registry entry. The module docstring and S52 say what is true.

## IDs

LOOP-7 (canary rounds; a round's result is the harness's, not the target's). Tests carry `REQ: LOOP-7`.

## Sources

- canary-uid: #583 L3 point 2 (comment 6079139240).
  - `run_target` starts the target with `subprocess.run(target["cmd"], env=env, cwd=ROOT, …)` as the harness's uid.
  - The target can therefore read `/proc/$PPID/environ` and the harness's real `HOME`. S52 says the allow-list stops accidental inheritance, not a hostile target.
  - The row may fold into the broker half of #515 Security 2, but that half is P3-4b-3a, which has merged, so the fold is moot.
- canary-env-r1: #583 Security re-sign (comment 6079715496) and delta L3 point 1 (comment 6079696946).
  - `TARGET_ENV_ALLOWED` holds `GOCACHE`, `GOFLAGS` and `GOTOOLCHAIN`.
  - `target_env` sets `GOTOOLCHAIN=local` and then applies the parent's value of each name the registry entry lists. So `"env": ["GOTOOLCHAIN"]` gets the parent's `auto`, against S52's "never downloads a toolchain".
  - `GOCACHE` is the variable behind the `GOCACHE=off` break S52 records.
- #607 Security (a later carry): the docstring at `tools/canary.py:17` says `GOTOOLCHAIN=local (no toolchain download)`. That is false while env-r1 is open, and it must match the code after it.
- Tests today: `tests/test_canary.py` `TargetEnvTest`.
  - `test_a_named_variable_comes_from_the_parent` names all three variables. It pops the parent's `GOTOOLCHAIN` first, so it never sees the override.
  - `test_a_target_never_fetches_a_go_toolchain` covers only an entry with no `env`.

## Requirements (each with a failing test first)

1. **No registry entry can undo `GOTOOLCHAIN=local`** (env-r1).
   - Remove `GOTOOLCHAIN` and `GOCACHE` from `TARGET_ENV_ALLOWED`, so `_env_names` rejects an entry that names either one.
   - Also set `GOTOOLCHAIN=local` after the parent values are applied, as a second layer.
   - No shipped target in `assurance/canary-targets.json` names either variable; check, and change the file only if one does.
   - Tests:
     - an entry naming `GOTOOLCHAIN` is rejected, and so is one naming `GOCACHE` (fails on main);
     - with the parent's `GOTOOLCHAIN=auto` and the allow-list check bypassed in the test, the target's environment still has `local` (fails on main);
     - fix the comment in `test_a_named_variable_comes_from_the_parent`, which describes the opposite of the code.
2. **The docstring says what the code does** (#607 point). Reword `tools/canary.py`'s module docstring, lines 15 to 20, to match requirement 1: the `GOTOOLCHAIN` value, the allow-list's current names, and the uid route from requirement 3. A test that greps the docstring is not needed. L3 checks it against the code.
3. **A target cannot read the harness's secrets** (canary-uid). Run each target, and each control, under an identity that cannot read the harness's `/proc` entries or its `HOME`.
   - **Preferred route: reuse the sandbox in `tools/depaudit.py`.** That module already runs untrusted code in a user namespace, mapping ids through `newuidmap` and `newgidmap` (tools ASSUMPTIONS D13). The `dependency-audit` job grants subordinate ids with `usermod`. A target that runs as a mapped subordinate uid is another kernel uid:
     - `/proc/$PPID/environ` and a 0700 `HOME` are closed to it;
     - its scratch `HOME` and `TMPDIR` must be made writable for that uid;
     - the repository at `cwd=ROOT` must stay readable to it.
   - Factor the sandbox entry into a shared helper rather than copy it. The PR says why if it cannot be shared.
   - **Fallback, only if the sandbox cannot run a `go test` target within the checkpoint:**
     - the harness calls `prctl(PR_SET_DUMPABLE, 0)` on itself through `ctypes` (the style is in `depaudit.py`), which makes its `/proc` entries root-owned;
     - it runs each target with `HOME` and `TMPDIR` in a scratch tree, and `chmod 0700`s its own `HOME` for the round.

     This route cannot hide a same-uid file the target can name, and it does nothing against `ptrace` when Yama's `ptrace_scope` is 0. State both limits in S52, and add a release row for the uid route.
   - Either route: a round still fails closed if the sandbox cannot start. A target that does not run is the runner's error, never a pass.
   - Tests, failing on main:
     - a control target that reads `/proc/$PPID/environ` gets EACCES or an empty read;
     - one that reads a file planted 0600 in the harness's `HOME` gets EACCES.

     Build them as controls in `tools/canary_controls.py`, beside `env-dump`. They run in the `dependency-audit` job, where subordinate ids exist. If the `canary` job's shipped rounds need subordinate ids too, add the `usermod` step there.
   - The shipped rounds in the `canary` job stay green.
4. **Records.**
   - loops S52: the allow-list, `GOTOOLCHAIN` set last, the route the target runs under and what it denies, and any limit left.
   - Remove S52's "until P3-4b-4c-canary-uid lands" and "BOARD P3-4b-4c-canary-env-r1 closes it" clauses once they are true.
   - `tools/ASSUMPTIONS.md`: D13's note, if the sandbox is shared.

## Threat check

- A hostile or compromised canary target reading the harness's environment or files: CI tokens on CI, real secrets on the box (requirement 3).
- A registry edit that silently re-enables toolchain downloads, a supply-chain path, or breaks rounds through `GOCACHE` (requirement 1).
- A sandbox that fails open and runs the target unconfined (requirement 3's fail-closed rule).
- A docstring or S52 that overstates the confinement, which a later reviewer then trusts (requirements 2 and 4).

## Scope

- `tools/canary.py`, `tools/canary_controls.py` (new controls only), and `tools/depaudit.py` (only to share the sandbox entry, with its tests still green).
- `tests/test_canary.py`, and `tests/test_depaudit.py` if the shared helper moves.
- `assurance/canary-targets.json`, only if a shipped entry names a removed variable.
- `.github/workflows/assurance.yml`: the `canary` job, only to grant subordinate ids.
- `broker/loops/ASSUMPTIONS.md` (S52) and `tools/ASSUMPTIONS.md` (D13).

**Not here:**
- LATER P3-4b-4c-canary l1 and l2;
- running canary rounds on the box (box row P3-4b-4c).

**Estimate:** ~90k. Checkpoint at 40k: requirements 1 and 2 green, and the sandbox route shown running one `go test` target or abandoned for the fallback.
