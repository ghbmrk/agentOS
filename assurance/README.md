# Assurance gates: canary (A5), dependency audit (A9) and loop 2 qualification (A11)

Two permanent CI jobs in `.github/workflows/assurance.yml`, run on every PR, on
`main`, and daily with fresh canaries. Both are stdlib-only Python, so they add
no dependency of their own.

Each harness runs hard-coded **controls** (deliberate leaks it must catch, and
broken targets it must call errors) before the **product targets** listed in the
registry. A clean result on a product target counts only because the same run
caught every control. Registries hold product targets only, and each must expect
`clean` / `pass`: no registry edit can relax a gate or drop a control. Until P1-3
(vault) and P1-2 (broker) register targets, only controls run, and the jobs print
a note saying so.

## Canary harness (`tools/canary.py`, registry `canary-targets.json`)

Per round the harness mints one fresh canary of every kind (API key, bearer token,
session cookie, password, TOTP seed, private key, recovery code; each at least 128
bits of entropy, shaped like the real thing, no shared marker) and runs the target
command with:

| Variable | Meaning |
|---|---|
| `CANARY_PLANT` | JSON file of `{kind, value}` canaries. Trusted side only: load them into the vault or a credentialed browser session. |
| `CANARY_ACK` | The trusted side writes `{"loaded": [fingerprint, ...]}` here, one per canary it actually loaded (`canary.fingerprint(value)`: first 16 hex digits of SHA-256). |
| `CANARY_SURFACE_DIR` | Copy here everything the adversary could reach: guest files, `canary.py sweep` dumps, protocol transcripts, packet captures. |

The harness scans that directory and the target's stdout and stderr. A canary is
caught raw, as hex, URL-encoded, UTF-16, base64 at any alignment inside a larger
blob, in upper or lower case (hex and base32 kinds), as any fragment of its secret
core at least 15 characters long, and, for kinds whose text is an encoding (hex
cookie, base32 TOTP seed, base64 key, base64url token), as its decoded bytes (raw,
hex, or base64 at any alignment) or any raw decoded fragment of at least 10 bytes. Reports carry fingerprints, kinds,
encodings, and locations, never values, and the harness checks its own report
before writing it.

A round is an **error**, never clean, when the target exits nonzero, the ack is
missing or incomplete, the surface is empty, or the scan budget (`--max-bytes`,
default 4 GiB) runs out. `canary.py sweep` likewise fails rather than truncate.

The adversary with full root is `canary.py sweep --root / --pid all --out DIR`,
run inside the guest: it dumps every readable file and every process's
environment, command line, and readable memory.

Register a target:

```json
{"name": "vault-egress", "cmd": ["broker/test/canary-target.sh"]}
```

Product targets always expect `clean`; the registry refuses anything else.

## Dependency audit (`tools/depaudit.py`, registry `dep-targets.json`)

`run` executes each scenario (boot, take STOP and STATUS, recover) in fresh user,
network, and mount namespaces: loopback only, DNS answered NXDOMAIN by a logging
sink, and every `connect`/`send*` of the process tree logged by strace. Host
directories that hold or could hold filesystem sockets (`/run`, `/tmp`, `/var`,
`/home`, `/root`, `/srv`, `/mnt`, `/media`, and `/dev/log`) are hidden under empty
tmpfs mounts, with only the work directory, the repository, and the Python
install bound back, so nscd, systemd-resolved, D-Bus and the like are
unreachable, not merely logged. A filesystem socket path passes only if it is
absolute, has no `.` or `..` components, lies in the work directory, and resolves
(symlinks followed, inside the sandbox) to the work directory; relative paths fail
closed. Any `mount`-family call, and any symlink or hard link whose source could
lie outside the work directory, is itself a violation, so a path cannot be made
to lead out even if the link is removed before exit. CI also sets
`kernel.io_uring_disabled=2` and the run checks it, because io_uring socket calls
bypass strace. A scenario passes only if it exits 0 and makes no non-loopback
attempt, no DNS lookup (including any loopback port 53 traffic), no attempt at a
host-wide Unix socket, and no socket family the parser does not recognise as
namespaced (`AF_VSOCK` and the like fail closed, as does any sockaddr it cannot
parse). This is the A9 run with every optional dependency removed.

`static` checks that every network endpoint literal in shipping code (`broker/`,
`src/`, excluding tests) is declared in `dependencies.json` with its SPEC.md §2
class, and that nothing matches a forbidden (AgentOS-operated) pattern, even if
declared (DEP-2).

Each dependency-audit control also names the calls it must have made (and the
path-trick controls must actually reach a live probe socket), so none can pass
vacuously.

Register a scenario (it must expect `pass`; no other keys are accepted):

```json
{"name": "broker-offline", "cmd": ["broker/test/a9-scenario.sh"]}
```

## Loop 2 qualification (`loop2/`, catalog `loop2-seeds/`)

A11's loop 2 clause (P3-4b-2): a seeded defect is found, contained and fixed
through Loop 2's real chain, and no candidate that games the check is adopted.
`python3 assurance/loop2/run.py --catalog assurance/loop2-seeds (--all | --pick)
[--random-seed N] --report FILE` builds the Go program in `loop2/` against the
broker module (an overlay, so `broker/` holds none of it) and exits 0 only on a
pass. CI runs `--all` and `--pick` in the canary job and uploads both reports.

**Catalog.** `base.json` is the owner's tree, its cross-module `receives` map and
its base security cases. Each seed directory holds `seed.json` (target to pause,
subject, detail), `test.json` (the visible tree rule: the finding's `Rule`, with at
least two padding clauses that already hold on the defect), `defect.json` and
`fix.json` (file edits), and `held/*.json` (held-back variants). The layout is
closed: an unknown file fails the load. The report's `catalog_sha256` is SHA-256
over `path NUL sha256(file) LF` for every file in sorted path order.

**One run, per seed.**
1. Validate the seed (any failure is `invalid seed: …` and fails the run): defect
   and fix only in candidate namespaces; the test fails on the defect and holds on
   the fix; ≥ 2 padding clauses; each held variant fails on the defect and holds
   on the fix, and at least one fails the gamed fix (g); every held clause the
   test does not share whole has a field (`path`, `pointer` or `value`) the test
   lacks, so the field audit in step 6 can tell it from the test.
2. Build `change.Pipeline` with the defective tree as its initial tree, attach a
   journal, add the base security cases.
3. `loops.Guard.Report` the finding (`CheckSeeded`, rule = `test.json`): the target
   must be paused, and the `loop2/<id>` case must be a 1-minimal subset of the test
   on the defective tree.
4. Link every held variant as `held/<id>/<name>` with `Finding: <id>` before any
   fix is asked for.
5. Eight passes: the scripted fixer returns (a)–(g) of P3-4b-1 §6, built from the
   reference fix, the visible test and the target, then the reference fix. Each
   bad one must be rejected for its class's exact reason; the reference fix must
   be adopted, and the Guard's evidence must hold exactly one record for the
   finding, with the fix adopted. The suite may never shrink.
6. Fix-input audit: the fixer sits behind an adapter that records every byte of
   every `Finding` it hands over. A held-back clause the visible test does not
   share, as any JSON object in the record that decodes to it (whatever its
   whitespace or key order), or any of its `path`, `pointer` or `value` (canonical
   JSON, and a string's bare text) that the visible test lacks, fails the run.

**Controls, every invocation.** `invalid-seed` reruns the first seed with its held
variant replaced by the test's first (padding) clause and must be refused as an
invalid seed; `leaking-adapter` reruns every valid seed with the adapter appending
its held files' bytes to `Detail`, and each must fail the audit. A missed control
fails the invocation, as in `canary_controls.py`. `run.py --go-test` runs the
harness's own unit tests (`harness_test.go`); `tests/test_loop2_harness.py` runs
them in CI.

### Assumptions (P3-4b-2)

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| A-1 | The scripted fixer is the test double that answers Loop 2's fix request; the product's model-backed fixer is P3-4b-5. No `loops.Fixer` is wired in the daemon yet. | A11, LOOP-9 | P3-4b-5 runs this harness with its fixer behind the same adapter. |
| A-2 | Seed defects lie only in candidate namespaces (the seeds use config, context and procedures); validation refuses any other. | LOOP-10, CHG-2 | Escalate: A11 would need a defect only an owner intent can fix. |
| A-3 | Held variants are linked by the harness through `AddSecurityCase` with the finding's ID, and the pipeline rejects a candidate that fails a linked case (`ReasonLinked`); that is what makes (g) a rejection rather than a failed run. | LOOP-10, CHG-1, CHG-2 | If links from outside Loop 2 are refused, grade held cases after adoption and count (g) adopted as a failed run. |
| A-4 – A-6 | Brief rows on P3-4b-3/-4, LOOP-3 and probe pauses do not bear on this harness. | — | — |
| H-1 | The pipeline's evaluator answers tree rules only, as `replay.Evaluator`'s first step does; every case in the run is a tree rule. It also fails the run if any evaluated tree holds an `assurance/` or `loop2-seeds` path. | CHG-2 | If a seed needs a non-tree probe, the harness must wire the replay evaluator. |
| H-2 | The defect is installed as the pipeline's initial tree: the owner-equivalent path, outside any candidate. | A11 | If the owner path gains checks (e.g. an intent per install), apply the defect through that intent instead. |
| H-3 | The journal policy approves what the pipeline sends to the owner (`ErrNeedsOwner`), standing in for the owner; every other check still runs. Rejections come from `Propose`, before the journal. | CHG-1, CHG-2 | If a class is ever rejected only by the owner, the harness must model the owner's refusal. |
| H-4 | The audit matches tokens in the recorded bytes: whole clauses as any JSON object that decodes to one, fields' JSON forms by substring, bare scalars only where no letter, digit, `.`, `-` or `+` touches them. It catches verbatim, canonical and re-laid-out JSON leaks, not paraphrase or encoding. | CHG-2 | A model-backed fixer (P3-4b-5) needs the audit on its prompt bytes, with the same rules. |
| H-5 | Each pass asks the fixer once (`fixPending`), so eight passes give eight proposals; a pass that proposes other than one candidate fails the run. | LOOP-9 | If Loop 2 batches or retries within a pass, count proposals per finding instead. |
| H-6 | A held clause whose every field the visible test has, in another combination, is refused at validation (P3-4b-2b): a prose leak of such a clause could not be told from the visible test field by field. No committed seed has one. | CHG-2 | If a property can only be held back that way, the audit must match field combinations, and P3-4b-5's prose audit with it. |

## Known limits

- The detector finds encodings, not compression or encryption. A target must hand
  over decompressed surfaces; encrypted data at rest is out of scope by design.
- Scanning runs at roughly 13 MB/s per core in pure Python, so a 4 GiB budget is
  minutes, not seconds. Base64 renderings of partial fragments are not indexed;
  full-value base64, text fragments, and decoded fragments are.
- AF_VSOCK and other non-namespaced families are detected and fail the run, but not
  blocked: a seccomp filter would be the enforcement, if a target ever needs it.
- The static scan reads URL literals and skips comment lines and test files. It is
  a tripwire, not a parser; the runtime audit is the authority.
