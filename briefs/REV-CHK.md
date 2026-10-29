# REV-CHK: checks for review findings seen on two or more PRs

Work item #803. Written 2026-10-29 against main at 98ffab5. This brief files no code: it names six finding kinds that reviews raised on two or more PRs with no lint, test or CI check catching them, and proposes one row per check (OPERATING §4 "Recurring findings become checks"; token rule 11). Each row is its own work item and session: REV-CHK-src #3898, -mut #3899, -links #3900, -names #3901, -crlf #3902, -save #3903.

## Sources read

- `reviews/{security,potency,ux}/README.md`, "Recurring kinds" and "Checks that replaced findings".
- The review probes in the project folder (`builds/2026-10-23-*` to `builds/2026-10-29-*`, about 200 files from L3, Security and lens rounds since cut 4, when verdicts moved into PR comments).
- Fix-list commit subjects on main since 2026-10-22 (`git log --no-merges | grep -E 'L3|Security|finding'`).
- Existing checks: `tools/doclint.py`, `tools/mutgate.py`, `.github/workflows/*`, the boundary tests (`childproc/gate_test.go`, `daemon/inference_test.go`, `clerk/devslot/conformance`, `clerk/camera/decode_test.go`), `broker/kernel/privfile`.

## Kinds that get a check (one row each)

| Row | Kind | Sightings | Why no check catches it today |
|---|---|---|---|
| REV-CHK-src | A boundary or import lint is evaded by a file it does not parse: assembly, cgo, `//go:linkname`, or a build-tagged file | #3356 (a driver's `.s` file opens a socket and the imports check passes), #3640 (non-Go sources across six rounds), #3754 (a `//go:build sometag` wrapper reaches `os/exec` past `TestOnlyChildprocStartsAProcess`), #3818 (a `#cgo` line behind a backslash-continued C comment), #3043 (core.txt type-check missed tagged files) | Each sighting was fixed inside the one lint that missed it. About 20 boundary tests under `broker/` read Go sources; four of them read `SFiles`/`CgoFiles`/ignored files, and the others do not. |
| REV-CHK-mut | A defence can be reverted and the suite still passes (a surviving mutant) | Potency README (#583, #585, #588, #589, #599); since cut 4: #2885, #3310, #3488 (`AddrHeads`' lying-connection checks untested), #3554 (delta mutants), #3177 (third_party, outside tier A) | `tools/mutgate.py` (MUT-tierA, #1814) and `tests/test_mutgate.py` exist, but no workflow runs them. Every mutant above was found by hand. |
| REV-CHK-links | A root-side file operation follows a link a guest, clerk or other uid planted | Security README (#584, #588; check still "to add"); since cut 4: #3282 (a hard link of a root socket into the routes directory), #3382 (UMask and service-directory links), #3624 (a store directory that is a symlink) | `privfile.Check` refuses a symlink for callers that use it, but 30-odd non-test files hand-roll `O_NOFOLLOW` or call path-based `os.*`, and nothing says which root-side calls must go through it. |
| REV-CHK-names | A name or label check accepts blank, invisible or invalid-UTF-8 text | #3284 (printable-but-invisible characters pass the kernel's `shape()`), #3438 (`Named` accepts a blank or invalid-UTF-8 query), #3871 (ENF-wifi-name: a Wi-Fi identity that is not a name token) | Each parser has its own predicate (21 non-test files call `utf8.ValidString`; `follow/name.go`, `kernel/state.go`, `enforcer/...` each differ) and its own hand-picked bad inputs. |
| REV-CHK-crlf | A gate-list or workflow parser reads a lone CR (or another line break) as a line end, so a line means other than it shows | #1347 and #1583 (`lane-gate.yml`: a `\r` hidden in a comment), #3721 (a lone `\r` in the G2 list passes the CLI through `read_text()`, raised by both L3 and Security) | `g1_scope.py` and `tests/test_workflows.py` now refuse it; the other list readers in `tools/` (`risk_tier`, `trusted_base`, `premerge`, `assumptions_ids`, `ci_scope`, `old_core`/`trusted_core` readers) are unchecked. |
| REV-CHK-save | A failed or interrupted save leaves memory, disk and what was told disagreeing | #3311 (a re-seal not retried after a failed put), #3444 (a crash between the kernel's dispatch and the clerk's switch), #3476 (a save rolled back while the lock was released), #3434 (rolling back to a lower cap), #3868 (a turn-on whose save fails leaves the gate on), #3881 (a restart forgets a may-have-been-sent text) | `privfile.WriteAtomic` has a crash hook (`stop`), but no check requires a caller's package to test it; each package grew its own fault store (`flakyStore`, `failPut`, ...) after review found the hole. |

## Kinds considered, no row

- **A revoked, spent or cancelled signed item is accepted again** (#3137 ES256 re-encoded signature, #3678 plan id replayed with a fresh seq, #3697 a cancelled loosening re-accepted): each instance needs the item's identity rule, which no mechanical check knows. Held by review; the Security lens README should carry this sentence as the entry (OPERATING §4), in the next PR that edits it.
- **A hostile peer that stalls or floods holds a lock or turn** (#3077, #3601, #3612, #3642, #3846): recurring, but the probes share no surface; a stall harness would be a new component with one caller per protocol. Revisit if a fourth protocol hits it.
- **A test writes `time.Local`** (#3181, #3865): already filed as #3886.
- **A DECISIONS cell over 300 characters** (#3330, #3537, D-203): `doclint.py` already catches it; the rework is builders not running doclint before pushing, which the builder skill covers.
- The Potency README's "a brief's scope omits the test files the change forces" and the UX README's CH-12 rows name old-core packages (`loops`, `machprobe`) that D-139 freezes; no post-cut-4 sighting was found, so no row.

## Shared rules (every row)

- Load the `agentos-builder` skill; claim the row's issue with `state:building`.
- A check lands with a mutation subtest: each shape it must refuse is fed through it on a synthetic instance and fails, and the clean tree passes (positive control). A check that passes on its own revert is not done.
- The row's PR adds the kind to "Checks that replaced findings" in the lens README named below and removes it from "Recurring kinds" there. `reviews/*/README.md` and `.github/` are gate files (`premerge.py --needs-mark` prints `mark`), so these PRs need the separate Security accept (D-137).
- Each check states its bound in that README entry: what it catches, and what stays held by review.
- G2 freeze: `tools/`, `tests/`, `.github/`, `reviews/` and `briefs/` are on the G2 list. A row that adds a file under `broker/` checks `tools/g1_scope.py` at claim time and, if the path is frozen, gets an `exempt-pr` line (D-198), batched with any other pending exemption.
- D-111: re-check open PRs' files at claim time; the scopes below were disjoint from every open PR at 2026-10-29 18:35Z (dispatch survey).

## REV-CHK-src: plain-Go source lint for `broker/`

**Scope:** `tools/srclint.py` (new), `tools/srclint_allow.txt` (new), `tests/test_srclint.py` (new), one step in `.github/workflows/ci.yml`.
**Do:** fail when any file under `broker/` outside `vendor/`, `third_party/` and `testdata/` that some build could compile into a non-test package is not plain Go: a `.s`, `.c`, `.h`, `.cc`, `.syso` or other non-Go source; a `.go` file with `import "C"`, a `#cgo` line in any comment form, or `//go:linkname`; or a build constraint naming a tag outside the set the repo's workflows and image build pass (today `linux`, `amd64`, `arm64`, `race`, `ignore`, `agentos_e2e`, `agentos_box`, `infer_llamacpp`, `libavcodec`, `vision_onnx`; read the set from the workflows and `image/`, not a hand list). Each exception is one allow line with a path and a reason (today `cmd/agentos-camdecode/camdecode/h264.go`). A stale allow line fails. With this in place, every boundary lint holds for the files it parses, so they do not each need to read `SFiles` and `CgoFiles`.
**Bound:** reflection, `unsafe` and raw syscalls stay held by review (childproc r8 l1, l2).
**Lens README:** Security.
**Requirement IDs:** KRN-2 (the trusted base the import lints bound).
**Acceptance tests:** `tests/test_srclint.py::test_refuses_each_shape` (a synthetic tree with an assembly file, a cgo import, a `#cgo` behind a backslash-continued C comment, a `go:linkname`, an unknown-tag file and a `.syso` each fails, with the path named), `::test_main_is_clean` (the real tree passes), `::test_stale_allow_line_fails`, `::test_tag_set_comes_from_the_builds` (a workflow that adds `-tags newtag` admits it; removing it makes a `newtag` file fail).
**Size:** S. **Model:** Opus 5.5 (it guards tier-A boundaries).

## REV-CHK-mut: run the mutation gate in CI

**Scope:** `.github/workflows/mutgate.yml` (new), `tools/mutgate.py` and `tests/test_mutgate.py` if the run step needs a change, `tests/test_workflows.py` (a pin for the new workflow).
**Do:** on a PR that touches a tier-A broker package (`mutgate.py packages`), run gremlins (pinned `v0.6.0`, as the tool's docstring says) on only the touched packages, then `mutgate.py gate` against the base; the job fails the PR's checks, so the existing merge rule (CI green) enforces it. Record the run time on the first three PRs in the PR body; if a package takes more than 15 minutes, shard by package as `broker-race` does rather than dropping it.
**Bound:** the gate fires only where the diff adds a `REQ:` marker and a covered line on which a mutant lives (the tool's existing claim). Non-tier-A code (#3177's `third_party`) and uncovered code stay held by review.
**Lens README:** Potency (it owns the surviving-mutant kind).
**Requirement IDs:** none: assurance tooling (D-086).
**Acceptance tests:** `tests/test_workflows.py::test_mutgate_runs_only_on_touched_tier_a_packages` (the workflow's package list comes from the diff and `mutgate.py packages`; a PR touching only `docs/` runs nothing), `tests/test_mutgate.py::test_gate_fails_a_marked_live_line` (exists; keep green), and one live run on a branch that adds a `REQ:` line over a known survivor (e.g. #3488's `AddrHeads` check before its fix) and fails.
**Size:** S. **Model:** Sonnet 5.5 (tier C tooling) unless `risk_tier.py` says otherwise.

## REV-CHK-links: root-side path operations go through `privfile`

**Scope:** a lint test beside `broker/kernel/privfile` (new `pathops_lint_test.go`), its allow file, and the call sites it forces to change in the packages it covers (expect a handful; list them in the PR; if more than ten, split by package and file the rest as rows).
**Do:** derive the root-side set mechanically: the binaries whose systemd unit under `image/` has no `User=`, and the non-test packages they link (`go list -deps`). In those packages, fail any path-based `os` call that can follow a link (`Open`, `OpenFile`, `Create`, `ReadFile`, `WriteFile`, `Remove`, `RemoveAll`, `Rename`, `Chmod`, `Chown`, `Mkdir`, `MkdirAll`, `Stat`, `Link`) unless it goes through `privfile` or an `openat2`/`O_NOFOLLOW` helper, or its call site has an allow entry with the reason (for example "the directory is root-owned 0700 and no other uid writes it").
**Bound:** an allow entry's reason is checked by review; links planted through a path the check deems safe (a parent directory another uid can write) stay held by review.
**Lens README:** Security (it closes that README's open "follows a link" row).
**Requirement IDs:** KRN-2.
**Acceptance tests:** `TestRootSidePathOpsGoThroughPrivfile` (a synthetic root-side package calling `os.Remove` on a joined path fails; the same call through `privfile` passes), `TestRootSideSetComesFromTheUnits` (adding a unit without `User=` brings its binary's packages into the set), `TestStaleAllowEntryFails`.
**Size:** M. **Model:** Opus 5.5 (tier A).

## REV-CHK-names: one hostile-text corpus for every name check

**Scope:** a new test-only package `broker/internal/hostiletext/` (the corpus and a `Run(t, accept func(string) bool)` helper), and one test in each package with a name or label check: `broker/kernel` (`shape`), `broker/follow` (`name.go`), `broker/enforcer` (Wi-Fi name), and the `Named` query from #3438 (find its package at claim time).
**Do:** the corpus holds, at least: empty, whitespace-only, NBSP-only, zero-width (U+200B, U+200C, U+200D, U+2060, U+FEFF), bidi controls (U+202A to U+202E, U+2066 to U+2069), tag characters (U+E0000 block), lone CR, LF, U+0085, U+2028, NUL, other C0 and C1 controls, invalid UTF-8 (`\xff`, an overlong `\xc0\xaf`, a lone surrogate encoding), each also embedded inside a valid name. `Run` asserts every entry is refused and that a plain token is accepted (positive control). A lint test in the package fails when a non-test broker file defines a function named like a name check (`shape`, `*Name`, `valid*Name*`) that no test passes to `Run`.
**Bound:** a check under another name is held by review; the lint's name list is in its doc comment.
**Lens README:** Security.
**Requirement IDs:** none new; each package's test cites the IDs its check already serves.
**Acceptance tests:** `broker/internal/hostiletext::TestRunFailsAnAcceptingCheck` (an `accept` that allows a zero-width name fails `Run`), the per-package `TestNameCheckRefusesHostileText` in each of the four packages, `TestEveryNameCheckRunsTheCorpus` (a synthetic `validFooName` with no `Run` caller fails).
**Size:** M. **Model:** Opus 5.5 (the kernel and enforcer are tier A).

## REV-CHK-crlf: every gate-list reader refuses hidden line breaks

**Scope:** `tests/test_list_readers.py` (new), and the readers in `tools/` it shows to accept (`risk_tier.py`, `trusted_base.py`, `premerge.py`, `assumptions_ids.py`, `ci_scope.py` and any other that reads a list in `tools/*.txt` or `broker/core/core.txt`).
**Do:** for each list file and the function that reads it, write a copy with each of `\r` alone, `\r\n`, U+0085, U+2028, U+2029, NUL and a form feed inside a line, and assert the reader refuses (raises or exits non-zero) naming the line; the unmodified file parses. A reader that accepts is fixed in the same PR, reading bytes or `newline=""` and refusing as `g1_scope.py` does.
**Bound:** files that are not gate lists stay out.
**Lens README:** Security.
**Requirement IDs:** none: assurance tooling (D-086).
**Acceptance tests:** `tests/test_list_readers.py::test_each_reader_refuses_hidden_breaks` (parametrised over reader and break; fails today on at least one reader, or the PR says which reader already refused each case), `::test_each_list_parses_clean`, `::test_every_list_file_has_a_reader_case` (a new `tools/*.txt` with no case fails).
**Size:** S. **Model:** Opus 5.5 (it touches `risk_tier.py`, `trusted_base.py` and `premerge.py`, which are gate files).

## REV-CHK-save: every atomic-save caller tests the crash

**Scope:** a lint test beside `broker/kernel/privfile` (new `crashtest_lint_test.go`); no production change unless a caller has no way to pass `stop` in a test, in which case the PR adds that seam to that caller only.
**Do:** fail when a non-test package calls `privfile.WriteAtomic` and none of its tests reaches that call with a non-nil `stop` (static: the call site's `stop` argument is a field or parameter, not a literal `nil`, and a `_test.go` file in the package sets it). The check covers the disk side only.
**Bound:** whether memory and what the owner was told agree after the failure (the substance of #3311, #3476, #3868, #3881) stays held by review; the lint makes the failure path exist in the suite so the review has a test to extend.
**Lens README:** Security.
**Requirement IDs:** none new: each caller's test cites the IDs its save already serves.
**Acceptance tests:** `TestEveryWriteAtomicCallerTestsACrash` (a synthetic package with a `WriteAtomic(dir, name, b, nil)` call and no test fails; with a test-set `stop` field it passes), and a run over main listing the callers that fail today in the PR body.
**Size:** S. **Model:** Opus 5.5 (tier A package). File as `class:later` with `recheck`: its bound is narrower than the kind.

## Order

None depends on another. REV-CHK-src and REV-CHK-crlf are the cheapest and close false-pass kinds, so dispatch them first. REV-CHK-src and REV-CHK-mut both edit `.github/workflows/`, but different files.
