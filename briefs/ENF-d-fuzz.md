# ENF-d-fuzz: the enforcer's fuzz targets run in CI's fuzz loop and the soak

Board section: Devices, hardware and image (SPEC §13-14). Work item #3749, item 1, a later finding from ENF-d (#3660). Item 2, which registers `broker/enforcer/wire` in `tools/trusted_base_parsers.txt`, applies only once the kernel links that package. It moves to ENF-o (#3673), the row that links it, and this PR's body says so on #3749.

**Problem, checked on main 2c3ec6f2:** the enforcer has four fuzz targets that decode bytes from outside the box or from a confined process: `enforcer/channel:FuzzParse` (the channel from the core), `enforcer/mdns:FuzzParse` (multicast DNS from home devices), `enforcer/radio:FuzzUp` (frames from a radio stack) and `enforcer/radio/ble:FuzzDecode` (BLE frames). None is in `.github/workflows/ci.yml`'s fuzz loop, and none is in `soak.yml`'s matrix, so only their seed corpora run, as unit tests. Meanwhile the loop still lists old-core targets.

**Requirements:** LOOP-7 / FUZZ-broker-ci (every decoder of untrusted bytes is fuzzed in CI), NET-2 Channel.

1. Add the four targets to the fuzz loop's `for t in …` list in `ci.yml` and to `soak.yml`'s target matrix. If a target needs root because its package's `TestMain` re-execs, give it its own step that runs as root, as the Thread step does, or leave it out with a named reason in the PR. Do not skip it silently.
2. Extend `FuzzStepTest` so that every `func Fuzz…` under `broker/enforcer/` is listed in both workflows, or appears in a named exemption list with its reason. That turns this finding into a check.

**Scope:** `.github/workflows/ci.yml` (the fuzz step's target list only), `.github/workflows/soak.yml` (the matrix only), `tests/test_ci_scope.py` (`FuzzStepTest`), this brief.

**Acceptance tests:**
- LOOP-7: `tests/test_ci_scope.py::FuzzStepTest::test_enforcer_fuzz_targets_listed`. Every enforcer fuzz function is in both workflows or exempted with a reason. Catches a new decoder that is never fuzzed.
- LOOP-7: the existing `FuzzStepTest::test_fuzz_step_targets_exist` passes with the new entries. Catches a misspelt target.
- The PR body shows one CI fuzz-step log line per new target, with its exec rate.

**Guard files:** `.github/workflows/ci.yml` and `.github/workflows/soak.yml`, one list each.

**Dependencies:** none. Several open PRs edit `ci.yml` in other steps, and under D-320 (#5956, open) that does not block the build.

**Tier / gate:** run `tools/risk_tier.py` (`.github/workflows/` rates A). L3 runs on the strongest model. If `premerge.py --needs-mark` prints `mark`, a separate Security accept is also needed.

**Usage estimate:** one session, about 40k.
