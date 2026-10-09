# RT-1: Risk tiers for the image, guest build and CI; unmatched paths default to B

Board section: Owner-benefit review (2026-10-09). Finding from the 2026-10-09 owner-benefit review (point 5), reproduced with the repository's own tool.

**Tier:** A (the change edits `tools/risk_tier.py`, which is tier A by its own rule). Strongest model. Small: about 80 lines with tests, about 40k tokens.

**Needs:** nothing. Start first: every later image package (IMG-1 to IMG-5, UPD-b3) is reviewed at the depth this sets.

## Today

`tools/risk_tier.py` matches tier A only under `broker/<TIER_A_BROKER>/`, `broker/go.mod`, `broker/go.sum`, `assurance/` and three `tools/` prefixes; tier B only under `broker/`, `guest/` and SPEC.md; anything else is C. So these print C at 9b4bf8a:

- `image/build.sh`, `image/finish_image.py`, `image/mkosi/**` (the A/B verity layout, the boot chain, `mkosi.finalize`'s tree check);
- `image/mkosi/mkosi.extra/usr/lib/systemd/system/agentosd.service` (the broker's privileges, `NoNewPrivileges`, cgroup delegation) and the other units there (`agentos-health`, `-fallback`, `-drive-id`, `-boot-report`);
- `.github/workflows/*.yml`, including `image.yml` (builds the shipped image, pins actions by SHA) and `ci.yml` (runs `risk_tier.py` and doclint, so an edit there can switch off the gates themselves);
- `.claude/settings.json` (agent permissions).

And these print B though they decide what the guest runs or installs: `guest/openclaw/package-lock.json`, `guest/openclaw/build-rootfs.sh`, `guest/openclaw/openclaw.json5`, `guest/*/launch.json`, `guest/builder/build-rootfs.sh`.

P2-1 (#41) merged as tier C for this reason. Packages that knew better declared A by hand (P3-4b-3r-confine-r3 for `NoNewPrivileges`); the tool should not depend on that.

## Requirements (local IDs)

- **RT-1a, tier A paths.** Add to tier A:
  - `image/` except `*.md` (README, ASSUMPTIONS) and `image/fuzz-targets.json`'s test-only use if the builder finds it is test-only (record the reason in a comment);
  - `.github/` (workflows and actions: they build the image, gate merges and push to main);
  - `.claude/` (agent permissions);
  - in `guest/`: `*/build-rootfs.sh`, `*/package.json`, `*/package-lock.json`, `*/launch.json`, `openclaw/openclaw.json5`;
  - any `*.service`, `*.socket`, `*.timer` or `*.conf` under a `systemd` directory outside `spikes/` (this covers `broker/cmd/agentos-localui/agentos-localui.service` and `broker/cmd/agentos-modem/agentos-modem.service`, already A through `cmd`, and any unit added later).
- **RT-1b, explicit tier C; unmatched paths are B.** Replace "anything else unmatched is C" with an explicit C list: top-level `*.md` other than SPEC.md, `docs/`, `briefs/`, `reviews/`, `decisions/`, `spikes/`, `tests/`, `tools/` (except the tier-A prefixes), `image/*.md`, `LEDGER.md`, `METRICS.md`, `TRACE.md`. Any path matching none of the rules is B. A new top-level directory then gets a lens pass until someone classes it.
- **RT-1c, docs follow the tool.** Update OPERATING §3's table to match (it already says the tool is authoritative) and the module docstring. CLAUDE.md is unchanged.

## Tests (`tests/test_risk_tier.py`, written first)

- Each path in "Today" above has the tier RT-1a gives it.
- Every file under `image/mkosi/` and every unit file found by walking the repo (outside `spikes/`) is A: the test walks the tree, so a new unit cannot slip in at C.
- A path under a made-up top-level directory (`newdir/x`) is B; `docs/x.md`, `briefs/x.md`, `tests/test_x.py` stay C; `image/README.md` is C.
- The existing cases still pass (the `TIER_A_BROKER` rename guard included).

## Scope

`tools/risk_tier.py`, `tests/test_risk_tier.py`, `docs/OPERATING.md` (§3 only), `tools/ASSUMPTIONS.md` (one row: why `.github/` is A, D-054's over-trigger trade).

## Not in scope

Re-reviewing what already merged at C: that is IMG-5. Enforcing the tier in CI (today the tier is only printed to the step summary): raise as `later` if the builder sees value.
