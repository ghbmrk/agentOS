# KEY-9-reach-inbound-wiring: count the root-run page admit step in the trusted core

Board section: Owner channel and approvals (SPEC §10). Work item #5678, a release finding on #5677 (KEY-9-reach-b2-cut, #5671). Starts after #5677 merges: its files (`broker/cmd/agentos-localui`, `broker/localui`, `broker/netguard/inbound`) are this row's scope.

**Requirements:** KRN-2 (the trusted base is measured, and only shrinks), D-310 (the trusted-lines ceiling), HW12-port1-set, CH-9, HW-12 (behaviour kept, not changed).

**The gap.** `agentos-localui.service` runs `ExecStartPre=+/usr/lib/agentos/agentos-localui -admit-port1 …` as root at every page start. That step picks port 1 from sysfs (`localui.Port1`, read twice by `settledPort1`), checks a named one (`localui.Wired`), renders `inbound.InboundPageAdmit` and loads it with `nft -f`. Nothing it runs is in `tools/trusted_core.txt`'s roots, so a change to `Port1`, `Wired`, `ifaceRe` or `InboundPageAdmit` that puts a wrong name in the page set grows no measured line and needs no core-scoped review. Running it from `agentos-localui` also runs, as root, every `init` of the ~2,200-line page binary's whole import graph (localui, change, card, firstboot, localapi and the rest).

**Decision taken here (recommendation, open to L3).** Make the root step its own small binary and count exactly it, rather than either alternative:

| Option | Counted | Root-run code outside the count | Trusted lines |
|---|---|---|---|
| `root cmd/agentos-localui` | the whole page binary | none | thousands, plus many `known` lines (each needs a Mark decision): over the ceiling |
| `root netguard/inbound` only | 252 (all of `inbound`, most of it the static ruleset renderer no root step runs) | `Port1`, `Wired`, `settledPort1`, the port1 file write, and the page binary's inits | +252 |
| **new binary + one small package as roots** | only what root runs | none | about +200 (estimate) |

Use `tools/trusted_core.txt` (`root` lines), not `broker/core/core.txt`: open PR #5670 edits core.txt, and a `wiring` line there only feeds the unbudgeted trusted-process report. Adding a `root` line needs no `Trusted-core:` decision (only adding a `known` or `allow` line or dropping a root does; `trusted_base.py` checks exactly those). The design must add no `known` line: the new roots link only the standard library.

**Build.**
1. New package `broker/netguard/port1` (tier A by the `netguard` prefix): `Port1`, `Wired` and their helpers moved from `broker/localui/wired.go`; `Settled` (today's `settledPort1`); `Admit` (today's `InboundPageAdmit`, its interface-name check and the table and page-set names it renders); and `Write` (today's `O_EXCL|O_NOFOLLOW` 0644 port1 file write). Standard library only. One source for each name: `netguard/inbound` keeps its exported names as aliases or wrappers of `port1`'s (`inbound` importing `port1` is fine; the reverse is not), and `localui` and `agentos-localui` call `port1.Port1` and `port1.Wired` instead of their own copies. Move code; don't change it.
2. New binary `broker/cmd/agentos-port1` (tier A by the `cmd` prefix): today's `admitPort1` and `runNft`, with the same flags (`-iface`, `-port1-file`) and the same messages. `runNft` uses `os/exec` with `/usr/sbin/nft -f -`, an empty `Env` and the script on stdin, not `childproc` (361 lines and a `known` line); say in ASSUMPTIONS why that is enough for a root `ExecStartPre` under systemd (no inherited descriptors beyond 0–2, fixed absolute path, no environment).
3. `tools/trusted_core.txt`: `root netguard/port1` and `root cmd/agentos-port1`, with a comment naming #5678 and the unit line that runs them.
4. Wire it: `agentos-localui.service` `ExecStartPre=+/usr/lib/agentos/agentos-port1 -port1-file /run/agentos-localui/port1`; `image/build.sh` builds and installs `agentos-port1`; `image/mkosi/mkosi.finalize`'s unit check, `broker/e2e/boxe2e`'s drop-in, `Port1`'s two-ports message and every test that names the old line follow. `agentos-localui` drops `-admit-port1`; given the flag, it exits non-zero naming the replacement line (see the update stage).
5. Offset (D-310). Main has 381 lines of room after #5677, earmarked for b2a (#5672, ~180) and b2b (#5673, ~120); both briefs cut any shortfall themselves. This row must end under the ceiling at its base (the CI check), and should land at or below the base measure so the earmark holds: take the cut from #5677's noted candidates, `kernel/proc`'s `Owner` and `Content` client types (~280 lines, unreached by any binary; their users are tests in `owner/kernelsock` and `cmd/agentos-unlock`), moved to an untrusted package or test files, if no open PR touches `broker/kernel/proc` at build time. Otherwise land the growth inside the room and say so in the PR.

**Lifecycle (integration owner: this package).** The step runs at every page start; the outcomes are unchanged except who runs them.

| Stage | Outcome |
|---|---|
| First boot / start | `agentos-port1` admits port 1 alone into `inet agentos_inbound page`, writes its name to the port1 file; the page serves only on that port |
| Restart (unit restart, #4882 port change) | the step re-runs; the `O_EXCL` write fails closed if a stale file survives (RuntimeDirectory is cleared by systemd, as today) |
| Update (image with the new unit) | the shipped unit uses `agentos-port1`. A box with an owner drop-in still naming `agentos-localui -admit-port1 -iface X` fails closed: the page serves nothing and the journal names the replacement line. Record in `cmd/agentos-port1/ASSUMPTIONS.md` that no owner box carries such a drop-in today (the drop-in is only needed on two-port boards) |
| Stop | `ExecStopPost` flushes the page set, unchanged |
| Failure in the step | no file is written, the page refuses to serve (`servedPort1`), unchanged |

**Scope:** `broker/netguard/port1/` (new), `broker/cmd/agentos-port1/` (new), `broker/netguard/inbound/inbound.go` and its test, `broker/localui/wired.go`, `broker/localui/wired_test.go`, `broker/localui/ASSUMPTIONS.md`, `broker/cmd/agentos-localui/` (main, test, service, ASSUMPTIONS), `broker/e2e/boxe2e/main_linux.go`, `image/build.sh`, `image/mkosi/mkosi.finalize`, `image/mkosi/made.allow` and `tests/test_image.py` if they name the binary list, `tools/trusted_core.txt`, and for the offset `broker/kernel/proc/` client files, their test users and the new untrusted package; `tools/risk_tier.py` and `broker/daemon/arc2_test.go` only as guard files below; this brief.

**Guard files:** `tools/risk_tier.py` needs no entry (`netguard/*` and `cmd/*` are tier A by prefix); a class for the offset's new untrusted package if one is made; `broker/daemon/arc2_test.go` import rules only if its planes test asks for the new packages. All pre-approved here.

**Acceptance tests:**
- KRN-2: `tools/trusted_base.py measure` lists `netguard/port1` and `cmd/agentos-port1` as roots with no new `known` line; evidence in the PR body (before and after, from #5677's merge on main). A new test in `tests/` (or the existing trusted-core test) fails if `agentos-localui.service`'s `ExecStartPre=+` names a binary that is not a `root` of `tools/trusted_core.txt`: this catches the next root step added outside the count.
- HW12-port1-set: `cmd/agentos-port1` tests carry today's `admitPort1` cases from `agentos-localui/main_test.go` (settled port 1, named port must be wired, link or existing file refused, nft failure leaves no file, one name in the set); they fail if the move drops a check.
- CH-9 / HW-12: `netguard/port1` carries today's `Port1`, `Wired` and `InboundPageAdmit` tests (USB, Thunderbolt, removable, radio, two ports, bad names); `inbound`'s ruleset tests still pass against the aliased names.
- Update stage: `agentos-localui -admit-port1` exits non-zero with a message naming `agentos-port1`; `mkosi.finalize`'s unit check and `tests/test_image.py` fail on the old line.
- D-310: the `trusted-base` CI check passes (measure under the ceiling).

**Tier / gate:** tier A, and a gate file (`tools/trusted_core.txt`; `premerge.py --needs-mark` prints `mark`): L3 and a separate Security accept from a fresh session. One session, strongest model; estimate 110k tokens (90k without the offset). Split the offset into its own row if the build passes 120k before it starts.
