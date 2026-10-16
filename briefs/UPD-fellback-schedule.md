# UPD-fellback-schedule: refuse a fallen-back release in `schedule()`

Work item #1924 (release, tier A). Source: state-machine audit 2026-10-16, §2.4 and R2b.

## Goal

A release that fell back on this box is never handed to the activator again through `Schedule`, only through a newer release. Today only `ScheduleFirstBoot` checks `FellBack`; `Schedule` checks `ErrRetired` but not `FellBack`. The applier relies on Loop 3 never re-proposing the release (`broker/apply/ASSUMPTIONS.md` A1), while the owner-facing fallback line already promises "It won't be tried again". The fix moves the check into the shared path, under the applier lock, so both entry points refuse it structurally.

## Requirement IDs

UPD-1 (automatic fallback; the box must not boot-loop into a bad release), UPD-6.

## Outcomes by stage

| Stage | Outcome |
|---|---|
| `Schedule` of a fallen-back version, new adoption | `ErrFellBack`; the adoption is retired and settled with `StageDropped` (A5's refusal rule); nothing pending; `Tick` installs nothing |
| `Schedule` of a fallen-back version after a process restart | same (FellBack is saved state) |
| `Schedule` of a newer version after a fallback | admitted as before |
| `ScheduleFirstBoot` of a fallen-back version | `ErrFellBack`, unchanged |

## Acceptance tests

**Acceptance tests:** `broker/apply/fellback_test.go` (two tests below; the first fails on main).

- UPD-1: `broker/apply/fellback_test.go::TestScheduleRefusesAFallenBackRelease` — fall release 1 back under adoption a1, restart, `Schedule(1, "a2")` returns `ErrFellBack`, a2 is dropped, `Tick` hands nothing over. Fails on main (Schedule admits it and Tick installs it a second time).
- UPD-1: `broker/apply/fellback_test.go::TestScheduleAdmitsANewerReleaseAfterAFallback` — release 2 is still admitted and installs; catches an over-broad check.
- UPD-3 (regression): `broker/apply/firstboot_test.go::TestFirstBootFallbackIsRememberedAndNotRetried` keeps passing.

## Scope

`broker/apply/apply.go`, `broker/apply/fellback_test.go` (new), `broker/apply/settle_test.go` (three tests that rescheduled a fallen-back release now assert the refusal and clear the record to stand in for a later release), `broker/apply/ASSUMPTIONS.md`, `briefs/UPD-fellback-schedule.md`. Tier A (update path). All on the G1 list (`tools/g1_scope.py`).

**Guard files:** none (no new package).

## Out of scope

An owner retry of a fallen-back release (A1 asks the wiring for one; `Retry` clears only the unrecorded count). Filed as `class:later`.

## Estimate

Small: one check, two tests, one ASSUMPTIONS edit. Under 60k tokens.
