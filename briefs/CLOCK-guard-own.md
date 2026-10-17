# CLOCK-guard-own: the clock guard opens as its own dependency and fails closed

Work item: #1246 (release, tier A). Source: Mark-approved simplification, project Questions thread, 2026-10-13.

## Scope

`broker/cmd/agentosd/questions.go`, its tests (`questions_test.go`, and the nil-guard expectation in `sleepsec_test.go`), and one section in `broker/cmd/agentosd/ASSUMPTIONS.md`. Tier A: every binary in `broker/cmd`. **Guard files:** none (no package added or linked).

## Problem

TIM-1 fails open. `questions.open` creates the box clock guard, then the question book; only when both succeed is the guard stored. A question store that fails to load (or no owner channel, which returns before the guard is made) leaves `q.g` nil, so `restricted()` is false: the sleeper sleeps on an unchecked box clock, and STATUS's `Clock` note is empty, so nothing shows.

## Change

- `openClock` opens the guard, stores it and starts its loop. `open` calls it first, before the owner-channel check and `question.New`, so the guard runs whatever happens to the book. The book still takes `guard.Now`.
- `restricted()` is true when no guard is open (not yet, or `clock.New` failed): an unopened guard reads as restricted.
- `Clock()` with no guard returns `Time check: not running (time-sensitive checks restricted).`, so STATUS shows the restriction.
- `main.go` is unchanged: the sleeper is wired after `qs.start`, and follow (OSS-10) already treats a nil guard as "nothing followed".

**Acceptance tests:**
- TIM-1: `broker/cmd/agentosd/questions_test.go::TestTheClockGuardOutlivesAQuestionStoreFailure`: a corrupt `questions.json` with an unreadable `clock.json`, with and without an owner channel; questions are off, yet the guard is open, the sleeper's `clock` check holds and STATUS shows `Time check: restricted since`. An unopened `questions` restricts and shows `not running`. Fails without the change (restricted() false, empty line).
- TIM-1: `sleepsec_test.go::TestSleepWorkChecks` now pins that an unopened guard holds the agent awake and an agreeing one does not.

Failure path: a corrupt question store lets the agent sleep on a box clock no check has confirmed.

## Handoff and estimate

One session, under 60k tokens. L3 and Security reviews on the strongest model.
