# SR3-4f-r1-f1: acceptance check for `Install` after an other-root boot

Work item: #776 (release, tier A). Source: Security on #647 (A12(4)) and the L3 delta point 1 on #647 (comment 6087139165).

## Scope

A new `broker/apply/activatortest` package (`disk.go`, `disk_test.go`); in `broker/apply/ASSUMPTIONS.md` the A4 and A12 rows; in `broker/apply/apply.go` the `Activator.Install` doc comment only; and the activator acceptance paragraph in `briefs/P2-1.md`. Tier A: the activator decides which `/usr` the box boots (UPD-1, UPD-1a).

## Problem

`broker/apply` A12 sets four conditions on the real activator after an other-root boot, and no brief names them, so P2-1 or W5b could land an activator without them. The worst is A12(4): an `Install` of N+1, booted on N-1 with N blessed and the default, that starts writing N's slot while N's blessed entry is still the default (or its removal is written but not synced) leaves a box whose default entry has no tries left pointing at a torn slot after a power cut. No test can catch that today: the only activator is the fake in `rig_test.go`.

## Change

`activatortest` models the ESP (entries with a try count or blessed, the default, a sync) and the two `/usr` slots (writes tear the slot until synced) as a `Disk` that a power cut stops before any step. `Violations` runs `Install` of N+1 on the A12 disk cut before each step in turn, then uncut, and checks both the synced and the written ESP after each cut: the booted slot is never written; the default is N-1's entry or an entry whose slot holds all of its image; no blessed entry points at a slot that does not hold its image; `Install` returns an error after the cut; and after a reboot onto the synced view an uncut `Install` finishes with N+1 counted and default on N's slot, N's entries gone and N-1 still blessed. `Check` fails a test with each violation. A reference activator in the test file passes it; P2-1's activator passes it over an adapter of its ESP and slot I/O (`briefs/P2-1.md`). A12(1) and (2) need the loader and stay on P2-1's QEMU acceptance. A12(4) and the doc comment say "durably (ESP written and synced)".

**Acceptance tests:** UPD-1, UPD-1a: `TestReferenceActivatorPasses` (`broker/apply/activatortest/disk_test.go`) shows the check can be passed; `TestCheckCatchesA12Defects` shows it fails an activator that writes the slot before retiring its entry, one that retires it without syncing the ESP, and one that takes the slot without the default as inactive (so writes the booted slot); `TestCheckCatchesNilAfterCut`, `TestCheckCatchesNoFinish` and `TestCutStopsEveryWrite` pin the harness itself.

Failure path: a power cut after the first byte of N's slot is written, with N's blessed entry still the synced default, boots a torn `/usr` with no fallback.

## Handoff and estimate

One session, under 100k tokens. L3 and Security reviews on the strongest model.
