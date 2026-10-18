# W5-Dc-r23: the Wi-Fi page waiting notice goes out as an approval-class text

Work item: #989 (release, tier A). Source: lens 6087280647 pt 3 on #652. This brief also records the disposition of the other seven W5-Dc rows dispatched with it (#981, #982, #983, #985, #986, #987, #988); none of them is built here.

## Scope

`broker/grants/gate.go` (the `Owner` interface and the one notice in `Submit`'s hold path), `broker/grants/rig_test.go` (the fake owner records each text's class), the two other fakes of the interface (`broker/mail/gate_test.go`, `broker/cmd/agentosd/mail_test.go`, a no-op `Post`), a new `broker/grants/noticeclass_test.go`, one row (GR37) in `broker/grants/ASSUMPTIONS.md`, and the PW2 row of `broker/cmd/agentosd/ASSUMPTIONS.md`, whose limitation this closes. Tier A: grants and owner pacing.

**Guard files:** none (no new package).

## Problem

When a change or grant can only be confirmed on the local Wi-Fi page (or with the recovery key), the gate texts the owner once: "Waiting for your confirmation on my Wi-Fi page, or your recovery key." It sends that through `Owner.Inform`, which `owner.Channel` posts as `ClassUpdate`. Update texts are never urgent, so in quiet hours the notice is held and the owner may first see it after the request has expired (CH-15, CH-12). The grants `Owner` interface has no way to name a class (agentosd ASSUMPTIONS PW2).

## Change

Add `Post(class owner.Class, text string) error` to the grants `Owner` interface; `owner.Channel` already has it, so the daemon wiring is unchanged. Send the waiting notice with `Post(owner.ClassApproval, ...)`. Approval is the class every other owner request from the gate uses, so the notice is paced exactly like the request it announces: urgent in quiet hours when the owner has made approvals urgent, held otherwise, and never later than the request itself. `security` was the other option the issue names; it would break quiet hours for every page-only change, which the owner did not ask for. The other `Inform` notices (outcomes and reports) stay `update`.

**Acceptance tests:** CH-15, CH-12: `TestPageWaitNoticeIsApprovalClass` (`broker/grants/noticeclass_test.go`) proposes a release with no local UI, flushes, and checks the one notice was posted as `owner.ClassApproval`, not through `Inform`. It fails before the change (the notice is recorded as `ClassUpdate`).

Failure path: in quiet hours the notice is held as an update and released after the request it announces has expired.

## Other rows dispatched with this package

None is done on main. None is built here, for these reasons:

| Row | Issue | Disposition |
|---|---|---|
| r15 hold eviction priority | #986 | Built inside SIM-owner-hold (#764), which rewrites the hold (D-095; briefs/SIM.md lists r15). |
| r16 held-text visibility | #987 | Built inside SIM-owner-hold (#764) (D-095; briefs/SIM.md lists r16). |
| r17 forget reach into the hold | #988 | Built inside SIM-owner-hold (#764) (D-095; briefs/SIM.md lists r17). |
| r5 source-side forget end to end | #983 | Built inside SIM-erase (#768) (D-095; briefs/SIM.md lists r5). |
| r2 digest time default | #981 | L1 spec diff, needs Mark. SIM-pull (#765) deletes the digest, which makes it moot once merged; recommend retiring it then. |
| r3 digest store outage line | #982 | L1 spec diff, needs Mark; moot after SIM-pull for the same reason. |
| r14 W5-Dc-r1 provisional choices | #985 | L1 spec diff, needs Mark; overlaps SIM-sd (#761), which rewrites CH-15; recommend folding it into SIM-sd. |

## Handoff and estimate

One session, under 60k tokens. L3 and Security reviews on the strongest model.
