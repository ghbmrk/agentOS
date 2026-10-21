# KRN-cosign: a big change needs a second passkey

Work item: D-146 item 5 (the hardware-key plan Mark approved 2026-10-21 13:32:42Z). Tier A. It follows KRN-passkey (#2663) on the same branch.

## Goal

A tricked or stolen phone passkey cannot alone hand out big new power. A big change needs two enrolled passkeys, one of them an anchor (a hardware key). Each rule sits at its enforcement point and fails closed:

1. **Big grants.** A grant batch is big when, with the grants still in their hold, it gives any holder a verb it lacked or a daily budget past the owner's line (default more than double), against the live grants. A holder's budget at a clerk adds up each root's largest cap. A big batch is granted whole only when two passkeys, one an anchor, co-sign the whole batch; the keys' own signatures do not count. `Issue` and the fold share the check. Failure path: one phone tap grants the home clerk a new verb or ten times its budget.
2. **Very large one-offs.** A one-off under a bare root that spends more than the line times the largest live daily cap of a clerk key under that root needs a co-signature over that plan. `Admit` and `clerk.Check` both check it. Failure path: one phone tap spends without limit through the bare root.
3. **The line.** The owner sets the line (`SetLine`, at least 100%). Raising it is itself big. Each co-signature names the count of changes so far, so it cannot be replayed. Lowering it narrows. Failure path: one tap raises the line, and every later grant passes as small.

Also: SPEC KEY-4 names a root's holders as the enrolled passkeys, as the code has it since #2663.

Out of scope: the ceremony that collects the hardware key's tap and the owner notice (#2643), and the follow-ups in #2670. Known limit (CLK-2): for a key under a granted root the clerk's owner set includes cut-off passkeys, so a kernel that is compromised and also holds a lost phone's private key could report a grant that phone signed after it was cut off; the clerk cannot date a signature without the log, and an honest kernel refuses it.

## Scope

`broker/kernel/`, `broker/clerk/`, `broker/browser/` (its test fixture), `briefs/KRN-cosign.md`, `decisions/D-146.md`, `SPEC.md` (KEY-4 wording).

**Guard files:** none (no new package).

## Acceptance tests

- KEY-4, KEY-6, ID-1, D-146: `broker/kernel/cosign_test.go::TestABigGrantNeedsASecondPasskey`, `::TestTheLineDecidesWhatIsBig`, `::TestNewRootsAddToTheBudgetTheLineMeasures`, `::TestRaisingTheLineNeedsTwoPasskeys`, `::TestAVeryLargeOneOffNeedsASecondPasskey`
- CLK-2, D-146: `broker/clerk/clerk_test.go::TestClerkRefusesAVeryLargeOneOffWithoutASecondPasskey`
- EVL-1: `broker/kernel/sim/sim_test.go::TestSweepFaultsTakeEffect` (big grants refused without a second passkey) and `::TestSweepHoldsInvariants` (a co-signed batch is never refused)

## Estimate

About 100k tokens, single session.
