# FIRSTBOOT-text: first-boot gate wording

Board section: none. This is a LATER.md row (L3 on #379, points 3-5), started at the coordinator's request on 2026-10-09, a deviation from D-048 (LATER rows wait for the first release). Owner confirmation of the exception is pending; the PR does not merge before it.

**Needs:** UPD-3 (merged in #379). No new requirement IDs; the tests below claim UPD-3 and CH-21.

## Scope (files that may change)
- `broker/firstboot/firstboot.go` (wording and failure classification only)
- `broker/firstboot/firstboot_test.go`
- `broker/firstboot/ASSUMPTIONS.md` (one row)
- `briefs/FIRSTBOOT-text.md`, `LATER.md` (remove the row)

Out of scope: gate behaviour. `Step`, `Hold`, `Trusted` and `Progress` keep the same open/held outcomes and the same returned errors.

## Requirements and acceptance tests
All text is first person (CH-21): "I", never "the box". `broker/voice` already lints this.

1. **Point 3.** An unexpected `ScheduleFirstBoot` error (not `ErrApplying`, not `ErrFellBack`) no longer reads "updating to version N". STATUS says update N could not be started and that I will try again; `Hold()` gives a matching reason. The error is still returned; the gate stays held. Test pins STATUS and the `Hold()` text exactly.
2. **Point 4.** With several mirrors failing, STATUS reflects all of them, not the last. Unverified then unreachable, and unreachable then unverified, give the same mixed message; all-unverified and all-unreachable keep their current messages. Test pins the mixed text exactly, in both orders.
3. **Point 5.** In `fell_back`, `Hold()` and `Status()` give the same wait: AI and accounts stay closed until a newer update is out. Test pins both texts.
4. Existing pinned texts (offline, unreached, unverified, installing, fell back, starting) are unchanged; the test pins each.

## Usage estimate
About 40k tokens, tier B expected (text only), Sonnet-class builder.
