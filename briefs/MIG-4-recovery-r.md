# MIG-4-recovery-r: replace the recovery key (REC-4) and the backup recipient with it, split into r1 to r4b

Work item: #3391. Tier A. Design: D-201 (Mark's option C on the Decisions 8 card, from the #3391 findings, issuecomment-6442114960). The row crosses four trust zones (the kernel, the keeper's root one-shots, the unlock step at boot, the owner side), so it splits into five sessions, each its own work item: r1 #3391, r2 #3407, r3 #3408, r4a #3409, r4b #3410. This file is the brief for all five; each builder reads the shared part and its own section.

## What is wrong today

Only enrollment writes `handoff.RecipientEntry` (`cmd/agentos-enroll/main.go`, `putRecipient`). There is no REC-4 rotation in the new core: the only rotation code is the frozen old vault's (`broker/recovery/rotate.go`, `broker/localui/rotwire.go`). So a box enrolled before MIG-4-recovery-e1 never gets a recipient, and a rotated recovery key would leave the kernel sealing backups to the retired key's recipient. On a running box no process holds the store key (STO-2a-e) and the tpm slot unseals nothing after the unlock step's cap (#2977), so only a factor from the Owner Card, or the next boot's unlock, can open the store.

## Shared decisions

1. **Two routes (D-201).** Route A, the everyday one: on the running box the owner scans the store passphrase (or types the current recovery key), confirms the new card, and taps a hardware key; a root one-shot opens the store with that factor and commits; the kernel switches at once. No restart, and nothing changes before the owner has confirmed the new card. Route B, only when the whole card is lost: the owner taps a hardware key, the box restarts, and `agentos-unlock`, which has the store open through the TPM, makes the new key and commits; the page then shows the new card. Route B changes the slot before the owner confirms; that is the price of having no card factor.
2. **The kernel is the only checker of the owner's hardware keys.** The owner's anchors live in the kernel's log (`State.Anchors`); the store's `kernel/anchors` entry has no production writer. So neither root step reads anchors. The kernel checks the anchor cosign over `kernel.RecoveryRotateHash(old, next)`, logs the approval, and returns an **approval** signed with its head key, which the root steps verify with `st.HeadKey().Public()` from the store they just opened. One key-check library (KRN-2), no anchor list outside the kernel.
3. **What the approval binds.** `old` is the recipient ID the store and kernel hold now (`backup.Recipient.ID()`, or `""` for a store enrolled before e1); `next` is the new key's recipient ID for route A, `""` for route B (the key does not exist yet). The approval is `{v, route, old, next, expires}` under a domain tag (`agentos-recovery-rotate/v1\n`), signed by the head key. It is single-use by construction: once the store's recipient changes, `old` no longer matches. Expiry: 15 minutes for route A; 7 days for route B, since it waits on a restart and the clock at boot is unsynchronised (residual risk 3).
4. **Slot and recipient change in one write.** A new `seal.Store.ReplaceAndPut(slotID, f, name, value)` replaces the recovery slot and puts `RecipientEntry` in one `commit`. A crash leaves the old card and old recipient, or the new card and new recipient, never a mix.
5. **The kernel switches only to an approved recipient.** Kernel call `recipient {wire recipient, approval}`: the approval verifies, its `old` equals the kernel's current recipient ID, its `next` equals the given recipient's ID; then `bk.recipient` changes at once. Nothing is logged for the switch (the store is its record; the approval was logged). From that moment no kept backup counts (e decision 6), so e4a's scheduler takes one at once.
6. **Order on route A:** confirm card, tap, kernel `recoveryrotate`, keeper one-shot, kernel `recipient`. A crash after the keeper's write and before the switch is repaired by the next kernel start, which reads the new recipient from the store; the page also retries `recipient` with the same approval while it is unexpired.
7. **The owner-side-to-keeper channel (route A).** A socket-activated root one-shot: `agentos-recovery-rotate.socket` (`ListenStream=/run/agentos-keeper/rotate.sock`, `SocketUser=root`, `SocketGroup=agentos-owner`, `SocketMode=0660`, `Accept=yes`, `MaxConnections=1`) and `agentos-recovery-rotate@.service` (`StandardInput=socket`, `StandardOutput=socket`, hardened like `agentos-keeper-enroll.service`, with no TPM device: it never needs one). One JSON request in (8 KiB bound), one fixed outcome word out. The card factors cross only the socket and process memory, never a file.
8. **Tier 4 is the anchor's tap on the local page,** as e2 and e4b implement it (`key.In(s.Anchors, c.By)` and `c.Over(hash)`), with the page showing what the tap signs.
9. **The new key is 32 random bytes** (`seal.RecoveryLen`). The card printing it in that length is #3406's fix, which r4a and r4b need.

## Lifecycle matrix (integration owner: r4a, which wires route A into the running path)

| Stage | Outcome | Slice |
|---|---|---|
| Route A, happy | new slot and recipient in one write; kernel switches; no backup counts; one taken at once | r1, r2, r4a |
| Wrong or missing factor | one-shot refuses `factor`; nothing changes | r2 |
| Approval missing, forged, expired, other route, or `old` stale | kernel or one-shot refuses; nothing changes | r1, r2 |
| Phone passkey or no tap | kernel refuses the approval | r1 |
| Owner abandons before confirming | no approval asked; nothing changes | r4a |
| Crash after keeper write, before switch | next kernel start reads the new recipient; page retry switches with the same approval | r2, r4a |
| Kernel restart between approval and keeper | approval still verifies (head key is the store's); `old` still matches | r1, r2 |
| Box enrolled before e1 | `old = ""`; rotation writes the first recipient; STATUS names this page | r1, r2, r4a |
| Two requests at once | one-shot runs one at a time (`MaxConnections=1`, plus a lock file in `-state`) | r2 |
| Restart after route A | unlock hands the new recipient; the old card opens nothing | r2 |
| Route B, happy | after restart the store holds a new key and recipient; kernel holds the key; page shows it; confirm wipes it | r3, r4b |
| Route B, request expired or stale | unlock ignores it, starts normally, and says so on stderr | r3 |
| Route B, kernel restarts before the card is shown | key gone from memory; recipient already new; owner asks again (another restart) | r3, r4b |
| Route B on a box not unlocked by TPM | unlock applies requests only when it opened the tpm slot; otherwise route A | r3 |

## r1: the kernel approves and switches (#3391)

**Scope:** `broker/kernel` (`cosign.go`: `RecoveryRotateHash`; `log.go`, `state.go`: a `TRecoveryRotate` kind `{route, old, next}` with no state effect beyond its replay checks; `Kernel.RecoveryRotate`), `broker/kernel/proc` (`backup.go`: the approval and the switch under the backup lock; `kernelsock.go`: `recoveryrotate`, `recipient`), `broker/clerk/handoff` (the approval's type, encoding, `SignApproval` and `VerifyApproval(pub, now)`, shared with r2 and r3), `broker/owner/kernelsock` (client methods), their ASSUMPTIONS rows, this brief.
**Requirement IDs:** REC-4, BAK-1.
**Acceptance tests:**
- REC-4 tap: `kernel/recoveryrotate_test.go::TestRecoveryRotateNeedsAnAnchor`: a phone passkey's, wrong-hash or missing cosign refuses; an anchor's logs one entry and replays. Catches an owner side approving alone.
- REC-4 binding: `kernel/proc/backup_test.go::TestApprovalBindsOldNextRouteAndExpiry`: an approval for another `old`, `next`, route or past its expiry fails `VerifyApproval`; another store's head key fails. Catches a replayed or cross-box approval.
- BAK-1 switch: `::TestRecipientSwitchesAtOnceOnlyWhenApproved`: a matching approval switches and `backups` then counts nothing; a stale `old`, a recipient whose ID is not `next`, or a route-B approval refuses and keeps the old recipient. Catches a rooted owner side redirecting backups.
- `clerk/handoff/handoff_test.go::TestApprovalRoundTripAndBounds`: oversized or malformed approvals refuse.
**Guard files:** none (no new package). **Gate:** a D-159 row citing D-201, if `trusted-base` grows.
**Estimate:** 80k tokens.

**As built (r1, for r2 to r4b):** `handoff.Approval{Route, Old, Next, Expires}` (milliseconds), `handoff.RouteCard` (`a`) and `RouteLost` (`b`), `SignApproval(head, a)` and `VerifyApproval(head.Public(), b, now)`, which checks shape, signature and `now < Expires`; the caller checks the route and `Old`. Expiry constants are `handoff.CardApprovalFor` and `LostApprovalFor`; the encoded form is at most `handoff.MaxApproval` bytes, so r2's 8 KiB request bound holds it. Kernel calls: `recoveryrotate {next, cosign}` answers `{approval}`; `recipient {recipient (wire), approval}` answers nothing, and a retry once switched succeeds. Owner client: `owner/kernelsock` `RotateMsg(old, next)`, `RecoveryRotate`, `SwitchRecipient`, refusals `ErrRotateSig`, `ErrApprovalStale`, `ErrApprovalExpired`.

## r2: the keeper's one-shot (#3407)

**Scope:** `broker/clerk/seal/seal.go` (+test: `ReplaceAndPut`), `broker/cmd/agentos-enroll/main.go` (+test: `-rotate-recovery`, reading the request on stdin), the two unit files of decision 7 under `image/mkosi/mkosi.extra/usr/lib/systemd/system/`, the units' image test if one lists keeper units, ASSUMPTIONS rows, this brief.
**The mode:** read `{factor: "passphrase"|"recovery", secret, next (hex, 32 bytes), approval}`; open the store with that factor only (`seal.Unlock`); verify the approval with the store's head key, route A, unexpired; check `old` against the store's `RecipientEntry` (`""` if absent) and `next` against `RecipientFor(next)`; find the one recovery slot; `ReplaceAndPut`; wipe every secret; answer `ok` or a fixed refusal word (`factor`, `approval`, `stale`, `busy`, `store`).
**Requirement IDs:** REC-4, BAK-1, STO-2.
**Acceptance tests:**
- `clerk/seal/seal_test.go::TestReplaceAndPutIsOneWrite`: after a write that fails before rename, the old slot and old entry open and read; after success, only the new.
- `cmd/agentos-enroll/main_test.go::TestRotateRecoveryReplacesSlotAndRecipient`: the old key no longer opens the store; the new does; `RecipientEntry` is `RecipientFor(new)`; the passphrase and tpm slots are untouched.
- `::TestRotateRecoveryRefuses`: a wrong factor, an approval from another head key, expired, route B, stale `old`, or `next` not matching changes nothing (store bytes equal).
- `::TestRotateRecoveryPreE1Store`: a store with no recipient gets one under an approval with `old = ""`.
- `::TestRotateRecoveryIsSerial`: a second run while the lock is held answers `busy`.
**Needs:** r1 for the approval's form (start on r1's branch once its interface is review-accepted, OPERATING §5). **Gate:** D-159 row; the unit files may make it a gate-file PR (`premerge.py --needs-mark`).
**Estimate:** 70k tokens.

**As built (r2, for r3 to r4b):** `seal.Store.ReplaceAndPut(slotID, f, name, value)` returns the new slot's ID like `Replace`. The units are `agentos-keeper-rotate.socket` and `agentos-keeper-rotate@.service`: the `agentos-keeper-` prefix is what lifts the main side's mask on the store. The socket is at `/run/agentos-keeper/rotate.sock`. The request is one JSON object read to the end of the connection, so the client ends its write half: `{"factor": "passphrase"|"recovery", "secret": base64 of the factor's bytes, "next": 64 hex digits, "approval": base64}`. The answer is one line: `ok`, `request`, `factor`, `approval`, `stale`, `busy` or `store`. The serial lock is a `flock` on the `-state` directory, which `-rotate` also takes (ASSUMPTIONS MIG-4-recovery-r2-2).

## r3: the lost-card route at boot (#3408)

**Scope:** `broker/cmd/agentos-unlock/main.go` (+test: `-recovery-request PATH`), `broker/clerk/handoff` (`KernelKeys.NewRecovery`, handoff tag v7), `broker/kernel/proc` (`kernelmain.go` keeps it; `kernelsock.go`: `recoverycard` returns it, `recoverycarddone` wipes it), `broker/owner/kernelsock` (client), `agentos-keeper-kernel.service` (the flag), ASSUMPTIONS rows, this brief.
**The step:** only when it opened the tpm slot, and before the cap, unlock reads the request file (`O_NOFOLLOW`, regular, 4 KiB bound; it sits in the owner's state directory, and its integrity is the head signature), verifies a route-B approval whose `old` matches the store, makes 32 random bytes, `ReplaceAndPut`s the slot and recipient, and hands the key and the new recipient on descriptor 3. An absent, unreadable, stale or expired request is ignored with one stderr line; the box always starts.
**Requirement IDs:** REC-4, BAK-1.
**Acceptance tests:**
- `cmd/agentos-unlock/main_test.go::TestLostCardRequestReplacesAtBoot`: the store's old recovery key opens nothing; the handed key opens it; the handed recipient is its `RecipientFor`.
- `::TestLostCardRequestIgnoredUnlessValid`: route-A, expired, stale, forged or symlinked requests change nothing and the kernel starts with the old recipient.
- `::TestLostCardOnlyAfterTPMOpen`: a passphrase unlock ignores the request.
- `kernel/proc/kernelsock_test.go::TestNewRecoveryHeldUntilDone`: `recoverycard` returns it until `recoverycarddone`, then refuses; it is in no log or backup.
**Needs:** r1 (approval), r2 (`ReplaceAndPut`); r1 edits `kernelsock.go`, so start after it merges (D-111). **Gate:** D-159 row.
**Estimate:** 80k tokens.

**As built (r3, for r4b):** the request file is `/var/lib/agentos/recovery-request` (agentosd's root-only state directory; unlock's `-recovery-request`), holding exactly the route-B approval bytes `RecoveryRotate(ctx, "", cosign)` returns; write it whole (temp file and rename). Unlock removes it once carried out. Kernel calls: `recoverycard` answers `{key}` (32 bytes) or `ErrNoRecoveryCard`; `recoverycarddone` wipes it. Owner client: `owner/kernelsock` `RecoveryCard`, `RecoveryCardDone`, `ErrNoRecoveryCard`. The hand-off tag is v8 (v7 went to MAIL-keys). The rotation runs after the cap, not before (ASSUMPTIONS MIG-4-recovery-r3-2).

## r4a: the route-A page and STATUS (#3409)

**Scope:** owner side: `broker/cmd/agentosd` (the flow and the keeper client over `/run/agentos-keeper/rotate.sock`), `broker/localapi`, `broker/localsrv`, `broker/localui` (the page), and `broker/cmd/agentosd/backups.go`'s no-recipient STATUS line, which now names this page (superseding ASSUMPTIONS MIG-4-recovery-e4a-4). Reuse `card.NewDisplay` with `Rotate: &card.Parts{Recovery: true}` for show-and-confirm, and e4b's hardware-key tap.
**Requirement IDs:** REC-4, BAK-1, STO-2 (the passphrase is scanned or typed on the local page, never by text or voice).
**Acceptance tests:** the matrix rows marked r4a, each a test in the touched package: no keeper call and no approval before the card is confirmed; the decision-6 order, with a fake kernel and keeper; a crash between keeper and switch retries the switch; the factor never reaches a log, a file or the kernel; STATUS for a pre-e1 box names the page.
**Needs:** r1, r2, #3406 (the card's 32-byte form), #3403 (holds the agentosd slot; D-111 serial). **Estimate:** 100k tokens.

**As built (r4c, #3606):** a retry after the keeper's lost answer: `-rotate-recovery` answers `ok` and writes nothing when the store's recipient already equals the approval's `next` and `RecipientFor(next)`; when the request's factor does not open the store it tries `next` as the recovery key, so the old card's key works for the retry (ASSUMPTIONS MIG-4-recovery-r4c-1). agentosd needs no new state: the retry tap's ok keeps the switch as before.

## r4b: the lost-card page (#3410)

**Scope:** owner side, the same packages as r4a: a "card lost" choice that gathers the tap over `RecoveryRotateHash(old, "")`, gets the route-B approval, writes it to the request file in agentosd's state directory, and offers the restart through the existing reboot path; after the restart, shows `recoverycard` through the card display and calls `recoverycarddone` on confirm.
**Requirement IDs:** REC-4.
**Acceptance tests:** the matrix rows marked r4b: no request without the tap; after the restart the page shows the card and confirm wipes it; a kernel restart before confirm tells the owner to ask again.
**Needs:** r3, r4a; agentosd serial. **Estimate:** 70k tokens.

## Residual risks

1. A rooted owner side sees the new key (it renders the card, as at setup) and could show the owner one card while submitting another. The anchor tap binds only the recipient ID the page names. Setup carries the same trust; a fix needs a display outside the owner side.
2. Route B changes the slot before the owner confirms, so a kernel restart before the card is shown leaves a slot nobody holds until the owner asks again. Accepted in D-201.
3. Route B's expiry reads the boot clock before time sync; a box with a wrong clock may apply an old (but still matching) request or ignore a fresh one. The `old` binding stops replay after any rotation.
4. Rotation protects only against copies made afterwards (REC-4, STO-2): backups sealed before it still open with the old key.

**As built (r4b, #3410):** the lost-card key is a card's 160 bits, not 32 random bytes (decision 9 predates #3406's form): unlock puts `handoff.StoreRecoveryKey(bits)` in the slot and hands the bits (`handoff.CardKeyLen`, tag v9), so the kernel's `recoverycard` answers 20 bytes the page prints with `card.RecoveryKeyText`. The page's ops are `page_recovery_lost_begin`, `page_recovery_lost` (writes the approval with `privfile.WriteAtomic`), `page_recovery_lost_state`, `page_recovery_lost_withdraw`, `page_recovery_restart` (writes `/run/agentos-recovery-restart`, whose path unit starts `agentos-reboot.service`), `page_recovery_lost_card` and `page_recovery_lost_done`; the card shows through `card.Display` with `Made` (no cancel).
