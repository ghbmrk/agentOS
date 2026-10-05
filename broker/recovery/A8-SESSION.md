# A8 owner session: portability and recovery on real hardware

What the cloud build proved, and what only Mark's hands can confirm. Run after
P2-1 (image), P2-2 (card and local page), P2-3 (modem), P2-4b (TPM slot) and the
recovery wiring in the vault process are merged. Print this page; fill the
Observed column.

**Proved in CI (no hardware):** restore onto a new drive from a backup and from
the old drive (`recovery_test.go`); backups open with the recovery key only and
reject damage; restored drives trust no host and start restricted; revoked
grants and spent budgets are not revived (`restrict_test.go`); lost phone and
lost number flows on the modem simulator, with the old number ignored
(`owner_test.go`); card rotation (`rotate_test.go`); key-slot file holds only
TPM, passphrase and recovery slots, and no key, seed, grid seed, passphrase or
recovery key appears in any plaintext on either drive or in the backup
(`a8_test.go`, also run by the canary harness every CI run).

**What the learning plane keeps at rest (W3-tasks):** the learn directory
(`/var/lib/agentos/learn`, broker only, files 0600) holds owner task texts
(`tasks.json`), the guest's task values and their hash key (`values.json`,
`values.key`), the change pipeline's state with its cases, and the IDs of
forgotten goals (`forgotten.json`, no content), all
plaintext on the box's encrypted volume. Step 10's scan covers it with the
rest of the drive. Forgetting a task removes its text, values and cases
from the learn directory, and undoes the skills and procedures learned
from it, clearing their files from the pipeline's history (change C23).
The journal, machine snapshots and backups made before the forget still
hold them, and the old blocks of a rewritten `change.json` stay on the
drive until overwritten, so the scan may still find a forgotten task's
canary there.

**You need:** the box drive (set up on PC-T, your trusted PC), a second PC
(PC-U) never used with it, a spare drive of at least the same size, a USB
stick for the backup, the Owner Card with both sheets, your phone with the code
generator, a second SIM or phone number. The scan runs on the box itself, so the
recovery key is never typed into another computer.

| # | Do | Expect | Observed | Pass |
|---|---|---|---|---|
| 1 | Plug the drive into PC-U and power on. | A text: "Unknown host [model]. Join the box's Wi-Fi to unlock." | | |
| 2 | On the box's Wi-Fi page, give only an approval code (no passphrase). | Refused. Nothing unlocks. | | |
| 3 | Scan the passphrase from the card; give no code; wait 16 minutes. | The page and a text say the unlock expired; the box is still locked. | | |
| 4 | Scan the passphrase again and reply to the text with a code. | Unlocked; STATUS works by text. | | |
| 5 | Restart PC-U. | It asks for the passphrase and code again (not trusted). | | |
| 6 | Add PC-U as a trusted host: code plus confirm on the Wi-Fi page. Restart. | Comes up with no input (unattended restart). | | |
| 7 | Remove PC-U as a trusted host. Restart. | Asks for the passphrase and code again. | | |
| 8 | Move the drive back to PC-T and restart. | Comes up with no input. | | |
| 9 | Create two pre-allowances on the Wi-Fi page (G1, G2). Press **Back up now** and pick the USB stick. Then text `REVOKE G1`. | Backup reports done with its date; G1 revoked. | | |
| 10 | With the USB stick still attached, press **Scan drive (A8)** on the Wi-Fi page and type the recovery key and the passphrase from the card. It runs `agentos-a8scan` over every partition of the box drive, read-only, and over the USB stick. | Each target: "nothing found"; the control line and key-slot line say ok. | | |
| 11 | Press **Restore** on the Wi-Fi page, pick the USB stick and the spare drive, and type the recovery key. Boot the spare drive on PC-T. | Not trusted: asks for passphrase and code. After unlock, a text: "Box restored from a backup made DATE. Pre-allowances and today's budget are paused until you review them on the box page (one step)." | | |
| 12 | Before re-confirming, ask the agent for something G2 covers. | It asks for approval instead of running. | | |
| 13 | On the Wi-Fi page, re-confirm G2 only (code plus confirm). Ask again for G1's and G2's actions. | G2 runs; G1 asks (it stays revoked). The page also offered Keep all and Start budgets fresh. | | |
| 14 | Press **Restore** again, this time picking the original drive (both plugged in) as the source. | Same as 11, but the text says "restored from its old drive". | | |
| 15 | Lost phone: on the Wi-Fi page, re-enroll with the recovery key; add the new entry to the code generator. Text a code from the old entry. | Old code refused; a code from the new entry unlocks. | | |
| 16 | Lost number: on the Wi-Fi page, start a number change with the recovery key; text `HELP` and then the shown code from the second number. | HELP does not use up a try. Old number gets "owner number moved to ...NNNN" with how to move it back; the new number gets the welcome text. | | |
| 17 | From the old number, text STOP, STATUS, and a valid code. | No reply, no effect. | | |
| 18 | Rotate everything on the Wi-Fi page (recovery key as authority). Press **Save card**, print it, and type back the value the page asks for. Rejoin the box's new Wi-Fi. Try the old passphrase on PC-U. | Nothing changes until the typed-back value matches. Then the old passphrase is refused and the new card's works. The done page offers **Back up now**. The old USB backup still restores with the old recovery key (expected: rotation protects only against later copies). | | |
| 19 | Type the recovery key with one character changed into the Restore page. | The page names the group that looks mistyped. | | |

Send the filled table (a photo is fine). Any failed row comes back to the
builder with the row number.
