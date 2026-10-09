# HOST-1c: Firmware-change disclosure and BitLocker prevention

Board section: Backlog refill (2026-10-05).

Firmware-change disclosure and BitLocker prevention (HW-8, ONB-7): boot instructions use the one-time boot key and never Secure Boot off; BitLocker is never mentioned unless the owner asks about a recovery prompt, then the plain-words answer from the owner's guide (aka.ms/myrecoverykey, or the IT department for a work PC); owner's-guide change list; turn off or disclose systemd-boot's persistent `LoaderSystemToken` and the TPM storage root key **Part 1 (this package):** the owner's guide (`docs/owners-guide.md`): starting with the one-time boot key, the whole list of host changes (`broker/hostchange`, pinned by test), and the recovery-key answer, the only place BitLocker is named; the card's quick-start says the PC's disks are left untouched. **Part 2:** the box answers from the guide when the owner asks about a recovery-key prompt (needs P2-2); turn off or keep `LoaderSystemToken` and the persistent SRK (P2-1 image choice). **For P2-1 (Security on #183):** the drive ships no `fbx64.efi` or `BOOT.CSV` (shim's fallback would add Boot#### entries and change BootOrder); no MOK enrollment, so no MokList writes; HOST-1e's UEFI-variable diff checks both. **Spec-diff pending:** HW-8's list names a pcrlock NV index the code does not use and omits the V6 vault counter and the D7 lockout and dictionary-attack settings

**Needs:** HOST-1a, P2-2

**Gate:** lenses

**State on the board before the 2026-10-08 index split:** part 1 merged (#183); part 2 queued (needs P2-2)
