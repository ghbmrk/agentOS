# agentOS owner's guide

This guide answers common questions about your box. This part covers your PC and the daily digest.

## Starting agentOS on your PC

agentOS runs entirely from its own drive. It does not open, change, or repair your PC's own disks, and it does not set your PC's clock. When you take the drive out and start the PC again, the PC is as it was, apart from the few small things listed below.

Many PCs start from the drive by themselves, with no screen or keyboard. If the box's Wi-Fi does not appear a few minutes after you turn the PC on, the PC did not start from the drive. Then use its one-time boot key; you'll need a screen and keyboard for that one start: turn the PC on, press its boot key a few times until a menu appears, then choose the USB drive. The back of your card lists the boot key for each major PC brand. This choice lasts for one start only. If the boot menu does not offer the USB drive either, check your PC against "Which PCs can run agentOS" below.

You never need to change your PC's settings, and you never need to turn Secure Boot off.

You can give agentOS one of the PC's internal disks for more space, on the box's Wi-Fi page, under Settings > Storage. Everything on that disk is erased first, and the box asks you to confirm. Until you do that, no internal disk is used.

## Which PCs can run agentOS

agentOS starts on most recent Windows PCs. These are the kinds of PC it can and cannot run on:

- <!-- host: supported --> **PCs with an Intel or AMD processor and current start-up firmware (UEFI, the program that starts a PC before Windows),** which covers most Windows 10 and 11 PCs sold in about the last ten years.
- <!-- host: unsupported windows-on-arm --> **Windows laptops with an ARM processor, such as Snapdragon models.** agentOS cannot run on them: their processor cannot run its start-up program.
- <!-- host: unsupported pre-uefi --> **Older PCs whose start-up firmware predates UEFI (sometimes called "legacy BIOS" only).** agentOS cannot run on them: their firmware cannot find its start-up program.
- <!-- host: unsupported mac --> **Macs, with an Intel or Apple processor.** agentOS does not support them.

## What agentOS changes on your PC

This is the whole list. A few small things are stored in the PC's own firmware and security chip, and only in the cases below.

- <!-- host-change: boot-order --> **The start-up order, only if you change it yourself.** The one-time boot key leaves it as it was.
- <!-- host-change: loader-system-token --> **One random number in the PC's firmware.** agentOS's start-up program stores it the first time, so that each start begins with fresh randomness. It holds nothing about you.
- <!-- host-change: tpm-srk --> **A standard key in the PC's security chip (TPM), if the chip has none yet.** Most Windows PCs already have it.
- <!-- host-change: tpm-vault-counter --> **On a PC you trust: one counter in the security chip for each agentOS drive you trust it with.** It only counts up, so an old copy of your drive cannot pretend to be the current one. It stays in the chip after the drive is gone; it holds nothing about you.
- <!-- host-change: tpm-lockout --> **If you turn on a start-up PIN: the security chip's lockout setting.** The box holds it while the PIN is on, so wrong PINs stay limited. When you turn the PIN off it gives back the setting and the chip's limit on wrong guesses, as they were. Wrong PINs count toward the chip's limit, which Windows shares.
- <!-- host-change: sbat-level --> **Possibly, an update to the PC's list of blocked old start-up programs,** if agentOS's start-up program carries a newer list than the PC has. Windows Update installs the same list too.
- <!-- host-change: windows-recovery-prompt --> **Rarely, a question from Windows at its next start.** If it happens, see below.

Nothing else on the PC changes.

## If Windows asks for a recovery key

Sometimes, after the PC has started agentOS, Windows asks for a "BitLocker recovery key" the next time it starts. BitLocker is Windows' own disk lock. Windows asks because it noticed the PC started differently. Your files are safe, and agentOS did not change your Windows disk.

This is Windows' key, not the recovery key on your agentOS card.

- **Home PC:** the key is saved in the Microsoft account you sign in to Windows with. Open aka.ms/myrecoverykey on your phone, sign in, and type the key shown for this PC.
- **Work or school PC:** ask your IT department for the key.

After you type the key once, Windows starts normally again.

## Your daily digest

Each morning at 8:00 the box texts you one short digest, even on a quiet day, when it says there is nothing else to report. If your phone was off or out of signal, the box keeps trying for the rest of that day and the next. If the box cannot tell whether a digest reached you, it never sends it twice; the next digest says so instead. If the box cannot read its own digest records, it sends you one short line saying so that day, and STATUS shows it until it is fixed. Reply STATUS any time for more.
