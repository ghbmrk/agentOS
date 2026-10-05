# AgentOS owner's guide

This guide answers common questions about your box. This part covers your PC.

## Starting AgentOS on your PC

AgentOS runs entirely from its own drive. It does not open, change, or repair your PC's own disks, and it does not set your PC's clock. When you take the drive out and start the PC again, the PC is as it was, apart from the few small things listed below.

Most PCs start from the drive by themselves, with no screen or keyboard. If the box's Wi-Fi does not appear a few minutes after you turn the PC on, the PC did not start from the drive. Then use its one-time boot key; you'll need a screen and keyboard for that one start: turn the PC on, press its boot key a few times until a menu appears, then choose the USB drive. The back of your card lists the boot key for each major PC brand. This choice lasts for one start only.

You never need to change your PC's settings, and you never need to turn Secure Boot off.

You can give AgentOS one of the PC's internal disks for more space, on the box's Wi-Fi page, under Settings > Storage. Everything on that disk is erased first, and the box asks you to confirm. Until you do that, no internal disk is used.

## What AgentOS changes on your PC

This is the whole list. A few small things are stored in the PC's own firmware and security chip, and only in the cases below.

- <!-- host-change: boot-order --> **The start-up order, only if you change it yourself.** The one-time boot key leaves it as it was.
- <!-- host-change: loader-system-token --> **One random number in the PC's firmware.** AgentOS's start-up program stores it the first time, so that each start begins with fresh randomness. It holds nothing about you.
- <!-- host-change: tpm-srk --> **A standard key in the PC's security chip (TPM), if the chip has none yet.** Most Windows PCs already have it.
- <!-- host-change: tpm-vault-counter --> **On a PC you trust: one counter in the security chip for each AgentOS drive you trust it with.** It only counts up, so an old copy of your drive cannot pretend to be the current one. It stays in the chip after the drive is gone; it holds nothing about you.
- <!-- host-change: tpm-lockout --> **If you turn on a start-up PIN: the security chip's lockout setting.** The box holds it while the PIN is on, so wrong PINs stay limited. When you turn the PIN off it gives the setting back; the limit on wrong guesses it set stays. Wrong PINs count toward the chip's limit, which Windows shares.
- <!-- host-change: sbat-level --> **Possibly, an update to the PC's list of blocked old start-up programs,** if AgentOS's start-up program carries a newer list than the PC has. Windows updates keep the same list.
- <!-- host-change: windows-recovery-prompt --> **Rarely, a question from Windows at its next start.** If it happens, see below.

Nothing else on the PC changes.

## If Windows asks for a recovery key

Sometimes, after the PC has started AgentOS, Windows asks for a "BitLocker recovery key" the next time it starts. BitLocker is Windows' own disk lock. Windows asks because it noticed the PC started differently. Your files are safe, and AgentOS did not change your Windows disk.

This is Windows' key, not the recovery key on your AgentOS card.

- **Home PC:** the key is saved in the Microsoft account you sign in to Windows with. Open aka.ms/myrecoverykey on your phone, sign in, and type the key shown for this PC.
- **Work or school PC:** ask your IT department for the key.

After you type the key once, Windows starts normally again.
