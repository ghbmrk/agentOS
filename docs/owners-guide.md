# agentOS owner's guide

This guide answers common questions about your box. This part covers your PC, the daily digest and the enforcer's access point.

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
- <!-- host-change: mor --> **Only after a power cut, or if the PC is switched off without agentOS shutting down: a request to the PC to clear its memory at its next start.** That start takes a little longer, once. When agentOS shuts down normally, it first erases what it kept in memory, then takes the request back.
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

## If the enforcer was compromised

The enforcer controls its access point, the Wi-Fi box beside it, and can change anything on it. So whenever the enforcer may have been compromised, make the enforcer trustworthy first, then clean the access point.

**How you find out.** agentOS texts you that the enforcer may be compromised when it no longer matches what you set up, or sends something outside its fixed format. STATUS shows the same line until you finish the steps below. A compromised enforcer can stay silent, so follow the steps below even without a text if a setting loosened that you did not loosen, the enforcer refused a passkey that worked before, or its case was opened.

Only replacing the enforcer is certain to remove an implant in its own software; a reinstall may leave it. If you keep it:

1. **Reinstall the enforcer.** Use the flasher on your own computer to put the enforcer's signed software back. This erases its keys, passkeys and settings. Then, from your own computer plugged into the enforcer's admin port (the network socket on the enforcer kept for your own computer), add a new passkey and restore the saved settings from before you think the problem began.
2. **Trust it again with a hardware key.** Open the agentOS owner page and approve the enforcer with your hardware key. This replaces the old approval, as when you replace an edge device's key.
3. **Clean the access point.** Only replacing it with a new one is certain to remove what an attacker may have put on it. If you keep it, reinstall its software from its recovery mode first, every time; this guide will add those steps, and say whether a reinstall is as certain as a replacement once that has been tested. Then factory-reset it: with it powered on, hold its reset button for about 10 seconds, then let go. The reset erases every file in its settings area, its Wi-Fi networks are gone for now, and it comes back as a new access point the enforcer does not recognise. A reset alone does not undo changes to the access point's own software, and you cannot see such changes from outside. <!-- Recovery-mode steps, and whether the OpenWrt One's NOR recovery image is write-protected against root, come from ENF-g-11's live run (broker/enforcer/ap/ASSUMPTIONS.md ENF-g-12). -->
4. **Connect the access point to the enforcer again.** Keep its cable in the enforcer's access-point port. Its Wi-Fi is gone, so plug a laptop, or a phone with an Ethernet adapter, into the enforcer's admin port. Open the enforcer's page and choose to set up the access point again. The enforcer accepts the access point as it is now, then puts back its networks and Wi-Fi passwords. The enforcer's page does not offer this choice yet; it arrives in a coming update. <!-- The re-pin control is slice l's (ENF-l, #3670); drop the previous sentence when it ships. The admin port's printed label is fixed with the enforcer's hardware. -->
5. **Pair your devices again and change the passwords.** The enforcer held every Wi-Fi password, radio key and keypad code, so pair each device again and set a new password for each network.

Until you connect the access point again, the enforcer refuses to talk to the cleaned access point, because it no longer recognises it.
