# AgentOS hardware test checklist (S1 boot, S2 modem)

Print this. Tick boxes and write on it; send a photo of it with the results folder when done.

## 0. Prepare the drive (once, on any laptop)

- [ ] Download the image: open the pull request's **Checks** tab → **testkit-image** → **Artifacts** → `agentos-testkit` (a zip).
- [ ] Install **balenaEtcher** (Windows, Mac, Linux). Put the SSD in the enclosure and plug it in.
- [ ] Unzip it. Optional check: the SHA-256 of `agentos-tk_1.raw` matches `SHA256SUMS` (Windows: `certutil -hashfile agentos-tk_1.raw SHA256`; Mac: `shasum -a 256 agentos-tk_1.raw`).
- [ ] Etcher: **Flash from file** → `agentos-tk_1.raw` → **Select target** → the SSD (check the size; everything on it is erased) → **Flash**.
- [ ] If Windows asks to format a drive, click **Cancel**. If a Mac says the disk is not readable, click **Ignore**.
- [ ] A drive named **TESTKIT** appears. It holds `README.txt` and `s2.conf`. Eject it.

## 1. S1: boot test, one PC at a time (about 15 minutes each)

For each PC:

1. PC fully **off**. Unplug other USB drives.
2. Plug the SSD into the fastest port: USB4/Thunderbolt (⚡) first, then USB-C, then a blue USB-A port. Note which.
3. Press power **once**. **Touch no keys.** Start a stopwatch.
4. Wait up to **15 minutes** (longer on an old USB-A port). The PC boots three times (screen and fans may come and go), then **switches itself off**. That is a pass.
5. If it boots its own system (e.g. the Windows logo), or is still on after 15 minutes: hold power until it's off and try the fixes below.

**Fixes, in order. Stop at the first that works and record it:**

- A. Enter firmware setup (usually **F2** or **Del** while powering on). Put USB first in the boot order. Leave **Secure Boot on**. Save, power off, repeat steps 3–4.
- B. Only if A is impossible: one-time boot menu (key below), pick the SSD. Record the key and that a screen was needed.
- C. Diagnostic only: if it boots only with Secure Boot **off**, record that. It's an important finding, not a pass.

Boot-menu keys (common, not guaranteed): Dell F12 · HP Esc then F9 · Lenovo F12 · ASUS F8 or Esc · Acer F12 · MSI F11 · Gigabyte F12 · ASRock F11 · Intel NUC F10 · mini PCs often F7 or Esc.

| # | PC vendor and model | Port used | Off by itself, no keys? (Y/N) | Minutes to off | Fix needed (none / A / B / C) | Notes |
|---|---|---|---|---|---|---|
| 1 | | | | | | |
| 2 | | | | | | |
| 3 | | | | | | |
| 4 | | | | | | |
| 5 | | | | | | |

Pass for S1: at least 3 of 3 vendors switch off by themselves with no keys, either straight away or after fix A once.

On the N95, also read the results file's `agent_and_replay_fit` line: **PASS** means the agent machine and one replay machine fit in memory beside the rest of the floor budget. Note it here: ________

## 2. S2: modem test (about 20 minutes per modem)

Use one PC that passed S1, ideally the N95 floor machine.

- [ ] SIM checked in a phone (can call and text), SIM PIN off.
- [ ] On a laptop, open `s2.conf` on the TESTKIT drive. Set `RUN_S2=yes` and `OWNER_NUMBER=` your mobile number with country code (e.g. `+15551234567`). Save, eject.
- [ ] PC off. SIM in **modem A**, antennas on. Plug in modem and SSD. Keep your phone nearby.
- [ ] Power on. Touch no keys. After the reboots (about 5 minutes; on its first run a Quectel modem restarts once to turn on its audio, a setting it keeps; the result file shows how to undo it), you get a text:
  - [ ] **Reply `PING`.**
  - [ ] The box **calls you**. Answer. It reads 4 digits twice. **Press those digits on your keypad.** It hangs up after about 40 s.
  - [ ] A text asks you to **call the box**. Call the number that texted you. It answers and reads 4 new digits. **Press them.**
  - [ ] A final text, "S2 done: …", then the PC switches off.
- [ ] Repeat with **modem B** (same SIM).

| Modem | Texts arrived? | Call to you rang? | Digits clear? | Call to box answered? | Voice quality 1–5 | Delay or echo? |
|---|---|---|---|---|---|---|
| A | | | | | | |
| B | | | | | | |

No first text within 10 minutes: power off; the result file on the drive says why (modem not found, not registered, etc.).

## 3. Send results

- [ ] Plug the SSD into a laptop. Copy the **`results`** folder from TESTKIT and upload it to the project chat with a photo of this sheet.
- [ ] **Don't upload `private/`**: it holds call recordings. Listen to them yourself if you like.
- [ ] Edit `s2.conf`: set `RUN_S2=no` and erase your number.
