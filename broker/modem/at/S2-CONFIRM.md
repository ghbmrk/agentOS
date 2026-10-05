# What S2 must confirm before the driver is final

The driver's vendor commands, interface numbers and URC formats come from
the vendors' AT manuals and the S2 test kit (`spikes/S1S2-testkit`); the
simulator (`atsim`) encodes the same readings. These are the points only
the real modems can settle. Each names the S2 result that answers it, or
the extra reading to take while S2 runs, and the change if it fails.

| # | Check | Evidence from S2 | If it fails |
|---|---|---|---|
| C1 | Calls work at all on Mark's carrier: IMS registered, so VoLTE calls connect (most carriers have shut down 3G voice). | `ims_registration`, `call_out`, `call_in` | No voice: MVP is text-only (PLAN S2 fallback); the driver's SMS path stands. |
| C2 | `AT+CGMM` answers `EC25` or `EG25…` on the Quectel and `SIMCOM_SIM7600G-H` on the SIMCom. | `modem` line (manufacturer, model) | Add the string to `Profile.Models`. |
| C3 | The AT port is USB interface 2 on both modems; the SIMCom audio port is interface 4. | Extra: `ls -l /sys/bus/usb-serial/devices/` with the modem in | Change `ATInterface` / `AudioInterface`. |
| C4 | Quectel: the UAC flag is the last field of `AT+QCFG="usbcfg"`, the modem re-enumerates with a sound card after `AT+CFUN=1,1`, and `AT+QPCMV=1,2` puts call audio on it at 8 kHz S16_LE mono. | `quectel_uac`, `audio_route uac <card>`, Quectel `call_*` PASS | Fix `EnsureUAC` or `AudioOn`. |
| C5 | SIMCom: `AT+CPCMFRM=0` is accepted, `AT+CPCMREG=1` works only once the call is connected, and PCM flows on the audio port at 20 ms per 320 bytes with no underrun. | `audio_route serial <tty>`, SIMCom `call_*` PASS and seconds of uplink | Drop `CPCMFRM` from `Init`; adjust pacing. |
| C6 | **Keypad source.** On a VoLTE call, the owner's key presses appear as tones in the uplink audio. | `call_out` / `call_in`: "decoded keypad" equals the digits sent | If audio is fine but keys are missing, set `Keys: KeysModem` for that vendor and confirm the URC format (C7). |
| C7 | The modems' DTMF reports: Quectel `+QTONEDET: <ASCII code>` after `AT+QTONEDET=1`; SIMCom `+RXDTMF: <key>` after `AT+DDET=1`. Only needed if C6 fails. | Extra: enable it, press keys, read the AT port | Fix `Profile.Key`. |
| C8 | Calls show in `AT+CLCC` with mode 0 and the caller's number while ringing (caller ID on), and `AT+CHUP` ends them on both modems. | `call_in` answered only for the owner's number | Fall back to `+CLIP` for the number; `ATH` is already the hangup fallback. |
| C9 | Texts: `AT+CPMS="ME","ME","ME"` is accepted, `+CMTI` arrives on the AT port, and a long text from the owner's phone (two or more segments) arrives whole. | `sms_in` PASS; extra: send a 200-character text | SIM storage is the fallback already; fix URC routing (`AT+QURCCFG`, SIMCom port). |
| C10 | The keypad gate on real speech: muting stays near the key presses (a few frames each) and ordinary speech is never decoded as a key. | Extra: the recorded `call-*.raw` files in `private/`, run through `at.Decode` and the gate offline | Retune the gate's loose test. |
| C11 | The modem restart after `AT+CFUN=1,1` takes under the 20 s the kit allows. | `quectel_uac` then registration | Lengthen the reopen wait. |

Recordings stay in the kit's `private/` folder and never leave the drive;
C10 is run on the drive or by Mark, not uploaded.
