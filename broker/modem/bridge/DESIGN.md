# P2-3w: the modem bridge — design read

**Status.** Design read for the Security, UX and Potency lenses. Nothing is built yet.
**Thread.** P2-3c builder thread.
**Requirements.** CH-1, CH-2, CH-5, CH-12, ADP-12, ARC-2, CRED-1.

## Problem

No process drives the modems today:

- `cmd/agentosd/main.go:384` says so: owner texts arrive only through `owner.sock`, and the channel's own outbound texts (alerts, approvals, the digest) are never sent.
- `agentos-egress` serves `sign.sock` and `sms.sock` to a `-modem-uid` that nothing runs as.
- The AT driver (P2-3), `secondline` (ADP-12), `sipline` (P2-3b) and `smsapi` (P2-3c) are all built and tested, but nothing links them.

## Process and uid layout

| Process (user) | Holds | Links | Serves | Connects to |
|---|---|---|---|---|
| `agentosd` (agentosd) | owner channel, grants, journal | `owner`, `daemon`, new `bridgeproto` (JSON types only) | `owner.sock` (PeerUID = modem uid, exists today) | — |
| **`agentos-modem` (agentos-modem)**, new | both modems' tty and audio (udev rule `71-agentos-modem.rules`), `secondline.Tool`, `sipline` | `modem/at`, `secondline`, `sipline` (sipgo, pion), `smsapi` client, `sipsign` client, `bridgeproto` | nothing | `owner.sock` (agentosd); `sign.sock` and `sms.sock` (agentos-egress, both uid-checked) |
| `agentos-egress` (vault) | SIP password, API token, shared send budget | unchanged | `sign.sock`, `sms.sock` (unchanged) | — |

**Why the bridge is always the client.** The bridge parses hostile input: PDUs from any sender, SIP from the provider, RTP. So it is the less-trusted side, and it connects to sockets the more-trusted processes serve and check by uid. This matches `verify.sock` and `sign.sock`.

**Why agentosd links none of it.** agentosd still links none of sipgo, pion, sipline, sipsign or smsapi; the ARC-2 fence tests stay as they are. Its only new dependency is `bridgeproto`.

## Socket contract (`owner.sock`)

Today `owner.sock` has one op, `message`. It stays, so the simulator and tests keep working. New ops:

| Op | Direction | Meaning |
|---|---|---|
| `inbound` `{line:"owner"\|"second", from, text, at, named}` | bridge → agentosd | One received text. `owner` texts go to `Channel` as now; CH-1's owner-number check stays in agentosd, and the bridge's `from` is never trusted beyond what a modem could forge. `second` texts become `secondline.Untrusted` for the agent, never control. |
| `outbox` (long poll, at most 25 s) | bridge pulls | The next outbound item: `{id, line:"owner", to, text}` for the channel's own texts, or `{id, line:"second", kind:"text"\|"call", to, text}` for a grant-approved third-party send. The `to` of an `owner` item is always the owner's number; agentosd builds it. |
| `sent {id, error_code}` | bridge → agentosd | Result of an outbox item, as a fixed code (`ok`, `down`, `recipient`, `limited`, `refused`, `unreachable`, `too_long`). `Send` in agentosd blocks on it, with a 60 s timeout ending in `ErrDown`, so the channel keeps its synchronous `modem.Modem` semantics. |
| `state {owner_line, second_line, texts}` | bridge → agentosd, on change and every minute | **Closed enums only**, mapped to fixed STATUS and digest lines in agentosd, the same pattern as #142's `SecondLineState`. The bridge never supplies owner-facing wording. Values: `owner_line`: ok, down, swapped, unbound; `second_line`: ok, down, unregistered (a registration lost after setup; the P2-3c binding), carrier_blocked (Twilio 30034 or 30007; potency R1 on #159). |

On the agentosd side, a `bridgeModem` implements `modem.Modem`:

- `Send` queues the text to the outbox and waits for its `sent` result.
- `Inbox` is fed by `inbound`.
- `daemon.Config.Modem` is set to it, so `Channel.Run` replaces `Boot` plus `Tick`.

A bridge that isn't connected makes `Send` return `ErrDown` after the timeout, which the channel already handles. Limits: one bridge connection for the outbox, at most 64 queued items, and owner items ahead of second-line items.

## Owner wording (UX)

- **Line-state lines** are fixed strings in agentosd, written in sipline.OwnerText's style and naming the box's Wi-Fi page. Proposed:
  - "Your box can't reach its phone modem. Check it's plugged in." (owner_line down)
  - "Second line: the box lost its sign-in to your provider. Check the account on the box's Wi-Fi page." (unregistered)
  - "Second line: your provider's carrier is blocking texts from this number. For a US number, check its A2P 10DLC registration." (carrier_blocked)
- **Agent-facing refusals** for second-line sends come from `sipline.OwnerText` and `smsapi` codes, never `err.Error()`. Senders are shown as `Untrusted.Sender()`.

## Parts (one PR each)

1. **Owner channel texts.**
   - `cmd/agentos-modem`: owner modem through `at.Open`, with Roles checked from the setup record.
   - `bridgeproto`; the `inbound`, `outbox`, `sent` and `state` ops; `bridgeModem` in agentosd.
   - Tested end to end over the AT simulator and a real `owner.sock`.
   - BOARD: the new P2-3w row; P2-3's stale "in review" corrected.
2. **Second-line texts.**
   - `secondline.Tool` in the bridge, on a second SIM or the SIP account (`sipline` with `Texts` = `smsapi.NewClient(sms.sock)`, `Sign` = `sipsign.NewClient(sign.sock)`).
   - `second` outbox items; inbound Untrusted texts to the agent.
   - `state.second_line`, including `unregistered`.
3. **Calls.** Third-party calls with the disclosure (outbox `kind:"call"`; the bridge plays the disclosure and then the agent's audio over a stream op), plus the inbound "can't take calls" answer on a second SIM.
4. **Delivery status** (potency R1 on #159). The vault process polls the status of HTTP-sent texts; carrier error codes 30034 and 30007 map to `carrier_blocked`.

## Security questions for the lens

- **S1. Can a hostile bridge do worse than today?** It can already forge any inbound owner text, the way a forged SMS can (CH-1 checks are unchanged). It can drop or delay outbound texts, but it cannot change their recipients, because agentosd builds `to` for owner items and grants decide second-line items. It cannot supply owner wording, since `state` is enums only.
- **S2. Outbox starvation.** The 64-item cap and the 60 s `sent` timeout mean a stuck bridge degrades to `ErrDown`, which the channel already reports. The current owner-socket idle limits (8 connections, 60 s idle) stay.
- **S3. Budget.** Second-SIM sends spend the tool's budget, which resets when the bridge restarts. Account sends spend the vault's budget (#164).

## Not in scope

- Owner voice calls (CH-5 keypad) over the bridge: P2-3 tuning on hardware (S2).
- Dual-SIM or eSIM.
