# P2-2w c4b: setup lists the home networks in range

Board section: Backlog refill (2026-10-05); work item #1219. Release row split from P2-2w c4 (#1218, briefs/P2-2w-c4.md).

**Requirements:**
- ONB-3: the home network is a minimum-path step; the owner picks it from a list instead of typing its exact name.
- CRED-1: the scan carries no password and returns names only.
- ARC-2: agentosd's control path calls no inference; agentosd links netjoin's client, never godbus (D-108).
- Binding conditions: Security L6 (setup's ops close for good after finish), L8.3 (the helper serves agentosd's uid alone on its one socket), L8.5 (godbus on the system bus only) and L8.6 (nothing logged).

**Acceptance:** A1 (setup on hardware, with P2-1).
**Implementation risk:** tier A. **Needs:** P2-2w c4 (merged, #1218). **Gate:** lenses (security: strongest tier).

## What to build

1. **A read-only scan in `agentos-netjoin`.** A second op, `scan`, on the helper's one socket. It reads NetworkManager's devices, keeps the Wi-Fi ones, calls `Device.Wireless.GetAllAccessPoints` on each, and reads each access point's `Ssid` and `Strength`. It requests no scan, writes nothing and needs no polkit action, so `50-agentos-netjoin.rules` is unchanged. Its seam (`netjoin.ScanNM`) is separate from the join's `NM`, and has no write.
2. **Names only.** The answer is at most `MaxNetworks` (20) SSIDs, strongest first, each shown once. A name that is empty, longer than 32 bytes, not UTF-8, or holds a control character is dropped (a hidden network has an empty one). No BSSID, frequency or strength leaves the helper. The helper bounds its reads with `ScanWait` (3 s); agentosd's call is bounded by `ScanTimeout` (4 s), inside the page's 10 s.
3. **agentosd.** `netjoin.Client.Networks` re-checks the answer (count and each name). Setup serves it as `page_setup_networks` (`localapi.OpSetupNetworks`), closed after finish like every setup op, at most `ScansPerMinute` (20) a minute. With no helper, an error or the limit, it answers an empty list.
4. **The page.** `AgentosdSetup.Networks` asks agentosd. With a list, the network step shows it, plus a field to type a name that is not listed (a scan can miss the home network); with an empty list it takes a typed name, as before.

## Acceptance tests

1. `netjoin.Scanner`: Wi-Fi devices only; empty, hidden, non-UTF-8, control-character and over-long names dropped; duplicates once at their best strength; strongest first; at most 20; a failed device or access point read skips it; a failed device list answers an empty list.
2. The helper's socket: `scan` answers the list to agentosd's uid, refuses other uids before reading, and takes no arguments but `{}` or none.
3. `nmBus`: the scan makes only its reads (the devices, `DeviceType`, `GetAllAccessPoints`, `Ssid`, `Strength`) on NetworkManager paths, and the join's call test still passes unchanged. The polkit rule test still passes unchanged.
4. `Client.Networks`: a good answer is returned; an answer over 20 names, or with a name the helper would drop, is an error.
5. `page_setup_networks`: is in `SetupOps`; answers the list; answers an empty list with no helper or on an error; is refused once setup is finished; is limited per minute.
6. agentosd's setup mode serves the helper's list through `page_setup_networks`.
7. The page: with a list, the step shows each name as an option and a typed-name field, and a typed name wins over the selected one; `AgentosdSetup.Networks` carries the list across `InProcess`, and an error gives none.

Run tests with `-race`.

## Scope (files)

- `broker/netjoin/`: `netjoin.go` (op, answer, bounds, `Showable`), a new `scan.go`, `server.go` (the second op), `client.go` (`Networks`), a new `scan_test.go`, `netjoin_test.go` (the `Endpoint` call), and two rows in `ASSUMPTIONS.md`.
- `broker/cmd/agentos-netjoin/`: `main.go` (the scan's reads on `nmBus`) and a new `scan_test.go`.
- `broker/localapi/setup.go`: the op, its answer and bounds; `localapi_test.go` (the op count).
- `broker/localsrv/setup.go` (the `Networks` field and op) and a new `setupscan_test.go`.
- `broker/cmd/agentosd/`: `setup.go` (the scan's wiring) and a new `setupscan_test.go`.
- `broker/localui/`: `setuphooks.go` (`Networks` only), `pages.go` (the `wifi` template), `setup.go` (the typed name in `network`), and a new `setupc4b_test.go`.

## Out of scope

Requesting a scan (`RequestScan`, polkit `wifi.scan`), hidden networks (LATER P2-2w c3 f3), hiding the box's own setup access point from the list, and LATER #1215.

## Estimate

About 80k tokens for one session. The figure is a checkpoint, not a cap (docs/OPERATING.md §5).
