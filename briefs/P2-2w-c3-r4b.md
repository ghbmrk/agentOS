# P2-2w c3 r4b: the Wi-Fi station beside the access point

Board row: #936 (P2-2w c3 r4), second half. Split 2026-10-20 from the hardware triage: [r4a](P2-2w-c3-r4a.md) ships NetworkManager and polkitd and leaves every device unmanaged except `wlsta0`; this half creates `wlsta0` beside the access point and points the helper at it. This half is the **integration owner** for the home Wi-Fi join: it owns the lifecycle matrix below, and r4a, #935 and the helper (P2-2w c3, merged) are its pieces.

**Requirements:**
- ONB-3, ONB-1: the home network is a minimum-path step completable with the kit and a phone, so the phone stays on the box's access point while the box joins the home Wi-Fi.
- ONB-4: the join completes within the target time.
- DEV-2: the home network is untrusted. `wlsta0` sits behind the `agentos_inbound` drop like every other uplink and is never exempt.
- CH-9: the access point stays WPA3-SAE and the local UI unreachable from the home network. The station never carries the UI's listener, its subnet check, or `NftRules`.
- SPEC v1.0 §6.1 custody exceptions, STO-2: the home Wi-Fi password never enters a log and reaches the drive only under the sealed store's encryption (r4a holds it in RAM until #935).
- HW-1, HW-4, HW-10: the M6 Ultra's radio is the target; the behaviour on it is read, not assumed.

**Acceptance:** A1 (setup's network step on hardware).
**Acceptance tests:** 1-8 below.
**Guard files:** none (no new package).
**Implementation risk:** tier A (`broker/cmd`, `*.service`, `image/`). **Gate:** lenses (security: strongest tier).
**Needs:** r4a merged; #1113's M6 Ultra reading of the radio's interface combinations (AP plus managed, and `#channels`). Coordinate with #935 and PR #2537, which touch `broker/netjoin/ASSUMPTIONS.md`.
**Usage estimate:** about 140k tokens; check in at 100k.

## Lifecycle outcomes (owned here)

| Stage | Outcome |
|---|---|
| First boot, setup open | `wlsta0` exists if the radio allows AP plus managed; setup's `Station()` is true and offers Wi-Fi. Otherwise no `wlsta0`, `Station()` false, setup offers Ethernet. |
| Join | The helper writes the one connection; NetworkManager activates it on `wlsta0`; the phone stays on the access point. |
| Confirm (AP switches to the card's network) | The loader takes the AP Down then Up; `wlsta0` survives or is re-created, and NetworkManager reconnects without a new join. |
| Loader restart (`agentos-ap`) | Same as confirm: `wlsta0` is re-created if gone, never duplicated. |
| Helper restart (`agentos-netjoin`) | No change to `wlsta0` or the connection. |
| Reboot | `wlsta0` comes back; no saved network until #935 adds persistence, so setup's network step asks again if setup is still open. |

## Scope (files)

- `broker/cmd/agentos-ap/`: `main.go`, its tests, `agentos-ap.service`.
- `broker/localui/aploader.go`, `aploader_test.go`, `station.go`, its tests, `broker/localui/ASSUMPTIONS.md`.
- `broker/cmd/agentos-netjoin/agentos-netjoin.service` and its unit-file test.
- `broker/netjoin/ASSUMPTIONS.md` (N2, N13 only; append-only rows exempt from D-111).
- `image/mkosi/mkosi.conf` (`Packages=` gains `iw`), `image/mkosi/exec.allow` if `iw` ships an exec-channel file.
- `image/ci_boot.sh` (the hwsim boot in test 7), `tests/test_image_station.py` (new), `image/ASSUMPTIONS.md`.

Not in scope: NetworkManager's config (r4a), the helper's code beyond its unit's flags, the store for saved networks (#935), a second USB radio.

## What to build

- **Who creates the station.** The loader (`agentos-ap`, root) creates `wlsta0` on `wlan0`'s phy right after `APLoader.Start` and before `Up`, and again after every Down/Up. It uses Debian's `iw` (`iw phy <phy> interface add wlsta0 type managed`): reuse beats new nl80211 code; the PR says why if it chooses otherwise.
- **Only when the radio allows it.** The loader reads the phy's interface combinations (`iw phy <phy> info`) and creates `wlsta0` only if one combination allows AP and managed together. A missing or unparsable answer creates nothing (a guard does not fail open into a half-working radio). The decision is logged once as allowed or not, never with network names or keys.
- **One channel.** If the allowed combination has `#channels <= 1`, the station's channel moves the AP: the loader takes the AP Down then Up on the station's channel. Whether the M6 Ultra needs this comes from #1113's reading; the brief does not assume it.
- **Netjoin's flag.** `agentos-netjoin.service` passes `-station wlsta0` (never `wlan0`) and orders `After=agentos-ap.service`. The unit's other hardening stays as P2-2w c3 test 7 checks it.
- **Setup's answer.** `StationDevice` keeps returning true for `wlsta0` throughout setup (#1495, localui L48); no change to `Config.Station` callers.
- **Dead code.** Delete `APLoader.Station` (single-radio handover, no non-test caller) and its tests.
- **The drop.** `wlsta0` gets no rule in `agentos_inbound` and no `.network` file; r4a's finalize check and I17's radio test keep that true.

## Acceptance tests

1. Loader unit tests with a fake `iw`: AP plus managed allowed creates `wlsta0` once, after Start and before Up; not allowed, an error, or unparsable output creates nothing and `Station()` is false; a second Start does not create a duplicate. A mutation that creates the station on an unparsable answer must fail.
2. Single-channel case: with `#channels <= 1` the loader's call order is Down, Up on the station's channel; with more channels it does not touch the AP.
3. Unit-file test: `-station wlsta0` is present, `wlan0` is not a `-station` value, `After=` names `agentos-ap.service`, and the existing hardening assertions still pass.
4. `APLoader.Station` no longer exists (a build of its old test fails to compile, so the test is deleted with it); `go vet` and the localui tests pass.
5. CH-9: the diff touches none of localui's listener, source-subnet check or `NftRules`, and their existing tests pass.
6. A synthetic canary PSK (`wifi_psk`, from #2537 if merged, else a local synthetic value) sent through the helper in test 7 appears in no journal line, no file on the drive, and no loader log.
7. `ci_boot.sh` boots with `mac80211_hwsim` (two radios: one stands in for the box; the other is moved into its own network namespace before the loader starts, since the loader takes every `phy80211` interface (localui I16), and runs a test WPA2 access point there with a synthetic SSID), and on that boot: `wlsta0` exists; NetworkManager manages only it; a join through the helper's socket reaches `joined`; DNS resolves over the station; the box's own AP stays up; the inbound probe finds every port dropped on the station's address; health still reads `forward=off`. A loader restart and a reboot then give the matrix's outcomes.
8. ASSUMPTIONS: localui records the station's creator and the combination check; netjoin N2 and N13 name `wlsta0`; image records `iw` and the hwsim boot.

Every lifecycle row above has at least one test among 1-7; the PR maps them.

## Out of scope

- A second USB adapter.
- Persistence of the saved network (#935).
- Listing networks in range (#1282, which follows this half).
