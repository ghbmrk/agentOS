# P2-2w c3 r4a: NetworkManager and polkitd in the image

Board row: #936 (P2-2w c3 r4), first half. Split 2026-10-20 on the hardware triage's recommendation: this half ships the services the home Wi-Fi helper (`agentos-netjoin`, P2-2w c3) talks to and extends the uplink tree check to them; [r4b](P2-2w-c3-r4b.md) adds the station device and the helper's `-station` flag. Netjoin, localui and agentos-ap are outside D-139's frozen list, and D-139 keeps hardware, image and Wi-Fi work going (decisions/D-139.md).

**Requirements:**
- ONB-3: the home network is a minimum-path step. Today the helper has no NetworkManager to call and answers `failed` (broker/netjoin N2, N13).
- ONB-4: Wi-Fi setup completes within the target time; this half only makes the services present.
- DEV-2: the home network is untrusted. Adding a network manager must not open a port, turn forwarding on, or manage a link nobody asked it to.
- CH-9: the access point stays WPA3-SAE and the local UI unreachable from the home network. NetworkManager must never touch `wlan0` (the access point) or the wired uplink.
- SPEC v1.0 §6.1 custody exceptions and STO-2: the home Wi-Fi password is root-only and held on the drive only under the sealed store's encryption. Until #935 picks the store, nothing this half ships may write it to the drive.

**Acceptance:** A1 (setup's network step on hardware, with r4b).
**Acceptance tests:** 1-7 below.
**Guard files:** none (no new package).
**Implementation risk:** tier A (`image/`). **Gate:** lenses (security: strongest tier).
**Needs:** #2540 (IMG-1) merged or closed first: it edits `image/ci_boot.sh`, `image/README.md` and `image/ASSUMPTIONS.md`, all in this scope (D-111). #1428 has merged.
**Usage estimate:** about 120k tokens (one image change, one finalize check, one boot check).

## The property this half must hold

With NetworkManager and polkitd running, the box behaves on every network exactly as it does today: no device is managed by NetworkManager except the station interface r4b creates, no packet is forwarded, nothing listens on a home-network address, no probe leaves the box on NetworkManager's own initiative, and no Wi-Fi password lands on the drive. The finalize check states this property and fails closed: a file it cannot read, a key it does not know, or a value it cannot parse is a build failure, never a pass.

## Scope (files)

- `image/mkosi/mkosi.conf`: `Packages=` gains `network-manager`, `polkitd` and `wpasupplicant` (mkosi installs no Recommends, so the supplicant must be named). `RemoveFiles=` for any shipped NetworkManager file the check below would refuse and nothing needs (for example a dispatcher script).
- `image/mkosi/mkosi.extra/usr/lib/NetworkManager/conf.d/50-agentos.conf` (new).
- `image/mkosi/mkosi.extra/usr/lib/systemd/system/NetworkManager.service.d/agentos-inbound.conf` (new), the same ordering drop-in networkd and resolved carry.
- `image/mkosi/mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset`: enable `NetworkManager.service`; disable `NetworkManager-wait-online.service` and `NetworkManager-dispatcher.service`.
- `image/mkosi/mkosi.finalize`: the NetworkManager part of the I21 tree check.
- `image/mkosi/exec.allow` and `image/mkosi/tmpfiles.allow`: entries for the udev rules and tmpfiles lines the packages ship, each by its SHA-256 or exact line.
- `image/ci_boot.sh`: the boot checks in test 6.
- `tests/test_image_nm.py` (new; kept apart from `tests/test_image.py`, which several open PRs edit).
- `image/ASSUMPTIONS.md` (amend I17 and I21, add one row), `image/README.md`.

Not in scope: anything under `broker/` (r4b and #935 own the helper), `image/build.sh`, the station device, the store for saved networks (#935).

## What to build

Fixed points for the builder:

- **Only the station is managed.** `50-agentos.conf` sets `[keyfile] unmanaged-devices=*,except:interface-name:wlsta0`, the station name r4b creates. `[main] no-auto-default=*` so NetworkManager makes no connection for the wired port (networkd keeps it, I19). `wlan0`, every Ethernet port, veth, bridge and tun stay unmanaged whatever their names.
- **Saved networks live in memory only.** `[keyfile] path=` points under `/run` (tmpfs), so the helper's `Update2(TO_DISK)` writes to RAM and a reboot forgets the network. This is the interim answer to §6.1 until #935 builds the sealed-store version; it is the reversible default this brief picks, and the comment on #936 asks Mark to confirm it. The finalize check refuses a keyfile path that is not under `/run`. `/etc/NetworkManager/system-connections` must not exist in the image.
- **No forwarding and no sharing.** NetworkManager enables `ip_forward` only for a shared connection (`ipv4.method=shared` or `ipv6.method=shared`) or an explicit `ipv4.forwarding`/`ipv6.forwarding`. The image ships no connection file at all, the conf sets nothing that changes that, and the helper's fixed settings (broker/netjoin L8.4) use `auto`. The existing `agentos-health` `forward=off` line stays the runtime check.
- **No outbound probe.** `[connectivity] enabled=false`.
- **DNS through resolved.** `[main] dns=systemd-resolved`; resolved's LLMNR and mDNS stay off (`50-agentos-uplink.conf`).
- **polkit authorises only the helper.** `[main] auth-polkit=true`; polkitd 0.106 or later runs the JS rule `50-agentos-netjoin.rules` the image already installs (I17). No other rule ships that answers `YES` for a NetworkManager action.
- **Ordering.** `NetworkManager.service` has `Requires=` and `After=agentos-inbound.service`, like networkd (I11).
- **Finalize check.** Extend the I21 code in the same style (`network_violations`, the `UPLINK_KEYS` allowlist): read every file NetworkManager reads at start (`/usr/lib/NetworkManager/conf.d`, `/etc/NetworkManager/NetworkManager.conf`, `/etc/NetworkManager/conf.d`, `/run/NetworkManager/conf.d` if present, the connection directories, `dispatcher.d`) and fail unless: the conf files hold only allowlisted sections and keys with the values above; no connection file and no executable dispatcher script ships; the keyfile path is under `/run`. Control or non-ASCII bytes fail, as for `.network` files.

## Acceptance tests

1. `tests/test_image_nm.py` parses `50-agentos.conf` and asserts the property above key by key: managed only `wlsta0`, `no-auto-default=*`, keyfile path under `/run`, connectivity off, `dns=systemd-resolved`, `auth-polkit=true`. Removing or changing any one line must fail a test.
2. The finalize check refuses, each in its own fixture tree: a connection file with `method=shared` (IPv4 and IPv6), one with `ipv4.forwarding`, any shipped connection file at all, a keyfile path off `/run`, `unmanaged-devices` that no longer covers `wlan0` or an Ethernet name, an unknown key, an unreadable file, a non-ASCII byte, and an executable dispatcher script. A clean tree passes. A mutation that makes the check skip an unreadable file must fail a test (a guard does not fail open).
3. `mkosi.conf` lists the three packages; the preset enables NetworkManager and leaves wait-online and dispatcher disabled; the drop-in orders NetworkManager after `agentos-inbound.service` with `Requires=`.
4. Every udev rules file and tmpfiles line the new packages ship has its `exec.allow` or `tmpfiles.allow` entry, and the existing allowlist check still fails on an unlisted one.
5. polkitd's version in the built image is 0.106 or later (read from the package list mkosi writes, not assumed).
6. `ci_boot.sh`, on the first boot: `NetworkManager.service` is active; `nmcli -t -f DEVICE,STATE device` lists every device as `unmanaged`; `systemctl --failed` is empty; the health line still reads `forward=off inbound=drop`; `pkcheck` for `org.freedesktop.NetworkManager.settings.modify.system` answers yes for the `agentos-netjoin` user and no for another system user; no file exists under `/etc/NetworkManager/system-connections`. The host-forward probe of the existing boot still finds every port dropped.
7. ASSUMPTIONS: I17 no longer says NetworkManager is absent; I21 names the NetworkManager files the check reads; a new row records the in-memory keyfile store, its reason (§6.1, STO-2) and what replaces it (#935).

Run `python3 tools/doclint.py` and the image tests locally; the image workflow's boot is the check for test 6.

## Out of scope

- The station interface and the helper's `-station` flag (r4b).
- Keeping a saved network across reboot (#935, which also amends L8.7).
- Listing networks in range (#1282).
