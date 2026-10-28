# ENF-j: the enforcer's radio stacks (NET-2 Confined radio stacks, NET-6)

Spike for #3668, brief `briefs/ENF.md`. No product code. It chooses the Zigbee and Thread host stacks, the controller for Matter and lock devices, and the USB radios for the Protectli V1410, and measures how each can be confined. Measured 2026-10-28 on the CI container (Linux 6.18, x86-64, no IPv6 in the kernel).

## Answer

| Need | Choice | Runtime added | Confidence |
|---|---|---|---|
| Thread | OpenThread's own POSIX daemon, `ot-daemon`, built with border routing, SRP server, SRP advertising proxy and its built-in mDNS; not `otbr-agent` | none (C++) | measured from source |
| Thread radio | Nordic nRF52840 Dongle (PCA10059) running OpenThread's RCP firmware, built from `openthread/ot-nrf528xx` source | none | [Inference] |
| Matter and Matter-over-Thread locks | `matter.js` (`@matter/main`) as controller | Node.js | measured from packages |
| Zigbee and Zigbee locks | `zigbee-herdsman` with `zigbee-herdsman-converters` | Node.js (the same one) | measured from packages |
| Zigbee radio | an EFR32MG21 or MG24 dongle (Sonoff ZBDongle-E, or Home Assistant Connect ZBT-2) with Silicon Labs' EmberZNet NCP firmware, driven by herdsman's `ember` driver | none | [Inference] |
| Z-Wave | none: SPEC names only Zigbee, Thread and Bluetooth | — | SPEC |

The Zigbee and Matter choices add a Node.js runtime to the enforcer image, so per #3668 they are a question for Decisions (below). Decision 6 in the brief records the choice as pending that answer.

## Candidates and measurements

Package counts are `npm ls --all` or `pip list` after a clean install into an empty directory; dates are the registries' last release. Nothing third-party was executed: building OpenThread here was refused by the session's permission check, so each stack's confinement needs come from reading its source (OpenThread at `3d645eb`, 2026-10-28) and package manifests, and the probe below measures the confinement itself.

### Zigbee host

| Candidate | Language | Install | Last release | License | Notes |
|---|---|---|---|---|---|
| **zigbee-herdsman 11.1.1 + converters 26.125.0** | TypeScript on Node | 25 packages, 43 MB; one native addon (`@serialport/bindings-cpp`, prebuilt, rebuild from source in the image) | 2026-10-20 / 2026-10-27 | MIT | 401 vendor files, about 3,570 `zigbeeModel` entries; drivers for EZSP/Ember, Z-Stack, deCONZ, ZBOSS, ZiGate and zigbee-on-host. Pulls `bonjour-service` for adapter discovery only, which the confinement makes inert. |
| zigpy 2.4.1 + bellows 1.2.1 + zigpy-znp 1.1.1 | Python | 30 packages, 57 MB | 2026-10-28 | GPL-3.0 | ZHA's library; device quirks live in `zha-quirks`. Adds Python, and Matter would still need a second stack. |
| shimmeringbee `zstack`/`zigbee`/`zcl` | Go | — | last commit 2024-07-14 | Apache-2.0 | No runtime, but dormant for 27 months and Z-Stack only. Adopting it means owning a radio-facing parser that anyone in range reaches. Rejected. |
| Silicon Labs Z3Gateway / zigbeed | C | — | — | Silicon Labs MSLA | No runtime; not open source, not in Debian, tied to one vendor's SDK. Rejected. |
| A new Go Zigbee host | Go | — | — | — | Fails reuse (SPEC §2): a full ZDO/ZCL host plus device quirks is several packages of new radio-facing code. Rejected. |

### Thread host

`ot-daemon` (OpenThread core plus its POSIX platform, BSD-3-Clause) now carries everything the enforcer needs in one binary: `OT_BORDER_ROUTING`, `OT_SRP_SERVER`, `OT_SRP_ADV_PROXY`, `OT_DNSSD_DISCOVERY_PROXY` and `OT_MDNS` are core build options (`etc/cmake/options.cmake`). `otbr-agent` adds Avahi or mDNSResponder, D-Bus, a REST server and a web UI, none of which the enforcer needs, so it is not chosen. The CLI arrives over a Unix socket (`src/posix/platform/daemon.cpp`), which is the narrow interface's transport.

What `ot-daemon` needs from the kernel (from `src/posix/platform/*.cpp`): a tun device via `TUNSETIFF` (`netif.cpp:3255`), `NETLINK_ROUTE` to set its own addresses and routes, IPv6 UDP and raw ICMPv6 sockets, and, with border routing on, the same on its infrastructure interface. Its mDNS also opens IPv4 sockets (`mdns_socket.cpp:508`), which stay inside the namespace.

### Matter controller

| Candidate | Language | Install | Last release | License | Notes |
|---|---|---|---|---|---|
| **matter.js (`@matter/main` 0.18.0)** | TypeScript on Node | 12 packages, 151 MB (ships ESM, CJS and sources); no native addon unless BLE | 2026-10-20 | Apache-2.0 | Open Home Foundation's new Matter server (npm `matter-server` 1.5.5, 2026-10-26) is built on it, so it is the maintained controller in the largest open home stack. Door Lock cluster included. BLE commissioning uses `@stoprocent/noble` (raw HCI) or a BLE proxy. |
| connectedhomeip (`chip-tool` or a C++ controller on the SDK) | C++ | not measured: the SDK checkout and its gn/ninja build were not run here | — | Apache-2.0 | No runtime and BLE through BlueZ D-Bus, but no Debian package; the image pipeline would carry the SDK build. Chosen only if Decisions refuses a runtime. |
| python-matter-server 8.1.2 | Python over the C++ SDK | — | 2025-12-15 (SDK wheels 2025-07-01) | Apache-2.0 | Being replaced by the matter.js server. Rejected. |

### Locks

Matter-over-Thread locks (Door Lock cluster) go through the Matter controller; Zigbee locks (ZCL Door Lock, 0x0101) through herdsman. Both clusters carry lock, unlock with an optional PIN, PIN-code users with schedules, and lock-operation events, which is what slice q's visitor codes and relock need. Z-Wave locks stay out: SPEC NET-2 names Zigbee, Thread and Bluetooth, and adding Z-Wave is a SPEC change.

## Confinement measured

`run.sh` builds `probe/` (standard library only) and runs it under two profiles. Each runs as `nobody`, with no-new-privileges and a seccomp filter that denies ptrace, mount, namespace changes, bpf, kernel modules, kexec, keyrings, perf, userfaultfd, cross-process memory, io_uring and `AF_PACKET` sockets (`probe/main.go`, `denied`).

- **serial** (Zigbee): a private, empty network namespace, no capabilities, and seccomp also denies `AF_INET`, `AF_INET6` and `AF_NETLINK`. The stack gets its serial device by file ownership and the command interface as a Unix socket.
- **thread** (Thread and the Matter controller): `nobody` owns a new user and network namespace, so the capabilities it holds act only on that namespace. It creates `wpan0` there from a tun node the launcher granted it, and sets it up itself, which is what `ot-daemon` does.

Result on this kernel, every check as expected:

| Check | serial | thread |
|---|---|---|
| Read the enforcer's policy file (root, 0700 directory) | refused | refused |
| ptrace, unshare | refused | refused |
| `AF_PACKET` socket | refused | refused |
| Unix socket for the command interface | allowed | allowed |
| Interfaces visible | lo | lo, then its own wpan0 |
| `AF_INET`, `AF_INET6`, `AF_NETLINK` sockets | refused | allowed (namespace-local) |
| Create and bring up wpan0 | — | allowed |
| UDP to a LAN address | — | refused: network unreachable |

Negative control: the same probe run as root with no confinement fails 5 of its 8 serial checks and sees `eth0`, so it detects missing confinement.

Not measured here: IPv6 traffic on wpan0 (this kernel has no IPv6), real radios, and the candidates' own syscall sets. ENF-k records each stack's syscalls on hardware with `strace -f -c` and turns the deny list into an allowlist.

## Design consequences for the slices

1. **One network namespace holds Thread and the Matter controller, and nothing else.** `ot-daemon` and the matter.js process share a namespace containing lo, `wpan0`, and a dummy `infra0` that `ot-daemon` uses as its infrastructure link, so SRP registrations reach the controller's mDNS without any LAN interface. [Inference] that `ot-daemon` advertises on a dummy interface; ENF-q2's first test checks it. Matter devices on Wi-Fi are out of this namespace and of scope until a slice adds a filtered veth from Devices.
2. **Zigbee has no IP at all.** herdsman runs in the serial profile; its only paths are the dongle and the Unix socket.
3. **BLE commissioning of Matter devices goes through the BLE stack's interface.** matter.js on Linux uses raw HCI (`noble`), which would take the adapter from BlueZ. Instead the controller's BTP traffic (connect, write, indicate on the Matter GATT service) is a declared op of the BLE process (ENF-k), as the Matter server's `ble-proxy` package already does for remote radios. Pairing is a loosening at home, so this path is rare.
4. **[Risk] A radio process holds its network's keys.** The Matter process holds the fabric's operational credentials and herdsman holds the Zigbee network key, so a compromised radio process can unlock a lock it controls even though it cannot touch the rules. Confinement stops it from reaching the policy, the page, the LAN or the other stacks; it does not stop misuse of its own devices. Mitigations within NET-2: the pre-authentication surface (Thread MLE and joiner, Zigbee MAC/NWK) is in `ot-daemon` and the NCP firmware, separate from the Matter process; the enforcer relocks after the owner-set interval and texts any unusual-time unlock it observes. Splitting fabric keys out of the controller is later work.
5. **USB.** Only the two radios' (and the BLE dongle's) vendor and product IDs are authorised; other USB ports stay off (NET-2 Hardening, decision 9). Each dongle sits on a short USB 2.0 extension away from USB 3 ports [Inference, common interference advice]. Firmware: the Thread RCP is built from source in the image pipeline; the Zigbee NCP is Silicon Labs' signed binary, pinned by hash, since no open Zigbee NCP firmware exists.

## Question for Decisions (also on #3668)

**Which runtime may the enforcer image carry for its radio stacks?**

- **A. Node.js, one runtime for Zigbee and Matter (recommended).** zigbee-herdsman and matter.js, both maintained, both the bases of the largest open home stacks; Node is a Debian package; one runtime serves both stacks, each in its own confined process. Cost: about 120 MB for the Node binary plus 194 MB of pinned npm packages in the image, and an npm supply chain pinned by lockfile hash.
- **B. No runtime: Thread and Matter only, Zigbee later.** `ot-daemon` plus a C++ controller on the Matter SDK. Smallest image and no npm, but the Matter SDK build joins the image pipeline, and Zigbee locks and sensors are unsupported until a later row.
- **C. Python.** zigpy for Zigbee plus the C++ SDK for Matter (python-matter-server is being retired). Two large stacks and a GPL-3.0 dependency, for no gain over A.

Decision boundary: A is right if Zigbee devices must work at first release; B is right if Matter-over-Thread devices alone are enough and image size or supply chain weighs more.

## Model usage

One session, about 75k tokens.
