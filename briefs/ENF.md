# ENF: the enforcer (NET-2 to NET-7, STO-4)

Board section: Devices, hardware and image (SPEC §13-14). D-178 (the enforcer is standard), D-190 (drones). SPEC NET-1 to NET-7, STO-4, STO-1 (head copies), STO-5, DEV-2 (the enforcer channel exception), A18, A19's home-control clauses, G6. Tier A throughout (KRN-2 puts the enforcer in the trusted base, STO-4 reviews it at the kernel's tier). Strongest model for every slice. Twenty slices, each one session, each its own work item (#3658 to #3675, #3692, #3694 and #3702, listed under **Slices**).

## The gap

SPEC makes the enforcer part of every installation (D-178) and G6 must pass before the first release, but no code, image or work item exists for it. DRONE-enforcer (#3517), DRONE-dock (#3518), DEV-withings-ble-c (#3277), TN-home (#2947), DEV-homekit's live part (#3291) and CAM-node's settings channel (`broker/camwire` already frames enforcer-to-node bundles) all wait on it. Without it the core either reaches home devices with no box between it and them, or home control does not ship.

- **Failure path:** a rooted core, a planner output, or anyone off the Owner network loosens a rule, unlocks a door, turns on a heater, adds a destination or a device, or hides an alert, because the box that should refuse it does not exist or trusts the core.

## Threat and properties

Attackers: a rooted core (holds the channel, the owner line and every camera's video), a rooted edge, any device on Devices or Household, any guest, anyone in radio range, and anyone on the internet. Properties, each owned by a slice and tested there:

- **P1. Rules change only by the owner's passkey, at home (NET-4, NET-6).** Every loosening is an owner assertion over a diff the enforcer rendered itself, on its own origin and relying-party name, served only to the Owner network and the wired admin port, applied 10 minutes later and cancelable. The channel cannot carry one.
- **P2. Tightenings are a closed list (NET-4).** Anything not on it is a loosening. Off-list devices tighten at once, rate-limited; safety-list devices only lock and relock at once, and every other tightening of one needs an owner assertion on a signed link.
- **P8. Safety-list devices act only on the owner's word at home (NET-6, STO-3, STO-4).** Every turn-on or open needs a once-only, named, short-window assertion on the page; their secrets live only on the enforcer.
- **P3. The channel is three fixed-schema kinds (NET-2 Channel, DEV-2).** Device commands, closed-list tightenings, reads. Parsed strictly, rate-limited, a burst pauses it until the owner resumes it on the page. For a safety-list device: reads, lock and relock, and only the one named secure-direction command; a drone's return to dock.
- **P4. Default deny on every segment (NET-2 Segments, NET-3).** Per-device allow lists, the core's signed destination list resolved by the enforcer's own resolver, an edge segment that hears nothing from the enforcer, Guests counted only as a whole, no inbound from the internet.
- **P5. Fails safe to the last signed policy (NET-2, STO-5).** Core down, silent or hostile changes nothing; the light and the page say so.
- **P6. The enforcer's own record is the truth (NET-2 Texts and calls).** Alerts show on its light, page and log even when the core drops or forges the text.
- **P7. Policy is keys (STO-4).** Lists and rules are KEY-1 keys rooted in the owner's passkey and checked with `broker/kernel/key`, with no second rule system; versions only rise.

## Decisions (the brief's; a builder who finds one wrong stops and comments on the work item)

1. **Code lives in `broker/enforcer/` and `broker/cmd/agentos-enforcer/`, as enforcer code under the drone's rule.** The enforcer shares no kernel, secret or update source with agentOS (NET-2 Channel), so, as `broker/drone` already does (`broker/daemon/arc2_test.go`, `TestDroneImportsNothingFromAgentOS`), everything under `broker/enforcer/` and its main links nothing from agentOS except `broker/kernel/key` (STO-4 requires the same key-check library; it imports only the standard library), `broker/drone` and `broker/camwire` (enforcer-side halves already built), and named third-party packages. Slice a adds the arc2 rule and its transitive test; each later slice that adds a third-party import adds it there with a sentence on why reuse of a mature component fails without it.
2. **One policy document per version, one key per version (STO-4, P7).** The policy is a canonical JSON document (segments, devices with their network, Wi-Fi identity and allow list, the safety list with each device's named secure direction, the core's destination list, device-to-device pairs, standing rules, freezes and holds, drone limits by reference to `broker/drone`'s policy). A version is a `key.Root{Clerk: "enforcer", Serial: "policy/<version>/<sha256 of the canonical document>/<sha256 of the rendered diff>"}` whose signature is the owner's ES256 assertion (`key.PublicKey.VerifyAssertion` over `key.RootMsg`). That makes the challenge commit to both the change and what the owner saw (NET-4 Passkey rules). No new verb or caveat kind in `broker/kernel/key`; if a slice finds it needs one, it stops and asks on its issue.
3. **The tightening classifier is a pure function over two documents.** `Classify(old, new)` returns tightening (with which closed-list kind and device) or loosening; a change that mixes both is a loosening. Every path that applies a change goes through it.
4. **Firewall: nftables text, loaded atomically.** Slice e compiles the policy into one nft ruleset text (golden-file tested) and one small loader package, the only enforcer package allowed `os/exec`, runs `nft -f` to replace it atomically. A ruleset that fails to load leaves the previous one (P5).
5. **DNS and DHCP: dnsmasq, generated.** The enforcer's resolver for the core's list and for Devices uses dnsmasq's `nftset=` so only addresses its own resolver returned enter the allow sets (NET-2 The core's list). DHCP and DNS run only on the networks NET-2 Hardening lists; the edge's segment gets no listener at all. mDNS for signed pairs and the Wake-on-LAN relay are small Go services, since a general reflector is forbidden (NET-3).
6. **Radios run as confined processes behind one narrow interface (NET-2 Confined radio stacks).** BLE uses BlueZ (decided in briefs/DEV-withings-ble.md). Slice j's spike (`spikes/ENF-radio/README.md`) chose the rest: Thread is OpenThread's `ot-daemon` with border routing, SRP server and advertising proxy and its own mDNS (no `otbr-agent`); the Matter controller, which also drives Matter-over-Thread locks, is matter.js; Zigbee, including Zigbee locks, is zigbee-herdsman with its converters (pending Mark, question 3, since matter.js and herdsman add Node.js to the image). Each runs as its own unprivileged user with no-new-privileges and the spike's seccomp deny list, which refuses every namespace and mount entry point: Zigbee in an empty network namespace with no IP or netlink sockets; `ot-daemon` and the Matter controller together in a user-owned network namespace holding only lo, `wpan0` and a dummy `infra0`. BLE commissioning of Matter devices is a declared op of the BLE process, never raw HCI. No Z-Wave (SPEC NET-2 names only Zigbee, Thread and Bluetooth).
7. **The enforcer image reuses the core's image pipeline, with its own key and feed** (Mark chose A on question 1, D-229). A separate mkosi profile under `image/enforcer/`: Debian packages, `/usr` read-only on dm-verity in A/B slots, Secure Boot, boot counting and rollback, as `image/README.md` already does for the core, signed with an enforcer-only key and published on its own release feed, so neither box updates the other.
8. **Per-device Wi-Fi identity is a per-device VLAN** (Mark chose A on question 2, D-225). The enforcer generates each Devices password and the access point's hostapd `wpa_psk_file` maps it to that device's own VLAN; the enforcer pushes the file over the wired admin port and never shows it to the core. The enforcer then identifies a device by its VLAN tag, not by anything the access point reports.
10. **A safety-list device's secret reaches the enforcer sealed, inside the add-device loosening (STO-3, STO-4).** The enforcer has a pairing key pair (X25519 with ML-KEM-768, as D-149 seals backups; `crypto/ecdh` and `crypto/mlkem`, standard library). The core's pairing clerk seals the device secret to it, bound to the device's identity, and erases the plaintext at once, keeping only the sealed copy until the enforcer reports the secret held. The sealed secret rides the add-device proposal link (as a URL fragment the page posts back with the assertion), usually opened from the core's owner page during the setup session, since the owner is at home to enter Wi-Fi passwords anyway; the diff the owner signs names the device and the sealed secret's hash. The channel never carries a secret in either direction: its reads report only a fingerprint. If a device's secret cannot be sealed this way (the pairing protocol needs the controller's key live during pairing), the slice stops and asks on its issue.
11. **Hardware.** The enforcer is the Protectli V1410 already named in briefs/DEV-homekit.md and briefs/DEV-withings-ble.md, with USB radios chosen by slice j: an nRF52840 Dongle running OpenThread RCP firmware built from source, an EFR32MG21 or MG24 dongle running Silicon Labs' EmberZNet NCP firmware pinned by hash, and a btusb Bluetooth dongle; only their USB IDs are authorised. One OpenWrt access point with VLAN support. Every acceptance test below runs in CI or a VM; live runs are later rows' work.

## Code layout

| Path | Slice | What |
|---|---|---|
| `broker/enforcer/policy/` | a, i | Canonical document, versions, `Classify`, pending loosenings with the 10-minute wait, standing rules |
| `broker/enforcer/page/` | b | The enforcer's own HTTPS origin: confirm screen, diff rendering, assertion check, cancel, resume channel |
| `broker/enforcer/enrol/` | c | Setup secret, first passkey, recovery code, factory-reset state |
| `broker/enforcer/wire/` | d | The channel's frame and message schema (both ends import it; standard library only) |
| `broker/enforcer/channel/` | d | Strict parser, safety-list check, rate limits, pause |
| `broker/enforcer/nft/` | e, i | Ruleset compiler and loader |
| `broker/enforcer/dns/`, `broker/enforcer/mdns/`, `broker/enforcer/wol/` | f | dnsmasq config, pair relay, Wake-on-LAN relay |
| `broker/enforcer/ap/` | g | Access point config and push |
| `broker/enforcer/alert/`, `broker/enforcer/heads/` | h | Texts and calls, the light, head copies and revocations |
| `broker/enforcer/traffic/` | i | Per-device summaries |
| `broker/enforcer/radio/` | k | Confined radio process host and BLE |
| `broker/enforcer/pairseal/`, `broker/enforcer/devsecret/`, `broker/clerk/enfpair/` | r | Sealed pairing hand-off (both ends; standard library only), the enforcer's device-secret store, the core clerk's sealing helper |
| `broker/enforcer/action/` | s | Asserted safety-list tightenings and once-only turn-on or open challenges |
| `broker/enforcer/locks/` | q | Lock rules over the radio interface |
| `broker/enforcer/radio/thread/`, `broker/enforcer/radio/matter/`, `broker/enforcer/radio/zigbee/` | t | The three stacks' launchers, configs and declared-op adapters |
| `broker/cmd/agentos-enforcer/` | l | The daemon: wiring and the lifecycle matrix |
| `image/enforcer/`, `.github/workflows/enforcer-image.yml` | m | The signed image and its CI boot |
| `broker/e2e/enforcer/` | n | A18 in VMs |
| `broker/kernel/enforcer/` | o | The kernel's channel client (core side) |
| `broker/cmd/agentosd/` | p | Wiring the client (serial slot) |

## Guard files (pre-approved in each slice's scope)

- `tools/risk_tier.py`: slice a adds `"enforcer"` to `TIER_A_BROKER` with a comment citing STO-4; slice l adds `cmd/agentos-enforcer` if `risk_tier` does not already class it A through the core list. Tier A and a gate file, so the PR needs the separate Security accept (OPERATING §7).
- `broker/daemon/arc2_test.go`: slice a adds an `enforcer` rule map and `TestEnforcerImportsNothingFromAgentOS` (decision 1); slices that add an import extend it (f, k and q are expected to, and list it in their Scope so the D-111 guard serializes them; any other slice that finds it needs one adds the file to its claim comment); slices o and r add the core-side lines.
- `tools/g1_scope_g2.txt`: the G2 freeze holds and does not name these paths, so each build PR gets a one-line `exempt-pr N` companion PR with its own Security accept (D-198).
- `image/` and `.github/workflows/`: slice m only.

## Lifecycle matrix (integration owner: slice l)

Slice l wires every piece into `agentos-enforcer` and owns this matrix as one table-driven test in `broker/cmd/agentos-enforcer/lifecycle_test.go`; slice n reruns the starred rows in VMs.

| Stage | Outcome | Built in |
|---|---|---|
| First boot, factory state* | Setup network only; only the enrolment page answers; no rule but default deny | c, g, l |
| Enrolment* | First passkey enrolled with the setup secret; recovery code shown once; setup network replaced by the Owner network; core's claim pages reachable from Owner only | c, g |
| Normal | Policy version N enforced; channel open | a, d, e, l |
| Loosening pending, then power loss | Pending loosening survives restart with its original deadline; cancel still works | a, l |
| Core down or silent* | Last signed policy enforced; light and page say core down | h, l |
| Channel burst* | Channel paused; resumes only from the page | d, b |
| Older policy offered | Refused without a fresh assertion; with one, it is a loosening | a, b |
| Update applied, self-check fails* (VM only: slice n) | Rolled back to the other slot; policy unchanged | m |
| Factory reset with the case code | Policy kept; no loosening until a new passkey is enrolled | c, l |
| Recovery code used | Replacement passkey only, after 10 minutes; text, page alert, light | c, h |
| Core key revoked (KEY-7) | Channel refuses the revoked sub-key; head copies keep the revocation | h, o |
| Safety-list device paired | Secret held by the enforcer, released only to that device's process; core holds no copy | r, l |
| Safety-list turn-on asserted | Runs once inside its window; a replay or a channel request is refused | s, l |

## Slices

Each slice: one session, strongest model, tests first (CLAUDE.md), every touched package's `ASSUMPTIONS.md`, the guard files above where they apply. Sizes are estimates and checkpoints (OPERATING §5).

### ENF-a (#3658): policy and keys (STO-4, NET-4 Tightening, Loosening, Standing rules, NET-2 Recovery)

**Scope:** `broker/enforcer/policy/` (new), `broker/enforcer/doc.go`, `tools/risk_tier.py` (one line), `broker/daemon/arc2_test.go` (enforcer rule).
**Builds:** the canonical document and its encoder (decision 2); `Verify(current, next, assertion)`; versions that only rise; `Classify` (decision 3) with the closed list: remove one destination from one device, cut one device's vendor cloud, remove one pair, isolate or remove one device, plus a lock's lock and relock; for a safety-list device every closed-list kind except lock and relock classifies as an asserted tightening (applies at once, but only with an owner assertion over that change, which slice s collects); the pending-loosening store (deadline = assertion time + 10 minutes, cancel, survives restart through an injected store); standing rules (create or widen = loosening, narrow or revoke = tightening, applied inside their window only); the per-device tightening rate limit; the export of the signed versions (documents and assertions, never a Wi-Fi password or device secret) for the core's backup (NET-2 Recovery, BAK-1), served as a channel read by slice d.
**Acceptance tests:**
1. STO-4: `policy::TestVersionKeyVerifiesWithKernelKeyLibrary`: a version signed by the owner's ES256 credential verifies; one signed by another credential, another RP ID, without UV, or over another diff hash is refused. Catches a second rule system or an unbound diff.
2. NET-4: `policy::TestClassifyClosedList` (table over every field of the document, each row for an off-list and a safety-list device): only the closed-list kinds return tightening; for a safety-list device only lock and relock return an at-once tightening and the rest return asserted tightening; every other change, and any mix, returns loosening. Catches a widening that slips through as a tightening, or a safety-list device cut off without the owner.
3. NET-4: `policy::TestLooseningWaitsAndCancels`: applies at exactly +10 minutes on a fake clock, not before, never after cancel, and survives a restart of the store. Catches an early or lost apply.
4. NET-2 Recovery: `policy::TestOlderVersionRefused`: a lower or equal version is refused; a restore of an older document is accepted only as a new, higher version with a fresh assertion. Catches rollback. `policy::TestExportRestoresAndHoldsNoSecret`: the export restores through that path and contains no Wi-Fi password or device secret. Catches a backup the core could use to learn a secret.
5. NET-4 Standing rules: `policy::TestStandingRuleWindow`: a visitor code rule applies inside its window only; narrowing applies at once, widening waits. Catches a core-widened rule.
6. STO-4: `daemon::TestEnforcerImportsNothingFromAgentOS`. Catches a shared kernel or secret.
**Size:** about 120k. **Depends on:** nothing new (`broker/kernel/key` is on main).

### ENF-b (#3659): the confirm screen and passkey assertions (NET-4 Owner's surface, Passkey rules, NET-6)

**Scope:** `broker/enforcer/page/` (new) and its templates.
**Builds:** an HTTPS server on the enforcer's own name (certificate limited to that name, NET-4) that listens only on the Owner VLAN and wired admin interfaces and also refuses by source address; renders a proposal or a pending change from the policy itself in plain words with consequences; issues a challenge per rendered diff (decision 2) and checks the assertion; shows pending loosenings with cancel; shows whether the passkey is synced (backup-eligible flag); resumes a paused channel; shows NET-1's limits in its fixed words and each device's `contained`, `contained except radio` or `not containable` label from the signed policy, never from the device; refuses framing (`frame-ancestors 'none'`, `X-Frame-Options`), cross-origin requests and any proposal link that is malformed or rate-limited.
**Acceptance tests:**
1. NET-6: `page::TestServedOnlyToOwnerAndAdmin`: requests from Household, Guests, Devices, the core's and the edge's segments get no answer. Catches a page reachable off the Owner network.
2. NET-4: `page::TestFalseDiffShowsTrueDiff`: a proposal link whose summary text disagrees with its change renders the change, and the assertion signs the rendered diff. Catches a core-drawn screen.
3. NET-4: `page::TestAssertionRefusals`: none, no UV, wrong RP ID, wrong origin, cross-origin, another diff, replayed: each refused. Catches a weak assertion check.
4. NET-4: `page::TestNotFramable`. Catches clickjacking by an agentOS page.
5. NET-2 Channel: `page::TestResumeOnlyFromPage`. Catches a channel the core can unpause.
6. NET-1: `page::TestLimitsWordingAndLabels`: the limits text equals SPEC's words; a device that reports itself contained still shows the policy's label. Catches a page that overpromises.
**Size:** about 140k. **Depends on:** ENF-a.

### ENF-c (#3663): enrolment, recovery and factory reset (NET-4 Enrolment and recovery, NET-2 Hardening, HW-10, D-178)

**Scope:** `broker/enforcer/enrol/` (new), the page's enrolment and recovery screens under `broker/enforcer/page/` (templates and handlers only).
**Builds:** the setup secret (printed in the case; the enforcer stores only its verifier), first-passkey enrolment over the setup network, the recovery code (generated on the enforcer, shown once, stored as a verifier), replacement-passkey enrolment after the 10-minute wait with a text, page alert and light, the handover that tells slice g to replace the setup network with the Owner network and shows its password and Wi-Fi QR only on the page, and factory reset by the case code (keeps the policy, blocks loosenings until a new passkey enrols). Passkey revocation is not a tightening (NET-4).
**Acceptance tests:**
1. NET-4: `enrol::TestFirstPasskeyNeedsSetupSecret`. Catches enrolment by whoever reaches the setup network.
2. NET-4: `enrol::TestRecoveryCodeEnrolsAfterWaitOnly`: only a replacement passkey, only after 10 minutes, cancelable by the current passkey, with an alert at start. Catches instant takeover by a stolen code.
3. NET-2 Hardening: `enrol::TestFactoryResetKeepsPolicyBlocksLoosening`. Catches a reset that opens the home.
4. HW-10, D-178: `enrol::TestSetupNetworkReplacedAtEnrolment`: after enrolment the setup network's password opens nothing. Catches a sticker that still works.
**Size:** about 110k. **Depends on:** ENF-b, ENF-g (the network handover interface).

### ENF-d (#3660): the channel (NET-2 Channel, Safety devices, Drones, DEV-2)

**Scope:** `broker/enforcer/wire/`, `broker/enforcer/channel/` (new).
**Builds:** the frame (fixed-length device-challenge frame included, as DEV-withings-ble part s needs), mutual authentication by pinned keys (the core's channel sub-key, checked against KEY-7 revocations from slice h through an interface), three message kinds, strict parsing with no other path, the safety-list check (reads; lock and relock; the one named secure direction; unnamable classes refused at naming; unknown type = reads only; camera, microphone, alarm, siren, sensor: no command except a drone's return to dock), a per-kind rate limit and burst pause, a log line per command, a read of the policy export (slice a) and of each safety-list device's secret fingerprint (slice r), never the secret, and a hook that asks slice h to text the owner when a heater turns off or a valve shuts. Proposal links are not on the channel: the core texts them; the channel only rate-counts them if the core announces them.
**Acceptance tests:**
1. NET-2: `channel::TestOnlyThreeKinds` with a fuzz target `FuzzParse`: a loosening, rule change, unlock, disarm, arm, or any unknown or overlong frame is refused and logged. Catches channel widening.
2. NET-2 Safety devices: `channel::TestSafetyListTable` (one row per class in NET-2): exactly the allowed commands pass. Catches an unlock or a turn-on by the core.
3. NET-2 Drones: `channel::TestDroneReturnOnly`. Catches a waypoint on the channel.
4. NET-2: `channel::TestBurstPauses`. Catches a flood.
5. NET-2: `channel::TestHeaterOffTexts`. Catches a silent safety command.
**Size:** about 120k. **Depends on:** ENF-a.

### ENF-e (#3661): segments and the firewall (NET-2 Segments, The core's list, Device paths, Cameras, NET-3, NET-1 limits)

**Scope:** `broker/enforcer/nft/` (new).
**Builds:** the compiler from a policy version to one nft ruleset (decision 4): the Owner, Household, Devices (device identity per the answer to question 2; decision 8 is the recommendation) and Guests networks; the core's and the edge's segments and the cable rule between them; per-device default-deny allow sets filled by slice f; device-to-device drop except signed pairs; inbound from the internet dropped, no UPnP or NAT-PMP; the ISP router's admin and LAN unreachable from every segment; IPv6 parity and router advertisements dropped; outside DNS and known encrypted-DNS resolvers blocked on Devices; Guests counted only in whole-network counters; log rules for blocked traffic and for core and edge connections to devices; the loader (atomic replace, previous ruleset kept on failure).
**Acceptance tests:**
1. NET-3, A18 Segments: `nft::TestGolden` for a fixture policy, and `nft::TestNetnsSegments` (network namespaces with veth and VLANs, root in CI) running the A18 Segments sentences that need no DNS. Catches a reachable segment.
2. NET-3: `nft::TestCopiedMACGetsOwnList`. Catches identity by hardware address.
3. NET-2 Segments: `nft::TestEdgeSegmentSilent`: no reply to DHCP, DHCPv6, router solicitation, DNS, or ARP for any address but the gateway's; a scan finds no open port. Catches a listener on the edge's segment.
4. NET-2: `nft::TestLoadFailureKeepsPrevious`. Catches an open window on a bad update.
**Size:** about 130k. **Depends on:** ENF-a, Mark's question 2 (#3662): options B and C change where identity comes from and so the Devices rules and test 2.

### ENF-f (#3664): resolver, pairs and Wake-on-LAN (NET-2 The core's list, NET-3 Casting, DNS, NET-2 Segments)

**Scope:** `broker/enforcer/dns/`, `broker/enforcer/mdns/`, `broker/enforcer/wol/` (new); `broker/enforcer/nft/` set names only; `broker/daemon/arc2_test.go` (an import line, if any).
**Builds:** the dnsmasq config generator (decision 5) with `nftset=` per allowed name for the core and each device; DHCP and DNS only on the networks NET-2 Hardening lists; port-53 redirect on Devices; the mDNS pair relay (one record set, one pair, one direction pair); the Wake-on-LAN relay for paired machines only.
**Acceptance tests:**
1. NET-2: `dns::TestOnlyResolvedAddressesAllowed` (netns, dnsmasq in CI): an address the resolver did not return for a listed name is dropped. Catches a core dialing an unlisted address under a listed name.
2. NET-3: `mdns::TestPairOnly`: a Devices record reaches only its paired device's network, never Owner otherwise. Catches a general reflector.
3. NET-2: `wol::TestPairedOnly`. Catches a relay that wakes anything.
**Size:** about 110k. **Depends on:** ENF-e.

### ENF-g (#3662): the access point (NET-3, HW-10)

**Scope:** `broker/enforcer/ap/` (new).
**Builds:** the OpenWrt access point's config from the policy (four networks, the setup network before enrolment, per-device PSKs on per-device VLANs per decision 8, vendor cloud, remote access, UPnP and app pairing off, admin only from the enforcer's wired port), pushed over the wired admin port with a pinned host key, verified by reading back, and re-pushed after any drift. Generates each device's Wi-Fi password and hands it only to the page (QR or text).
**Acceptance tests:**
1. NET-3: `ap::TestGoldenConfig` for a fixture policy, including that no core-held value appears in it. Catches agentOS holding a Wi-Fi password.
2. NET-3: `ap::TestRevokeOneRepairsNoOther`. Catches a shared secret.
3. NET-3: `ap::TestDriftRepushed` against a fake AP. Catches a changed AP config left in place.
**Size:** about 100k. **Depends on:** ENF-e, Mark's question 2.

### ENF-h (#3666): texts, the light and head copies (NET-2 Texts and calls, STO-1, STO-4, KEY-7)

**Scope:** `broker/enforcer/alert/`, `broker/enforcer/heads/` (new).
**Builds:** the fixed-wording texts and calls (the closed list in NET-2: ask or alert needing action by text, urgent safety event by call), sent as a channel message to the kernel for the owner line; the light's states (alert raised, recovery pending, core down, channel paused); the alert log; the head-copy store (kernel heads signed by its sub-key under the head domain, key-change entries, erase entries) and the revocation set the channel checks.
**Acceptance tests:**
1. NET-2: `alert::TestDroppedTextStillOnLight`. Catches reliance on the core.
2. NET-2: `alert::TestRoutineUnlockLoggedNotTexted`. Catches noise the owner pays for.
3. STO-1: `heads::TestKeepsEveryHeadRefusesFork`. Catches a rollback anchor that forgets.
4. KEY-7: `heads::TestRevokedSubKeyRefused`. Catches a stolen core's key still working.
**Size:** about 100k. **Depends on:** ENF-d.

### ENF-i (#3667): visibility and vendor firmware (NET-5, NET-7)

**Scope:** `broker/enforcer/traffic/` (new); `broker/enforcer/policy/` (freeze and hold fields); `broker/enforcer/nft/` (counters and the frozen-device rules).
**Builds:** per-device summaries from nft counters and blocked-traffic logs (destinations, bytes, blocked), short and summarised, served only as channel reads; freeze and security-fix hold as loosenings; a frozen device isolated and cut to its list; a lock or alarm freeze only with an assertion on a screen that names the risk. The audit of a vendor update is the core's device clerk's (DEV-1 qualification); the enforcer only applies the owner-signed result.
**Acceptance tests:**
1. NET-5: `traffic::TestSummaryShape`: per-device destination, bytes, blocked; nothing per packet; nothing for Guests but whole-network counters. Catches surveillance of guests.
2. NET-7: `policy::TestFreezeIsLoosening`, `nft::TestFrozenIsolated`. Catches a silent freeze.
**Size:** about 100k. **Depends on:** ENF-a, ENF-e, ENF-f.

### ENF-j (#3668): radio stacks spike (NET-2 Confined radio stacks, NET-6 locks)

**Scope:** `spikes/ENF-radio/` (new), this brief's decision 6 and slice q.
**Builds:** no product code. Chooses the Zigbee and Thread host stacks, the controller for Matter and lock devices on the enforcer, and the USB radios for the V1410, by reuse and dependency cost (SPEC §2, ARC-2); measures each candidate's confinement (unprivileged user, no network but its interface, seccomp) and writes slice q's scope. A choice that adds a language runtime to the enforcer image becomes a question on this issue for Decisions.
**Acceptance tests:** none: a spike; its output is the brief edit and the measurements in `spikes/ENF-radio/README.md`.
**Size:** about 80k. **Depends on:** nothing.

### ENF-k (#3669): confined radio host and BLE (NET-2 Confined radio stacks)

**Scope:** `broker/enforcer/radio/` (new), `broker/daemon/arc2_test.go` (its import lines).
**Builds:** the radio process host: one unprivileged process per stack, one narrow command interface that the channel's and slice s's commands also go through, no access to the policy store, and only its own devices' secrets from slice r's store; and the BLE stack on BlueZ that DEV-withings-ble-c (#3277) builds on.
**Acceptance tests:**
1. NET-2: `radio::TestRadioCannotChangeRule`: the radio process's credentials cannot open the policy store or the page's socket. Catches a radio exploit reaching the rules.
2. NET-2: `radio::TestOnlyDeclaredOps`. Catches a wide radio interface.
3. NET-2, A18 (ENF-k2-rx, #4196): `ble::TestBusPolicyRefusesOtherPeers` and `ble::TestReadDecodesOnlyWanted`: no other bus peer's call or signal reaches the BLE stack, and a body it would drop is never decoded. Catches a compromised bus peer flooding the stack.
**Size:** about 110k. **Depends on:** ENF-d.

### ENF-l (#3670): the daemon and lifecycle (integration owner)

**Scope:** `broker/cmd/agentos-enforcer/` (new), `tools/risk_tier.py` if needed.
**Builds:** wires a to k, r and s into one daemon and its services (page, channel, nft loader, dnsmasq, AP push, radios, alerts) with their users and state paths; owns the lifecycle matrix test above.
**Acceptance tests:** 1. every matrix row not marked VM only: `agentos-enforcer::TestLifecycle/<row>`. Catches pieces that pass alone and fail together.
**Size:** about 130k. **Depends on:** ENF-a to ENF-i, ENF-k, ENF-r, ENF-s.

### ENF-m (#3671): the signed image (NET-2 Hardening, decision 7)

**Scope:** `image/enforcer/` (new), `.github/workflows/enforcer-image.yml` (new).
**Builds:** the mkosi profile (decision 7), services limited to NET-2 Hardening's list, unused USB ports and the Wi-Fi radio off, hardware watchdog, automatic signed security fixes with rollback on a failed self-check, feature and policy-engine changes only with the owner's key, writable state on its own partition (sealed to the TPM if the V1410's is usable; the builder checks and records it in ASSUMPTIONS), and a QEMU Secure Boot boot in CI.
**Acceptance tests:**
1. NET-2 Hardening: `image/enforcer/ci_boot.sh` checks the open-port set equals the list, Wi-Fi and USB storage are off, and a self-check failure rolls back. Catches an extra service or a stuck bad update.
2. NET-2 Channel: `image/enforcer/finish_image.py` refuses an image signed with the core's key or carrying any agentOS release key. Catches a shared update source.
**Size:** about 130k. **Depends on:** ENF-l.

### ENF-n (#3672): A18 in VMs (A18 Segments, Channel, Approvals; A19's home-control clauses)

**Scope:** `broker/e2e/enforcer/` (new).
**Builds:** a QEMU harness with the enforcer image, fake core, fake edge, fake devices and a fake AP on VLAN bridges, running every A18 sentence that needs no hardware and the starred lifecycle rows.
**Acceptance tests:** `e2e/enforcer::TestA18/<clause>`, one per A18 sentence; the ones needing hardware are listed in its ASSUMPTIONS as live-only.
**Size:** about 130k. **Depends on:** ENF-m.

### ENF-o (#3673): the kernel's enforcer channel client (DEV-2, NET-2 Channel, STO-1)

**Scope:** `broker/kernel/enforcer/` (new), `broker/daemon/arc2_test.go` (its line).
**Builds:** the core side: dial the pinned endpoint with the kernel's channel sub-key; send device commands, tightenings and reads as `wire` messages; send each new log head and key-change entry; receive enforcer alerts and hand them to the owner line unchanged; send proposal links to the owner by text. Planners never reach it.
**Acceptance tests:**
1. DEV-2: `kernel/enforcer::TestOnlyWireKinds`. Catches a core that can send what the enforcer must refuse anyway (defence in depth, and a clean A18 log).
2. STO-1: `kernel/enforcer::TestEveryHeadSent`. Catches a missing anchor.
**Size:** about 100k. **Depends on:** ENF-d.

### ENF-p (#3674): wire the client into agentosd (serial slot, D-111)

**Scope:** `broker/cmd/agentosd/` (the files the client needs; named at claim), its ASSUMPTIONS.
**Acceptance tests:** `cmd/agentosd::TestEnforcerChannelStarts` and a restart test. Catches an unwired client.
**Size:** about 80k. **Depends on:** ENF-o and the `cmd/agentosd` serial slot.

### ENF-q (#3675): locks and safety devices on the radios (NET-6, NET-4 Standing rules, DEV-5)

**Scope:** `broker/enforcer/locks/` (new), plus `broker/daemon/arc2_test.go` (its import lines). Stack-independent: it drives locks only through slice k's radio interface, tested against a fake radio; slice t builds the stacks.
**Builds:** unlock or disarm only by slice s's once-only challenge naming the lock, action and short window; an unusual-time unlock needs a second assertion; relock after the owner-set interval; visitor codes from standing rules, set as the lock's own PIN-code schedule (Door Lock cluster, Matter and Zigbee alike); a routine unlock logged, an unusual-time one texted.
**Acceptance tests (the A18 Locks sentences):**
1. A18: `locks::TestVisitorCodeOnlyInsideWindow`.
2. A18: `locks::TestUnusualTimeNeedsSecondAssertion` and `locks::TestTextReplyIsNotSecondAssertion`.
3. A18: `locks::TestStandingRuleUnlockNoAsk`, `locks::TestUnlockOutsideRuleRefused` and `locks::TestCoreCannotWidenRule`.
4. A18: `locks::TestReplayedAssertionRefused`, `locks::TestAssertionForOtherLockOrActionRefused` and `locks::TestRelocksAfterInterval`.
5. A18: `locks::TestRoutineUnlockLoggedNotTexted`.
6. A18: `locks::TestFrozenDeviceIsolated`.
**Size:** about 100k. **Depends on:** ENF-b, ENF-d, ENF-k, ENF-s.

### ENF-r (#3692): safety-device secrets (STO-4, STO-3, decision 10)

**Scope:** `broker/enforcer/pairseal/`, `broker/enforcer/devsecret/`, `broker/clerk/enfpair/` (new); the page's add-device handler and template under `broker/enforcer/page/`; one test file in `broker/enforcer/channel/`; `broker/daemon/arc2_test.go` (the core's line for `pairseal`).
**Builds:** the sealed envelope (decision 10; both ends import `pairseal`, standard library only); the core-side helper the device-pairing clerk calls: seal, erase the plaintext, keep the sealed copy until the fingerprint read, then drop it; the enforcer's store for device secrets (on its state partition, sealed as ENF-m seals state), opened only after the owner's assertion over an add-device diff naming the device and the sealed secret's hash; release of a device's secret only to that device's radio or driver process; erase on device removal. Wiring the helper into each pairing clerk (HomeKit, Matter) is that device row's work, which lists ENF-r as a dependency.
**Acceptance tests:**
1. STO-4: `devsecret::TestOpensOnlyAfterAssertion`: a sealed secret opens only with an assertion over a diff naming its device and hash; the same envelope offered for another device, replayed, or without an assertion is refused. Catches a core that plants or swaps a device secret.
2. STO-3: `enfpair::TestCoreKeepsNoCopy`: after sealing, nothing the helper or its store holds decrypts to the secret, and the sealed copy is gone after the fingerprint read. Catches a core that keeps the key.
3. STO-4: `devsecret::TestReleasedOnlyToOwnDevice`: one device's process cannot read another's secret; the page and channel processes read none. Catches a radio exploit that collects keys.
4. NET-2 Channel: `channel::TestNoSecretOnChannel`: no channel kind or read returns secret bytes, only the fingerprint. Catches a fourth channel kind.
**Size:** about 120k. **Depends on:** ENF-a, ENF-b, ENF-d.

### ENF-s (#3694): safety-list approvals (NET-4 Tightening, NET-6)

**Scope:** `broker/enforcer/action/` (new); the page's action handlers and templates under `broker/enforcer/page/`.
**Builds:** (1) asserted tightenings of a safety-list device (slice a's asserted class: cutting its vendor cloud, isolating or removing it) and the device commands NET-4 puts beside them (turning a camera off, arming an alarm): rendered by the enforcer, applied at once on an assertion over that change, with no 10-minute wait; the channel's requests for them become a texted link, never an action. (2) Every turn-on or open of a safety-list device (heater, oven, plug, relay, valve open, garage door open, a drone flight on one named route): a challenge naming the device, the action and a short window, good once, served only at home (NET-6). The action goes out through the radio host's interface (slice k) or a driver behind it (slice q); ENF-q's unlock and disarm use the same challenge.
**Acceptance tests:**
1. NET-6: `action::TestTurnOnNeedsNamedOnceChallenge` (one row per safety-list class and action): the command runs only with an assertion naming that device, action and an unexpired window; a second use, another device or action, an expired window, or a channel request is refused. Catches a heater turned on by the core or by a replayed tap.
2. NET-4: `action::TestSafetyTighteningNeedsAssertion`: cutting the cloud, isolating, removing, camera off and arming apply only with an assertion and then at once; lock and relock need none. Catches a core that silences a camera or an alarm's phone alerts.
3. NET-6: `action::TestServedOnlyAtHome`: the action routes answer only the Owner network and the wired admin port. Catches an approval reachable from away.
**Size:** about 110k. **Depends on:** ENF-a, ENF-b.

### ENF-t (#3702): the radio stacks (NET-2 Confined radio stacks)

**Scope:** `broker/enforcer/radio/thread/`, `broker/enforcer/radio/matter/`, `broker/enforcer/radio/zigbee/` (new), each with its pinned lockfile or build pin; the image packages are slice m's.
**Builds:** each stack's launcher on slice k's host, with the spike's profiles (`spikes/ENF-radio/run.sh` becomes a Go test), and a small adapter per stack exposing only declared ops: reads, lock and relock, unlock and PIN-code schedules for slice q, the one named secure-direction command, and pairing. The Matter process's BLE commissioning goes through the BLE process. Defers to question 3: on B it builds Thread and Matter only, with a C++ controller on the Matter SDK.
**Acceptance tests:**
1. NET-2: `radio::TestStacksConfined`: each stack's process sees only its own interfaces, cannot read the policy store, cannot enter a new namespace or mount, and holds the spike's seccomp profile. Catches a stack run unconfined.
2. NET-2: `radio::TestStackOnlyDeclaredOps` for each of the three. Catches a wide adapter.
3. NET-2: `radio::TestSrpReachesController`: a simulated Thread node's SRP registration is resolvable by the Matter process inside the namespace, with no LAN interface. Catches the spike's one unverified inference.
**Size:** about 130k; split per stack if larger. **Depends on:** ENF-k, question 3.

## Questions for Decisions (also on the work items)

1. **Enforcer image base (ENF-m).** A: reuse the core's mkosi pipeline (Debian, dm-verity A/B, Secure Boot) with an enforcer-only signing key and feed (recommended: it already meets NET-2 Hardening and is reviewed; SPEC's "OpenWrt-class" reads as small and router-like). B: an OpenWrt x86 build (literal reading; needs new work for verified boot and A/B). C: Buildroot.
2. **Per-device Wi-Fi identity (ENF-e, ENF-g).** A: per-device PSK mapped to a per-device VLAN in the AP's hostapd file, pushed by the enforcer (recommended: identity is the VLAN tag the enforcer sees; no new service). B: the enforcer as a RADIUS server, AP holds no device passwords (one more service and dependency). C: one Devices VLAN and the AP's key-id events (trusts what the AP reports).

3. **Radio runtime (ENF-j, ENF-t; #3668).** A: Node.js for Zigbee (zigbee-herdsman) and Matter (matter.js), one runtime, each stack in its own confined process (recommended: both maintained and the bases of the largest open home stacks; about 315 MB in the image). B: no runtime, Thread and Matter only through the C++ Matter SDK, Zigbee later. C: Python (zigpy) plus the C++ SDK. Measurements in `spikes/ENF-radio/README.md`.

## Usage

Twenty sessions of 80k to 140k each, in waves that follow the Depends lines. Now: a and j. After a: b and d (and e, once question 2 is answered). After b and d: h, k, o, r, s, then p after o. After e: f and g; then i after f, and c after g. Then q (after k, s), t (after k and question 3) and l (after a to i, k, r, s); then m (after l) and n.
