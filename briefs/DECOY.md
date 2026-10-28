# DECOY: breach decoys, heartbeats and drills (KRN-12)

Board section: Migration to the capability kernel (D-139) for slices a, b, e and f; Devices, hardware and image (SPEC §13-14) for c and d. SPEC KRN-12, KRN-10 (its limits; a trip gets KRN-12's own response), CLK-4 (the detector), KEY-3, KEY-4, KEY-6 (narrowing and resume), CH-15 (security class), NET-2 (channel, texts and calls), NET-4 (tightenings), DEP-3, KRN-6 (the simulator). Decision D-232. Six slices, one session each, tests first (CLAUDE.md), every touched package's `ASSUMPTIONS.md`.

## The gap

Canaries exist only in tests. A running box that is breached raises no alarm: an intruder who reads a sandbox's environment, opens the sealed store's entries, scans the home network or kills the core's process is never seen, and the enforcer's alerts ride the core's owner line, so a rooted core can swallow them.

- **Failure path:** an injected planner or a rooted sandbox, host or edge finds a credential-shaped value, uses it, and nothing trips; or a rooted core stops sending and nothing notices.

## Decisions (the brief's; a builder who finds one wrong stops and comments on the work item)

1. **One table, one matcher.** `broker/decoy/` holds the table type, the generator calls and the matcher. The matcher is CLK-4's fixed-pattern detector (`broker/browser/filter.go`'s patterns, moved into `broker/decoy/match/` and imported back by the browser clerk) with the table's values and destinations added. It runs on the core only: the enforcer trips on its fixed addresses (decision 4) and imports nothing from `broker/decoy/`.
2. **No new grant kind.** A honey key is a key-shaped value signed by no root. The key check already refuses it (KEY-1); the kernel looks a refused key up in the table and, on a hit, logs a trip instead of a plain refusal.
3. **The table is sealed and logged.** It is stored in the sealed store (STO-2), so neither the image nor the repository shows a decoy, and it reaches the kernel as one logged event at first boot (KRN-1), so a replay gives the same trips (KRN-6). The wallet seeds are not in it (decision 5).
4. **The enforcer's decoy addresses are fixed.** They are 169.254.169.254 and a never-assigned range of each segment, shipped in the enforcer's image; DHCP never hands them out, nothing is read over the channel, and placements that name a host (an SSH `known_hosts` entry for "core-admin", a "Backups" share path) point into the range. Drop-and-trip rules on them are part of the enforcer's own ruleset; no listener runs, and a trip changes no rule.
5. **Wallets use a mature library.** BIP39 seeds and BIP84 receive addresses through an existing Go library (for example `btcsuite/btcd/btcutil/hdkeychain`); the PR names why if it picks another. The box never broadcasts a transaction and holds no code that spends. Seeds are made at setup, outside the table, and never logged.
6. **The enforcer's own line** (pending Mark's card; it gets its own D row and a NET-2 spec PR if chosen): ENF-h sends its texts and calls on a send-only modem and SIM of its own (`broker/modem/at` reused, inbound refused, no data bearer). If Mark picks "light and wallets only", slice d drops this and ENF-h stays as briefed.

## Slices

### DECOY-a (#3762): the table and the matcher (KRN-12 One table, Trips)

**Scope:** `broker/decoy/` (new), `broker/decoy/match/` (new), `broker/browser/filter.go` (imports the moved patterns), `tools/risk_tier.py` (one line; a gate file, so this PR also owes a separate Security accept, OPERATING §7).
**Builds:** the table (value, kind, destination, placement), its generation at first boot from the same generators that make real entries, its sealed storage and its first-boot log event (decision 3), and the matcher over bytes and destinations.
**Acceptance tests:**
1. KRN-12: `decoy::TestDecoyIndistinguishable`: for each kind, generated decoys and real entries pass the same format checks and a two-sample test on length and character classes finds no difference. Catches a decoy an intruder can skip.
2. KRN-12: `decoy::TestTableSealedAndReplayed`: the table is readable only through the sealed store, and replaying the log gives the same table and the same trips. Catches a public table or a nondeterministic trip.
3. CLK-4: `match::TestTableAndPatterns`: every table value and every existing CLK-4 pattern matches, split across two writes too; random high-entropy text without a table entry does not trip. Catches a lost CLK-4 case or a false trip.
**Size:** about 90k, tier A, strongest model. **Depends on:** #3761 and the D-232 row merged.

### DECOY-b (#3763): kernel trips and the response (KRN-12 Trips, Response)

**Scope:** `broker/kernel/` (trip entry, refusal lookup, outbound-path match, response, resume), `broker/kernel/key/` only if the refusal needs a typed reason. Trusted-core growth: a one-row DECISIONS PR naming this slice's PR and citing D-232 merges first, then the PR body carries `Trusted-core: <that row>` (D-159; `tools/trusted_base.py` accepts only a row naming the PR itself).
**Builds:** a `trip` log entry; a refused key that is in the table logs a trip; the kernel's outbound path runs the matcher; a trip pauses the keys of its scope (KEY-6's pause), stops planning, and queues one fixed-template security text; a honey-key trip stops only the citing planner session; a resume of a trip's pause needs a passkey assertion (KEY-4), a texted RESUME is refused with fixed wording.
**Acceptance tests:**
1. KRN-12: `kernel::TestHoneyKeyTripsSessionOnly`. Catches a careless planner stopping the box, or a honey key that authorizes.
2. KRN-12: `kernel::TestOutboundDecoyPausesScope`: a decoy value in an outbound request pauses that scope's keys before the request leaves, logs one trip and queues one security text. Catches a decoy that leaves.
3. KRN-12: `kernel::TestTripResumeNeedsPasskey`. Catches an intruder holding the owner's number undoing the pause.
4. KRN-6: `sim::TestTripDeterministic`: same log and events, same trip entries. Catches a nondeterministic matcher in the kernel.
**Size:** about 110k, tier A, strongest model. **Depends on:** DECOY-a (#3762).

### DECOY-c (#3764): the edge (KRN-12 Placement, Trips, Silence)

**Scope:** `broker/edgelink/` (matcher on the core side of the link, heartbeat kind), the edge's image profile under `image/` (placements as data).
**Builds:** the matcher on everything the core sends to the edge except one placement kind that only the kernel sends, at enrolment; the edge's dotfiles and jackpot files written from the table through that kind; a signed heartbeat from the edge each interval, a missed one alarmed on the core.
**Acceptance tests:**
1. KRN-12: `edgelink::TestDecoyToEdgeTrips`: a decoy in any kind but the kernel's placement kind trips; enrolment and re-enrolment after a restore trip nothing. Catches a guest's query smuggling a decoy out, or a false trip at every enrolment.
2. KRN-12: `edgelink::TestHeartbeatSilenceAlarms`: two missed beats raise one alarm, a late beat clears nothing without the log saying so. Catches a killed edge going unseen.
3. KRN-12: the image test that the edge image adds no listener for any placement. Catches a fake service.
**Size:** about 80k, tier A (the link), strongest model. **Depends on:** DECOY-b (#3763).

### DECOY-d (#3765): the enforcer (KRN-12 Placement, Trips, Silence; NET-2)

**Scope:** `broker/enforcer/decoy/` (new: the fixed addresses, decision 4), `broker/enforcer/nft/` (drop-and-trip rules), `broker/enforcer/channel/` and `broker/enforcer/wire/` (the heartbeat kind), `broker/enforcer/alert/` (trip and silence alerts; the own line only if Mark chooses it, decision 6), `broker/kernel/enforcer/` (sending the heartbeat).
**Builds:** the fixed decoy addresses, kept out of DHCP; drop-and-trip rules; a trip lights the light, shows on the page and sends an alert through the kernel like NET-2's other alerts, changing no rule; the core's signed heartbeat on the channel, silence alarmed with no cut; and, only if Mark chooses it (decision 6), the alerts sent on the enforcer's own send-only line.
**Acceptance tests:**
1. KRN-12: `nft::TestDecoyAddressDropsAndTrips` (network namespace). Catches a scan that goes unseen or reaches a listener.
2. KRN-12: `alert::TestCoreSilenceAlarmsNoCut`. Catches a dead core unseen, or a reboot that locks the owner out.
3. Only if Mark chooses the own line (decision 6; its NET-2 spec PR lands first): `alert::TestTextNeverRidesCore`: with the core dropping every channel message, the trip text still leaves on the own line. Catches a core that swallows alerts. Until then a trip or core silence at the enforcer is certain to show only on its light and page (NET-2 Texts and calls).
4. NET-2: `channel::TestHeartbeatStrictFrame`: the heartbeat frame carries only its fields and signature. Catches a heartbeat kind that smuggles anything else.
5. KRN-12: `nft::TestTripChangesNoRule`. Catches an automatic cut the owner did not make (NET-4).
**Size:** about 120k, tier A, strongest model. **Depends on:** ENF-d (#3660), ENF-e (#3661), ENF-h (#3666), DECOY-a.

### DECOY-e (#3766): placements and the wallets (KRN-12 Placement, Outside canaries)

**Scope:** `broker/decoy/place/` (new), the planner sandbox and host image placements under `image/`, the sealed store's decoy entries (`broker/clerk/seal/`), the planner's key view (honey keys), `broker/decoy/wallet/` (new), the edge seed copy through DECOY-c's placement path, the owner-page step (`broker/localui/`, sub B's directory: coordinate on the issue first).
**Builds:** environment variables, dotfiles and jackpot files in the sandbox and host; decoy root and recovery entries in the sealed store; honey keys in the planner's view; three wallets made at setup, each seed planted at one boundary (the host's jackpot files, never the planner sandbox; the edge's; the sealed store, which every backup carries), receive addresses shown as QR codes in one optional owner-page step, never the seeds.
**Acceptance tests:**
1. KRN-12: `place::TestEveryPlacementFromTable`: each placement's bytes are a table entry, wallet seeds aside, each credential-shaped decoy names a destination in the enforcer's decoy range, and each kind on the list is placed. Catches code at a place or a missed place.
2. KRN-12: `wallet::TestSeedNeverLeaves`: the seed appears only in its decoy copies; logs, texts, the owner page and STATUS carry the address only, and no seed is in the planner sandbox. Catches a seed leak the owner pays for.
3. DEP-3: `wallet::TestSkippedStepCostsNothing`. Catches a required optional step.
**Size:** about 110k, tier A, strongest model. **Depends on:** DECOY-a (#3762), DECOY-b (#3763), DECOY-c (#3764, the edge's placement path).

### DECOY-f (#3767): drills (KRN-12 Drills)

**Scope:** `broker/kernel/sim/` (drill scenario), `tests/` or `evals/` (the intruder playbook script), STATUS's broken line in the kernel's STATUS view.
**Builds:** a scripted intruder search over the sim box in the order KRN-12 lists; per tripwire, time to detect and false trips recorded in the log; a scheduled run (default weekly); STATUS lists a tripwire whose last drill is missing or failed as broken.
**Acceptance tests:**
1. KRN-12: `sim::TestDrillTripsEveryPlacement`: every table placement and enforcer decoy address trips within one minute of simulated time at its exit; the wallets are watched by the owner's phone and are not drilled. Catches a dead tripwire.
2. KRN-12: `sim::TestDrillNoFalseTrips`: an ordinary week of sim tasks trips nothing. Catches an alarm that cries wolf.
3. KRN-12: `kernel::TestStaleDrillShowsBroken`. Catches a tripwire trusted without proof.
**Size:** about 80k, tier A (`broker/kernel/sim/`), strongest model. **Depends on:** DECOY-b to DECOY-e.
