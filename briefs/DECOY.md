# DECOY: breach decoys, heartbeats and drills (KRN-12)

Board section: Migration to the capability kernel (D-139) for slices a, b, e and f; Devices, hardware and image (SPEC §13-14) for c and d. SPEC KRN-12, KRN-10 (a trip is a proof), CLK-4 (the detector), KEY-3, KEY-4, KEY-6 (narrowing and resume), CH-15 (security class), NET-2 (channel, texts and calls), NET-4 (tightenings), DEP-3, KRN-6 (the simulator). Decision D-232. Six slices, one session each, tests first (CLAUDE.md), every touched package's `ASSUMPTIONS.md`.

## The gap

Canaries exist only in tests. A running box that is breached raises no alarm: an intruder who reads a sandbox's environment, opens the sealed store's entries, scans the home network or kills the core's process is never seen, and the enforcer's alerts ride the core's owner line, so a rooted core can swallow them.

- **Failure path:** an injected planner or a rooted sandbox, host or edge finds a credential-shaped value, uses it, and nothing trips; or a rooted core stops sending and nothing notices.

## Decisions (the brief's; a builder who finds one wrong stops and comments on the work item)

1. **One table, one matcher.** `broker/decoy/` holds the table type, the generator calls and the matcher. The matcher is CLK-4's fixed-pattern detector (`broker/browser/filter.go`'s patterns, moved into `broker/decoy/match/` and imported back by the browser clerk) with the table's values and destinations added. `broker/decoy/match/` is standard library only, so the enforcer may import it under the drone rule (`broker/daemon/arc2_test.go`), like `broker/kernel/key`.
2. **No new grant kind.** A honey key is a key-shaped value signed by no root. The key check already refuses it (KEY-1); the kernel looks a refused key up in the table and, on a hit, logs a trip instead of a plain refusal.
3. **Decoys are picked by a sealed secret.** Each entry's decoy bit is an HMAC of its generated value under a sealed-store slot key (STO-2), so neither the image nor the repository nor a copy of the table without that key shows which entries are decoys.
4. **The enforcer makes its own decoy addresses.** It generates them in its own segments with its own generator, never takes them from the core, and serves them as a channel read so the core can plant references (an SSH `known_hosts` entry for "core-admin", a "Backups" share path). Drop-and-trip rules on them are part of the enforcer's own ruleset; no listener runs.
5. **Wallets use a mature library.** BIP39 seeds and BIP84 receive addresses through an existing Go library (for example `btcsuite/btcd/btcutil/hdkeychain`); the PR names why if it picks another. The box never broadcasts a transaction and holds no code that spends.
6. **The enforcer's own line** (pending Mark's card; it gets its own D row and a NET-2 spec PR if chosen): ENF-h sends its texts and calls on a send-only modem and SIM of its own (`broker/modem/at` reused, inbound refused, no data bearer). If Mark picks "light and wallets only", slice d drops this and ENF-h stays as briefed.

## Slices

### DECOY-a (#3762): the table and the matcher (KRN-12 One table, Trips)

**Scope:** `broker/decoy/` (new), `broker/decoy/match/` (new), `broker/browser/filter.go` (imports the moved patterns), `broker/daemon/arc2_test.go` (allowlist line), `tools/risk_tier.py` (one line).
**Builds:** the table (value, kind, destination, placement), its generation at first boot from the same generators that make real entries, the sealed decoy bit (decision 3), and the matcher over bytes and destinations.
**Acceptance tests:**
1. KRN-12: `decoy::TestDecoyIndistinguishable`: for each kind, generated decoys and real entries pass the same format checks and a two-sample test on length and character classes finds no difference. Catches a decoy an intruder can skip.
2. KRN-12: `decoy::TestBitNeedsSealedKey`: without the slot key, the table alone reveals no decoy bit. Catches a public selector.
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

**Scope:** `broker/edgelink/` (matcher on the core side of the link, heartbeat kind), the edge's image profile under `image/` (placements as data, the link-local metadata address answered with a static reply or dropped).
**Builds:** the matcher on everything the core sends to the edge; the edge's dotfiles and jackpot files written from the table at enrolment; a signed heartbeat from the edge each interval, a missed one alarmed on the core.
**Acceptance tests:**
1. KRN-12: `edgelink::TestDecoyToEdgeTrips`. Catches a guest's query smuggling a decoy out through a fetch.
2. KRN-12: `edgelink::TestHeartbeatSilenceAlarms`: two missed beats raise one alarm, a late beat clears nothing without the log saying so. Catches a killed edge going unseen.
3. KRN-12: the image test that the metadata address gets only the static reply or none, and that no listener is added. Catches a fake service.
**Size:** about 80k, tier A (the link), strongest model. **Depends on:** DECOY-b (#3763).

### DECOY-d (#3765): the enforcer (KRN-12 Placement, Trips, Silence; NET-2)

**Scope:** `broker/enforcer/decoy/` (new: its own addresses, decision 4), `broker/enforcer/nft/` (drop-and-trip rules), `broker/enforcer/channel/` and `broker/enforcer/wire/` (the heartbeat kind, the address read), `broker/enforcer/alert/` (trip and silence alerts; the own line, decision 6), `broker/kernel/enforcer/` (sending the heartbeat).
**Builds:** decoy addresses per segment; drop-and-trip rules; a trip cuts the tripping box's internet (a NET-4 tightening), lights the light and texts; the core's signed heartbeat on the channel, silence alarmed with no cut; the alerts sent on the enforcer's own send-only line.
**Acceptance tests:**
1. KRN-12: `nft::TestDecoyAddressDropsAndTrips` (network namespace). Catches a scan that goes unseen or reaches a listener.
2. KRN-12: `alert::TestCoreSilenceAlarmsNoCut`. Catches a dead core unseen, or a reboot that locks the owner out.
3. NET-2: `alert::TestTextNeverRidesCore`: with the core dropping every channel message, the trip text still leaves on the own line. Catches a core that swallows alerts.
4. NET-2: `channel::TestHeartbeatStrictFrame`. Catches a fourth kind that carries anything else.
**Size:** about 120k, tier A, strongest model. **Depends on:** ENF-d (#3660), ENF-e (#3661), ENF-h (#3666), DECOY-a.

### DECOY-e (#3766): placements and the wallets (KRN-12 Placement, Outside canaries)

**Scope:** `broker/decoy/place/` (new), the planner sandbox and host image placements under `image/`, the sealed store's decoy entries (`broker/clerk/seal/`), the planner's key view (honey keys), `broker/decoy/wallet/` (new), the owner-page step (`broker/localui/`, sub B's directory: coordinate on the issue first).
**Builds:** environment variables, dotfiles and jackpot files in the sandbox and host; decoy root and recovery entries in the sealed store; honey keys in the planner's view; three wallets made at setup, each seed planted at one boundary (sandbox and edge jackpot files, sealed store, backup), receive addresses shown as QR codes in one optional owner-page step, never the seeds.
**Acceptance tests:**
1. KRN-12: `place::TestEveryPlacementFromTable`: each placement's bytes are a table entry and each kind on the list is placed. Catches code at a place or a missed place.
2. KRN-12: `wallet::TestSeedNeverLeaves`: the seed appears only in its decoy copies; logs, texts, the owner page and STATUS carry the address only. Catches a seed leak the owner pays for.
3. DEP-3: `wallet::TestSkippedStepCostsNothing`. Catches a required optional step.
**Size:** about 110k, tier A, strongest model. **Depends on:** DECOY-a, DECOY-b.

### DECOY-f (#3767): drills (KRN-12 Drills)

**Scope:** `broker/kernel/sim/` (drill scenario), `tests/` or `evals/` (the intruder playbook script), STATUS's broken line in the kernel's STATUS view.
**Builds:** a scripted intruder search over the sim box in the order KRN-12 lists; per tripwire, time to detect and false trips recorded in the log; a scheduled run (default weekly); STATUS lists a tripwire whose last drill is missing or failed as broken.
**Acceptance tests:**
1. KRN-12: `sim::TestDrillTripsEveryPlacement`: every placement trips within one minute of simulated time at its exit. Catches a dead tripwire.
2. KRN-12: `sim::TestDrillNoFalseTrips`: an ordinary week of sim tasks trips nothing. Catches an alarm that cries wolf.
3. KRN-12: `kernel::TestStaleDrillShowsBroken`. Catches a tripwire trusted without proof.
**Size:** about 80k, tier B. **Depends on:** DECOY-b to DECOY-e.
