# EDGE-link-core: the core side of the edge link, with edge keys as kernel log entries (HW-15, HW-17, REC-2, BAK-1), split into a to d

Work item: #3290, found designing #3253 (the f brief on #3269, `briefs/MIG-4-recovery-f.md` once it merges, decisions 4 and 5). Tier A. The row crosses four trust zones (the kernel log, enrollment and unlock, a new process that parses bytes from another box, the owner side), so it splits here. Each slice is its own work item and session: a (#3290), b (#3295), c1 (#3296), c2 (#3297) and d (#3298). This file is the brief for all of them; each builder reads the shared part and its own section.

**Decided (Mark, 2026-10-26, Decisions 8 card, "A"):** a hardware key's assertion signs a later or replacement edge key; it is live at once, with no KEY-4 hold, and the old key is cut in the same step, as `Enroll` and e2's backup target already work. The other options were a phone passkey with KEY-4's hold, or a phone passkey at once. KEY-4 names no such case, so an L1 spec-diff owes the exception ("SPEC change owed" below); slices a and d wait on it.

## Shared decisions

1. **One live edge key at a time, bound to this core.** HW-15 has one dedicated cable and one edge. An `edge.enrolled` entry names the edge's Ed25519 public key and the core's head public key (the key `SetupMsg` binds, which every restore regenerates, BAK-1). `State.LiveEdge()` is the key of the last `edge.enrolled` whose head key is the running kernel's, unless an `edge.revoked` or `edge.cut` came after it. A restored log therefore carries every old enrolment and revocation (BAK-1, f decision 4) and trusts none of them (REC-2), with no restore flag: its head key differs.
2. **Log kinds (LOG-5, KRN-1).** Closed set, version 1, in a new `kernel/edge.go`:
   - `edge.enrolled` {key, head, first, replaces, sig}: a widening (`Widening` lists it, so it anchors). `first` is true only for the setup capture (decision 3). Any other enrolment carries the anchor signature over `EdgeEnrollHash(n, head, key, replaces)` with its own domain string, where `n` is the count of `edge.enrolled`, `edge.revoked` and `edge.cut` entries before it, as `LineHash(n, …)` binds a line change so an old approval cannot replay (`cosign.go`). It names the key it replaces, if one is live; the same entry revokes it.
   - `edge.candidate` {key, nonce, sig}: an input entry, folded as given (REPLAY-1): a hello the link process reported (decision 5). Only the link uid's `edgecandidate` call appends it, and only when its key is neither live nor revoked and differs from the latest candidate's; the link port is the only source, so the kernel logs at most one candidate a minute whatever the key, and drops any other hello in that minute, so alternating or fresh keys cannot flood the log. The kernel checks the hello's signature before logging it. It widens nothing.
   - `edge.revoked` {key}: a narrowing, unsigned, like `untarget` (e2). The owner cuts the edge without a replacement.
   - `edge.cut` {slot}: a narrowing and an input entry, folded as given: the kernel appends it at a start that the unlock step reports was not by this PC's TPM slot (an unknown host, §12.2), naming that slot. A moved SSD then trusts no edge key even after the PC is later made trusted (HW-15 "move").
   - The kernel refuses an `edge.enrolled` whose key was ever revoked or replaced in this log, at any head key (KRN-7, HW-15 "never accepts a key it has revoked"). `Rederive` (REPLAY-1, #2934) re-derives each refusal and each `LiveEdge` change; every input those decisions read is in the log (`edge.candidate`, `edge.cut`'s slot, the enrolment's signature), so the kernel holds nothing outside it (KRN-1).
3. **The first key: captured before the confirm, fixed at it, logged at setup.** Before the Owner Card confirm there is no sealed store and no kernel (enrollment runs at the confirm, from the card's factors). So `agentos-link` (c2), in its pre-store mode, takes one hello (decision 5) on the link interface only. The first valid hello wins and is written to a root-only capture file; later hellos are ignored. Enrollment (b) reads that file at the confirm, puts the key in the sealed store under `handoff.FirstEdgeEntry` (`kernel/first-edge`) and removes the file; enrollment for a restore removes the file and stores none. The kernel's `Setup` appends `edge.enrolled{first}` as the entry directly after the sequence-1 `anchors.set` (so sequence 2), with no edge entry before it, and the fold refuses `first` anywhere else. The window closes for good both ways: enrollment never reruns over a store, and a restored log already holds its `anchors.set`. A box with no edge on the cable at the confirm logs no first key; the owner adds the edge later in the page step (HW-15 "an edge added after the Owner Card confirm").
4. **The core's link key is a kernel key; the link process never holds it.** Enrollment generates an Ed25519 link key into the sealed store (`handoff.LinkKeyEntry`, `kernel/link-key`); unlock hands it to the kernel in `KernelKeys`. It is not backed up (BAK-1 "never the kernel's keys"): a restore runs enrollment again and makes a new one. `agentos-link` terminates TLS with a `crypto.Signer` whose `Sign` calls a new kernel call, `linksign`, which signs only a TLS 1.3 server CertificateVerify input (64 spaces, the server context string, a zero byte, a 32- or 48-byte transcript hash) and refuses anything else. This follows Mark's page-CA choice (f decision 2): a compromised link process can complete handshakes while it is compromised but cannot copy the key.
5. **Transport: Go's `crypto/tls`, TLS 1.3 only, one port, two modes.** No new dependency (§2). The core is the server, on one TCP port, bound with `SO_BINDTODEVICE` to the link interface (named by the unit's configuration), and that interface's input chain drops everything but that port (HW-16 "accepts no connection from the edge except on the link"). Both sides present self-signed Ed25519 certificates. The handshake requires a client certificate and checks only its shape (self-signed, Ed25519); it pins nothing. After the handshake the core asks the kernel `edgekey`, on every connection and never cached across one. **Served mode:** the peer's key equals `LiveEdge()`, and the connection carries decision 6's frames; a `hello` on it closes it. **Hello mode:** any other key. The connection carries exactly one `hello` frame within 5 seconds, which the core reads, reports (`edgecandidate`; in pre-store mode, the capture of decision 3) and then closes; nothing is delivered or sent, and any other frame closes it with a fault count. A revoked key's hello is read and dropped. The hello's body is exactly 64 bytes: the edge key's Ed25519 signature over `agentos.edge.hello.v1\x00` followed by the connection's 32-byte TLS exporter value (`ExportKeyingMaterial("agentos edge hello", nil, 32)`), which is the nonce. The exporter is fresh per handshake and bound to it, so a hello cannot be replayed onto another connection, and the logged {key, nonce, sig} lets the kernel check the signature again on replay. Pre-store mode runs the same exchange with an ephemeral core key, since no link key exists yet; the edge pins the core's key only after enrolment (Unowned gaps). Key exchange is pinned to `X25519MLKEM768`, matching D-149's hybrid rule. A key revoked or cut mid-connection closes that connection within one second of the entry (the kernel's answer carries the log length, and `agentos-link` re-asks on a ticker).
6. **Strict framing, both directions (HW-15, HW-17).** A frame is: version (1 byte, 1), kind (1 byte), origin length (2 bytes), body length (4 bytes), origin, body. Nothing else. Kinds are a closed set with a direction and a body cap each:

   | Kind | Direction | Origin | Body cap | Label at the core |
   |---|---|---|---|---|
   | `fetch` | core to edge | the URL | 64 KiB | (outbound) |
   | `fetched` | edge to core | the URL it answers | 16 MiB | `public` (PLN-3 (1)) |
   | `text` | edge to core | the sender's number | 64 KiB | untrusted, second line (CLK-8) |
   | `call` | edge to core | the caller's number | 64 KiB per frame | untrusted, second line (CLK-8) |
   | `device` | both | the relayed device's declared name (NET-2) | 64 KiB | untrusted device state |
   | `hello` | edge to core, hello mode only | empty | exactly 64 bytes | (never delivered) |

   Origin is at most 1024 bytes of valid UTF-8 with no control characters. An unknown version or kind, a kind in the wrong direction, an over-cap length, a bad origin or a short read closes the connection; the parser never resynchronises or skips. The label comes from the kind table above at the core, never from anything the edge sends. Only counts of faults are logged, never content (CLAUDE.md).
7. **Where items go.** `agentos-link` serves delivered items, each with kind, origin, body and label, on one local socket to one configured consumer uid, and takes outbound `fetch` and `device` frames on the same socket. Which component consumes and sends (the kernel's fetch path, the second-line clerk, the device relay) is not this row's (Unowned gaps).
8. **The page step (CH-9; a hardware key, as decided).** The candidate is the key of the latest `edge.candidate` entry that is neither live nor revoked, so it is log state, not memory. The owner page shows its fingerprint with fixed kernel wording, and the hardware key signs `EdgeEnrollHash(n, head, candidate, live)`. The kernel's `edgeenroll` call takes the signature and logs the entry only when the signed key is that candidate's, which only the link uid can put in the log from the link port, so a key the owner side substitutes must also be on the cable. agentosd then texts the owner a tamper alert for every non-first enrolment, after a restore too (HW-15), from the log entry, not from the page.
9. **Each defence names its revert mutant** (potency recurring kind). Every acceptance test below says, in a comment, which one-line revert it fails on, and the reviewer reruns it.

## Lifecycle matrix (integration owner: d, which wires the page step, the alert and the end-to-end test)

| Stage | Outcome | Slice and test |
|---|---|---|
| First boot, edge on the cable before the confirm | first hello captured; stored at enroll; `edge.enrolled{first}` at sequence 2, after `anchors.set`; the edge connects | c2 (capture), b (store), a (log), d (end to end) |
| First boot, no edge before the confirm | no first key; status says no edge is paired and names the page step | b, d |
| A second hello before the confirm | ignored; the first stays | c2 |
| A hello after the confirm | never a first key; logged as a candidate only | a, c2 |
| A restore's enrollment | the capture file is removed and no first key is stored or logged | b |
| Edge added after the confirm | page step, hardware key, logged; tamper alert texted | a, c2, d |
| Replacement edge | same step; old key revoked in the same entry; alert | a, d |
| Edge cut without replacement | `edge.revoked`; its connection closes within a second | a, c2, d |
| Revoked key reconnects or is re-enrolled | handshake refused; re-enrol refused at any head key | a, c2 |
| Restart | `LiveEdge` replays the same | a |
| Restore (REC-2) | new head and link keys; no edge trusted; status asks for the page step in the restore visit; alert after it | a, b, d |
| Unknown-host start (§12.2) | `edge.cut` logged; stays cut after the PC is made trusted, until the page step | a, b |
| Backup | the log section holds every edge entry; the link key is never in it | a (entries), e3 (#3251, the log section) |
| Wipe and new setup without a backup | a new box: a new log and Owner Card, so §12.1 applies again | none (Residual risk 3) |

## a: edge keys in the kernel log (#3290)

**Scope:** `broker/kernel` only (`setup.go` included): new `edge.go` (+`edge_test.go`): the four kinds, their schema lines in `state.go`'s `schema` and `Widening`, `EdgeEnrollHash` beside `LineHash` in `cosign.go`, `Kernel.EdgeFirst` (called by `Setup` only, so `setup.go` takes the first key), `Kernel.EdgeCandidate`, `Kernel.EdgeEnroll`, `Kernel.EdgeRevoke`, `Kernel.EdgeCut`, `State.LiveEdge()` and `State.EdgeRevoked(key)`; `rederive.go` for the new kinds; `kernel/ASSUMPTIONS.md`.
**Requirement IDs:** HW-15, HW-17 (the edge's enrolment proof), REC-2, KRN-1, KEY-7.
**Acceptance tests:**
- `kernel/edge_test.go::TestFirstEdgeOnlyAtSetup`: a first key logs only as sequence 2, directly after the sequence-1 `anchors.set`; anywhere else, and after any edge entry, it refuses. Catches a reopened first-key window, and a fold that refuses every first key.
- `::TestEnrollNeedsAnAnchorAndCutsTheOld`: a phone passkey's, a stale-hash or a missing signature refuses; an anchor's logs one entry that makes the new key live and the old one revoked. Catches a replacement that leaves two keys live.
- `::TestRevokedNeverReturns`: a revoked or replaced key's re-enrolment refuses, also under another head key.
- `::TestRestoredLogTrustsNoEdge`: a replay of the same log under a new head key gives no `LiveEdge`, and keeps every revocation. Catches a restore that revives the old edge (REC-2).
- `::TestCutHoldsUntilEnrol`: after `edge.cut`, no key is live until a page-step enrolment, and the logged signature of the enrolment before the cut, replayed under the same head key, refuses (the count moved). Catches the replay in the L3 model `builds/2026-10-26-pr3300-edge-enroll-replay-model.py`.
- `::TestEnrollOnlyTheLoggedCandidate`: a signed key that is not the latest candidate's refuses; a candidate whose hello signature fails, or any second candidate within a minute, whether the same key, an alternating one or a fresh one, logs nothing.
- `::TestEdgeDecisionsRederive`: `Rederive` over a log with candidates, an enrolment, a cut and a refusal gives the same `LiveEdge` and refusals from the log alone.
- `::TestEdgeEntriesReplay` and a `Rederive` case: the state survives a restart; an unknown kind version or an oversized key refuses (LOG-5).
**Needs:** the KEY-4 spec-diff below merged; e2 (#3284) merged, since it edits `kernel.go`, `state.go` and `cosign.go` (D-111, serial kernel lane). **Guard files:** none (no new package). **Gate:** trusted-core growth: a D-159 row citing HW-15 and REC-2 as the approved design, merged first.
**Estimate:** 80k tokens (a fourth kind, the candidate).

## b: the link key, the first key and the unlock slot reach the kernel (#3295)

**Scope:** `broker/clerk/handoff/handoff.go` (+test: `LinkKeyEntry`, `FirstEdgeEntry`, and `LinkKey`, `FirstEdge` and `Slot` fields in `KernelKeys`, each size-bounded on the wire), `broker/cmd/agentos-enroll/main.go` (+test: generate the link key; read, store and remove the capture file), `broker/cmd/agentos-unlock/main.go` (+test: hand both and the slot that opened the store), `broker/kernel/proc/kernelmain.go` (+test: pass the first key to `Setup`; call `EdgeCut` on a start not by the TPM slot), their ASSUMPTIONS rows.
**Requirement IDs:** HW-15, REC-2, BAK-1 (the link key stays out of backups).
**Acceptance tests:**
- `cmd/agentos-enroll/main_test.go::TestEnrollMakesALinkKeyAndTakesTheFirstEdge`: the store holds a link key and the captured key; the capture file is gone; a malformed or badly signed capture stores no first key and enrollment still finishes.
- `clerk/handoff/handoff_test.go::TestKernelKeysCarryTheLinkKeys`: round trip; oversized or malformed values refuse.
- `cmd/agentos-enroll/main_test.go::TestRestoreEnrollStoresNoFirstEdge`: a capture file present at a restore's enrollment is removed and no `FirstEdgeEntry` is stored.
- `cmd/agentos-unlock/main_test.go::TestUnlockHandsTheSlot`: a TPM unlock and a passphrase unlock hand different slots; a store with neither entry hands none (old boxes still start).
- `kernel/proc/kernelmain_test.go::TestUnknownHostCutsTheEdge` and `::TestSetupLogsTheFirstEdge`.
- `kernel/proc/backup_test.go::TestBackupHoldsNoLinkKey`, if e3 has merged; otherwise e3's builder adds it.
**Needs:** a; e3 (#3251) and f1 (#3253) edit the same files (D-111): start after both merge. **Guard files:** none. **Gate:** D-159 row, if the trusted core grows.
**Estimate:** 60k tokens.

## c1: the link library (#3296)

**Scope:** new package `broker/edgelink` (+tests and a fuzz test): the frame codec of decision 6 (`ReadFrame` for one direction, `WriteFrame`), the kind table with caps, directions and labels, the hello of decision 5 (`SignHello`, `VerifyHello` over the exporter value), and the TLS configurations of decision 5 taking a `crypto.Signer`. No socket, no process, no kernel import. `broker/edgelink/ASSUMPTIONS.md`.
**Requirement IDs:** HW-15 (strict framing, mutual authentication), HW-17, PLN-3 (labels by kind).
**Acceptance tests:**
- `edgelink/frame_test.go::TestFramesRoundTripAndRefuseEveryBadField`: table cases for each field: unknown version or kind, wrong direction, a length one over each cap, a truncated header or body, invalid UTF-8 or a control character in the origin. Each closes with a fixed error and reads no further.
- `edgelink/fuzz_test.go::FuzzReadFrame`: never panics; never returns a frame its re-encoding does not reproduce byte for byte.
- `edgelink/tls_test.go::TestHandshakeShape`: any self-signed Ed25519 client completes the handshake and its key is returned; no client certificate, another key type, TLS 1.2 or a classical-only key exchange fails.
- `edgelink/hello_test.go::TestHelloBindsItsConnection`: a hello verifies only against its own connection's exporter value; one from another connection, under another domain, or not exactly 64 bytes refuses. This pins the hello for the edge-side row.
- `edgelink/tls_test.go::TestSignerSeesOnlyCertificateVerify`: the signer the server calls receives only the CertificateVerify input shape decision 4 names (the shape `linksign` will check).
- `edgelink/kind_test.go::TestLabelComesFromTheKind`: no field of a frame changes the label.
**Needs:** nothing; it can start now. **Guard files:** `tools/risk_tier.py` (`edgelink` in `TIER_A_BROKER`), `tools/trusted_base_parsers.txt` (`parser .../broker/edgelink -- frames and handshakes from the edge`), `broker/daemon/arc2_test.go` (stdlib only). **Gate:** gate-file PR (`risk_tier.py`): the separate Security accept; body line `Trusted-base: parsers -- edgelink decodes the edge's frames`.
**Estimate:** 80k tokens.

## c2: the link process on the core (#3297)

**Scope:** new `broker/cmd/agentos-link` (+tests): the pre-store mode (decision 3's capture), the served mode (the listener bound to the link interface, the handshake through `edgelink`, `edgekey` at each handshake and on the close ticker, the candidate of decision 8, the consumer socket of decision 7); the kernel calls `linksign`, `edgekey`, `edgecandidate` (reported by the link uid only) and `edgeenroll`, `edgerevoke` (owner socket) in `kernel/proc/kernelsock.go` (+test) and their client methods in `broker/owner/kernelsock`; the link unit and its interface's input rule in the image's unit files; `broker/core/core.txt` (`wiring cmd/agentos-link`).
**Requirement IDs:** HW-15, HW-16 (no other connection from the edge), HW-17.
**Acceptance tests:**
- `cmd/agentos-link/capture_test.go::TestFirstHelloWinsOnlyBeforeTheStore`: the first valid hello is written; a second, a badly signed one, or any hello once the store exists, is not.
- `cmd/agentos-link/link_test.go::TestOnlyTheLiveEdgeIsServed`: the live key's items arrive on the consumer socket with the kind's label; any other key gets one hello read, reported and closed, with no item delivered; a non-hello frame from it, a second frame, or no hello within 5 seconds closes with a fault count; a revoked key's hello is not reported; `edgekey` is asked on every connection.
- `::TestRevokeClosesTheConnection`: an `edge.revoked` closes an open connection within a second.
- `::TestBadFrameClosesAndCounts`: a bad frame from the live edge closes the connection and adds one fault count, with no content in the log.
- `::TestListensOnTheLinkInterfaceOnly` (the bind and the input rule's rendering).
- `kernel/proc/kernelsock_test.go::TestLinksignSignsOnlyCertificateVerify`: any other input refuses; a kernel with no link key answers a fixed refusal.
- `kernel/proc/kernelsock_test.go::TestEdgecandidateOnlyFromTheLinkUid`: `edgecandidate` from any uid but the link's refuses and logs nothing; `edgeenroll` for a key that is not the logged candidate refuses.
**Needs:** a, b, c1. e3 (#3251) and f1 (#3253) edit `kernelsock.go` (D-111). **Guard files:** `broker/core/core.txt` (wiring line), `broker/daemon/arc2_test.go` (`cmd/agentos-link` imports `edgelink` and `owner/kernelsock` only). **Gate:** gate-file PR: the separate Security accept; D-159 row for the kernel lines.
**Estimate:** 100k tokens.

## d: the owner side (#3298)

**Scope:** owner side only: the page step of decision 8 (candidate fingerprint, the hardware-key prompt, `edgeenroll`), the cut action (`edgerevoke`), the status lines (no edge paired; edge not trusted after a restore or an unknown-host start, with the step that fixes it), and the tamper alert texted from each non-first `edge.enrolled` entry. Files in `broker/cmd/agentosd`, `broker/localui`, `broker/owner`; agentosd edits run serially (D-111).
**Requirement IDs:** HW-15 (page step, alert), REC-2 (the edge in the restore visit), CH-9.
**Acceptance tests:** the matrix rows marked d, each a test in the touched package: the step shows the candidate and logs on the hardware key's signature; no step without a candidate; an alert for each later enrolment, after a restore too, and none for the first; the status lines for no edge and for an untrusted edge; and one end-to-end test (`broker/e2e`) from a captured first hello through setup, a replacement, a revocation and a restored log.
**Needs:** c2, and the KEY-4 spec-diff below. **Estimate:** 80k tokens.

## SPEC change owed (L1 spec-diff, before a and d)

Mark's answer A is not among KEY-4's no-hold cases: HW-17 makes the edge's key a node key, and KEY-4 holds "a new key" about 24 hours. The L1 spec-diff names the exception and stays word-neutral (D-152). Proposed, for L1 to settle:

- KEY-4: "The owner's phone passkey, which may be cloud-synced, is enrolled under them by a hardware key's signature, at once" becomes "The owner's phone passkey (which may be cloud-synced) and the edge's key are enrolled under them by a hardware key's signature, at once" (+4 words).
- HW-15, the second "in an owner-page step (CH-9) that accepts a key only on the link port" (the later or replacement edge) becomes "in that owner-page step, signed by a hardware key (KEY-4)" (-4 words).

## Unowned gaps (not in a to d)

- **The edge's own side.** No row builds the edge box's link client: its key, its hello, its pin of the core's link key, and how it accepts a new core key after a restore (a physical step on the edge, since a restored core's link key is new). File it with this brief's framing and hello (decision 5, c1's `TestHelloBindsItsConnection`) as its interface. Its pin is also the only thing that could enforce HW-15's "never opens the first-key window again" on a wiped core (Residual risk 3).
- **The consumers.** The kernel's public fetch path (PLN-3, HW-16), the second-line clerk (CLK-8) and the online-device relay (NET-2) read from and write to c2's socket. Each is its own row.

## Residual risks

1. Whoever is on the link cable before the Owner Card confirm is the first edge (HW-15's design; like the page CA's first install, §19 risk 30).
2. A compromised `agentos-link` can inject items, but only as untrusted input with the kind's label, and can complete handshakes while compromised, but cannot copy the core's link key, enrol a key without the owner's signature, or revive a revoked one.
3. A wiped core set up again without a backup is indistinguishable from a new box and opens §12.1's first-key window; nothing on the wiped SSD survives to stop it. This conflicts with HW-15's "reinstall" wording; it is a `later` spec-gap for L1, tied to the edge-side row's pin.
4. A start by passphrase on the same PC (for example after a firmware update the TPM policy does not cover) cuts the edge too, and costs one page step.
