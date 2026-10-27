# EDGE-link-core: the core side of the edge link, with edge keys as kernel log entries (HW-15, HW-17, REC-2, BAK-1), split into a to d

Work item: #3290, found designing #3253 (the f brief on #3269, `briefs/MIG-4-recovery-f.md` once it merges, decisions 4 and 5). Tier A. The row crosses four trust zones (the kernel log, enrollment and unlock, a new process that parses bytes from another box, the owner side), so it splits here. Each slice is its own work item and session: a (#3290), a2 (#3345, the follow-up of a), b (#3295), b2 (#3364, the follow-up of b), c1 (#3296), c2 (#3297, built as c2a, c2b #3458 and c2c #3459) and d (#3298). This file is the brief for all of them; each builder reads the shared part and its own section.

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
8. **The page step (CH-9; a hardware key, as decided).** The candidate is the key of the latest `edge.candidate` entry that is neither live nor revoked, so it is log state, not memory. The owner page shows its fingerprint with fixed kernel wording, and the hardware key signs `EdgeEnrollHash(n, head, candidate, EdgeReplaces(candidate))` (a2: the last enrolled key, at any head). The kernel's `edgeenroll` call takes the signature and logs the entry only when the signed key is that candidate's, which only the link uid can put in the log from the link port, so a key the owner side substitutes must also be on the cable. agentosd then texts the owner a tamper alert for every non-first enrolment, after a restore too (HW-15), from the log entry, not from the page.
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

## a2: Rederive re-derives edge decisions, and a restore's enrolment revokes the last key (#3345)

Follow-up of a, from Security's release points 9 and 10 on #3341 (comment 6432393545; probes P1 to P3 in `/mnt/project-files/builds/2026-10-27-pr3341-security-probes_test.go`). The PR body carries `Defect: EDGE-link-core-a`.

**Decisions.**
1. **Rederive takes the head key** (point 9a). The signature becomes `Rederive(anchors, head, es)`: a candidate of `LiveEdge(head)` is not a decision the kernel at `head` makes, so it diverges. Entries before the last restore were written under another head key; for them the liveness check passes, so they never diverge falsely, and only the current head's span is checked exactly (recorded in ASSUMPTIONS). The alternative, recording that Rederive cannot check liveness, leaves a forged candidate able to replace the pending one unseen; one argument closes it.
2. **Rederive compares canonical bytes** (point 9b). `edgeDecision` returns `entry(e.Type, b)` from the decoded struct, as the other decisions do, never `e.Body`; a body with extra or reordered fields diverges.
3. **An enrolment replaces the last enrolled key, at any head** (point 10, HW-15 "revokes the old key in the same step"). `State.EdgeReplaces(k)` is the key of the latest `edge.enrolled` that is not revoked, whatever its head key and whether or not a cut came after it, unless that key is `k`. `Kernel.EdgeEnroll` sets `Replaces` to it and `enrollOK` checks `Replaces` equals it, live and at fold. So after a restore (new head key) or a cut, enrolling another edge B revokes the old key A in the same entry, and a hello from A (a stolen old box) never logs again; re-enrolling A itself, the usual case after a restore or a moved SSD, revokes nothing. The cut case goes past point 10's wording: the gap is the same (an unrevoked old key one tap from return), so the rule is too. `Kernel.EdgeReplaces(k)` exposes it so d's page shows the key being replaced and signs `EdgeEnrollHash(n, head, candidate, EdgeReplaces(candidate))`. `LiveEdge` and the hash are unchanged.

**Scope:** `broker/kernel` only: `edge.go`, `edge_test.go`, `rederive.go`, `rederive_test.go`, the `Rederive` call sites in `task_test.go`, `erase_test.go` and `sim/sim.go` (the new argument), `ASSUMPTIONS.md` (the `EDGE-link-core-a` row: replace its `Rederive` and `Replaces` sentences).
**Requirement IDs:** HW-15, REC-2, KRN-1, KEY-7, REPLAY-1.
**Acceptance tests** (each comment names its one-line revert mutant, decision 9):
- `kernel/edge_test.go::TestRederiveCatchesALiveKeyCandidate` (P1): a candidate of the live key appended past the kernel diverges at its sequence under the running head key, and the same log under another head key does not. Mutant: drop the head liveness check from `edgeDecision`.
- `::TestRederiveComparesCanonicalBodies` (P2): an `edge.enrolled` and an `edge.candidate` that each carry an extra field diverge. Mutant: return `e.Body` as the derived body.
- `::TestRestoreEnrolRevokesTheLastKey` (P3): with A enrolled under head H, the log replayed under H', a candidate B enrolled names `Replaces` A; A is revoked, A's later hello logs nothing, and A is never pending. Mutant: `Replaces: k.LiveEdge()` in `EdgeEnroll`.
- `::TestReenrolTheSameEdgeAfterRestore`: under H', A's candidate enrolled names no `Replaces`, A is live at H' and nothing is revoked. Mutant: replace the last key even when it is the enrolled one.
- `::TestCutThenAnotherEdgeRevokesTheOld`: after `edge.cut`, enrolling B names `Replaces` A and revokes it. Mutant: the cut clears the last key.
- `::TestEnrollReplacesOnlyTheLastKey` (renames `TestEnrollReplacesOnlyTheLiveKey`): an anchor-signed enrolment written past the kernel whose `Replaces` is not `EdgeReplaces` folds to nothing and diverges, both under the enrolled head and after a restore. Mutant: drop the `Replaces` check from `enrollOK`.
**Needs:** a merged (#3341). No open PR touches `broker/kernel` outside `proc` (D-111); #3082's scope shares `kernel/ASSUMPTIONS.md`, so whichever starts second waits. **Guard files:** none. **Gate:** trusted-core growth: a D-159 row citing HW-15 and REC-2 as the approved design (as D-191 did for a), merged first. After the build, Security re-signs (point 9's note).
**Estimate:** 40k tokens.

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

## b2: small-order edge keys, and killing tests for b's cut and capture checks (#3364)

Follow-up of b, from its reviews on #3359: L3 points 1 and 2 (comment 6433663497) and Security point 1 (comment 6433666388). The PR body carries `Defect: EDGE-link-core-b`.

**Decisions.**
1. **A small-order key is no edge key.** Go's `ed25519.Verify` takes the eight points of order dividing 8 in any encoding, and anyone can sign for one (the identity key, with R the identity and S zero, verifies over any message). `kernel.SmallOrder(k)` refuses them with no new dependency: it maps y to the Montgomery u = (1+y)/(1-y) and relies on crypto/ecdh refusing X25519's all-zero output, which X25519's multiple-of-8 scalars give for exactly the low-order u. `edgeKey` adds it, so `EdgeCandidate`, `EdgeEnroll`, `EdgeRevoke`, `SetupWithEdge` and the fold all refuse one with `ErrEdgeKey`; enrollment's `readCapture` refuses one too. Not an exploit path today (only whoever is on the cable before the confirm can plant one, and that person is the first edge anyway, residual risk 1), so it is `later`, built here because it is one function.
2. **The capture owner is a parameter.** `readCapture(path, owner)` checks the file's uid against `owner`; enrollment passes its euid (root). A plain-user test then sees a file of another uid refused, which it cannot set up by chown. So c2 must write the capture file as root (mode 0600), or enrollment takes no first key.
3. **The cut's slot and error are tested where they happen**, in the kernel process (`kernelmain.go` is unchanged): the logged `edge.cut` names the slot that opened the store, and a cut the kernel refuses starts no kernel.

**Scope:** `broker/kernel/edge.go` (+test), `broker/kernel/ASSUMPTIONS.md`, `broker/kernel/proc/kernelmain_test.go`, `broker/cmd/agentos-enroll/main.go` (+test), `broker/clerk/handoff/ASSUMPTIONS.md`.
**Requirement IDs:** HW-15, HW-17.
**Acceptance tests** (each comment names its one-line revert mutant, decision 9):
- `kernel/edge_test.go::TestSmallOrderEdgeKeysRefuse`: all 14 small-order encodings (libsodium's list, each order checked by repeated addition) refuse at `EdgeCandidate` (with the identity key's forged hello), `EdgeEnroll` and `SetupWithEdge`, logging nothing; generated keys pass. Mutant: `edgeKey` back to the length check.
- `cmd/agentos-enroll/main_test.go::TestCaptureIsTheOwnersAndNoSmallOrderKey`: a file of another uid, and a forged small-order capture, are refused. Mutants: the uid check made false; `kernel.SmallOrder(edge) ||` dropped.
- `kernel/proc/kernelmain_test.go::TestUnknownHostCutsTheEdge` (extended): the cut names `passphrase` or `recovery`, as the slot was; a slot out of shape returns `ErrEdgeSlot`, never comes up, and leaves the edge live. Mutants: `EdgeCut(clock(), "x")`; EdgeCut's error ignored.
**Needs:** b (#3359) and a2 (#3347) merged. **Guard files:** none. **Gate:** trusted-core growth: a D-159 row citing HW-15 and REC-2 as the approved design, merged first.
**Estimate:** 40k tokens.

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

## c2: the link process on the core (#3297), split into c2a, c2b and c2c

Split at its build (2026-10-27). The kernel socket files were held by open PRs (#3438, #3450; D-111), and the image's files by #3440. The unit, the user and the input rule were also more than the 100k estimate held. Each slice is its own session.

### c2a: agentos-link (#3297)

**Scope:** new `broker/cmd/agentos-link` (+tests, ASSUMPTIONS.md). It has the pre-store mode (decision 3's capture: a root parent writes, a child under the link's uid reads) and the served mode. The served mode covers the listener bound to the link interface, the handshake through `edgelink`, `edgekey` at each handshake and on the close ticker, the hello reported as decision 8's candidate, and the consumer socket of decision 7. It also holds the client of the kernel's link socket (`linkkey`, `linksign`, `edgekey`, `edgecandidate`; ASSUMPTIONS EDGE-link-c2-3). Also `broker/core/core.txt` (`wiring cmd/agentos-link`), `broker/daemon/arc2_test.go`, `tools/trusted_base_parsers.txt` and `tools/g1_scope_g2.txt`.
**Requirement IDs:** HW-15, HW-16 (no other connection from the edge), HW-17.
**Acceptance tests:**
- `cmd/agentos-link/capture_test.go::TestFirstHelloWinsOnlyBeforeTheStore`: the first valid hello is written, owned by the writer's euid (root in the unit) with mode 0600 (b2 decision 2: enrollment takes no other). None of these is written: a second hello, a badly signed one, a small-order key's, or any hello once the store exists.
- `cmd/agentos-link/link_test.go::TestOnlyTheLiveEdgeIsServed`: the live key's items arrive on the consumer socket with the kind's label. Any other key gets one hello read, reported and closed, with no item delivered. A non-hello frame from it, a second frame, or no hello within 5 seconds closes with a fault count. A revoked key's hello is not reported. `edgekey` is asked on every connection. The core's outbound frames reach the live edge.
- `::TestRevokeClosesTheConnection`: the kernel no longer naming the key live closes an open connection within a second.
- `::TestBadFrameClosesAndCounts`: a bad frame from the live edge closes the connection and adds one fault count, with no content in the log.
- `::TestListensOnTheLinkInterfaceOnly`: the socket is bound to the named interface (`SO_BINDTODEVICE`); a bad or missing interface refuses.
**Guard files:** `broker/core/core.txt` (wiring line), `broker/daemon/arc2_test.go` (`cmd/agentos-link` imports `edgelink`, `kernel`'s pure edge helpers and `sockets` only), `tools/trusted_base_parsers.txt` (the parser line). **Gate:** gate-file PR: the separate Security accept; a D-198 `exempt-pr` companion for the G2 freeze. The trusted core does not grow (agentos-link is no root of `tools/trusted_core.txt`).

### c2b: the kernel's link socket and the owner's edge calls (#3458)

**Scope:** `kernel/proc/kernelsock.go` (+test). A `LinkSide` serves `linkkey`, `linksign`, `edgekey` and `edgecandidate`. Its socket admits the link's uid alone. `edgekey` answers `{live, revoked}` from `LiveEdge` and `EdgeRevoked`. The owner side gains `edgeenroll` and `edgerevoke`, and the edge errors cross as wire errors. Also `kernel/proc/kernelmain.go` (`LinkSock`, `LinkUID`, a peer), `cmd/agentos-kernel` (`-link-sock`, `-link-uid`), and the owner client methods `EdgeEnroll` and `EdgeRevoke` in `broker/owner/kernelsock`. `cmd/agentos-link/main.go` is unchanged; its test serves the real side.
**Requirement IDs:** HW-15, HW-16.
**Acceptance tests:**
- `kernel/proc/kernelsock_test.go::TestLinksignSignsOnlyCertificateVerify`: any other input refuses; a kernel with no link key answers a fixed refusal.
- `kernel/proc/kernelsock_test.go::TestEdgecandidateOnlyFromTheLinkUid`: `edgecandidate` from any uid but the link's refuses and logs nothing, and the owner and meter sides have no link call. `edgeenroll` for a key that is not the logged candidate refuses.
- `cmd/agentos-link/kernel_test.go::TestSpeaksTheKernelsLinkWire`: the link's client against the real `LinkSide`, so the two cannot drift.
**Needs:** c2a; #3438 and #3450 merged (D-111). **Guard files:** none. **Gate:** D-159 row for the kernel lines (the trusted core grows), merged first.
**Estimate:** 50k tokens.

### c2c: agentos-link in the image (#3459)

**Scope:** the capture unit (root, `ConditionPathExists=!` the store, stopped by enrollment's unit before it runs) and the served unit (the link's uid, after the kernel, `-kernel-sock` and `-consumer-sock`). Also the link's user (`sysusers.d`), `image/build.sh`, and enrollment's `-first-edge` with the capture path. The input rule is a `link` set in `broker/netguard` `InboundRules` and `inbound.nft`. The rule admits the link port on that interface only; the served unit adds its interface as root, as the page's unit does for the page set. Plus the finalize allowlists these need.
**Requirement IDs:** HW-15, HW-16.
**Acceptance tests:**
- `netguard/inbound_test.go::TestInboundLinkPortOnTheLinkOnly`: the link port is accepted only on the interface in the link set, and nothing else on that interface is (the rule's rendering, from c2's `TestListensOnTheLinkInterfaceOnly`).
- `tests/test_image.py`: the units' commands, users and ordering (capture before enrollment, never with a store; served after the kernel).
**Needs:** c2a, c2b; #3440 merged (D-111). **Guard files:** the image's allowlists. **Gate:** as the image's tests require.
**Estimate:** 50k tokens.

## d: the owner side (#3298)

**Scope:** owner side only: the page step of decision 8 (candidate fingerprint, the hardware-key prompt, `edgeenroll`), the cut action (`edgerevoke`), the status lines (no edge paired; edge not trusted after a restore or an unknown-host start, with the step that fixes it), and the tamper alert texted from each non-first `edge.enrolled` entry. Files in `broker/cmd/agentosd`, `broker/localui`, `broker/owner`; agentosd edits run serially (D-111).
**Requirement IDs:** HW-15 (page step, alert), REC-2 (the edge in the restore visit), CH-9.
**Acceptance tests:** the matrix rows marked d, each a test in the touched package: the step shows the candidate, its hello's age (a stale hello can be pending after a cut or a restore; Security note 11 on #3341) and the key it replaces, and logs on the hardware key's signature; no step without a candidate; an alert for each later enrolment, after a restore too, and none for the first; the status lines for no edge and for an untrusted edge; and one end-to-end test (`broker/e2e`) from a captured first hello through setup, a replacement, a revocation and a restored log.
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
