# MIG-4-untrusted-reconnect-a: enrol and cut off a passkey on the owner page

Work item #2779 (MIG-4-untrusted-reconnect), slice (a), from the split in issue comment 6396976126. Serial `cmd/agentosd` chain (D-111): this row takes the next slot. Tier A. Written 2026-10-25 against main at 38fdf54.

**What changed since the split comment.** Its prerequisite (1), the external-signer seam, has merged as #3116 (KEY-passkey-seam; `broker/kernel/ASSUMPTIONS.md` MIG-2-a). `kernel/key` now exports the signed messages (`EnrollMsg`, `LinkMsg`, `CosignMsg`, ...), `Challenge(msg)`, the WebAuthn `Assertion`, its one accepted encoding `AssertionSig`, and `key.ES256(rpID, point)`. The kernel process's owner socket already serves `enroll`, `unenroll` and `enrollments` (`kernel/proc` `Owner`). What is missing is all owner side.

**Why this slice is narrower than the split's (2).** Reading the code turned up two facts that move Reconnect and the exact approval out of it:
1. **agentosd cannot produce the grant that `ExitOwner.Stage(plan, grant)` takes.** The new grant comes from an OAuth code exchange. agentosd links no network client (ARC-2, `TestDaemonLinksNoCredentialCustody`), and under D-154 the clerk redeems the code itself so that agentosd keeps nothing of either frame. That is how the Gmail Connect page already works (`clerk.SignIn`, `run.MailOwner.GmailBegin` and `GmailFinish`, #3006). A raw-grant `Stage` has no lawful caller on the owner side. The exit clerk's owner socket needs a sign-in-then-stage seam instead: `Begin(plan, use)` returns the consent address, and `Finish(plan, pasted)` redeems the code in the clerk, stages the grant for that plan and returns its digest. `clerk/run` is sub A's, so this is a cross-lane prerequisite. The question is on #2779.
2. **No process hosts the exit clerk.** Nothing outside `clerk/run` calls `NewExitHost`, `OpenExit` or `ServeExitOwner`. That waits on #2682.

So the work divides as follows:
- **(a) this brief:** the passkey ceremony, Enroll, Unenroll with the `ErrAnchor` reply. It is buildable now, and its page cannot be turned on until the owner page has HTTPS (see "Runtime prerequisite").
- **(c) Reconnect (new slice):** the owner text for `reconnect <account>`, the sign-in step, the exact approval over a `change-account` link (`LinkMsg` → `Challenge` → `AttachLink`) and the submit. It waits on (1) and (2) above. **#2643 (a) folds into (c)** because it is the same path: item a.1's deduped owner text, a.2's sign-in step and a.3's proof of the owner are (c)'s three parts. **#2643 (b) does not fold in.** #2738 delivered it on the clerk side (`broker/clerk/run/ASSUMPTIONS.md` MIG-4-run-u: `not-owner-approved`, `grant-not-staged`), and (c) is its owner-side caller. (c) also carries #2779 comment 6372265455's CH-10 clause and the D-150 line "agentOS never asks you to sign in to Google inside it". It also settles whether the Gmail Connect reconnect gets the same exact approval (TN-gmail-page-L62 leaves that `later` `recheck`), so the two reconnect routes do not differ silently.
- **(b) approval cards:** unchanged from the split comment. It waits on the browser clerk being hosted, and it reuses this slice's assertion ceremony for the exact approval.

The exact-approval signing path goes to (c), its first caller, rather than shipping here with no caller.

## Runtime prerequisite: the owner page needs HTTPS on a name

WebAuthn runs only in a secure context, and its RP ID must be a domain. MIG-2-a also requires the client data's origin to be `https://<RP ID>` on a host that serves only the owner page. The local UI today is plain HTTP on the box's address, with no script except the unlock page's hashed one (`broker/localui/ASSUMPTIONS.md` L6, L13). SPEC CH-9 (§19 risk 30) gives the target: the core serves every step over HTTPS on its own local name, behind a certificate authority name-constrained to that name, generated at first boot and kept like a sealed-store secret. No BOARD row builds it. This slice therefore:
- takes the RP ID as configuration (`-passkey-rp-id` on agentosd and agentos-localui, empty by default). It serves the passkey page and ops only when the RP ID is set, as `-connect-gmail` gates the Connect page until the mail unit ships;
- builds and tests everything below that boundary in Go, with a software ES256 authenticator in the tests (no real secret, no hardware);
- leaves an HTTPS owner-page row (CH-9 authority, serving certificate, localui over TLS on the core's name) for the coordinator to file. It touches `localui` and the sealed store (STO-2), so it is not this slice's.

## Where the owner side gets the anchors (L3 6399436255 item 1)

The owner side needs the anchors (the hardware keys logged at setup, `State().Anchors`) for four things: to list them, to tell which anchor signed an enrolment, to refuse a non-anchor before the kernel does, and to refuse cutting one off with a clear reply. Today nothing on the owner side can read them. `enrollments` returns only `{Enrolled, Unenrolled}`, `OwnerSide` has no anchors read, and agentosd holds none.

**Chosen: a read on the kernel's owner socket, as its own kernel-lane prerequisite slice (a0).** It adds `"anchors"` to `kernel/proc` `OwnerSide`'s owner reads, returning `k.State().Anchors`, and `Owner.Anchors()` beside `Enrollments()`, with one test that a running kernel answers with the setup anchors and a setup-only kernel refuses (the existing guard). That is about 10 lines in `broker/kernel/proc/kernelsock.go` and its test. It changes no `kernel.Kernel` signature: docs/LANES.md's frozen seam already allows owner-side reads of `State()`, so the lists there do not change. It is sub A's directory, so (a0) is its own PR under the lane widening (or sub A's, if the widening has ended), reviewed at the kernel lane's tier. (a) stacks on it once its interface is accepted (OPERATING §5, speed rules).

**Rejected: anchors from the #3138 unlock handoff (#3151).** The handoff goes from the root-run unlock step to the kernel process only. Giving agentosd a copy would make it a new handoff recipient, which grows the trusted core and overlaps #3151's whole scope. It would also be a second source that could differ from the log, while the kernel checks `Enroll` against the log's anchors. The log is the authority, so the owner side reads it.

**What the owner side does with them.**
- **Which anchor signed:** the page asks `get()` with an empty `allowCredentials`. The kernel stores keys, not WebAuthn credential IDs, so it cannot list credentials. agentosd verifies the canonical assertion over `EnrollMsg(pending)` against each anchor (`PublicKey.Verify`, at most `MaxAnchors` of them) and takes the one that verifies as `Enrollment.By`.
  - Assumption (agentosd ASSUMPTIONS row): an anchor must be a discoverable (resident) credential, so it can sign without its credential ID. If setup later stores credential IDs, the page lists them in `allowCredentials` instead.
- **`ErrPasskeyNotAnchor`:** the assertion verifies under an enrolled passkey that is not an anchor. agentosd checks this against `Enrollments` and the anchors before calling `Enroll`.
- **`ErrPasskeyBadAssertion`:** no anchor and no passkey verifies it.
- **`ErrPasskeyRefused`:** the kernel refused after these pre-checks passed. `Kernel.Enroll` returns `ErrNotEnrolled` for every failure, so the pre-checks only make the reply exact; the kernel still decides.
- **Cut off:** an anchor is refused with the `ErrAnchor` reply before the call, and `kernelsock.ErrAnchor` still maps to that reply if the kernel refuses.

**No HTTP serving (L3 item 2, release, taken).** `agentos-localui` refuses to start with `-passkey-rp-id` set while it serves plain HTTP, which is always until #3153, and names #3153 in the error. So the flag cannot be turned on early by mistake. The handlers are tested through `localui.Config` directly.

## This slice

1. **`broker/owner/kernelsock`:** add `Enroll(ctx, key.Enrollment)`, `Unenroll(ctx, key.PublicKey)`, `Enrollments(ctx)` and `Anchors(ctx)` to the written-out wire (`enroll`, `unenroll`, `enrollments`, and (a0)'s `anchors`, as `kernel/proc` `Owner` speaks them). Add `ErrAnchor`, a sentinel the client returns when the kernel's refusal is `kernel.ErrAnchor`. Match the wire refusal against `kernel.ErrAnchor.Error()` exactly, inside kernelsock; that text never reaches the page. A setup-only kernel refuses all three, as it already refuses `status`.
2. **`cmd/agentosd/passkeys.go` (new):** the owner side's passkey ops. It is the only new code that imports `kernel/key`, which agentosd may already import (`broker/daemon/arc2_test.go`), so no guard file changes.
   - **List:** `Anchors` and `Enrollments` read back as the anchors, the enrolled passkeys and the cut-off ones. Each is shown as a short fingerprint, an algorithm, and the time it was enrolled if the log has one. Nothing is cached in agentosd, so the list survives a restart because the log does.
   - **Enrol begin:** given the new credential's P-256 point from the page's `create()` (raw `0x04‖X‖Y`, at most 65 bytes, parsed with `key.ES256(rpID, point)`, which rejects a point off the curve), return the challenge `key.Challenge(key.EnrollMsg(pk))` for the anchor to sign. Keep the pending point bound to the page session for at most 5 minutes. A new begin replaces it.
   - **Enrol finish:** given the anchor's `get()` assertion, canonicalise it with `key.AssertionSig` (high S becomes low S before anything hashes it, KEY-7), find `By` and run the pre-checks as in the anchors section above, then build `key.Enrollment{Passkey, By, Sig}` and send it to `Enroll`. The kernel verifies `By` against its anchors and the signature against `EnrollMsg(Passkey)`. agentosd checks nothing the kernel checks, and it signs nothing.
   - **Cut off:** `Unenroll(pk)` for a listed key. On `kernelsock.ErrAnchor`, reply with the fixed `ErrAnchor` reply below.
   - Every op refuses unless the session token is live (`localsrv` checks it, as for `page_account_begin`). Every kernel refusal maps to one of a closed set of fixed codes, and kernel text never reaches the page.
3. **`broker/localapi`:** the ops `page_passkeys`, `page_passkey_begin`, `page_passkey_finish`, `page_passkey_cut_off`, their frames with byte bounds (point 65, assertion parts bounded by `MaxPasskeyAssertion`, which the builder picks with a reason), and the fixed codes (`ErrPasskeyAnchor`, `ErrPasskeyNotAnchor`, `ErrPasskeyBadAssertion`, `ErrPasskeyRefused`, `ErrPasskeyStale`, `ErrPasskeySetup`, `ErrPasskeyUnavailable`).
4. **`broker/localsrv/passkeys.go` (new):** handlers for those ops behind the session check, with a `Passkeys` interface in raw bytes that agentosd implements, so `localsrv` gains no `kernel/key` import. It applies a rate limit on begin like `EnrollsPerMinute`, and registers the ops in `localsrv.go` only when `Config.Passkeys` is set.
5. **`broker/localui/passkeys.go` (new) and the page:** `/passkeys/` behind sign-in, mounted only with `-passkey-rp-id`.
   - It lists the keys. "Add a phone passkey" runs `navigator.credentials.create()` (ES256 only, `userVerification: "required"`, `rp.id` the configured RP ID), sends the point, gets the challenge, then asks the hardware key with `get()` (empty `allowCredentials`, UV required), and posts the assertion.
   - "Cut off" asks for confirmation, then posts.
   - The ceremony needs script, so this page alone adds one script pinned by its SHA-256 in the CSP, as the unlock page does (L6). The script talks only to same-origin endpoints, holds no secret, and renders only kernel-derived fields.
   - Add an ASSUMPTIONS row in `localui` (and one in `localsrv`) recording the gate, the hash-pinned script and the RP ID rule.
6. **The `ErrAnchor` reply (#2740 item 2, REC-3):** fixed page text: "That is one of your hardware keys. A hardware key is replaced only through recovery, with your Owner Card. To stop a lost phone, cut off the phone's passkey instead." It is one constant, so the test pins its words.
7. **`cmd/agentosd/main.go`, `cmd/agentos-localui/main.go`:** the `-passkey-rp-id` flags, and wiring the kernelsock owner into `localsrv.Config.Passkeys`. These are call sites only.

## Lifecycle matrix (integration owner: this package)

| Stage | No RP ID set | Setup-only kernel | Running kernel | After agentosd or kernel restart |
|---|---|---|---|---|
| List | page not mounted, op unregistered | `ErrPasskeySetup` ("finish setup first") | anchors, enrolled, cut off | same list, read from the log |
| Enrol | — | `ErrPasskeySetup` | enrolled once the kernel accepts it | a pending begin is gone, so the owner starts again |
| Cut off | — | `ErrPasskeySetup` | phone: cut off for good; anchor: the `ErrAnchor` reply | a cut-off key stays cut off |

## Scope

`broker/owner/kernelsock/{kernelsock.go,kernelsock_test.go}`, `broker/cmd/agentosd/{passkeys.go,passkeys_test.go,main.go,ASSUMPTIONS.md}`, `broker/localapi/{localapi.go,localapi_test.go}`, `broker/localsrv/{passkeys.go,passkeys_test.go,localsrv.go,ASSUMPTIONS.md}`, `broker/localui/{passkeys.go,passkeys_test.go,pages.go,ASSUMPTIONS.md}`, `broker/cmd/agentos-localui/{main.go,main_test.go}`, this brief. It does not touch `kernel/`, `clerk/` or `docs/LANES.md`: every call is on the frozen owner seam (`Enroll`, `Unenroll`, and the `Enrollments` and (a0) `Anchors` reads of `State()`).

**Guard files:** none. No package is added. `cmd/agentosd` already may import `kernel/key` and `owner/kernelsock`, and `localsrv` gains no import.

**Prerequisite (a0), its own kernel-lane PR:** `broker/kernel/proc/{kernelsock.go,kernelsock_test.go}`. Acceptance test: `broker/kernel/proc/kernelsock_test.go::TestOwnerReadsTheAnchors`, in which a running kernel returns the setup anchors in order and a setup-only kernel refuses. It catches a read that drifts from the log.

**Requirement IDs:** KEY-4, ID-1, CH-3, CH-7, REC-3, CLK-1.

**Acceptance tests:**
- `broker/owner/kernelsock/kernelsock_test.go::TestEnrollAndUnenrollReachTheKernel`: against a real `kernel/proc` `OwnerSide`, an anchor-signed ES256 enrollment is listed after `Enroll`, and listed as cut off after `Unenroll`. It catches a wire name or frame that drifts from `kernel/proc`.
- `kernelsock_test.go::TestUnenrollingAnAnchorIsErrAnchor`: returns `kernelsock.ErrAnchor`, not a generic `Refused`, and the log is unchanged. It catches the fixed reply silently degrading to a generic failure (#2740).
- `kernelsock_test.go::TestASetupOnlyKernelRefusesPasskeyOps`.
- `broker/cmd/agentosd/passkeys_test.go::TestEnrolsAPhonePasskeyFromTheCeremony`: a software ES256 authenticator's `create()` point plus a software anchor's `get()` over the returned challenge enrol the phone key. The kernel's `Enrollments` lists it with the configured RP ID. It catches a challenge computed over the wrong bytes.
- `passkeys_test.go::TestAnAssertionForAnotherPasskeyEnrolsNothing`: the anchor signed `EnrollMsg(X)` but the session's pending point is Y, so the kernel refuses and nothing is enrolled. It catches a page or attacker substituting the key being enrolled (KEY-4).
- `passkeys_test.go::TestAHighSAssertionIsAttachedLowS`: an authenticator's high-S signature is enrolled once, under its `AssertionSig` form. It catches a second ID for one tap (KEY-7).
- `passkeys_test.go::TestAPhonePasskeyCannotEnrolAnother`: an assertion by an enrolled non-anchor passkey yields `ErrPasskeyNotAnchor`. It catches a phone widening the owner set (KRN-passkeys).
- `passkeys_test.go::TestTheAnchorThatSignedIsFound`: with two anchors, an assertion by the second is enrolled with `By` set to the second. A garbage assertion yields `ErrPasskeyBadAssertion` and calls no `Enroll`. It catches a wrong or missing `By`.
- `passkeys_test.go::TestCutOffAnAnchorIsRefusedBeforeTheKernel`: the `ErrAnchor` reply, with no `unenroll` sent.
- `passkeys_test.go::TestAPendingEnrolmentLapsesAndIsBoundToItsSession`: a finish after 5 minutes, or from another session, yields `ErrPasskeyStale`.
- `passkeys_test.go::TestNoKernelTextReachesThePage`: every refusal maps into the closed code set.
- `broker/localsrv/passkeys_test.go::TestPasskeyOpsNeedALiveSession`, `::TestPasskeyFramesAreBounded`, `::TestPasskeyOpsAbsentWithoutConfig`.
- `broker/localui/passkeys_test.go::TestPasskeyPageOffWithoutRPID`, `::TestPasskeyScriptMatchesItsCSPHash`, `::TestCutOffAnAnchorShowsTheRecoveryReply` (pins item 6's words), `::TestPasskeyPageRendersOnlyFingerprints`.
- `broker/cmd/agentos-localui/main_test.go::TestPasskeyRPIDRefusedOverPlainHTTP`: start-up fails, naming #3153, when `-passkey-rp-id` is set and the UI serves plain HTTP (L3 item 2).

**Recurring kinds to check (from the lens READMEs for owner, localui, localsrv):** a fixed page text for every refusal; no secret or kernel text in logs; a cross-origin POST is refused before the op runs; bounded frames; a test that the real wire matches the written-out client.

**Dependencies:** (a0) above, accepted (build time). #3116 (merged). #2778 and #2783 slices (a) and (b) (merged; the owner seam's kernelsock client exists). Runtime only: the HTTPS owner-page row above, and #3138 (the unlock handoff carries typed anchors), without which an ES256 hardware key cannot yet be an anchor that the clerks check. If #2858 (TN-passkey hold) merges first, the list shows a new passkey's live-from time from the log.

**Usage estimate:** about 110k tokens. The checkpoint is at 90k: kernelsock and the agentosd ops green.
