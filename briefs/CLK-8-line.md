# CLK-8-line: the second-line clerk

Board section: Migration to the capability kernel (D-139). Work item #3735; SPEC CLK-8 ("A second line"), CH-1, DEP-3, KEY-2, VRB-2, CLK-1, CLK-2, CLK-3, KRN-8, HW-15. Tier A (a credential holder, a send path to third parties). Authority: D-227 (Mark, "Delete, rebuild later", cmsg_01R91wiieBzMSvPKFsAJVvuK9dfdh6jst4ztNfubyNwnVs); where SIP runs, D-236 (option C, keeper filters). Written 2026-10-29 against main at the commit this brief merges on. Class `later` until the row is scheduled for MVP acceptance.

## Why

D-227 deletes the old second-line accounts with the vault process (MIG-4-exit p #3685, d1 #3686; `cmd/agentosd/secondline.go` goes in c3 #3684). Third-party texting and calling are missing until this row lands. CLK-8 wants a clerk behind the `send` verb: never the owner-channel number, E.164 recipients the clerk verified or the owner supplied, one rate budget per line, an opening statement on calls, logged transcripts, inbound texts and calls as untrusted data, and the whole line optional.

## What main shows (reuse, do not rewrite)

- `broker/modem/sipline`: a reviewed SIP-over-TLS line (SL1 to SL15 in its `ASSUMPTIONS.md`): registration, SIP `MESSAGE` texts both ways with provider-vouched senders, SRTP calls that play PCM, the no-calls clip, every dial through `netguard`. Its password never enters the line: digest challenges go to a `Signer` (`signer.go`). It dials through sipgo's `net.Dialer` hooks (`sipline.go`). No production code calls `sipline.Open`.
- `broker/sipsign`: `Account.Sign` (digest answers, only for the recorded realm, only REGISTER, MESSAGE, INVITE, BYE and CANCEL, only `qop=auth`), `Settings` and its checks, realm learning (SL3). Its HTTP `Handler` and `Client` are the vault's `sign.sock`, served by `cmd/agentos-egress` until d1.
- `broker/sendrules`: `CheckRecipient`, `Premium`, `PremiumDialed`, `SameNumber` (pure), and a `Budget`.
- `broker/smsapi`: texts over a provider's HTTP API with a vault-held token; its importers are `cmd/agentos-egress` (d1 deletes), `localui/secondline.go` (p deletes) and `sipline`'s `Texts` option.
- `broker/clerk/inbox/imapsmtp`: the pattern D-236 reuses. The mail clerk ends TLS itself and relays the stream to a parser process holding no credential (`imapconn`), through a filter that passes only the commands the typed request needs (#2937 gap 2).
- `broker/modem/secondline`: the old tool over a second SIM or an account; it needs the owner modem in-process, which the new core does not give a clerk.
- `broker/edgelink`: kinds `text` and `call` exist edge to core, labelled `untrusted-second-line`. There is no core-to-edge text or call kind and no edge-side process (EDGE-link-core, Unowned gaps).
- The kernel's clerk wire (`kernel/proc.ServeClerk`), the clerk key on descriptor 3 (`clerk/clerkkey`), sealed slots (`clerk/seal`, `clerk.Secrets`) and `key.Arg.Source` (owner, clerk, planner) already carry what a send-verb clerk needs; `cmd/agentos-clerk-mail` and `cmd/agentos-clerk-model` are the patterns.

## Where SIP runs (decided: D-236, option C, keeper filters)

Mark tapped C on the CLK-8 card in Decisions 8 (cmsg_01R91wiieBzMSvPKFsAJVvuKFgCheAbR5yXsk6xU1KXTo1); the options are in `answers/2026-10-29-clk8-sip-third-option.md` (project files). A (keeper signs, line ends TLS) and B (whole SIP stack in the keeper) are rejected.

1. **The keeper ends TLS.** The keeper-side clerk dials the provider through `netguard` and ends TLS itself (D-154 rule 3 holds literally). It holds the password and adds every digest.
2. **The line parses.** The main-side line process (`sipline`: sipgo, SIP parsing, SRTP media) dials nothing over TCP. It gets the plaintext stream as typed frames on the `sockets` seam (rule 1; no descriptor crosses). Media stays main-side, over UDP under the line's own outbound rule.
3. **The keeper filter** frames every outbound request by `Content-Length` and passes only:
   - REGISTER to the account's registrar, for the account's own address, at most once per 30 s;
   - MESSAGE whose Request-URI and `To` equal one admitted recipient and whose body equals the admitted words byte for byte, with a fixed `Content-Type: text/plain`. One such MESSAGE passes per admission, plus one resend only when the provider answered that MESSAGE 401 or 407;
   - responses to inbound requests with no body, except one `application/sdp` answer to an inbound INVITE (the no-calls clip, SL9); ACK and BYE inside that inbound dialog; and CRLF keep-alives.

   Anything else, including a line-supplied `Authorization`, a duplicate or folded `Content-Length`, `To` or `Content-Type`, or a second request inside a body, drops, and the counter shows in the clerk's status. Where a request needs a digest, the line leaves a fixed placeholder `Authorization` carrying the challenge's realm and nonce. The keeper replaces it with its own answer, only for the recorded realm (SL3) and only over the method and Request-URI the filter just passed (`sipsign.Account.Sign`). The placeholder is untrusted, but the answer is written only into the keeper's own TLS stream.
4. **Inbound.** Bytes from the provider pass to the line untouched, with one exception. The keeper frames responses only to read the status code, `Call-ID` and `CSeq` that match a 401 or 407 to the admitted MESSAGE (the resend rule above). This is the only inbound read in the keeper. What the line reports is untrusted, as it already is (`untrusted-second-line`).

**Residual.** A taken-over line process can lie about inbound senders (already untrusted) or about a delivery outcome (at-most-once still holds, since the keeper never resends on its own). It can also deny service. It cannot change words or recipients, send twice, register beyond the rate, or see the password. The `qop=auth` body gap under A is closed.

**Size.** The filter is trusted-core growth, approved by the tap at about 300 to 500 lines with a fuzz target (D-236). The builder's first-step estimate (*inference*, from the rules above) is about 450: framing and headers about 200, rules about 120, the digest step about 40 over `sipsign`, the inbound status read about 50, counters about 40. Part a2 reports the measured count. Past 500, it stops and goes back to Mark through the coordinator before building on.

## Design points settled here (flagged for the reviews)

1. **Texts first; calls and the edge SIM later.** An outbound call needs speech for its words; no package renders speech (sipline's `Say` plays PCM, and only the disclosure clip is rendered). Calls are part (d), after a speech-rendering row; the edge SIM is part (e), after the edge's own side and a core-to-edge kind exist. Until then the line is an owner-held calling account. CLK-8 allows either transport.
2. **No HTTP-API texting.** `smsapi`'s path is dropped: SIP `MESSAGE` only. An owner whose provider texts only by HTTP API has calls (after d) but no texts here; a later row can add one HTTP-API provider as a keeper clerk exit (D-154 rule 3 then holds, since it is a bearer token). Part (b) deletes `broker/smsapi/` and `sipline`'s `Texts` option.
3. **One budget per line** is the key's rate caveats (`KRateDay`, `KRateRecipient`), charged by the kernel's ledger for every `send` on this clerk whatever its transport. `sendrules.Budget` is not used.
4. **Recipients.** In this row a `to` passes only as an owner-created contact (`Source` clerk, matched by the exact number) or an E.164 number the owner fixed (`Source` owner). A planner-supplied number is refused (KEY-2). A short or premium-rate code passes only as an owner-created contact (`sendrules.Premium`). The owner's own number and either of the box's numbers never pass (CH-1, CH-19). Numbers the clerk reads from a cited source are a `later` item (Unowned gaps), since CLK-8's default admits them only for businesses.
5. **The filter's binding (C).** The rules in "Where SIP runs" item 3, enforced on the bytes rather than on a signing request. Admission stays in part a's `Do`; the filter consumes each admission ticket once. INVITE joins in (d).
6. **At most once (CLK-2, KRN-8).** A send cancelled before the filter passes its MESSAGE is not sent and not counted as possibly sent. One whose MESSAGE passed the filter but whose answer is lost is "may have been sent": never resent under its idempotency key, and a late provider answer does not flip it (cases.md §4, #271 W5-D7, applied to this line).
7. **Inbound.** A text to the line becomes an untrusted item labelled `untrusted-second-line`, its sender shown by `sipline`'s vouched rules (SL5). A text from the owner's number gets the main-number reply and reaches no planner; (a) carries its own copy of `modem/secondline`'s `MainNumberText` sentence, since it does not import that package. Calls to the line get the no-calls clip (SL9) until (d).
8. **Transcripts.** Each sent text's effect entry carries the recipient and the words the clerk admitted; each inbound text is logged as its untrusted item. Log I/O only through the kernel (D-154 rule 7).
9. **Custody.** Only the clerk holds the password, in its own sealed slot under its clerk key; no hash of it leaves (cases.md §6, D-103/#1106). Setup takes only a provider-generated password of at least 12 characters (SL2).

## Lifecycle matrix (integration owner: part b, which wires both processes, the units and the matrix test)

| Stage | No account set | Account set, provider reachable | Account set, provider down or refusing |
|---|---|---|---|
| First boot | clerk starts, reports unavailable; a `send` step on it refuses with "no second line" and nothing is sent (DEP-3) | n/a | n/a |
| Owner sets it up (part c) | settings checked, password sealed, realm learned within 30 min and confirmed by the owner on the page before anything else is signed (SL3, kept in c's check step) | registers; first send works | page and STATUS say what to check (`sipline.OwnerText`) |
| Restart or update | unavailable as before | slot reopens, line re-registers, no send repeats | STATUS line until it reaches the provider |
| Restore or move (BAK-1) | unavailable | slot restored; realm kept; first registration confirms it | as left of this column |
| Owner removes it | n/a | slot erased, line closed, later sends refuse as unavailable | same |

## Split

- **(a) CLK-8-line-a, the clerk library (PR #3881; built under A).** `broker/clerk/line/`: the declaration, the admit check (points 3, 4 and 6), the account record, inbound item shaping and the owner texts all stand under C. Only `sign.go`, the A signing binding, is replaced, and it was isolated in its own file for this purpose. #3881 merges as built. Its sign tests prove a binding that a2 deletes.
- **(a2) CLK-8-line-a2, the keeper filter (one session, about 90k; after a merges).** In `broker/clerk/line/`, `sign.go` and `sign_test.go` become `filter.go` and `filter_test.go`. `filter.go` is a pure filter: it takes outbound bytes and the admitted tickets and returns the bytes to write or a drop. It also takes inbound response heads for the resend rule, and adds the digest over `sipsign.Account.Sign`. A fuzz target `FuzzFilter` drives it. It runs no socket. `TestTheSigningBindingIsOneFile` goes. In its first step the builder checks the item 3 placeholder and 401 resend flow against sipgo's client and reports the filter's line count on the PR (stop past 500, as above).
- **(b) CLK-8-line-b, the processes (one session, about 150k; after a2, d1 #3686 and p #3685).** `broker/cmd/agentos-clerk-line/` (keeper): the kernel socket via `ServeClerk`, the owner socket for set, remove and state, the provider dial through `netguard` with TLS ended here, and the relay of the stream through a2's filter to the line's uid as typed frames. It also serves the planner side for inbound items. `broker/cmd/agentos-line/` (main side): `sipline.Open` over the relayed stream, through a new dial seam in `sipline` that hands sipgo a `net.Conn` built on the frames (a `net.Pipe` or a loopback listener in the line's own namespace, whichever sipgo accepts; this is the build risk). It uses a `Signer` that returns the placeholder `Authorization`. It also handles the send call from the clerk's uid only. Both use the `sockets` seam (D-154 rule 1). Their units, users and presets go in `image/`, and the line's outbound rule there allows UDP media only, no TCP to the provider. `broker/smsapi/` is deleted, and so are `sipline`'s `Texts` option and `sipsign`'s HTTP `Handler`, `Client` and `Store`. The matrix test goes in `broker/e2e` against `sipsim`. If the estimate at start passes 150k, cut the image units into (b2).
- **(c) CLK-8-line-c, the owner page and STATUS (one session, about 80k; after b and p #3685).** The owner-page step to set, check (including the SL3 realm confirm) and remove the account on the clerk's owner socket (fixed per-field refusals, as `cmd/agentos-egress/sipaccount.go` worded them, git history), and the STATUS lines agentosd's old `secondline.go` carried ("confirm your provider", "couldn't reach your provider"). If STATUS is rendered in `cmd/agentosd`, c joins the agentosd slot (D-111).

## Acceptance tests

**Acceptance tests:**
- CLK-8 recipients, part a: `broker/clerk/line/line_test.go::TestPlannerSuppliedNumberIsRefused` (a `to` with `Source` planner refuses; catches a clerk that trusts the planner's number), `::TestOnlyContactsAndOwnerFixedNumbersPass` (a clerk-sourced number that is no owner-created contact refuses; catches a business default skipped), `::TestShortCodeNeedsOwnerContact`, `::TestOwnerAndBoxNumbersNeverPass` (CH-1, CH-19; catches the line being used to ask the owner for a code).
- CLK-8 one budget, part a: `::TestTextsShareTheKeysRateCaveats` (the eleventh text past a ten-a-day caveat refuses whatever its recipient; catches a per-transport budget).
- CLK-2 and KRN-8, part a: `::TestLostAnswerIsMayHaveBeenSentAndNeverResent`, `::TestCancelBeforeHandOffIsNotCounted`.
- Signing binding (point 5 under A), part a (#3881): `sign_test.go::TestSignsMessageOnlyForAnAdmittedSendOnce`, `::TestRegisterSigningIsRateLimited`; a2 deletes them with `sign.go`.
- Keeper filter (D-236), part a2: `broker/clerk/line/filter_test.go::TestOnlyAdmittedWordsAndRecipientPass` (one changed byte of the words, a different Request-URI or `To`, or another `Content-Type` drops; catches a body or recipient rewrite), `::TestAdmittedMessagePassesOnceAndOneChallengedResend` (a third copy drops, and so does a second copy with no 401 or 407 before it; catches a double send), `::TestRegisterOnlyToTheRegistrarAndRateLimited`, `::TestAmbiguousFramingDrops` (duplicate or folded `Content-Length`, `To` or `Content-Type`, a request inside a body), `::TestLineSuppliedAuthorizationDrops`, `::TestDigestOnlyForRecordedRealm`; `FuzzFilter` (on any line bytes, no written MESSAGE differs from an admitted one or passes more often than the rule allows, and no output carries the canary password except inside the keeper's digest).
- CLK-1 custody, part a: `::TestPasswordNeverInStatusErrorsOrLog` (a canary password appears in no status, error, owner text or log entry); `::TestShortPasswordRefusedAtSetup`.
- Inbound (point 7), part a: `::TestInboundTextIsUntrustedItem`, `::TestOwnerTextingTheLineReachesNoPlanner`.
- DEP-3, part a: `::TestNoAccountMeansUnavailableAndNothingSent`.
- D-154 rules 1 and 4, part b: `broker/cmd/agentos-clerk-line/imports_test.go::TestKeeperLinksNoSIPStack` (no sipgo, pion or `sipline` in the keeper binary); `broker/cmd/agentos-line/main_test.go::TestLineHoldsNoPassword` (the line's config and environment carry none), `::TestLineDialsNoProvider` (D-154 rule 3: the line opens no TCP connection, and its image rule allows none).
- Lifecycle matrix, part b: `broker/e2e/secondline_test.go::TestSecondLineLifecycle` (each cell above against `sipsim`, restart included, with a sent text read back at the simulated far end and its transcript in the log).
- Owner page, part c: `broker/localui/secondline_test.go::TestSetupRefusalsNameTheFieldNeverTheValue`, `::TestRemoveErasesTheSlot`; STATUS: a test that each line names a step the owner can take (UX recurring kind, CH-12).

Recurring kinds from the lens READMEs, as criteria: each defence above has a test that fails when it is reverted (potency, surviving mutants); a guard fails closed on a missing or invalid value (security); the declared scope includes the test files the change forces (`imports_test.go`, `arc2_test.go`); no problem text names a step that cannot work (UX).

## Scope

- (a) `broker/clerk/line/` (new, with tests and `ASSUMPTIONS.md`); `broker/daemon/arc2_test.go` (its import rule).
- (a2) `broker/clerk/line/` (`sign.go` and `sign_test.go` out; `filter.go`, `filter_test.go` and the fuzz corpus in; `ASSUMPTIONS.md`).
- (b) `broker/cmd/agentos-clerk-line/`, `broker/cmd/agentos-line/` (new); `broker/modem/sipline/sipline.go`, `sipline_test.go`, `texts_test.go`, `ASSUMPTIONS.md` (drop `Texts`; add the relayed-stream dial seam); `broker/sipsign/` (drop the HTTP half); `broker/smsapi/` (delete); `broker/e2e/secondline_test.go`; `image/` units, sysusers, preset and `build.sh` command list; `tools/ci_split.py`; the guard files below.
- (c) the owner page's second-line step and routes in `broker/localui/` (new `secondline.go` after p deletes the old one), STATUS lines where they are rendered, `broker/localui/ASSUMPTIONS.md`.

**Guard files:** (a) adds `broker/clerk/line/`, under `broker/clerk/` on the G2 list; `tools/risk_tier.py` classes an unnamed broker package tier A; its imports of `sipsign` and `sendrules` need a rule in `broker/daemon/arc2_test.go`, pre-approved. (b) adds two mains: `tools/g1_scope_g2.txt` (an `allow` line each, as `broker/cmd/agentos-clerk-mail/` has) and `broker/daemon/arc2_test.go`, pre-approved. The filter is keeper-domain growth approved under D-236. a2 and b carry `Trusted-core: D-236` in their PR bodies, and each reports the filter's own line count, whether or not `tools/trusted_base.py` counts it (no root of `tools/trusted_core.txt` imports either today).

## Unowned gaps (not in a to c)

- **(d) Calls.** Needs a speech-rendering row (none exists). Then: `call` declared on `send`, the disclosure first, the words rendered from the admitted `msg`, the transcript as the words said, and INVITE in the signing binding.
- **(e) The edge SIM.** Needs the edge's own side (EDGE-link-core Unowned gaps) and a core-to-edge `text` kind in `broker/edgelink`; inbound already has `text` and `call`. `broker/modem/secondline` stays for that row to reuse or delete.
- **Source-read recipients** (`later`). A number the clerk reads from a source item the step cites, admitted by CLK-8's default only when that source is a business: the criterion is a test that a number read from a person's message refuses and one from a business's page or mail passes. Needs the kernel's clerk wire to give a clerk the cited item.

## Estimate

a about 100k (built, #3881), a2 about 90k, b about 150k, c about 80k: four sessions; C costs about one session more than A. Usage is the builder's to record on the PR.
