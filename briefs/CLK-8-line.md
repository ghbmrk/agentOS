# CLK-8-line: the second-line clerk

Board section: Migration to the capability kernel (D-139). Work item #3735; SPEC CLK-8 ("A second line"), CH-1, DEP-3, KEY-2, VRB-2, CLK-1, CLK-2, CLK-3, KRN-8, HW-15. Tier A (a credential holder, a send path to third parties). Authority: D-227 (Mark, "Delete, rebuild later", cmsg_01R91wiieBzMSvPKFsAJVvuK9dfdh6jst4ztNfubyNwnVs). Written 2026-10-29 against main at the commit this brief merges on. Class `later` until the row is scheduled for MVP acceptance.

## Why

D-227 deletes the old second-line accounts with the vault process (MIG-4-exit p #3685, d1 #3686; `cmd/agentosd/secondline.go` goes in c3 #3684). Third-party texting and calling are missing until this row lands. CLK-8 wants a clerk behind the `send` verb: never the owner-channel number, E.164 recipients the clerk verified or the owner supplied, one rate budget per line, an opening statement on calls, logged transcripts, inbound texts and calls as untrusted data, and the whole line optional.

## What main shows (reuse, do not rewrite)

- `broker/modem/sipline`: a reviewed SIP-over-TLS line (SL1 to SL15 in its `ASSUMPTIONS.md`): registration, SIP `MESSAGE` texts both ways with provider-vouched senders, SRTP calls that play PCM, the no-calls clip, every dial through `netguard`. Its password never enters the line: digest challenges go to a `Signer` (`signer.go`). No production code calls `sipline.Open`.
- `broker/sipsign`: `Account.Sign` (digest answers, only for the recorded realm, only REGISTER, MESSAGE, INVITE, BYE and CANCEL, only `qop=auth`), `Settings` and its checks, realm learning (SL3). Its HTTP `Handler` and `Client` are the vault's `sign.sock`, served by `cmd/agentos-egress` until d1.
- `broker/sendrules`: `CheckRecipient`, `Premium`, `PremiumDialed`, `SameNumber` (pure), and a `Budget`.
- `broker/smsapi`: texts over a provider's HTTP API with a vault-held token; its importers are `cmd/agentos-egress` (d1 deletes), `localui/secondline.go` (p deletes) and `sipline`'s `Texts` option.
- `broker/modem/secondline`: the old tool over a second SIM or an account; it needs the owner modem in-process, which the new core does not give a clerk.
- `broker/edgelink`: kinds `text` and `call` exist edge to core, labelled `untrusted-second-line`. There is no core-to-edge text or call kind and no edge-side process (EDGE-link-core, Unowned gaps).
- The kernel's clerk wire (`kernel/proc.ServeClerk`), the clerk key on descriptor 3 (`clerk/clerkkey`), sealed slots (`clerk/seal`, `clerk.Secrets`) and `key.Arg.Source` (owner, clerk, planner) already carry what a send-verb clerk needs; `cmd/agentos-clerk-mail` and `cmd/agentos-clerk-model` are the patterns.

## Open question (for Mark through the coordinator; the brief builds on the recommendation)

1. **Where SIP runs, given D-154 rule 3** ("no TLS ends outside the keeper"). (A, recommended) The keeper-side clerk holds the password, admits each send and signs its digest; a main-side line process under its own uid runs `sipline` (TLS, SIP parsing, SRTP), as SL2 already split it. The password never leaves the keeper, since a digest is a challenge answer, not a bearer token, so rule 3's purpose holds, but its letter does not: TLS ends in the line process. Residual: a taken-over line process can register the account (it already sees the line's traffic, as the edge does under HW-15) and, because `qop=auth` does not cover a body, change a text's words to a recipient the clerk admitted. (B) The clerk runs `sipline` itself and ends TLS: rule 3 holds literally, but a third-party SIP parser and an SRTP stack enter the keeper (rule 4), and call audio passes through it. Under B, part (a) drops the signing binding and part (b) has one process.

## Design points settled here (flagged for the reviews)

1. **Texts first; calls and the edge SIM later.** An outbound call needs speech for its words; no package renders speech (sipline's `Say` plays PCM, and only the disclosure clip is rendered). Calls are part (d), after a speech-rendering row; the edge SIM is part (e), after the edge's own side and a core-to-edge kind exist. Until then the line is an owner-held calling account. CLK-8 allows either transport.
2. **No HTTP-API texting.** `smsapi`'s path is dropped: SIP `MESSAGE` only. An owner whose provider texts only by HTTP API has calls (after d) but no texts here; a later row can add one HTTP-API provider as a keeper clerk exit (D-154 rule 3 then holds, since it is a bearer token). Part (b) deletes `broker/smsapi/` and `sipline`'s `Texts` option.
3. **One budget per line** is the key's rate caveats (`KRateDay`, `KRateRecipient`), charged by the kernel's ledger for every `send` on this clerk whatever its transport. `sendrules.Budget` is not used.
4. **Recipients.** In this row a `to` passes only as an owner-created contact (`Source` clerk, matched by the exact number) or an E.164 number the owner fixed (`Source` owner). A planner-supplied number is refused (KEY-2). A short or premium-rate code passes only as an owner-created contact (`sendrules.Premium`). The owner's own number and either of the box's numbers never pass (CH-1, CH-19). Numbers the clerk reads from a cited source are a `later` item (Unowned gaps), since CLK-8's default admits them only for businesses.
5. **The signing binding (under A).** The clerk signs REGISTER for its own account at most once per 30 s, and MESSAGE (later INVITE) only for a send it admitted, once, with a Request-URI equal to that send's recipient (`sipsign.Recipient`). Any other request is refused and counted in the clerk's status.
6. **At most once (CLK-2, KRN-8).** A send cancelled before the line takes it is not sent and not counted as possibly sent. One handed to the line whose answer is lost is "may have been sent": never resent under its idempotency key, and a late provider answer does not flip it (cases.md §4, #271 W5-D7, applied to this line).
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

- **(a) CLK-8-line-a, the clerk library (one session, about 100k; startable now).** `broker/clerk/line/` (+tests, `ASSUMPTIONS.md`): the declaration (operation `text`, verb `send`; `call` declared only in d), the admit check (points 3 to 6), the signing binding (point 5) over `sipsign.Account` in its own file and tests (`sign.go`), so it drops cleanly under B, the account record (settings, sealed password, realm) on `clerk.Secrets`, inbound item shaping (point 7), the owner texts for each refusal. It runs no socket and starts no process; tests drive it with `sipsim` through `sipline` and a fake kernel ledger. It imports `sipsign`, `sendrules`, `kernel/key` and `clerk`, never `sipline` outside tests.
- **(b) CLK-8-line-b, the processes (one session, about 140k; after a, d1 #3686, p #3685 and Mark's answer on the open question).** `broker/cmd/agentos-clerk-line/` (keeper: kernel socket via `ServeClerk`, owner socket for set, remove and state, the sign and inbound calls to the line's uid, the planner side for inbound items) and `broker/cmd/agentos-line/` (main side: `sipline.Open` with a `Signer` that calls the clerk, the send call to the clerk's uid only); both on the `sockets` seam (D-154 rule 1). Their units, users, presets and the line's outbound rule in `image/`; `broker/smsapi/` deleted, `sipline`'s `Texts` option and `sipsign`'s HTTP `Handler`, `Client` and `Store` deleted; the matrix test in `broker/e2e` against `sipsim`. If the estimate at start passes 150k, cut the image units into (b2).
- **(c) CLK-8-line-c, the owner page and STATUS (one session, about 80k; after b and p #3685).** The owner-page step to set, check (including the SL3 realm confirm) and remove the account on the clerk's owner socket (fixed per-field refusals, as `cmd/agentos-egress/sipaccount.go` worded them, git history), and the STATUS lines agentosd's old `secondline.go` carried ("confirm your provider", "couldn't reach your provider"). If STATUS is rendered in `cmd/agentosd`, c joins the agentosd slot (D-111).

## Acceptance tests

**Acceptance tests:**
- CLK-8 recipients, part a: `broker/clerk/line/line_test.go::TestPlannerSuppliedNumberIsRefused` (a `to` with `Source` planner refuses; catches a clerk that trusts the planner's number), `::TestOnlyContactsAndOwnerFixedNumbersPass` (a clerk-sourced number that is no owner-created contact refuses; catches a business default skipped), `::TestShortCodeNeedsOwnerContact`, `::TestOwnerAndBoxNumbersNeverPass` (CH-1, CH-19; catches the line being used to ask the owner for a code).
- CLK-8 one budget, part a: `::TestTextsShareTheKeysRateCaveats` (the eleventh text past a ten-a-day caveat refuses whatever its recipient; catches a per-transport budget).
- CLK-2 and KRN-8, part a: `::TestLostAnswerIsMayHaveBeenSentAndNeverResent`, `::TestCancelBeforeHandOffIsNotCounted`.
- Signing binding (point 5), part a: `broker/clerk/line/sign_test.go::TestSignsMessageOnlyForAnAdmittedSendOnce` (a second signature for the same send, a different Request-URI, and an unadmitted MESSAGE all refuse; catches a signing oracle), `::TestRegisterSigningIsRateLimited`.
- CLK-1 custody, part a: `::TestPasswordNeverInStatusErrorsOrLog` (a canary password appears in no status, error, owner text or log entry); `::TestShortPasswordRefusedAtSetup`.
- Inbound (point 7), part a: `::TestInboundTextIsUntrustedItem`, `::TestOwnerTextingTheLineReachesNoPlanner`.
- DEP-3, part a: `::TestNoAccountMeansUnavailableAndNothingSent`.
- D-154 rules 1 and 4, part b: `broker/cmd/agentos-clerk-line/imports_test.go::TestKeeperLinksNoSIPStack` (no sipgo, pion or `sipline` in the keeper binary, under A); `broker/cmd/agentos-line/main_test.go::TestLineHoldsNoPassword` (the line's config and environment carry none).
- Lifecycle matrix, part b: `broker/e2e/secondline_test.go::TestSecondLineLifecycle` (each cell above against `sipsim`, restart included, with a sent text read back at the simulated far end and its transcript in the log).
- Owner page, part c: `broker/localui/secondline_test.go::TestSetupRefusalsNameTheFieldNeverTheValue`, `::TestRemoveErasesTheSlot`; STATUS: a test that each line names a step the owner can take (UX recurring kind, CH-12).

Recurring kinds from the lens READMEs, as criteria: each defence above has a test that fails when it is reverted (potency, surviving mutants); a guard fails closed on a missing or invalid value (security); the declared scope includes the test files the change forces (`imports_test.go`, `arc2_test.go`); no problem text names a step that cannot work (UX).

## Scope

- (a) `broker/clerk/line/` (new, with tests and `ASSUMPTIONS.md`); `broker/daemon/arc2_test.go` (its import rule).
- (b) `broker/cmd/agentos-clerk-line/`, `broker/cmd/agentos-line/` (new); `broker/modem/sipline/sipline.go`, `sipline_test.go`, `texts_test.go`, `ASSUMPTIONS.md` (drop `Texts`); `broker/sipsign/` (drop the HTTP half); `broker/smsapi/` (delete); `broker/e2e/secondline_test.go`; `image/` units, sysusers, preset and `build.sh` command list; `tools/ci_split.py`; the guard files below.
- (c) the owner page's second-line step and routes in `broker/localui/` (new `secondline.go` after p deletes the old one), STATUS lines where they are rendered, `broker/localui/ASSUMPTIONS.md`.

**Guard files:** (a) adds `broker/clerk/line/`, under `broker/clerk/` on the G2 list; `tools/risk_tier.py` classes an unnamed broker package tier A; its imports of `sipsign` and `sendrules` need a rule in `broker/daemon/arc2_test.go`, pre-approved. (b) adds two mains: `tools/g1_scope_g2.txt` (an `allow` line each, as `broker/cmd/agentos-clerk-mail/` has) and `broker/daemon/arc2_test.go`, pre-approved. No root of `tools/trusted_core.txt` imports either, so no `Trusted-core:` line is owed; the builder confirms with `tools/trusted_base.py`.

## Unowned gaps (not in a to c)

- **(d) Calls.** Needs a speech-rendering row (none exists). Then: `call` declared on `send`, the disclosure first, the words rendered from the admitted `msg`, the transcript as the words said, and INVITE in the signing binding.
- **(e) The edge SIM.** Needs the edge's own side (EDGE-link-core Unowned gaps) and a core-to-edge `text` kind in `broker/edgelink`; inbound already has `text` and `call`. `broker/modem/secondline` stays for that row to reuse or delete.
- **Source-read recipients** (`later`). A number the clerk reads from a source item the step cites, admitted by CLK-8's default only when that source is a business: the criterion is a test that a number read from a person's message refuses and one from a business's page or mail passes. Needs the kernel's clerk wire to give a clerk the cited item.
- **`qop=auth-int`** (`later`, `sipsign`). Where a provider offers it, signing with it covers the MESSAGE body and closes A's rewrite residual.

## Estimate

a about 100k, b about 140k, c about 80k: three sessions. Usage is the builder's to record on the PR.
