# Arbitration 1 (main @ e841b78)

**Inputs:** PR #8 (UX review 1), PR #11 (potency review 1), PR #12 (security review 1), and PR #9 (Owner Card vault passphrase, CRED-8), which overlaps #12.
**Rule:** look for a design that improves all three lenses before splitting a difference. Two constraints are fixed: credentials never reach the model, and irreversible effects are always gated.
**Labels:** [Fact] verifiable · [Inference] reasoned, untested · **[Fork]** goes to Mark.

---

## Summary

Most of the 40-odd proposals don't conflict. Three questions are Mark's. Two are already on decision cards in the PR reviews thread (#11 D1 and D2), so this run adds a recommendation to those rather than asking again, and asks one new question (F2). The other conflicts resolve without him, and six ID clashes need renumbering before anything merges.

| # | Conflict | Lenses in tension | Resolution | Outcome |
|---|---|---|---|---|
| 1 | Egress of agent machines that hold private data (#11 REV-5 vs #12 REV-5) | Potency vs security | One REV-5 with security's labels, plus **public-link following** and #11's bounded research query, which recover most of potency's loss | Resolved; task text private (existing card D1) |
| 2 | Unknown-host unlock (#9 CRED-8 vs #12 CRED-8) | Security vs security, UX | Mark's passphrase from #9; **scan** it as a QR code (words as the fallback); code-generator seed **only inside the vault**, with the code checked after decryption | Resolved inside Mark's #9 decision |
| 3 | Codes on calls (#8 CH-17 spoken vs #12 CH-5 keypad) | UX vs security | Keypad only for codes; speech stays for chat; a call ends with "I'll text you the batch" when hands are busy | Resolved (security) |
| 4 | Seven-day unlock vs SIM-swap reads (#8 CH-14 vs #12 CH-19) | UX vs security | Keep 7 days. The unlock needs a code-generator code, and private content goes to the owner's evidence destination instead of SMS when one is set (#11 CH-18) | Resolved (all three gain) |
| 5 | Context-scoped replies (#11 ADP-10) | Potency vs security | **Earned and native:** offered only after the owner has approved a run of unedited replies on that account, threads started by a verified contact, and sending via the provider's own scheduled send so undo lives in the owner's mail app | Existing card D2: **Yes, with alert**, under these conditions |
| 6 | The box's SIM as a tool (#11 ADP-11) | Potency vs availability, security | Third-party calls and texts **never on the owner-channel line**; they use a second line (dual-SIM or eSIM modem, or an owner-held calling account) | **Mark chose second line** (2026-10-04) |
| 7 | Wi-Fi passthrough vs local UI trust (#8 ONB-5, D3 vs #12 CH-7) | UX vs security | Both land: passthrough plus WPA3, client isolation, and a per-device code sign-in for anything beyond setup, unlock, and status | Resolved (compatible) |
| 8 | Auto-adopted improvements (#11 CHG-6) vs stored injection (#12 CAP-3, ADP-10) | Potency vs security | Compatible once #12's enforced request shapes land: an auto-adopted skill can't send anything an adapter doesn't declare | Resolved (land after #12's ADP-10) |
| 9 | MMS evidence (#11 CH-18) vs SIM swap (#12 CH-19) | Potency, UX vs security | MMS carries only what a text may carry; private evidence goes to the fixed destination or the local UI | Resolved |
| 10 | Approval-code check vs "recipient exists" (#12 CH-10) and replies to thread participants (#11 ADP-10) | Security vs potency | Context-scoped replies use #12's existence rule for the thread starter | Resolved (folded into 5) |

---

## Resolutions

### 1. Egress follows data, without crippling research (REV-5)
**Tension.** Both lenses want a label that only rises. They differ on what a `private` machine may reach: potency allows any URL through a bounded, journaled `fetch`; security allows only an allowlist and treats every other destination as a disclosure intent. Potency's fetch leaves an unbounded channel in the URL itself. Security's rule makes every mixed private-and-research task a prompt or a split.

**What leaks is the request, not the response.** A `private` machine leaks only through what it chooses to send. So the resolution constrains what it can choose:
- **Public links are free.** A `private` machine MAY GET, unmodified, a URL that appears verbatim in **public** content delivered to it (a result a public machine returned, a public page). The attacker doesn't choose that link set, so the choice among links leaks little, and the broker rate-limits it.
- **Links from private content are intents.** A link found in private content (an email, a document) is a disclosure intent like any other novel request. Following an action link (confirm, accept, unsubscribe) is an irreversible effect, and an attacker who plants many links in an email turns the choice into a channel (1,024 links carry 10 bits per fetch).
- **Token-bearing URLs never qualify.** URLs carrying a sign-in, reset, or session token, recognized by fixed patterns (query parameters such as `token`, `code`, `key`, `sig`, `auth`, or high-entropy path segments), are never fetched from an agent machine. Opening one would hand the model a live session, which breaks CRED-1. They go to a credentialed executor as an intent, or to the owner.
- **Research by bounded query.** A `private` machine MAY start a `public` machine with a query (#11's revised REV-5). The query crosses under journaled size and rate bounds, and results return as untrusted input (public to private is free).
- **Other novel requests are intents.** Any other URL or request composed by a `private` machine is a disclosure intent (security's rule), pre-allowable per destination (ADP-9).
- The allowlist, the exclusion of user-content hosts from suggestions, and the inheritance rule stay as #12 wrote them.

**Why it dominates.** Security keeps "no silent exfiltration" and gains a stated, small bound on the residual. Potency keeps public-link following and research at full speed and pays only on novel queries from private context. UX adds no prompts for the common cases.

**Task text: private (Mark's card D1, PR reviews thread).** After review, #11 revised to private, which matches #12. With public-link following and bounded research queries, private task text costs potency little, so this run supports **Private**. The owner marks one task public by starting it with `PUBLIC`, which is added to CH-11's control words, so the opt-out is one word.

### 2. One CRED-8 (PR #9 and PR #12)
Mark already chose the card's vault passphrase plus an approval code (#9, DECISIONS.md). #12 reaches the same factor but fixes a weakness in #9: #9 keeps a copy of the code-generator seed outside the vault so the code can be checked before unlock, which means a copy of the drive exposes the seed.
- **Order:** passphrase first, then decrypt, then verify the code from the seed inside the vault, then proceed. The code stays a running-box check, as #9 intended, and the seed never sits outside the vault.
- **Input:** the card prints the passphrase both as a QR code (scanned on the local page) and as seven words (the typed fallback). Same secret and same entropy, with less typing (UX, ONB-6).
- **Owner:** #9 merges first as accepted. #12 then carries the delta on top: the seed moves inside the vault, the input becomes a scan, and #9's Argon2id memory floor, A8 checks, and tampered-boot risk all stay. The PR reviewer reached the same view.

### 3. Codes on calls (CH-5 vs CH-17)
#12's attack is concrete: the speech service is untrusted, so it can rewrite which request a spoken code approves. No design makes spoken codes safe without putting a recognizer in the broker, and ARC-2 forbids inference there. Keypad entry costs only hands-free approval. So: keypad only for codes and control words, decoded by the broker. When the owner can't use the keypad, the call ends with the batch texted for later. #8 removes "or spoken" from CH-17.

### 4. Seven-day unlock (UX D1) with a SIM-swap guard
#12 accepts seven days if findings 7 and 11 land. Combining #11's evidence destination closes most of the residual, a SIM swapper reading private data by chat:
- The session unlock needs a code-generator code or a grid cell (#12 CH-19). #8's CH-14 names that tier.
- When the owner has set an evidence destination (#11 CH-18), replies that carry content from private sources go there, and the text carries a one-line summary and a pointer. A swapper then gets summaries, not content.
- Without a destination, #12's residual stays as stated (§17 risk 11).

All three lenses gain. UX keeps one code a week, security shrinks the window's payoff, and potency gains rich replies anywhere.

### 5. Context-scoped replies (ADP-10 in #11), earned and native
Disclosure is bounded structurally (the composer sees only the thread and has no egress). The open risk is a wrong or committing reply to a real person. The resolution makes that risk measured and visible instead of blanket:
- **Earned.** CAP-6 offers the pre-allowance for an account only after the owner has approved a run of the agent's replies there unedited (default 20). Rejections and edits reset the count. This is the held-out-evidence principle (CHG-1) applied to autonomy.
- **Native undo.** Where the provider supports scheduled send, the reply is scheduled in the owner's own account for the undo window, so the owner can see and cancel it in their usual mail app, with no code needed.
- **Thread starter verified.** The thread must have been started by the owner or by a contact that meets #12's existence rule (owner-created or older than the hold). An attacker's cold email can't open an auto-reply channel.
- #12's secret-shaped-content filter (CH-19) applies to the composer's output.
- **Commitment filter.** The broker matches the reply against fixed patterns: amounts and currency, dates and deadlines, and commitment phrases ("confirm", "agree", "will pay", "approved", "sign", "accept"), in the owner's language list. A match makes that reply a normal approval request. This is a fixed-pattern check, not inference, so ARC-2 allows it.

**Mark's card D2 (PR reviews thread)** offers "Not for MVP", "Yes, with alert", or "Yes, silent". This run recommends **Yes, with alert**, under the three conditions above. Until an account earns it, behavior is identical to "Not for MVP": every reply is prompted, and the prompts produce the evidence. After that, each reply texts an alert with `UNDO <id>` (#8 CH-16). The reviewer's example, a trusted correspondent asking "confirm you'll pay by Friday", now falls back to a prompt through the commitment filter. The residual is a commitment phrased in a way the patterns miss. The alert and undo window cover that case, and the pattern list grows through Loop 2 regressions (LOOP-10).

### 6. The box's SIM as a tool (ADP-11 in #11)
Sharing the owner-channel line with third-party traffic risks carrier filtering of the only control path (DEP-1). It also publishes the owner channel's number to businesses, which turns it into an inbound injection surface. A second line removes both problems and keeps all of potency's reach: a dual-SIM or eSIM modem, or an owner-held calling account as an optional dependency (DEP-3). The cost is a second prepaid plan for owners who want this.

**Decided (Mark, 2026-10-04): second line only.** It is specced now and built after S2. ADP-12 MUST NOT place third-party traffic on the owner-channel line. The second line is an optional dependency (DEP-3): without it, the tool is unavailable and the owner channel is unchanged.

### 7–10. Compatible as written
- **7.** #8 ONB-5 passthrough and #12 CH-7 (WPA3, isolation, per-device sign-in) both land. #12's sign-in exempts the setup, unlock, and status pages, so onboarding is unchanged.
- **8.** #11 CHG-6 lands after #12's ADP-10 (request shapes). With shapes enforced, an auto-adopted skill can't create an effect its adapters don't declare, which is what makes silent adoption safe. #12's CAP-3 provenance rule keeps injected "preferences" out of the held-out suite.
- **9.** #11 CH-18: an MMS carries only content a text may carry under CH-19. Private evidence goes to the fixed destination or the local UI.
- **10.** Folded into 5.

### Recommended; Mark confirms by merging
No lens loses on any of these, but each one lands in SPEC.md, so Mark's merge is the decision.
- #11 D4, CHG-6 auto-adopt: yes, ordered after #12's ADP-10.
- #12 D5: superseded by Mark's #9 decision plus resolution 2.
- #12 D6, security fixes wait for one fast-channel attestation: yes. The cost is hours of delay, against fleet-wide compromise from one stolen key.
- #12 D7, TPM+PIN: an owner option, off by default.
- #8 D2, first PC trusted by default: yes. #12 finding 16 is the accepted residual.
- #8 D3, passthrough: yes, with #12 CH-7 (resolution 7).
- #11 D1 and #12 D4, data labels: yes, as resolution 1. Task text private, as on Mark's existing card.
- **Decided (Mark, 2026-10-04): yes.** #12 CH-19, the weekly unlock by code-generator code. This run recommends yes. The owner opens the code generator once a week instead of reading a texted code, and that one step is what makes a 7-day window safe against a SIM swap. It does change something he'll notice every week, so it is his call.

---

## ID clashes (renumber before merge)

Checked against #11 at bf968f2, which already applies this table: there is no REV-6 and no separate egress rule (it cites #12's REV-5), replies are ADP-11, the SIM tool is ADP-12, evidence is CH-20, and the potency test is A15. Only one egress requirement, #12's REV-5, lands.

| ID | #8 | #11 | #12 | #9 | Assignment |
|---|---|---|---|---|---|
| REV-5 | — | egress classes | data labels | — | **#12 owns**, with resolution 1 added; #11 drops its REV-5 and cites it |
| CH-18 | — | evidence delivery | code hygiene | — | #12 keeps CH-18; #11's becomes **CH-20** |
| CH-19 | — | — | owner-channel disclosure | — | #12 keeps it |
| ADP-10 | — | context-scoped replies | request shapes | — | #12 keeps ADP-10; #11's replies become **ADP-11**, SIM tool **ADP-12** |
| CRED-8 | — | — | rewrite | rewrite | #9 merges first; #12 rebases its rewrite into a delta (resolution 2) |
| A14 | — | potency test | security test | — | #12 keeps A14; #11's becomes **A15** |
| §8.2 | rewrite | — | rewrite | rewrite | #12's scan wording on top of #9, plus #8's "unlocks this session only; trusted is a separate tier-4 action" |
| §17 risks 10–12 | — | — | adds 10–12 | adds 10–11 | #9 takes 10–11; #12 renumbers to 12–14 and drops its duplicate of "card kept with the drive" |

**Merge order:** #9, then #8, then #12, then #11. Each later PR merges main and resolves textually. Mark merges all four (SPEC.md).

## Steering for the lens loops
- **UX (#8):** CH-14 unlock names the code-generator tier. CH-17 becomes keypad-only. Add `PUBLIC` (mark this task's text public) to CH-11.
- **Security (#12):** rebase CRED-8 and §8.2 as a delta on #9 (resolution 2). Add public-link following (public content only; links from private content are intents; token-bearing URLs never fetched) and #11's bounded research query to REV-5. Renumber §17.
- **Potency (#11):** drop REV-5 and cite #12's. Renumber CH-18→CH-20, ADP-10→ADP-11, ADP-11→ADP-12, A14→A15. Apply resolutions 4 and 9 now, and 5 (including the commitment filter) and 6 once Mark answers D2 and F2.
- **#9:** no change; merges first.

## Next run
Check that the four PRs merged in order with these IDs and resolutions. Then cross-check each lens's run 2 against the merged spec.
