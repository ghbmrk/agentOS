# AgentOS — Core System Specification v0.11

**Status:** Draft rewrite from first principles. Supersedes v0.10 (Google Doc titled "AgentOS — Specification v0.7"), which is left unedited.
**Normative language:** MUST / MUST NOT / SHOULD / MAY. Requirements carry IDs (e.g. `DEP-1`), and §15 traces each to an acceptance test.
**Evidence labels:** [Fact] established or verifiable · [Inference] reasoned, untested · [Risk] known open question.

---

## 0. What changed from v0.10

| v0.10 | v0.11 |
|---|---|
| Forked OpenClaw; mediated every escape path inside it | OpenClaw (or any agent runtime) runs **unmodified** as a guest; containment is structural |
| Process boundary = trust boundary | **Reversibility** = trust boundary: full agent power inside the box, gating only at irreversible effects |
| Installed Linux appliance on one reference PC | **The drive is the product:** runs from an external SSD on any compatible PC; the N95/8 GB unit is the **floor** |
| Owner's phone number as canonical address | **The box has its own number** on its own SIM. The owner's number is one signal among several. |
| Implicit hosted services (telephony, relay, app) | **No service operated by the AgentOS project, no relay, no app-store app, no domain or certificate authority** (§2) |
| Separate improvement / upstream / sharing mechanisms | **One change pipeline**, three sources, fed by **spare-capacity loops** (improve, secure, maintain) and accumulating into **the open-source project** via decentralized attestations |
| 12 acceptance tests, one gate | **12 tests, 5 gates**, riskiest first |

---

## 1. Purpose

AgentOS turns frontier AI the owner already pays for into **accepted work**, using a machine the owner physically controls. It **compounds** what it learns and keeps **authority and credentials** under the owner's sole control.

**North-star metric:** owner-minutes per accepted task (lower is better), subject to zero authority or credential violations.

---

## 2. Dependency budget

The product MUST work with only the dependencies in the first two rows.

| Class | Dependency | Why it can't be removed |
|---|---|---|
| **Inherent** | Electricity, an internet connection, the owner's phone (any phone that can text and call), and at least one frontier AI account | The purpose is to apply remote frontier intelligence; the owner needs some way to talk to the box |
| **Commodity (one)** | A **mobile carrier SIM** for the box (any prepaid plan) | A phone number requires a carrier. A SIM is swappable, needs no AgentOS account, and gives the box a backup internet link. |
| **Optional** | Ethernet; off-box backup target (owner's choice, encrypted); update mirrors; the public project repository and peer installations (§11B); the owner's existing accounts (Google, email…) | Each adds value; none is required to boot, control, or stop the system |
| **Forbidden** | Any server run by the AgentOS project; a relay; an app-store app; an AgentOS account; vendor activation; a public domain or certificate; telemetry | Each is a single point of failure, control, or surveillance outside the owner's hands |

- **DEP-1** Boot, owner control (status/stop), the journal, and recovery MUST work with only inherent and commodity dependencies, and MUST NOT need AI inference.
- **DEP-2** No component MAY require a service operated by the AgentOS project, now or after any update.
- **DEP-3** Every optional dependency MUST be removable without loss of control or data integrity. Losing it degrades capability only.
- **DEP-4** Software updates MUST be verifiable from content hashes and signatures alone, fetchable from any mirror, and installable offline from a drive. No update MAY be required for the system to keep working.

[Inference] With no relay, the owner reaches the box remotely only by **text and voice** through the SIM. Rich interaction (the live browser view) happens **only on the box's own local Wi-Fi**, which in practice means at home. This is the deliberate cost of zero third-party services (see §6.3).

---

## 3. Physical form

### 3.1 Components the owner receives
1. **The AgentOS Drive:** a USB4 dual-mode NVMe SSD (falls back to USB 3.x), preloaded with the system image. A short plug-in stick form is preferred, and 1–2 TB is recommended.
2. **The Owner Card** (printed; keep it like a passport). It carries:
   - the **setup secret** and its short **setup code**;
   - the **local Wi-Fi name and password** for the box's own access point;
   - a QR code joining that Wi-Fi and opening the local setup page;
   - the **vault passphrase** (at least 80 bits, e.g. seven words from a standard 7,776-word list), also printed as a QR code, used to unlock on a PC the box doesn't know (CRED-8);
   - two detachable sheets, each kept away from the box: the **paper approval-code grid** (fallback authenticator, CH-4), and the **recovery key** on its own sheet, so using the grid never takes the recovery key out of storage.
3. **Cellular modem with SIM slot**. MVP: a separate USB LTE modem with voice support. Target: built into the drive (§3.3).

- **HW-1** The image MUST NOT contain any per-owner secret not printed on that drive's card. The card and drive are produced as a pair. A drive bought without a card MUST generate a fresh card on first boot only when a local display, printer, or local web session is present (DIY path, §8.4).
- **HW-2** The modem MUST support SMS and voice to the host over USB. [Risk] Voice-over-USB support varies by modem; qualify specific models.

### 3.2 Host compatibility
- **HW-3** Supported hosts: x86-64 PCs with UEFI firmware, roughly the last decade. Windows-on-ARM laptops and pre-UEFI PCs are out of scope.
- **HW-4** **Floor profile:** 4 modest cores, 8 GB RAM, USB 3.2 Gen 2, no accelerator (reference: GEEKOM Air12 Lite, N95). Every requirement MUST pass at the floor. Larger hosts MAY only add throughput, never change semantics, authority, or test outcomes.
- **HW-5** Secure Boot MUST be supported through a Microsoft-signed shim [Fact: standard for mainstream distributions].
- **HW-6** Booting from USB without a screen works where firmware already prefers USB, or after a one-time boot-order change. [Risk] For "any PC, never a keyboard", the integrated key (§3.3) presses the boot key from a per-model recipe.
- **HW-7** Macs are not boot targets [Inference: Apple boot security requires interactive recovery-mode changes]. A macOS host app running the system in a virtual machine is a post-MVP option.

### 3.3 Target integrated form (post-MVP)
One device holds the NVMe SSD, a microcontroller that acts as a USB keyboard for blind boot selection, a Wi-Fi radio, and an LTE modem with a SIM slot. You plug one thing in.

---

## 4. Architecture

```
            text / voice (carrier)          local Wi-Fi (box's own AP, card key)
  owner phone ───────────────▶ SIM modem          owner phone ──▶ local web UI
                                   │                                  │
┌──────────────────────── HOST (immutable image on the drive) ───────┼────────┐
│ BROKER — trusted, small, deterministic, no inference                │        │
│  journal · grants/budgets · vault · adapters · admission/preemption │        │
│  owner channel · snapshot custody · change pipeline · release mgr ◀─┘        │
│      ▲ narrow sockets only                                                    │
│ ┌────┴─────────────┐ ┌───────────────────┐ ┌───────────────┐ ┌─────────────┐  │
│ │ AGENT MACHINES   │ │ CREDENTIALED      │ │ LOCAL INFER.  │ │ RECALL INDEX│  │
│ │ full power,      │ │ EXECUTORS         │ │ CPU/iGPU/NPU  │ │ (broker-    │  │
│ │ snapshot/fork/   │ │ logged-in browsers│ │ small model,  │ │  owned)     │  │
│ │ rollback; guests │ │ & provider        │ │ speech,       │ │             │  │
│ │ e.g. OpenClaw    │ │ adapters (1 acct  │ │ embeddings    │ │             │  │
│ │ (untrusted)      │ │ each)             │ │               │ │             │  │
│ └──────────────────┘ └───────────────────┘ └───────────────┘ └─────────────┘  │
└───────────────────────────────────────────────────────────────────────────────┘
```

| Component | Trust | Owns |
|---|---|---|
| **Host** | Trusted base | Immutable, signed image with A/B updates; an existing distribution, not a custom one |
| **Broker** | Trusted, minimal | All state that matters: journal, grants, budgets, vault, snapshots, releases, owner channel |
| **Agent machines** | Untrusted, disposable | Work: planning, code, experiments. Full root inside, no credentials, no direct path out except broker sockets and declared uncredentialed egress |
| **Credentialed executors** | Broker-controlled | One account each; driven only through the narrow action protocol (§7.3) |
| **Local inference** | Untrusted service | Small model, speech, embeddings; uses accelerators when present |

- **ARC-1** The broker MUST be the only component holding credentials, signing keys, or snapshot custody.
- **ARC-2** The broker's control path MUST NOT invoke AI inference.
- **ARC-3** Agent runtimes MUST run unmodified where their tool/plugin interfaces suffice. A runtime fork is permitted only with a recorded "interface X insufficient because Y."
- **ARC-4** Agent machines MUST be rebuildable from a known image at any time without losing durable state. Durable state lives only in broker-owned stores.
- **ARC-5** Agent machines and credentialed executors MUST run under a user-space kernel (e.g. gVisor) or hardware virtualization, never under namespaces alone. Guest code with root MUST NOT reach the host kernel's full system-call surface, because CRED-2 counts that kernel as trusted (S3: gVisor at the floor, measured for agent machines). [Risk] Browser executors and desktop kiosks (ADP-5) under gVisor or a microVM at the floor are unmeasured; S5 measures the browser case.

---

## 5. The trust boundary is reversibility

- **REV-1** Inside the box, agent machines MAY do anything: root, install packages, run code, break things. Every agent machine is snapshotted automatically at each step, and snapshots are broker-held, so the agent cannot delete them.
- **REV-2** Every **irreversible or external effect** MUST go through a journaled intent (§9). That covers sending, posting, buying, sharing, deleting remotely, disclosing data, changing an account, or creating/revealing a secret.
- **REV-3** The system SHOULD convert irreversible effects into reversible ones where possible: drafts instead of sends, staging copies, delayed send with an undo window, shadow runs.
- **REV-4** Agent primitives MUST include `checkpoint`, `fork(n)`, `diff`, `rollback`, `merge` on agent machines.
- **REV-5** **Information flow.** Disclosure cannot be rolled back, so it is gated by data label, not by reversibility. Each agent machine carries a label that only rises during its life:
  - `public`: it has seen only public input. Uncredentialed egress is open (CAP-2).
  - `private`: it has received owner data (mail, files, recall results, credentialed-executor reads, owner chat, event-bus content). Its outbound traffic goes only through the broker's egress proxy, to the task's allowed destinations: model providers, granted adapters, and destinations the owner has pre-allowed. Any other destination is a disclosure intent (REV-2). The proxy strips every credential and auth header the agent supplies: requests to allowed hosts carry only broker-injected owner credentials (ADP-10), and an allowed host reached without one gets read-only methods. Otherwise an attacker's own key or token would turn an allowed host into a drop box the attacker reads from their own account.
  - A `private` machine MAY start a `public` machine with a research query that is journaled and bounded in size and rate (numeric bounds frozen before A14).
  - Data flows freely from public to private machines; otherwise private to public is a disclosure. Forks inherit the label; rollback to a snapshot taken before the label rose, or a rebuild, resets it.
  - Suggested pre-allowances (CAP-6) never include hosts that publish user content (paste sites, file shares, URL shorteners), since an attacker can read what those receive.

---

## 6. Owner channel

### 6.1 Text and voice (anywhere)
- **CH-1** The box's number (its SIM) is the conversational address. Texts and calls reach the broker directly from the modem. No intermediary service is involved beyond the carrier.
- **CH-2** **STOP** and **STATUS** MUST be handled by the broker with all AI models and guests down.
- **CH-3** Command tiers:

| Action | Required proof |
|---|---|
| STOP (pause all dispatch) | Message from the owner's number (worst case of spoofing: a pause) |
| Task chat, STATUS | Owner's number + a session unlocked by an approval code within the last N hours |
| Approve a low-risk irreversible intent (CH-10) | The texted code from that request, replied from the owner's number |
| Approve a high-risk irreversible intent (CH-10) | Approval code from the code generator, in reply to that request's ID |
| Unlock on an unknown host (CRED-8) | Vault passphrase scanned on the local UI + approval code from the code generator, checked after decryption |
| New grant, raise budget, adopt a release, add a trusted host, recovery | Approval code + local confirmation or recovery key, per policy |

- **CH-4** Approval codes come from a standard code generator. [Fact] iPhone's built-in Passwords app generates them; on Android any authenticator works. The **paper grid** on the Owner Card's detachable sheet is the fallback: challenge–response, each cell single-use (CH-18). No AgentOS app exists. These codes are the high-risk tier of CH-10. Batching (one code per digest batch) and pre-allowances are the main ways to reduce prompts.
- **CH-5** Live calls: carrier voice → modem → broker → speech (local by default; hosted only by explicit policy) → guest. [Risk] Voice quality and latency over USB modems need qualifying. On a call, approval codes and control words are entered by keypad (DTMF), decoded by the broker, and never passed to the speech service or guests, which are untrusted (§4).
- **CH-18** **Code hygiene.** Texted codes are at least 6 digits, single-use, and bound to one request or batch. Three wrong replies void that request. Five wrong codes of any kind in 24 hours lock the low tier, so approvals need a code-generator code until the owner unlocks, and the owner is told. Paper-grid cells are single-use.
- **CH-19** **Owner-channel disclosure.** A session unlock (CH-3) requires a code-generator code or a grid cell, never a texted code, because a SIM swap receives texted codes. Outbound texts and speech whose content comes from anything other than the broker's own fixed templates MUST NOT carry verification codes or known secret formats; such content is replaced by a pointer to the local UI. The patterns are fixed and context-anchored (no inference, ARC-2): known token formats, and 4–10 character codes next to words such as "code", "OTP", "verification", or "PIN", so amounts, dates, and order numbers pass. Broker-originated texts carrying the broker's own CH-10 codes are exempt. This extends CRED-7 from vault values to secret-shaped content (CRED-3).
- **CH-10** **Two-tier approval.** Prompts should be rare in the first place: approvals are batched (one code covers a batch) and owner pre-allowances cover routine actions, so codes are needed only for what remains.
  - **Low risk** means **all** of: the recipient is one the broker verifies already exists in the owner's account (as in ADP-9), created by the owner or present longer than the owner's hold period (ADP-9), not added automatically by the service; any amount is under the owner-set limit; and the operation's verb is not excluded by the owner. Anything else is high risk. The box texts a one-time code bound to that request (or batch), and the owner replies with it from their number. The code works once and expires after a short owner-settable time (default 15 minutes). The request text is rendered by the broker in fixed wording from verified fields, never by the agent. Recipients appear as canonical identifiers (address, number, last 4 digits of an account), never display names, with look-alike characters folded to plain text. This still defeats spoofed texts and self-approval by the agent, which never sees the code. It proves possession of the owner's number only (§17 risk 9).
  - **High risk** means new or wider grants or pre-allowances, money above the owner-set limit, CRED-6 actions, and recovery. These require the code-generator code or the paper grid, which a SIM swap cannot obtain, plus local confirmation where CH-3 already requires it.
  - The owner sets the tier boundaries; changing them is a high-risk intent. The broker applies them to verified data, never to the agent's claims. Unclassifiable requests are high risk.
- **CH-6** Secrets MUST NEVER be requested or accepted over text or voice. The carrier sees that traffic, and transcripts reach models.

### 6.2 Local web UI (box's own Wi-Fi only)
- **CH-7** The broker runs its own Wi-Fi access point, secured with the card's Wi-Fi password, and serves a local web UI on it. The link is encrypted by WPA3-SAE (WPA2 only by owner opt-in, for older phones), and the access point isolates clients from each other. No domain or public certificate is required. Wi-Fi membership is not authority: beyond the setup, unlock, and status pages, the local UI requires a sign-in with an approval code, remembered on that device for the CH-3 unlock period.
- **CH-8** The local UI is used for setup, password logins to sites without OAuth (live view of a credentialed browser), reviewing diffs and files, and changing rules. It is never required for daily operation.
- **CH-9** The local UI MUST NOT be reachable from the home network or the internet.

### 6.3 What is deliberately not possible
Remote live browser view, remote file browsing, and push notifications, away from the box's Wi-Fi. Everything remote is text and voice. [Inference] OAuth "device code" sign-ins work remotely because they happen on the provider's own site. Scope limits vary by provider.

---

## 7. Identity, credentials, recovery

### 7.1 Owner identity
- **ID-1** Ownership is proven by the **setup secret** (card), the **approval-code seed** (enrolled once in the owner's code generator, plus the paper grid), and the **recovery key**. The owner's phone number is a signal, never sufficient alone.
- **ID-2** No developer key, no first-caller enrollment, no account with the AgentOS project.

### 7.2 Invariant C (credential custody)
- **CRED-1** No reusable authentication material (passwords, session cookies, OAuth/refresh/bearer tokens, API keys, private keys, approval-code seeds, recovery codes) MAY ever exist in memory, storage, snapshots, logs, the recall index, or I/O readable by any model-directed process.
- **CRED-2** Secure relative to the stated trusted base: host kernel, hypervisor, firmware, broker, credentialed-executor sandboxes. Compromise of that base is out of scope, and the spec says so.
- **CRED-3** Content the agent legitimately reads may contain secrets (a 2FA code in an email). That is governed by disclosure policy, not custody.

### 7.3 Credentialed executors
- **CRED-4** Logged-in browsers run in broker-owned sandboxes, one account each. Agents drive them only through a closed, versioned action protocol: navigate, click, type, select, read DOM/accessibility snapshot (password fields omitted), screenshot, download to workspace. Developer tools, arbitrary JavaScript, and cookie/storage/header access MUST NOT exist in the protocol.
- **CRED-5** A provider CLI MAY hold a consumer login token only if tool execution inside it is disabled and it acts purely as a model-call relay. Otherwise that provider uses an API key, injected by the broker's egress proxy into declared inference endpoints only (ADP-10). Relay input goes through the CLI's non-interactive mode; slash, bang, and tool syntax in relayed input MUST be inert, shown in S6 with a canary token that never appears in output.
- **CRED-6** Actions that reveal or create secrets (show API key, password reset, add device, export, change recovery) are irreversible intents requiring an approval code, even on allowlisted sites.
- **CRED-7** The broker MUST redact every vault value from all agent-bound output, logs, and the index. This is defense in depth.

### 7.4 Vault keys and hosts
- **CRED-8** The vault is encrypted on the drive, and nothing stored on the drive alone can release its key. The key is wrapped by independent slots:
  - **Trusted host:** a slot sealed to that PC's TPM, so it restarts unattended.
  - **Unknown host:** a slot derived from the Owner Card's **vault passphrase** through Argon2id with at least 256 MiB of memory, tuned to about 1 s at the floor (HW-4). The owner scans its QR code from the card on the local Wi-Fi page (CH-8), or types it as a fallback, never by text or voice (CH-6). The short setup code (§8.1) is not derived from it and never unlocks anything. The box also texts the owner and requires a high-tier approval code (CH-4), so an unexpected unlock is visible and a running box refuses one without the owner. The code authorizes the unlock; it does not decrypt anything. Anything that verifies approval codes (the code-generator seed, the grid) lives only inside the vault, since a verifier readable before unlock lets a drive copy compute codes; the code is therefore checked after decryption, in broker memory, and the running box discards the unlocked key if the code fails or does not arrive within the request's expiry.
  - **Recovery:** a slot for the recovery key (REC-1).

  The owner MAY replace the passphrase on the local UI. Replacement protects only against copies made afterwards: a copy of the drive taken earlier still opens with the old passphrase, so after a suspected card loss the owner also rotates the credentials in the vault. A lost drive is ciphertext: without the card, a TPM it was sealed to, or the recovery key, its key is out of reach of offline guessing. [Inference: at 80 bits or more behind Argon2id, offline search is infeasible]
- **CRED-9** Adding or removing a trusted host is a tier-4 action (CH-3).
- **CRED-10** **Executor output.** A credentialed executor stays on its account's declared origins (from its adapter); any other origin opens in a separate uncredentialed context. Declared origins include the account's identity-provider and payment-challenge origins. Executor output to agents (DOM text, accessibility snapshot) passes a fixed-pattern detector for known token formats and high-entropy values in secret-labelled fields; matches are redacted as in CRED-7, and screenshots of pages with a match are withheld. This covers secrets a site displays without a reveal step, which the vault does not know.

### 7.5 Recovery
- **REC-1** Recovery key + a backup (if the owner configured one), or the drive itself, restores everything onto new hardware.
- **REC-2** Restore MUST NOT revive revoked grants or spent budgets: restore enters restricted mode until the owner re-confirms standing grants.
- **REC-3** Lost phone: the owner re-enrolls the code generator using the recovery key. Lost SIM/number: a new SIM plus the recovery key; the new number is announced to the owner's number. A new holder of an old number can do nothing without codes.
- **REC-4** Every Owner Card secret (Wi-Fi password, setup secret, vault passphrase, paper grid, recovery key) can be rotated from the local UI as a tier-4 action, producing a new card to print or copy. Setup offers this in one line, for kits that others may have handled. Rotation protects only against copies made afterwards (CRED-8).

---

## 8. Onboarding (normative)

### 8.1 Steps
1. Insert the SIM into the modem. Plug the drive and modem into the PC (rear ports). Power on. No monitor or keyboard.
2. If the PC doesn't boot USB by itself: press its boot key once (MVP), or the integrated key does it (target).
3. The box boots and starts its own Wi-Fi. If Ethernet or a known network is available, it also connects out.
4. Owner scans the card's QR code. The phone joins the box's Wi-Fi and opens the local setup page.
5. Setup page:
   - choose home Wi-Fi (or Ethernet);
   - enter the owner's phone number;
   - enroll the approval-code seed into the phone's code generator (one tap on iPhone's Passwords app);
   - confirm the recovery key is stored;
   - accept default rules (spend cap, always-approve list, quiet hours);
   - make this PC a trusted host.
6. The box texts the owner from its own number: "AgentOS is running on [host, RAM]. Reply with the setup code from your card." The owner replies, and the box confirms. This proves the number path both ways.
7. **Connect AI:** per provider, an OAuth/device-code sign-in on the phone (works anywhere), or an API key entered on the local setup page. Never by text.
8. **Connect accounts:** OAuth/device-code where offered; otherwise a password login through the local live view of a credentialed browser.
9. "All set. What should I work on?"

- **ONB-1** Steps 1–9 MUST be completable with only the PC, drive, modem, SIM, card, and phone. No external service beyond the carrier and the providers being connected.
- **ONB-2** Disk on the host is never written. AgentOS runs entirely from the drive.

### 8.2 Moving to another PC
Plug in; the box texts "Unknown host [model]. Join the box's Wi-Fi to unlock." The owner scans the vault passphrase from the Owner Card on the local page (or types it) and replies to the text with an approval code (CRED-8). Optionally make it trusted.

### 8.3 Daily use
Text or call. Batched approvals carry evidence. A daily digest arrives at a set time. STOP always works.

### 8.4 DIY drive (no card)
Flash the image from any computer. First boot generates the card contents and shows them only on the local setup page (or a connected display), for the owner to print. Same flow afterwards.

---

## 9. Operation contract (the one primitive)

```
intent { id, goal_id, origin(authenticated), action, exact params/recipients/visibility,
         grant_ref, budget_reservation, preconditions, executor }
  → authorized | denied
  → dispatched → observed(result | outcome_unknown) → settled
```

- **OP-1** Same ID + same params returns the existing state. Same ID + different params is rejected.
- **OP-2** Once a request may have reached a service, the intent stays `outcome_unknown` until evidence resolves it. A new attempt ID is not proof the previous one did nothing.
- **OP-3** Authority, recipients, preconditions, and reservations MUST be rechecked immediately before dispatch.
- **OP-4** Restart = replay the journal. Unresolved intents are reconciled before new dispatch on that account.
- **OP-5** Grants, budget changes, trusted-host changes, release activations, and skill adoptions are themselves intents: one audit trail, one recovery rule.
- **OP-6** STOP blocks further dispatch, attempts supported cancellation, and reports unresolved effects. It never claims to undo remote actions.
- **OP-7** Permission, execution success, and goal quality are recorded separately. An allowed, successful action can still be wrong.

---

## 10. Capability services (the force multipliers)

| ID | Service | Requirement |
|---|---|---|
| **CAP-1** | Speculative parallelism | Agents MAY fork N machines, try approaches, test, keep the winner. N is set by measured free RAM; at the floor N may be 1 (sequential). Frontier spend is reserved per fork. |
| **CAP-2** | Reach | Any tool through an adapter (§10A). Credentialed browsers (§7.3) for logged-in sites; uncredentialed browsing with full power inside agent machines; local network devices by explicit grant. |
| **CAP-3** | Recall | A broker-owned local index of everything the system has seen, with provenance. Full text, embeddings, and structured facts. Owner corrections are stored as explicit, editable preferences, written only from the authenticated owner channel (owner texts, local UI) with that message as provenance. Results carry their source and reach agents as untrusted content, never as instructions. Deletion requests propagate. |
| **CAP-4** | Always-on | An event bus (mail, files, calendar, web changes, timers) triggers work. Interrupts for irreversible decisions only, batched into a digest unless urgent. |
| **CAP-5** | Compounding | Successful trajectories are recorded as replayable procedures. Recurring ones are compiled into scripts that consult a model only where assumptions fail. Compiled skills go through §11. |
| **CAP-6** | Attention optimizer | Approvals arrive batched and risk-tiered, with evidence. The system proposes (never assumes) converting always-approved classes into standing grants. |
| **CAP-7** | Collaboration | Multiple frontier participants may work one task through broker tools. Disagreements are settled preferably by running both (CAP-1), not by debate. This is guest behavior, not infrastructure. |

---

## 10A. Adapters: reaching any tool

AgentOS reaches current and future tools (frontier assistants, SaaS, local apps) through **adapters**. An adapter is a versioned, declarative package that maps a tool's operations onto broker intents. Adding a tool means adding an adapter, not changing the broker.

- **ADP-1** Every external tool is reached through an adapter that declares: tool identity, connection types, and the operations it exposes. This governs every effect that passes through the broker (credentialed or external-effect operations, REV-2); work wholly inside agent machines, including uncredentialed browsing (CAP-2), is unaffected. A broker-mediated operation the adapter does not declare does not exist for agents.
- **ADP-2** **Labels come from a fixed verb list, not from the adapter's author.** The broker defines a closed list of verbs (at least: read, draft, send, post, buy, share, delete-remote, change-account, reveal-or-create-secret), each with a built-in reversibility class and credential custody rule. An adapter maps each operation to one verb and cannot set a class itself. When a mapping is ambiguous, the stricter verb applies; where routes differ, the strictest route's class applies. Only operations that fit no verb go to the owner, as one summary per tool, and they stay draft-only until the owner answers. Public adapters adopted via §11B carry maintainer-checked mappings and are accepted under the single grant that connects the tool. The verb list, its classes, and these rules change only by owner-approved intent (OP-5, CHG-2).
- **ADP-3** Connection types, in **default** routing order: (1) API or MCP; (2) the tool's CLI or plugin interface; (3) its web app, in a credentialed browser (CRED-4) when logged in; (4) its desktop app under GUI automation (ADP-5). The router picks the first route that covers the operation, is healthy, and whose grant and custody the owner already holds.
- **ADP-4** **Routing is self-improving.** The order in ADP-3 is a starting default. Route choice per tool and operation is a Loop 1 candidate class (LOOP-4), scored on measured success, owner outcome, latency, cost, and breakage. A new route is adopted only through §11 (held-out suite, CHG-1) and rolls back on regression. Routing can only choose among routes the owner has already granted; it never changes a class or custody (ADP-2).
- **ADP-5** **Desktop-app executors.** A desktop app that holds a login runs in a broker-owned VM, one app and one account each, as a **single-app kiosk**: no shell, file manager, or other launchable program; file dialogs confined to a workspace directory; and, where the OS allows, the app's credential store unreadable by the user the app's UI runs as. Agents drive it only through the CRED-4 action protocol (accessibility tree, screenshot, click, type, select). In-app screens that reveal or create secrets are CRED-6 intents. Linux apps are within the floor guarantee, one executor at a time [Inference; unmeasured]. Windows (Wine or VM) and Android (emulator) executors are **optional capabilities outside the HW-4 guarantee**, available only on hosts that can run them. A desktop-app executor MUST host only apps whose saved login can be locked away from the user the app's UI runs as; other apps are reached by their API, CLI, or web route, or not at all (§17 risk 7).
- **ADP-6** Adapters are created and changed only through §11, including by agents when a new tool appears: draft the adapter, qualify it on recorded interactions (LOOP-5), pass the mismatch check (ADP-8), and request any new grants and the choices for unmapped operations from the owner (ADP-2). An adapter drafted from the owner's interactions is private-derived (OSS-3); only a clean-room re-creation (OSS-2) may be published via §11B.
- **ADP-7** An adapter whose observed behavior diverges from its declaration (a changed UI or API) is rerouted to its next healthy, already-granted route, or paused if none exists, and Loop 3 receives a repair candidate. Rerouting never widens authority, changes custody, or loosens an operation's class (ADP-2).
- **ADP-8** **Mismatch check.** Before adoption, an adapter is exercised against the tool's demo or sandbox environment (synthetic data only) where one exists. An operation whose observed effects exceed its verb (any outbound effect from a read- or draft-mapped operation) blocks adoption. [Risk] Effects the demo environment does not show can still be mislabelled; the stricter-verb rule (ADP-2) is the mitigation.
- **ADP-9** **Owner pre-allowance.** The owner MAY pre-allow irreversible operations, scoped per service, per operation, or both, to run without approval and without notification. A pre-allowance MUST be a deterministic predicate the broker checks (no inference, ARC-2), never a description the agent interprets:
  - **Verified inputs.** Every field the rule constrains (recipient, account, amount) is read by the broker from the source system (e.g. the invoice's contact in the tool itself) or fixed by the owner. A value the agent supplies never satisfies the predicate.
  - **Templated content only.** Content comes from an owner-approved template filled only from those fields, with no free text.
  - **Scope bounds**: per-item frequency, a daily rate, and an amount cap where relevant, in every rule.
  - **Optional hold** on records edited in the last N days, so a quietly tampered record cannot take effect at once (§17 risk 8).
  - **Fixed-wording approval.** The agent may draft a rule; the broker renders it back to the owner in fixed, spec-defined wording, never the agent's words.
  - **Asymmetric changes.** Granting or widening a rule is a new-grant intent (CH-3: approval code plus local confirmation or recovery key). Pausing or revoking needs only a text from the owner's number, like STOP.
  - **No match, no silence.** An operation that does not match a rule exactly falls back to a normal approval request.
  - **Audit.** Covered operations are still journaled (REV-2), visible on request and on the local UI, and halted by STOP.
  - **Exclusions.** CAP-6 may suggest a rule, never enact one. CRED-6 actions keep per-action approval under any rule.
- **ADP-10** **Enforced request shapes.** Each declared operation also declares the requests it makes: host, method, and path template, and for single-endpoint APIs (GraphQL, JSON-RPC) the operation name and a body schema. The broker's egress proxy injects a credential only into a request matching a declared operation of a granted adapter, and applies that operation's verb class and intent before forwarding. Anything else is denied and journaled. A model relay (CRED-5) declares inference endpoints only, so a provider key never reaches that provider's key-management, file-sharing, or billing endpoints. This makes the verb list (ADP-2) a property of traffic, not of the adapter's honesty.

---

## 11. One change pipeline

Sources: **local** (procedures, skills, routing, configs), **upstream** (new guest images such as OpenClaw releases, new host images), **shared** (packages from other installations).

Path: candidate → build in sandbox → evaluate on the frozen suite → adoption intent → activate with fallback → keep as a rollback point.

- **CHG-1** Held-out evaluation suites live in the broker. Candidates see only a dev split. Cases come from real tasks with owner outcomes (accepted, corrected, rejected) plus security fixtures, never solely from tests the candidate authored.
- **CHG-2** Changing suites, graders, or adoption policy is an owner-approved intent and cannot be validated by the change itself.
- **CHG-3** Security updates MAY auto-stage per standing policy. Behavior changes require owner approval unless a standing grant covers that class.
- **CHG-4** Sharing is opt-in, carries only public inputs and evidence, and works over any git-like channel the owner chooses. No registry or marketplace. The recipient re-qualifies locally and may reject.
- **CHG-5** Shared packages MUST NOT carry private corpora, sessions, identity material, or authority.

---

## 11A. Autonomous loops on spare capacity

The system improves and defends itself in otherwise-wasted time. Three loops share one scheduler, the change pipeline (§11), and the journal.

### Defaults
- **LOOP-0** All three loops and open-source contribution (§11B) are **on by default** and **modifiable** at any time, by text ("loops off", "stop sharing") or on the local UI. Settings: per-loop on/off, spare AI budget (default: local compute plus a conservative share of spare quota, shown in the digest), per-category contribution policy, and a global off switch. Onboarding states the defaults in one line, and the owner can change them there.

### Spare capacity
- **LOOP-1** "Spare" means local compute not needed by foreground or accepted work (RES-1), plus AI quota the owner has designated as spare, e.g. the unused part of a subscription's rate window. Spare work runs in the lowest admission class and MUST yield within the frozen preemption target.
- **LOOP-2** Spare AI usage has its own budget, separate from work budgets and visible in the digest. [Risk] Some consumer AI plans may restrict automated background use. Such routes are used for loops only if the provider permits it; otherwise loops use API-key routes or local models.
- **LOOP-3** The scheduler allocates spare capacity across loops by measured return: held-out gain or security findings per unit of cost. A loop that stops producing measured value gets less budget automatically. **When nothing worthwhile remains, the system sleeps.**

### Loop 1: self-improvement
- **LOOP-4** Mines the journal for failures, owner corrections, slow or expensive steps, and repeated trajectories, and turns each into a hypothesis and then a candidate (procedure, compiled skill, routing rule, context rule, configuration).
- **LOOP-5** **Counterfactual replay:** candidates are tested by replaying past tasks inside agent machines against recorded external responses, in shadow mode. No live external effects; any unrecorded call fails closed.
- **LOOP-6** Candidates are adopted only through §11 (held-out suite from real owner outcomes, CHG-1). Loop 1 cannot edit the suite, the graders, or its own budget (CHG-2).

### Loop 2: self-securing
- **LOOP-7** Continuous adversarial testing *from inside the sandbox*, with no more authority than any guest:
  - injection corpora against guests and collaborators;
  - fuzzing of the broker sockets and the credentialed-browser action protocol;
  - canary hunts (the A5 test, rerun continuously with fresh canaries);
  - attempts to tamper with evaluators and snapshots;
  - resource-exhaustion probes.
- **LOOP-8** Passive checks: image and dependency hashes vs the signed release; known-vulnerability matching against advisories (fetched like updates, DEP-4; works offline with the last snapshot); configuration drift; and expiry of credentials and certificates held in the vault.
- **LOOP-9** Every finding becomes: contain (pause the affected grant or executor) → preserve evidence → minimized regression case (added to the security suite permanently) → fix candidate through §11 → owner notified per severity.
- **LOOP-10** A fix that disables a check, widens authority, or reduces coverage of the security suite MUST fail qualification. The security suite only grows, except by owner-approved intent.

### Loop 3: maintenance
- **LOOP-11** Upstream intake (new OpenClaw or other guest images, host images, dependency updates) is evaluated in spare time through §11. Security updates are prioritized; checks never reported as current when offline.

---

## 11B. Accumulating into the open-source project

Every installation's verified gains can flow into one public project, and every installation benefits from everyone else's, without any runtime dependency on the project.

### What accumulates (public repository contents)
| Area | Contents | Main source |
|---|---|---|
| Core | Broker, host image definition, action protocol, schemas | Maintainers + contributions |
| Skills library | Compiled skills and procedures with applicability, tests, measured results | Loop 1 |
| Evaluation suites | Public task cases with expected outcomes (no private data) | Owners who opt in |
| Security corpus | Attacks, fixtures, minimized regressions | Loop 2 |
| Hardware database | Per-PC boot recipes (HW-6), modem qualification (HW-2), accelerator results | A1/A2 runs on real installations |

### Contribution flow: clean-room by construction

**Principle:** nothing derived from private data is ever published. Published artifacts are produced only by a process that **never had access** to private data, so leakage is ruled out by information flow, not by filtering or redaction (which can miss things).

- **OSS-1** **Two sides, one narrow bridge.**
  - The *private side* (journal, recall index, workspaces, real tasks) may emit only a **hint**: a record whose every field is an **enumerated value from a public schema**. Examples: `skill_gap{domain: calendar, format: ics, failure: timezone}` or `vuln{class: prompt_injection, vector: email_html}`.
  - Hints contain no free text, numbers, names, identifiers, or content. Information crossing the bridge is bounded to choosing among publicly listed options.
  - Every hint is logged and visible to the owner.
- **OSS-2** **Clean-room builder.** On receiving a hint, a fresh agent machine is created with **no** access to the vault, journal, recall index, private workspaces, credentialed executors, or owner channel. It sees only the hint, the public repository, public internet (read-only), and synthetic fixtures. It independently builds the generalized skill, test case, or regression from public information, and tests it on synthetic fixtures. **Only clean-room output can be published.**
- **OSS-3** **Never published, under any setting:** real task cases, private evaluation suites, trajectories, transcripts, compiled skills built from private trajectories (their clean-room re-creations may be), recall content, and owner preferences.
- **OSS-4** **Structured-only data:** hardware-database entries and attestations use fixed schemas of enumerated fields (vendor, model, firmware version, result class, software version). No serial numbers, free text, or timestamps finer than a day.
- **OSS-5** **Security findings:** loop 2 runs on synthetic data and canaries. A finding from real traffic crosses only as a `vuln{}` hint, and the regression is rebuilt in the clean room. Findings that could harm other installations go first by encrypted private report to the maintainers, under an embargo.
- **OSS-6** **Metadata:** each installation publishes under a pseudonymous signing key, unlinkable to the owner's identity, number, or accounts, and rotated periodically. Publications are batched and time-delayed to blur activity patterns. [Inference] Content leakage is structurally zero. The remaining exposure is network metadata (that *some* installation at an IP address published), which the owner can remove by routing publication through an anonymity network (optional setting).
- **OSS-7** **Owner control:** per-category policy is *automatic* (default, since content is clean-room), *ask each time*, or *never*. Hints are logged locally either way.

### Verification without a central service
- **OSS-8** **Decentralized qualification:** installations (on by default, LOOP-0) spend spare capacity (LOOP-1) reproducing public candidates and publish signed attestations: "passed/failed, on this hardware class, with these versions." Accumulated attestations replace project-run CI.
- **OSS-9** Attestations are evidence, never authority. Maintainers decide what enters canonical releases. Each installation still re-qualifies locally before adopting anything (CHG-4). [Risk] Fake installations can forge attestations, so they're weighted by reproducibility and maintainer review, never counted blindly.
- **OSS-10** Canonical releases flow back to every installation through the update path (DEP-4, UPD-1), per owner policy. Anyone may fork the project, and installations may follow any fork.
- **OSS-13** Incoming public artifacts are untrusted input: they run only in agent machines, and pass §11 locally before adoption.

### Dependency status
- **OSS-11** The public repository is a **publication channel, not a runtime dependency**. It can be hosted on any git service, mirrored anywhere, or carried on a drive. With it unreachable, nothing about operation, control, or recovery changes (DEP-3).
- **OSS-12** The license MUST be chosen before first public release, and upstream notices (OpenClaw and others) preserved. This spec grants no license.

---

## 12. Resources and accelerators

- **RES-1** Admission classes, in priority order: `foreground` (calls, STOP/STATUS, owner chat) > `accepted work` > `experiments`. Experiments MUST be frozen or killed within a frozen target time when foreground needs resources.
- **RES-2** A per-component memory budget is declared and enforced by cgroups. The broker refuses admission that would breach it. No swap thrashing, no out-of-memory kills of broker or foreground.
- **RES-3** The broker discovers accelerators (iGPU/NPU/GPU) and exposes them as an admission resource used by local inference. The identical service MUST run on CPU when no accelerator is present. Nothing in the broker depends on an accelerator.
- **RES-4** Reserve storage for a healthy release, the journal, and the recall index before discretionary downloads or snapshots. Old snapshots are pruned by policy.

---

## 13. Updates, backups, time

- **UPD-1** A/B image updates: stage → test → activate → health-check → commit or fall back. Rollback never rewinds revocations, spent budgets, deletions, or known external effects.
- **UPD-2** Updates come from content-addressed, signed sources: any mirror, or offline from a drive (DEP-4). The update-signing key is held offline by the project. [Risk] Project key custody and rotation need their own procedure.
- **UPD-3** **First boot updates before trust.** The preloaded image may be months old. On first network contact, before any AI or personal account is connected, the box fetches the latest **stable** release, verifies it, and activates it through A/B with fallback. Credentials never touch an outdated image. Offline first boot runs the preloaded image and says so, and the update applies when the box is next online.
- **UPD-4** **Channels:** *stable* (default), *fast* (early adopters, feeds attestations), *pinned* (no automatic updates, security notices only). Changeable by text or local UI.
- **UPD-5** **Cadence (defaults, modifiable):**

| Change type | Check | Apply |
|---|---|---|
| Security fixes | Daily | Auto-staged; applied at the next quiet window, typically within 24 h; automatic rollback on failed health check |
| Stable releases (host, broker, bundled guests such as OpenClaw) | Daily | After a **soak**: at least 7 days on fast **and** sufficient independent passing attestations (OSS-8), whichever is later, plus local requalification; then at a quiet window with random jitter |
| Behavior-changing releases | Same | Also need owner approval unless a standing grant covers that class (CHG-3) |
| Upstream projects directly (e.g. OpenClaw main) | Loop 3, spare time | Never adopted straight from upstream; enter users' boxes only via a qualified AgentOS release |
| Shared skills | Continuous | Through §11 locally, one at a time |

- **UPD-6** Updates never apply during a call, accepted work, or quiet hours the owner has excluded. Every update is a journaled intent with a rollback point.
- **UPD-7** [Inference] Soak plus attestations replaces a central staged rollout: early-channel installations act as the canary population without any project-run service.
- **UPD-8** **Update metadata** follows The Update Framework (TUF; reuse a maintained implementation): releases are signed by a threshold of k-of-n maintainer keys, keys rotate and revoke without reinstalling, timestamp metadata expires so a frozen mirror is detected when online, and no release older than the installed one is accepted, offline included; local A/B fallback to the previous slot (UPD-1) is exempt. Offline installs from a drive (DEP-4) need valid signatures and a newer version but not fresh timestamp metadata; the box says the update was installed without a freshness check, and checks on its next online contact. Security fixes (UPD-5) auto-stage only with the threshold signatures plus at least one independent attestation from the fast channel (OSS-8).
- **BAK-1** Backups are optional and owner-chosen: a second local drive, or encrypted upload to storage the owner already has. Without a backup, the drive is the only copy, and the owner is told so plainly.
- **TIM-1** Time comes from network time when online, with carrier network time (from the modem) as a cross-check. Large disagreements put the broker into restricted mode for time-sensitive checks.

---

## 14. Out of scope (v0.11)

Fleet orchestration; Mac or ARM boot; macOS-only and iOS-only apps (Apple's licence permits macOS virtualization only on Apple hardware [Fact]; iOS apps run only on Apple devices); any hosted AgentOS service; remote rich UI (needs a relay, so excluded by DEP-2); a marketplace; private-data federated training; large local models as a requirement; custom kernel or distribution work.

---

## 15. Acceptance tests and gates

| ID | Test | Requirements |
|---|---|---|
| **A1** | On ≥3 unmodified PCs from different vendors, with no monitor or keyboard (one boot keypress allowed in MVP), complete onboarding §8.1 using only the kit and a phone. Record per-model results. | HW-3–6, CH-1, CH-7, ONB-1/2, DEP-1/2 |
| **A2** | Floor profile: full workload on N95/8 GB with no accelerator, no swap thrashing; a live call preempts an experiment within target. On an accelerator host: discovery, measured benefit, identical behavior when disabled. | HW-4, RES-1–3, CAP-1 |
| **A3** | Delegated task by text, then a live call; two frontier providers (at least one consumer route, the other either); agent-machine execution; native result in the owner's account, edited on the phone and picked up. | CH-5, CRED-5, CAP-7, OP-7 |
| **A4** | Kill broker and guest mid-effect; drop an external acknowledgment; reconcile without duplication; STOP by text with all models down. | OP-1–6, CH-2, ARC-2 |
| **A5** | **Canary test:** canary credentials in the vault and canary sessions in credentialed browsers; an adversarial agent with full root and every protocol verb fails to surface any canary anywhere agent-reachable, across repeated runs. | CRED-1–7, ARC-1 |
| **A6** | Hostile guest attempts escalation, evaluator tampering, and injection via a collaborator's output; all fail structurally; the guest cannot obtain or replay a texted low-risk code, and cannot get a high-risk request classed as low risk; the guest is rebuilt; a regression is retained. In-box damage is undone by rollback. | ARC-4, REV-1/2, CHG-2, CH-10 |
| **A7** | One pipeline: a local candidate passes held-out cases from real tasks; a bad one is rejected; an upstream guest image and a shared package take the same path; rollback works. | CHG-1–5, UPD-1 |
| **A8** | Portability and recovery: move the drive to an unknown PC (passphrase scanned on the local page plus approval code; the code alone does not unlock), then a trusted one (unattended restart). The vault header holds only TPM, Argon2id-passphrase, and recovery-key slots; a scan of every plaintext partition finds no vault-key material (canary key) and no approval-code seed or grid verifier; a running box refuses unlock by code alone and by passphrase alone. Restore onto a new drive with the recovery key; revoked grants are not revived; the old number's new holder can do nothing. | CRED-8/9, REC-1–3 |
| **A9** | Dependency audit: with all optional dependencies removed, and with all outbound traffic logged, the system boots, takes STOP/STATUS, and recovers. No traffic to any AgentOS-operated endpoint ever. | DEP-1–4 |
| **A10** | Leverage vs an unmodified OpenClaw baseline and a direct provider CLI on the same host and accounts: owner-minutes per accepted task, tasks per week, second-run speedup from compiled skills, and approvals split into necessary vs avoidable. | §1, CAP-4–6 |
| **A11** | Spare-capacity loops: over a fixed period on the floor host, loop 1 adopts at least one candidate with a predeclared held-out gain and rejects a bad one; loop 2 finds a seeded vulnerability, contains it, adds a regression, and qualifies a fix; any live call preempts loops within target; spare budget is never exceeded; a fix that weakens a check is rejected. | LOOP-1–11 |
| **A12** | Open-source round trip: installation X publishes a public skill and a security regression (embargoed path for the latter); independent installation Y reproduces and attests; a maintainer merges; Z receives it via update, re-qualifies, and adopts or rejects. With the repository unreachable, X, Y, and Z operate normally. **Leakage audit:** canary private data is planted in the journal, the index, and workspaces; the clean room is shown unable to read any of it; no canary or derivative appears in any publication or hint; and hints contain only schema-enumerated values. | OSS-1–13, LOOP-0, DEP-3 |
| **A13** | Adapters: one tool reachable by API and by web, plus one logged-in Linux desktop app. Default routing picks the API; a simulated API break reroutes only to an already-granted route, with unchanged class and custody, and pauses when none exists; an agent-drafted adapter maps its operations to verbs, one deliberately mislabelled "draft" that sends in the demo environment blocks adoption (ADP-8), and an unmapped operation stays draft-only until the owner chooses; an owner pre-allowance lets one irreversible operation run with no approval or notification while still journaled and stopped by STOP, and the same operation with an agent-supplied recipient that differs from the source system falls back to an approval request; Loop 1 proposes a route change that is adopted only via the held-out suite, and a bad one is rejected. **Adversarial:** through the action protocol, an agent tries to reach a shell, a file manager, or the app's credential store from the desktop executor, and fails; canary sessions are never surfaced (as A5). | ADP-1–9, CAP-2 |
| **A14** | Security hardening: a `private` agent machine cannot reach any destination off its allowlist (direct, DNS, or via a credentialed executor) while a `public` one browses freely, and a fork inherits the label; host-kernel exploit probes from a root guest do not reach host memory; proxy requests matching no declared operation, including provider key-management endpoints, are denied and journaled; a private machine calling an allowed provider with a canary "attacker" key has the key stripped or the call denied; a credentialed executor refuses an off-origin navigation in its credentialed context, and a site that shows a canary token without a reveal step never surfaces it; update metadata with too few signatures, or for a release older than the installed one, is refused, offline too; expired timestamp metadata is refused online, while offline a signed, newer release installs with the no-freshness-check warning; wrong-code limits and lockout trigger as specified, and no outbound text carries a canary 2FA code from mail; a Wi-Fi client without sign-in sees only the setup, unlock, and status pages and cannot reach another client; an email asserting a preference creates none; a canary relay prompt with slash and bang syntax is inert. | ARC-5, REV-5, ADP-10, CRED-5, CRED-8, CRED-10, UPD-8, CH-7, CH-18, CH-19, CAP-3 |

**Gates (riskiest first):** G1 = A1 (hardware and screenless reality). G2 = A4, A5, A9, A14 on a VM (core correctness). G3 = A2, A3, A6, A8 on real hosts. G4 = A7, A10, A11, A13. G5 = A12 (needs a second and third independent installation).

Before any qualification run, freeze revisions, hardware profile, accounts, workloads, numeric targets, repeats, margins, and rollback triggers. Missing values make a run exploratory, not a pass.

---

## 16. Decisions log

| Date | Decision |
|---|---|
| 2026-10-04 | Pairing secret delivered with the media. Now realized as the **Owner Card**. |
| 2026-10-04 | Frontier access: consumer auth preferred, API keys as a qualified fallback. |
| 2026-10-04 | Accelerator support stays in MVP acceptance (A2). |
| 2026-10-04 | Box-owned number. Now realized as **the box's own SIM**, not a telephony service. |
| 2026-10-04 | Hardware spec is the floor, not the expected machine. |
| 2026-10-04 | Credentials definitionally secure (Invariant C). |
| 2026-10-04 | Update to latest stable on first boot before accounts connect; channel-based cadence with soak period (UPD-3–7). |
| 2026-10-04 | Loops and contribution on by default, modifiable; contribution is clean-room only, so no personal data can be published (§11B). |
| 2026-10-04 | Spare-capacity self-improvement and self-securing loops; accumulation into an open-source project (§11A, §11B). |
| 2026-10-04 | Zero or near-zero external dependencies: no AgentOS-operated services, no relay, no app-store app. |
| 2026-10-04 | Adapter contract (§10A). Default routing order API → CLI → web → desktop GUI, which loops may improve through §11 like everything else. |
| 2026-10-04 | Operation labels come from a fixed verb list with a demo-environment mismatch check; the owner answers only for unmapped operations. The owner may pre-allow irreversible operations per service and/or per action with no notification (ADP-9). |
| 2026-10-04 | Two-tier approval (CH-10): texted one-time codes for low-risk approvals, code-generator codes for high-risk ones; batching and pre-allowances minimize prompts. |
| 2026-10-04 | Security review 1 (`reviews/security/`): data labels gate disclosure (REV-5); off-drive factor for unknown-host unlock (CRED-8); enforced adapter request shapes (ADP-10); VM-class isolation (ARC-5); TUF update metadata (UPD-8); code hygiene and owner-channel disclosure (CH-18, CH-19); executor output limits (CRED-10); card rotation (REC-4). |
| Proposed | External-drive-only (no internal install). This spec assumes it; the owner has not formally confirmed. |

## 17. Open risks

1. **Firmware boot selection** without a keyboard on arbitrary PCs (HW-6). The integrated key is the full answer.
2. **Voice over USB modems** (HW-2, CH-5): model-dependent quality.
3. **Consumer AI routes** inside a no-tools adapter (CRED-5). The API-key fallback covers it.
4. **Classifying web actions** as reversible vs irreversible in credentialed browsers. MVP: per-site allowlist, everything else draft-only.
5. **Remote rich UI is gone by design.** If that proves too limiting, the only fix is an optional, owner-chosen, end-to-end-encrypted relay. That would be a deliberate exception to DEP-2's spirit, never a requirement.
6. **Project update-signing key** custody (UPD-2). UPD-8's threshold signing means one stolen key can't sign a release; the custody and rotation procedure is still needed.
7. **Desktop kiosk escape** (ADP-5). A GUI path out of the kiosk (a crash dialog, help browser, or app-embedded file picker) could reach the app's saved login. Mitigations: the login stored outside the UI user's reach, A13's adversarial escape step, and restricting desktop executors to apps where that holds.
8. **Tampered trusted source** (ADP-9). An attacker who edits the source record a pre-allowance trusts (e.g. a Xero contact's email) passes the predicate. Mitigations: scope bounds, the recent-edit hold, and the journal.
9. **Low-tier approvals by text** (CH-10). A SIM swap of the owner's number, or a stolen unlocked phone, can approve low-risk requests. Mitigations: the owner-set low-tier limits, reversibility windows, the journal, and STOP.
10. **Owner Card kept with the drive** (CRED-8). The card holds the vault passphrase, so whoever has both can decrypt the vault offline; the approval code gates only a running, unmodified box. Mitigations: the card says to store it apart from the drive, like a passport, and the owner can replace the passphrase on the local UI (which does not protect copies already made).
11. **Tampered boot path on an unknown host** (CRED-8). Secure Boot stops at the distribution's kernel; the initrd and the `/usr` root hash are not verified (S7). An attacker with brief access to the drive can modify them so the local page captures the passphrase when the owner next types it on an unknown host, then take the drive. The unknown-host path has no integrity check. Options: (a) accept for MVP and say so in the owner's guide; (b) optional per-PC MOK enrollment for owners with a screen; (c) an AgentOS shim through Microsoft review after MVP.
12. **Disclosure through allowed destinations** (REV-5). A `private` machine can still leak through an allowed destination whose received data an attacker can read and through research queries. Mitigations: a minimal default list, no user-content hosts in suggestions, size and rate bounds, and the journal.
13. **SIM swap inside the unlock window** (CH-3, CH-19). A swapper can read ordinary private data by chat until the unlock lapses or the owner notices their phone has lost service. Codes and secret-shaped content are already withheld.
