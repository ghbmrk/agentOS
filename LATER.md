# LATER: first-release critical path and backlog
Generated 2026-10-07 by the COST thread's audit; the coordinator updates it. Rows marked LATER are not started until the first release ships (DECISIONS D-048). Promote a row by moving it to "Release" with the acceptance test it now blocks.

## Summary
Non-merged rows audited: 129; the 67 stale rows it found were reconciled into BOARD.md on 2026-10-08 (DOC-3), and rows since merged were removed from the tables below. Open now: Release 45 (6 marked unsure), Later 12.
No security-fix row (SR2-*) is classed Later. P2-1 (host image, PR #41) has no board row but blocks IMG-1, HOST-1a/1b/1c part 2 and W3-builder-ship.

## Release (needed for A1–A15 or an invariant)
| ID | Needed for | Note |
|---|---|---|
| S5 | A5, A13 | CRED-4 action protocol; live run blocked on network policy |
| S8-W1 | A14, CRED-5 | Blocks every worker-held route; credential invariant |
| S8-live | A3 (CAP-11) | Needs Mark's Claude and ChatGPT plans |
| S8-codex-terms | A3, CRED-5 (unsure) | Decides Codex custody; a Claude plan route may already satisfy A3 |
| S1 | A1 (G1) | Test kit ready; waits on Mark's hardware |
| S2 | A1, A3 | Modem SMS and voice; waits on Mark's modems |
| P2-4-hw | A8 | Real-TPM trusted-host run; risk 14 |
| P3-4b | A11 (unsure) | Loop 2 active testing; Mark deferred 10-05, A11 loop-2 part stays open |
| UPD-b | A1, A14 (UPD-3) (unsure) | Update before accounts connect |
| CH-20w | A15 (CH-20) | Evidence delivery through the vault-held mail adapter |
| CRED-4b | A5, A13 | Credentialed browser executor; sessions only in the vault process |
| ADP-8 | A13 (ADP-8) | Mislabelled-draft check blocks adoption |
| ADP-5 | A13 | Desktop executor and kiosk-escape test; blocked on CRED-4b |
| OSS-6s | A12 | Publication sender, idempotent by day and batch |
| OSS-6j | A12 (OSS-6, DEP-2) | L3 on #330: the pull job is repository automation, not a service |
| OSS-6i | A12 (OSS-6) | L3 on #330: rotation is void if batches share a circuit |
| OSS-6p | A12 (OSS-6) | L3 on #330: OSS-6 values the sender needs |
| OSS-6a | A12 (OSS-6, OSS-7) | L3 on #330: silence vs ask-each-time |
| OSS-5t | A12 (OSS-5) | L3 on #330: embargoed report over Tor or not |
| OSS-6e | A12, clean-room invariant | Security ruling on #180: floor holds across restarts |
| OSS-10w | A12 (unsure) | Follow-fork wiring; OSS-1–13 are in A12's requirements |
| IMG-1 | A1 | CI scan for per-owner secrets in the image; blocked on P2-1 |
| P2-2w | A1, A14 (ARC-2) | Local UI process; sub-rows a, b merged, c and d open |
| P2-2w c | A1, A14 | Setup into agentosd; Security L6, L7 MUST |
| P2-2w d | A1, A3, A14 | Turns LocalUI on; unblocks approvals and CH-20p |
| SR2-3g | A5, A6 (security) | No host path in agent-visible tool errors |
| SR2-3h | A5, A6 (security) | runsc messages never reach the guest |
| SR2-4i | A2 (RES-2) | Host image enables iocost; blocked on host image |
| CH-21 | A14 (CH-21) | Name, first-person voice, spoofed NAME refused |
| HOST-1a | A1 (HW-8) | Part 2 needs P2-1 image |
| HOST-1b | A1 (HW-8) | Part 2 needs P2-2w live page |
| HOST-1c | A1 (HW-8, ONB-7) | Part 2 needs P2-2 |
| HOST-1e | A1 | Host-untouched hash harness |
| PE7-bus | A11, A2 (unsure) | Condition on the events-bus package; floor host |
| PE7-call | A11, A2 (unsure) | Condition on the inbound-call package |
| W3 | A11 | Learning process; steps 3a, 3c open |
| W3-builder-ship | A11 | Builder defaults; P2-1 side queued |
| W3-forget | A14 (CAP-3) | Owner FORGET; split a, b |
| W3-forget-b | A14 (CAP-3) | Authenticated forget log over restores; Security C3 |
| W5 | A11, A15 | Owner channel for loops, digest, hint emitter |
| W5a-resume | A14 (security) | Per-grant resume needs a fresh bound code; Security R2 |
| W5b | A7, A11 | Loop 3 update checks as a scheduler source |
| W5c | A12 | Clean-room builder in the scheduler |
| W6 | A8 (REC-1–3) | Recovery into vault process and local UI |
| W7 | A10, A15 (CAP-4–6) | Compiled skills live; attention optimizer; blocked |

## Later (backlog; do not start before first release)
| ID | Why it can wait |
|---|---|
| P2-8b | Deferred re-encrypt after trusted-PC removal; slot removal already covers CRED-9 |
| P3-6d | Digest wording for deleted procedures; no A-test needs it |
| CH-20p | Page view of kept replies; A15 needs delivery, not this view |
| CH-20a | Attachments conflict with security C4; needs review; not in A15 |
| CH-20m | MORE command for redirected replies; convenience |
| P2-2a f1 | L3 SHOULD on page wording after a changed item |
| ADP-13 | Optional box mailbox; no A-test needs it |
| HOST-1d | Optional internal-disk opt-in (HW-8a); A1 requires disks untouched |
| PE3 | Potency follow-up on replay-interruption counting |
| W3-off-a | STATUS wording goes dynamic; polish |
| W3-implicit | Potency C2 outcome label; refinement of attention optimizer |
| W8 | Owner builds; no brief, no A-test names it |
| ADP-14-get | GET links with side effects reached by `navigate` on recipe sites; recipe gate covers state-changing methods first |
| ADP-14-undo-fail | A failed `UNDO` reply gives site, reference and deadline and opens a task; UNDO success path is enough for A13 |
| ADP-14-offer | After repeated approved submits on one unknown site, offer its private-derived draft for adoption; cuts approvals, not needed for A13 |
| ADP-14-cred6 | Recipes declare their site's CRED-6 screens, undeclared ones trigger ADP-7 repair; CRED-6 already applies without a recipe |
| ADP-14-origins | Which origins the credentialed context may reach on a site with no recipe; every state-changing request there is already held |
| ADP-16-acct2 | A second account signed in inside a suite executor's app; ADP-16 kiosk already limits to one account's adapters |
| OSS-6e f1 | Security 319-1 (L3 asked for this line; lands before #319 merges): a missing or unreadable `boot_id` fails open, so each restart can count one day of the 20h floor again |
| W3-forget-b2 f2 | L3 on #321: a self-cancelled job still calls propose/Build with a cancelled ctx |
| W3-forget-b2 f3 | L3 on #321: no mutation test covers the post-build disjunct |
| P2-2w d f4 | L3 N1 on #322: OSS-10 is missing from the REQ marker in `pagewording_test.go` |
| P2-2w c1 f4 | L3 L1 on #320: `ReEnroll` does not delete the `owner-totp-setup-open` vault entry |
| P2-2w c1 f5 | L3 L2 on #320: no test covers a setup-open entry of the wrong kind |
| SR2-3g f7 | L3 R1 on #324: the `guesterr` import sits in the stdlib import group in `question_test.go`; style only |
| OSS-10w f1 | UX on #323: the alert wording "Switch back there" reads oddly after a switch back to the project |
| W3-forget-b2b f1 | Security 327-1: race between `worked()` and `takeBack(approved=false)` in `agentBackWithoutAsking`; re-check under `r.run` |
| DOC-3 f1 | L3 on #356: the SHAs on rows inferred as merged name the last commit touching the package, not its merge; relabel as "last touched" or cite the PR |
| DOC-3 f2 | L3 on #356: D-041 (license) has date `Pending`, not ISO; set it when the license is chosen |
| DOC-2 f1 | L3 on #357: doclint does not check DECISIONS cells ≤300 characters or that `decisions/D-NNN.md` links resolve (D-056) |
| CRED-4b f1 | L3 on #300 (#9): the browser gate passes the raw `cfg.Origins` to the driver, not the canonical keys (`gate.go:99`) |
| CRED-4b f2 | L3 on #300 (re-review #7): `exec.CommandContext` kills only the driver's group leader on ctx cancel; set `cmd.Cancel` to kill the process group (`gate.go:100`) |
| CRED-4b f3 | L3 on #300 (re-review #6): no test isolates the Lstat and O_NOFOLLOW symlink layers |
| CRED-4b f4 | L3 on #300 (K6): images in output files are not inspected |
| CRED-4b f5 | L3 on #300 (1960aed re-review #3): the label rule misses `accessTOKEN:` and suffixed labels (`accessTokenValue:`, `access_token_value:`); add to K11's part-2 corpus |
| CRED-4b f6 | L3 on #300 (e000ecc re-review): keep both `myApiKey=<hex>` and `myApiKey: <hex>` in the part-2 corpus |
| CRED-4b f7 | L3 on #300 (f135e43 re-review): the label rule redacts prose such as `See the secret 2024-holiday-party-photos album`; fails closed, noted next to K12 |
| CRED-4b f8 | L3 on #300 (1960aed re-review #4): camelCase false positives (`hotKey 2024-10-08-release-notes`, `useToken 2024-…`, `?sortKey=created_at_2024_desc`); fail closed, part-2 negative corpus |
| CRED-4b f9 | L3 on #300 (e000ecc re-review): an initialism or capitalised word before a label word is redacted (`USBKey 2024-10-08-firmware-notes`, `PGPKey: 2024-…`, `MyKey: 2024-…`); fail closed, part-2 negative corpus |
| CRED-4b f10 | L3 on #300 (f135e43 re-review): the label rule's value charset misses passwords with other punctuation (`password: Abc123@xyz789#Qq`) |

## Reuse candidates
| ID | Component | Why |
|---|---|---|
| CRED-4b, S5 | Playwright (Chromium over CDP) | Drives pages inside the sandbox; the narrow action protocol wraps it |
| ADP-5 | cage (Wayland kiosk compositor) | Single-app kiosk with no shell or file manager; add file-dialog confinement |
| HOST-1d | cryptsetup / LUKS2 | Vault-keyed disk encryption without custom crypto |
| SR2-4i | systemd resource control (IOWeight=, CPUWeight=) | Sets io.weight and cpu.weight per slice; add iocost QoS on the image |
| UPD-b | systemd-sysupdate (S7 stack) | First-boot update-before-trust already fits the chosen image stack |
