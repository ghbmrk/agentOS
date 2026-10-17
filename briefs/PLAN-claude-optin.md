# PLAN-claude-optin: Claude plan route as an owner opt-in (worker-held, user-driven)

Board row: work item #1380. Tier A for every build package. Needs: #1314 (merged); PR #2063 (the #1720 bwrap patch) for C3. This brief carries Mark's decisions of 2026-10-17 (00:34:46Z: "Claude should be an opt in worker that navigates the tos. It should not weaken the rest of the system"; 00:43:27Z: "No need for per task quota as already lots of quotas in sub. No reminder text - user effort. Otherwise implement A to D") and replaces the four open points of the earlier draft. It builds nothing itself; it splits the row into one L1 SPEC diff and five build packages.

**Requirements:** CRED-5 owner opt-in and worker-held W1-W9, CRED-1, CRED-7, CRED-8, CAP-9, CAP-11, ONB-3, CH-11, A14. Failure path: an opt-in owner has their Claude credential read or served by agentOS code, or the route weakens the rest of the system (D-114).

## Decisions

- **P1 Login volume opaque.** agentOS never reads it; it is encrypted at rest under a vault key (CRED-8); the volume holds the pasted token as one sealed file the launcher pipes to the CLI, plus what the CLI writes there (C1 evidence: on this path the CLI writes no credential). W2's schema check is dropped for Claude.
- **P2 The login is `claude setup-token`** (inference-only scope, CRED-5 W3).
- **P3 No preinstall.** Claude Code installs after opt-in, only at the version and hash in the signed release metadata. A version is adopted only after it has been public two weeks.
- **P4 No relay of sign-in codes.** The owner runs `setup-token` on their own device and pastes the token into the worker's sealed sign-in. If the pinned CLI cannot take a token that way, the route does not ship; this path is untested, so it is the first check of C1.
- **A** owner-initiated tasks only (no loop, schedule or inbound trigger starts a Claude run). **B** Claude Code's tool sandbox denies reads of its credential file (needs #1720, PR #2063). **C** a "CLAUDE OFF" text pauses the route and replies with the claude.ai revoke link. **D** tasks that read web pages or inbound mail never route to Claude.
- **Also:** the A14 canary every release; a scan of Claude results for the token pattern, run without reading the real token; a confirmed opt-in step to turn off "Help improve Claude", with its link; terms re-read each release; the #819 pause; API fallback (CAP-9).
- **Not built:** a per-task quota cap; a rotation reminder text.

## SPEC diff (L1, Mark approves) — package PLAN-claude-optin-spec

Needed, because current SPEC text says otherwise or is silent:
1. **CRED-5 worker-held W2:** the schema check at every mount does not apply to the Claude opt-in (volume opaque, encrypted under a vault key, CRED-8). CRED-8 gains the sentence that a provider login volume is encrypted under a vault key.
2. **CRED-5 owner opt-in:** "the owner runs Claude's own sign-in flow ... agentOS code never reads, copies or serves" conflicts with a paste into a page. State that the owner pastes a `setup-token` into the worker's sealed sign-in, which the worker launcher hands to the CLI through a pipe on `CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR` (the CLI has no login command that takes a token; C1 evidence below), never logging, parsing or serving it, and that a CLI that cannot take it so means no route.
3. **CAP-11 versions:** "versions change only through image updates" gains the exception: Claude Code installs after opt-in at the version and hash in signed release metadata, adopted two weeks after publication.
4. **CH-11:** `CLAUDE OFF` joins the closed control words (pause, with the revoke link in the reply).
5. **CAP-9 routing:** a Claude run starts only from an owner-initiated task; a task that reads web pages or inbound mail never routes to Claude.
6. **ONB-3 opt-in:** a confirmed step to turn off "Help improve Claude", with its link.
7. **A14:** the canary runs on every release that bumps the pinned Claude Code version.
Scope: `SPEC.md`, `briefs/PLAN-claude-optin.md`. **Acceptance tests:** none: SPEC text only; `tools/doclint.py` and the spec-diff review by Mark. **Guard files:** none. 20k tokens.

## Build packages (each needs the SPEC diff merged first; order C1 to C5)

**C1 PLAN-claude-optin-1: first check, opt-in record and page.** First, a supervised check (a spike under `spikes/`, no production code) that the pinned CLI accepts a pasted `setup-token` in a headless worker; if not, stop and tell the coordinator, the route does not ship. Then the opt-in record (journaled, revocable), the warning page, the "Help improve Claude" confirmation step. Scope: `broker/localui/claude_optin.go` (new), `broker/localui/claude_optin_test.go` (new), `broker/localui/ASSUMPTIONS.md`, `broker/provagent/declare.go`, `broker/provagent/declare_test.go`, `spikes/claude-setup-token/` (new). **Acceptance tests:** CRED-5: `TestClaudeRefusesWithoutOptIn`, `TestOptInRevokeRefuses`; ONB-3: `TestOptInRequiresHelpImproveStep` (fails if the step is skippable); `TestWarningQuotesClausesAndLink`. **Guard files:** `broker/provagent/declare.go` is tier A through `broker/core/core.txt`. 90k.

**C1 first check: evidence (2026-10-17). Verdict: GO, with the mechanism changed.** Script: `spikes/claude-setup-token/run.sh` (synthetic canary `sk-ant-oat01-PLACEHOLDER-S8`, all egress to a local stub; no real credential used).
- **CLI:** 2.1.288, the newest release public 14 days on 2026-10-17 (published 2026-10-02T18:30Z); linux-x64 binary sha256 `0298068b686e7fdbaf9402a7a587bb7f49c0b0e084de09f69145a0719207640c`.
- **Docs** (code.claude.com/docs/en/authentication, read 2026-10-17): `claude setup-token` runs the browser flow on the owner's device, prints a one-year OAuth token and "does not save the token anywhere"; it is consumed as `CLAUDE_CODE_OAUTH_TOKEN`; it "can only make model requests" (no Remote Control, no claude.ai connectors); needs Pro, Max, Team or Enterprise; `--bare` does not read it. No refresh: re-paste yearly or after revoke.
- **No login command takes a token.** `claude auth login` has only `--claudeai`, `--console`, `--email`, `--sso`; `setup-token` has no options; nothing reads a token from stdin or an argument. The binary reads `CLAUDE_CODE_OAUTH_TOKEN` or `CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR` (reads the fd to newline, then deletes the variable). With neither set it falls back to the fixed path `/home/claude/.claude/remote/.oauth_token`, and writes the token there only when `CLAUDE_CODE_REMOTE` is set (from strings; the no-credential case could not be isolated in this test container, which has its own file at that path).
- **Measured** (fresh HOME, `-p` with a Bash tool turn, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`):

| Case | Model calls | Bearer sent | Exit | Token in HOME | Token in the CLI's `/proc` |
|---|---|---|---|---|---|
| env var | 2 | canary | 0 | no | `environ` |
| fd 3 from a file | 2 | canary | 0 | no | `fd/3` (file stays open) |
| fd 3 from a pipe | 1 | canary | — | no | nowhere |
| `--bare` + env var | 0 | — | 1 | no | — |
| stub answers 401 | 2 | canary | 1, "Failed to authenticate. API Error: 401 …" | no | — |

- **Disk writes in HOME, every case:** `.claude.json`, `.claude/backups/.claude.json.backup.*`, and the session transcript `.claude/projects/<cwd>/<session>.jsonl`. None held the token.
- **Mechanism for C3:** the sealed sign-in stores the pasted token as one file on the encrypted login volume; the launcher pipes it to the CLI on fd 3 with `CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR=3` and closes its end. Never the env var (readable in `/proc/<pid>/environ`), never an fd onto the file. Keep `CLAUDE_CODE_REMOTE` unset and never mount `/home/claude/.claude/remote/`. The tool sandbox must still deny the token file and the CLI's `/proc/<pid>/` (same-uid memory reads stay possible), and the transcript directory must stay off the login volume and out of the journal.
- **SPEC impact:** item 2 of the SPEC diff above is corrected to the pipe (it named a login command that does not exist); P1 now says the volume also holds the pasted token. Not verified without a real token: acceptance by the real API, the real expired-token message, and an org-restricted account.

**C2 PLAN-claude-optin-2: install after opt-in.** Install at the signed release metadata's version and hash only; refuse a version public under 14 days; no install before opt-in. Scope: `broker/update/claude_install.go` (new), `broker/update/claude_install_test.go` (new), `broker/update/ASSUMPTIONS.md`. **Acceptance tests:** CAP-11: `TestClaudeNoInstallBeforeOptIn`, `TestClaudeInstallRefusesWrongHash`, `TestClaudeInstallRefusesVersionUnderTwoWeeks`. **Guard files:** none expected; name any in the PR. 70k.

**C3 PLAN-claude-optin-3: worker-held login and containment.** Encrypted opaque login volume (CRED-8), sealed sign-in paste with the token never stored, logged or read by agentOS; tunnel per `briefs/S8-W1-tunnel.md`; no memory checkpoint; hidden from all 13 worker tools; tool sandbox denies the credential file (B, needs PR #2063); managed policy turns provider-side fetch tools off. Scope: `broker/vm/claude_login.go` (new), `broker/vm/claude_login_test.go` (new), `broker/workers/` (hide test per tool), `broker/vault/loginvolume.go` (new), `broker/vault/loginvolume_test.go` (new), `broker/vm/ASSUMPTIONS.md`. **Acceptance tests:** CRED-1/5: `TestPastedTokenNeverInJournalOrLogs` (canary token), `TestLoginVolumeEncryptedAtRest`, `TestToolSandboxCannotReadLogin` (stub), `TestEachWorkerToolRefusesClaudeWorker` (13 subtests); CRED-8: `TestVolumeKeyWrappedUnderVault`. **Guard files:** `broker/vm/`, `broker/vault/` are tier A; check `broker/daemon/arc2_test.go` and `tools/g1_scope.txt` for new files. 130k, may split volume and sign-in.

**C4 PLAN-claude-optin-4: routing policy.** A (owner-initiated only), D (web or inbound-mail tasks never routed), C (`CLAUDE OFF` pauses and replies with the claude.ai revoke link), the #819 pause, API fallback, and the CRED-7 scan of Claude results for the token pattern without reading the real token. Scope: `broker/modelroute/claude_policy.go` (new), `broker/modelroute/claude_policy_test.go` (new), `broker/control/` (word handler and test), `broker/provagent/gate.go`, `broker/provagent/gate_test.go`. **Acceptance tests:** CAP-9: `TestLoopTaskNeverRoutesToClaude`, `TestWebReadingTaskNeverRoutesToClaude`, `TestMailReadingTaskNeverRoutesToClaude`, `TestPauseFallsBackToAPI`; CH-11: `TestClaudeOffPausesAndRepliesWithRevokeLink`; CRED-7: `TestResultWithTokenPatternWithheld`. **Guard files:** `broker/control/` core list; confirm. 90k.

**C5 PLAN-claude-optin-5: per-release canary and terms re-read.** The A14 canary (adversarial brief, canary login surfaces nowhere) on every release that bumps the pinned version; the terms re-read gate that checks each quoted clause against the page at each release. Scope: `broker/provagent/claude_release.go` (new), `broker/provagent/claude_release_test.go` (new), `tools/` release check (name it in the PR). **Acceptance tests:** A14: `TestCanaryRunsOnVersionBump`, `TestReleaseBlockedWithoutCanaryPass`; CRED-5: `TestReleaseBlockedWhenQuotedClauseChanged`. **Guard files:** `tools/risk_tier.py` and `tools/ci_scope*` are Mark-only merges if touched; avoid. 70k.

**Conflicts (D-111) at 2026-10-17 00:43Z.** C1 and C4 edit `broker/provagent` (held by #2015, and by PLAN-grok and PLAN-muse in `declare.go`). C3 depends on PR #2063. Build order by that: after #2015 and PLAN-grok.

**Acceptance tests:** none: the brief builds nothing; each package above names its own, and each gets its own brief file when it starts.
**Scope:** `briefs/PLAN-claude-optin.md`, `spikes/claude-setup-token/` (C1 first check). **Guard files:** none.
**Usage estimate:** brief only. Builders: strongest model, two reviews each.
