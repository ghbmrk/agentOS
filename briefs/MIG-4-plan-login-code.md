# MIG-4-plan-login-code: no sign-in secret reaches the guest

Work item #3111 (from the #3105 Security review, finding 3; D-250 Security read #4486 batch 3). Tier A.

**Defect.** In `broker/clerk/plan`, the Codex device steps' answers reach the sign-in guest whole: `usercode` carries the `device_auth_id` that polls for the code, and `devicetoken` carries the authorization code and PKCE verifier. Each is reusable authentication material in I/O a guest reads, which CLK-1 forbids.

**Fix.** The clerk keeps the secrets and gives the guest placeholders, as it does for tokens. A device step declares its answer's secret keys (`Secret`); each is swapped for a fresh placeholder of that sign-in guest, held in memory. A sign-in step declares the request keys that must carry one (`Takes`), refuses a request without that guest's own placeholder for that secret before anything is sent, and sends the real value. A code exchange must take its code and verifier, so the clerk redeems only a code it was given itself. A secret-declaring step passes an error answer's status only, and drops an answer that lacks a secret or repeats one elsewhere (`plan-secret`).

**Requirement IDs:** CLK-1, CLK-7.

**Scope:** `broker/clerk/plan/` (`plan.go`, tests, `ASSUMPTIONS.md`), the sign-in test helpers in `broker/clerk/run/plan_test.go` and `plansignin_test.go` (they now run the device steps), this brief.

**Guard files:** none (no package added; `broker/clerk/plan` is outside the trusted core).

**Acceptance tests:** all in `broker/clerk/plan/secret_test.go`:
- `TestPlanSignInSecretsNeverReachTheGuest` (CLK-1): no answer the guest gets holds the device id, code or verifier; the provider gets the real ones; a replayed exchange is refused. Fails if a secret passes through.
- `TestPlanSignInTakesOnlyTheGuestsOwnPlaceholders` (CLK-1, CLK-7): a real or made-up value, another guest's placeholder, swapped keys, or a forgotten guest's placeholder is refused with nothing sent.
- `TestPlanSignInDropsAnAnswerThatWouldLeakASecret` (CLK-1): a pending poll passes its status only; an answer missing a secret, not JSON, or echoing one in another key or a header is dropped.
- `TestPlanDeclarationKeepsSignInSecrets` (CLK-1): `New` refuses a code exchange that does not take its code and verifier, and a secret or take on the wrong step.
