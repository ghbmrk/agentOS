# P2-2w-c4e4-s2-private-config: setup's AI step shows a configured provider as fixed

Board section: Security and architecture review (2026-10-08). Source: Security S2 on PR #1588. Row #1608, class release, tier A. Not the same row as `P2-2w-c4e4-s2` (vault notices by text).

**Why it matters.** The vault's providers list (`broker/cmd/agentos-egress/providers.go`) carries `private_by_config`, and the providers page shows a configured provider as fixed: it hides the withdraw control and says "My configuration allows it, so it can't be withdrawn here" (`broker/localui/pages.go`, `PrivateByConfig`). Setup's AI step does not: `localapi.SetupProvider` and `localui.Provider` have no such field, so setup shows an untickable-in-effect box. An owner who unticks "may see private content" for a provider the configuration allows is told nothing, the vault keeps the allow (the withdraw returns `errPrivateByConfig`), and the page, the owner's belief and the vault disagree about CAP-9 consent.

**Requirements:** CAP-9 (the owner's answer about private content is what holds, or the page says it is not theirs to change), OWN-7.

**Fix.** Setup's list (`GET /setup/providers` in the vault, `privatechange.go`) reports the owner's marker only (D-115; `TestSetupsListIgnoresThePrivateFlag`, `privatechange_test.go:238`). Add a separate `private_by_config` signal there, leaving `private_ok` as the marker (Security S1 on #1588), and carry it through the hops setup uses: vault setup list → `agentosd` `enroller.Providers` (`broker/cmd/agentosd/setup.go`, built as `localapi.SetupProvider`) → `localapi.SetupProvider` → `localui.Provider` (`AgentosdSetup.Providers`, `setuphooks.go`). On the AI step (`setup.go` `boxLocked`, `pages.go` `private` template) a provider with the flag shows the box ticked and fixed (disabled, with the providers page's wording) and `aiPrivate` ignores a posted unticked value for it.

**Acceptance tests:** CAP-9, OWN-7:
- `TestSetupsListIgnoresThePrivateFlag` flipped (`broker/cmd/agentos-egress/privatechange_test.go`): with `-private-ok anthropic`, `GET /setup/providers` returns `private_by_config=true` for anthropic while `private_ok` stays the marker.
- `TestSetupProvidersCarryPrivateByConfig` (`broker/cmd/agentosd/`): the vault's flag reaches `localapi.SetupProvider`.
- `TestSetupAIStepShowsConfiguredProviderFixed` (`broker/localui/`): the box is checked and disabled with the fixed wording; a forged unticked post is not recorded as a withdraw.
- Control: the unflagged path (D-115: ticked on a plan sign-in, unticked on an API key) is unchanged; existing `localui`, `localapi` and `agentosd` setup tests stay green.

**Tests first.** The two tests above fail on main (no field). Add the field, then the template change.

**Out of scope.** The providers page (already handles the flag), the vault's withdraw rule, vault-notice texts (`P2-2w-c4e4-s2`).

**Guard files:** none.

**Scope:** `broker/cmd/agentos-egress/providers.go`, `privatechange.go` and `privatechange_test.go`, `broker/modelroute/providers.go` only if the shared struct needs the field, `broker/cmd/agentos-egress/ASSUMPTIONS.md`, `broker/localapi/setup.go`, `broker/cmd/agentosd/setup.go` and its test, `broker/localui/setup.go`, `setuphooks.go`, `pages.go` and tests, this brief.

**Dependencies:** none; check D-111 overlap with open PRs on `broker/localui/setup*` at start.

**Usage estimate:** 70k tokens, checkpoint at 70k. Builder model: strongest (tier A: `broker/localapi/setup.go`).
