# ARC3-guest-cloud-off: a CLI guest's config switches off provider cloud and remote features

Board section: Harness and operating model. Work item: #2417. Follow-up of ARC-3 (PR #2416); combined review of #2416, fix-list item 5e. **Tier A** (guest custody and egress).

**Why.** A broker-held CLI guest (Codex, Grok, Muse) holds a placeholder and the broker injects the credential into declared endpoints only. Nothing makes the guest's config turn off the provider's cloud tasks, remote or hosted execution, telemetry, history or sync, as CRED-5 W4 does for worker-held mode. Failure path: the guest starts a cloud task or syncs a session; data leaves outside ARC-6's interface and the injected credential serves more than model calls.

**Prerequisite (not this package).** The ARC-3 / ARC-6(a) sentence ("a CLI guest's declaration switches off provider cloud and remote features; a feature with no known off switch is `[Open]` and its endpoints are refused at egress") is a SPEC.md change, so it goes through an L1 spec-diff PR first (CLAUDE.md). The builder starts after it merges, or cites the Mark message it transcribes.

**Requirements:**
- ARC3-C1: each CLI guest's managed config switches off every cloud, remote and telemetry feature it has a known switch for; the switches are listed per CLI in that guest's `ASSUMPTIONS.md`.
- ARC3-C2: a feature with no known switch is marked `[Open]` there, and its endpoints are absent from the declaration's `Endpoints`, so egress refuses them and injects nothing.
- ARC3-C3: a declaration for a CLI guest that carries no cloud-off list fails `Validate` (qualifying a guest requires the list).
- ARC3-C4: model-endpoint calls still work with the credential injected.

**Change.** `broker/provagent/declare.go`: a `CloudOff` list in `Declaration` (config keys or flags), checked by `Validate` for CLI guests; `Builtins()` codex sets it from `guest/codex/managed_config.toml` (web_search, update check, notify already pinned; add the remaining keys the review names). Grok and Muse declarations get the same field when their rows land (ARC-3 order, #2423). Egress allow-list: only declared model endpoints.

**Acceptance tests:** (REQ: ARC3-C1..C4)
- `broker/provagent/declare_test.go::TestCLIGuestDeclarationNeedsCloudOff` (C3; mutant: skip the check).
- `tests/test_codex_worker.py::test_managed_config_turns_off_cloud_features` (C1; pins every listed key; mutant: drop one key).
- `broker/egress/...::TestCLIGuestCloudEndpointRefusedNoCredential` with a stub provider (C2; mutant: add a cloud endpoint to `Endpoints`).
- `broker/egress/...::TestCLIGuestModelEndpointStillInjected` (C4).

**Mutants:** drop a pinned key; allow a cloud endpoint; skip `Validate`'s list check. Each fails a named test.

**Out of scope.** Grok and Muse guest rows (#2423 order); worker-held mode (CRED-5 W4 stays as is).

**Scope:** `broker/provagent/declare.go`, `declare_test.go`, `broker/provagent/ASSUMPTIONS.md`, `guest/codex/managed_config.toml`, `guest/codex/ASSUMPTIONS.md`, `tests/test_codex_worker.py`, the egress test file the builder names in the PR, this brief.

**Usage estimate:** 80k tokens; checkpoint at 60k.
