# S8-codex-terms: OpenAI Codex custody decision

**Decision: broker-held custody (CRED-5 mode B) is allowed for Codex.**

Read 2026-10-07 from OpenAI's published Codex authentication documentation
([Authentication – Codex](https://developers.openai.com/codex/auth)), not from
third-party summaries. This closes the "OpenAI unverified" row in
[S8 RESULT §2](../S8-provider-workers/RESULT.md).

## What the docs say (verbatim sense)

1. **Proxy is an intended path.** Custom model providers may set
   `requires_openai_auth = true` so Codex "use[s] OpenAI authentication …
   when you access OpenAI models through an LLM proxy server." The broker's
   egress injection shape is that proxy: the worker holds placeholders; the
   broker speaks upstream with the real login.

2. **Access tokens for trusted private runners.** ChatGPT Enterprise
   "Codex access tokens" are "intended for trusted scripts, schedulers, and
   private CI runners" when automation needs ChatGPT-managed Codex
   entitlements without a browser sign-in. A single-owner AgentOS box is
   that class of runner, not a multi-tenant proxy farm.

3. **Local credential custody.** Cached login lives in `~/.codex/auth.json`
   or the OS keyring; the docs say to treat the file "like a password" and
   not to commit, paste, or share it. Headless setup by copying `auth.json`
   onto a private machine or container is documented as a fallback. That is
   worker-held custody (mode W), also allowed.

4. **API keys remain the automation default.** The same page recommends API
   keys for general CI/CD. AgentOS can offer an API-key grant as the
   CRED-5-clean path; ChatGPT-plan Codex stays available under (1)–(2).

## What the docs do not say

- No ban on a private host holding ChatGPT session tokens for the owner's
  own Codex CLI (contrast Anthropic's Claude Code page, which forbids
  collecting, storing, or intermediating Claude.ai credentials).
- No ban on TLS-terminating refresh through a private proxy when
  `CODEX_CA_CERTIFICATE` is set (the docs describe that CA hook for
  corporate TLS proxies).

## Consequence for CRED-5 / S8

| Mode | Codex | Claude |
|---|---|---|
| Broker-held (B) | **Allowed** (proxy + access-token language) | Ruled out (Anthropic terms) |
| Worker-held (W) | Allowed (`auth.json` / keyring on the worker) | Required |

S8-live should still confirm refresh-through-broker with a real ChatGPT
plan and that side calls (`wham/*`, analytics) stay denied at egress
(ADP-10). This package is terms-only; it changes no runtime code.

## Trace

| REQ ID | Evidence |
|---|---|
| CRED-5 | this RESULT (custody split) |
| S8-codex-terms | this RESULT |
