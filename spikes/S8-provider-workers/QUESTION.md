# S8: provider agents as workers

**Question.** Can the box spend an owner's AI subscription plans (Claude Pro/Max, ChatGPT Plus/Pro) before metered API keys, by running each provider's own agent CLI (Claude Code, Codex CLI) headless as a worker, within provider terms and without weakening custody?

Four mechanics (coordinator brief, 2026-10-05, from Mark's ask in the "Ask anything" thread):
1. Can Claude Code and Codex CLI run headless inside a worker machine with their tools on?
2. Can the login token be held by the broker and injected at egress, with only a placeholder in the sandbox (CRED-1)?
3. How does each CLI report quota and rate-limit windows?
4. How would the broker cap a run?

**Constraint.** Stay inside provider terms. No circumvention: the official, unmodified CLI is the only client that touches a plan's credential.

**Kill/pivot rule.** If a CLI cannot run headless with tools on, or a plan's credential cannot be kept away from model-directed code in any terms-compatible way, that provider stays API-key only (today's CRED-5 fallback).

**Time box.** Cloud part: one session, stubs only (no account). Live part: one session with Mark's accounts, listed in RESULT.md.
