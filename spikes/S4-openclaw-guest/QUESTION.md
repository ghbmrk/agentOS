# S4: OpenClaw unmodified as a guest

**Question (BOARD S4, PLAN.md §3):** Does OpenClaw run unmodified as a guest using only broker tools?

**Kill/pivot rule:** insufficient interface → record the exact seam; a minimal patch is allowed (SPEC ARC-3: a fork needs a recorded "interface X insufficient because Y").

**Pinned subject:** `openclaw@2026.9.8` from npm, built from openclaw/openclaw commit `fc23bc864e4553c2d215e479eeec47b67a0bf943` (tag `v2026.9.8`, 2026-10-02). Node 24.21.0.

**Method:**
1. Inventory every way OpenClaw acts on the world (tools, plugins, skills, MCP, subprocesses, browser, direct network clients, self-update, self-modification) from the pinned source.
2. Run OpenClaw with **no network** except one stub broker endpoint on loopback (`unshare -n`), configured only through its own config file (no source changes). The stub provides:
   - model access: an OpenAI-compatible endpoint that accepts only a placeholder key (stands in for the broker's egress key injection, CRED-5) and answers with a scripted model;
   - one broker tool, `effect_request`, over MCP (stands in for the journaled intent API, spec §9).
3. Drive agent turns that (a) reach the broker tool and (b) use `exec` inside the guest; record every outbound `connect()` with strace.

**Time box:** one working session; ~3% of the weekly allowance.

**Out of scope here:** the real broker, the real sandbox (S3), credentialed browsers (S5), consumer CLIs (S6).
