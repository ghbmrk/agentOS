# S8-W1-contain: the pinned Codex CLI's tools under gVisor, holding only a placeholder

Board section: Release rows. Source: work item #1720. Tier A (vm, credentials, the provider worker's tool sandbox). Needs #807 (image), #1015 (placeholder login), #1014 (forwarder), #809 (the runsc measurement this narrows). Distinct from #1380's D-064 test, which is the Claude opt-in volume.

**Why.** CRED-5's broker-held mode rests on the Codex CLI's tool subprocesses being unable to reach what the CLI itself holds: the in-worker forwarder on 127.0.0.1:18432, the route socket `/run/agentos/route.sock`, and `CODEX_HOME` with its placeholder `auth.json`. `tests/test_codex_worker.py` checks this with bwrap on a plain Linux host. Nothing checked it in a gVisor machine from the built image, where bwrap runs nested inside runsc (guest/codex/ASSUMPTIONS.md C5, folded in here).

**Requirements:**
- CRED-5 broker-held: a tool cannot reach the forwarder, the route socket or the login file.
- CRED-1: no real value in a worker; the run holds a synthetic canary only, and the canary never appears in tool output.
- A14: the login file is not readable from a tool, so it cannot reach a guest-bound result.
- C5 (guest/codex/ASSUMPTIONS.md): the CLI's bwrap sandbox works inside gVisor: a tool runs in its own net and mount namespaces, with no_new_privs and a seccomp filter.

**Change.**
- `broker/e2e/codexprobe`: a static probe that tries each denied surface (TCP to the forwarder, connect to the route socket, read and list `CODEX_HOME`, writes to `/` and `CODEX_HOME`) and the allowed one (write to the workspace), and prints one JSON line of booleans plus its Seccomp, NoNewPrivs and namespace links. It never prints what it read.
- `broker/e2e/codex_contain_test.go`, `TestIntegrationCodexContainment`: copies the built rootfs, adds the probe, seeds a chatgpt-mode placeholder `auth.json` carrying a synthetic canary, and creates a `pw-` worker with the codex declaration. A scripted Responses endpoint on the route socket asks for one `exec` tool call running the probe. A control run of the probe beside the CLI (same env, no CLI) must reach every surface; the run through the CLI must reach none but the workspace, under seccomp mode 2 and no_new_privs, in namespaces other than the control's.
- A CI step in the machines job builds the rootfs and runs the test.

**Acceptance tests:** CRED-5, CRED-1, A14, C5: `TestIntegrationCodexContainment` (broker/e2e/codex_contain_test.go).

**Revert mutants (each must turn the test red).**
- Drop `--unshare-net` from the CLI's sandbox (the tool reaches the forwarder).
- Bind `CODEX_HOME` into the tool sandbox (the tool reads `auth.json`).
- Run the tool without the sandbox (namespaces equal the control's).

**Threats Security must check.**
- A tool reaching the forwarder over loopback, which would let it spend the plan login.
- A tool reaching `route.sock` directly.
- A tool reading or rewriting the placeholder `auth.json`.
- Failing closed being mistaken for containment: a tool that never runs proves nothing, so the test requires the probe line from a real tool run.

**Out of scope.** The forwarder itself (#1014), the vault entry (#1015), live qualification (#809), the Claude opt-in volume (#1380), `guest/codex/ASSUMPTIONS.md` (#1504).

**Scope:** `broker/e2e/codex_contain_test.go`, `broker/e2e/codexprobe/*`, `broker/e2e/ASSUMPTIONS.md`, `guest/codex/build-rootfs.sh` (header comment and any fix the test needs), `.github/workflows/ci.yml` (one machines step), this brief.

**Usage estimate:** 120k tokens. Builder model: Opus-class (tier A).
