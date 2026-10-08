# SR2-3j: Effect denial reasons reach the guest only as fixed text

Board section: Backlog refill (2026-10-05).

Effect denial reasons reach the guest only as fixed text (security finding 3, L3 on #324): `guest/mcp.go` `state()` returns `Permission.Reason`, which is a policy error's raw `Error()` (`journal/engine.go`, e.g. `grants/gate.go` attempts read), redacted and clipped but unfiltered. Map policy errors to fixed reasons at the gate (or allowlist them as Safe), with a ref and broker-log line otherwise, and add a canary policy to the SR2-3g integration test. Also (release finding 362-2, Security on #362): `gvisor.Exec`'s error names the exec log's host path and is safe only while workers refs it; return a pathless `vm` sentinel that workers maps to fixed text ("command did not start" versus "runtime failed after the command started, it may have run"), which also covers Potency's finding on #362

**Needs:** SR2-3g

**Gate:** security check
