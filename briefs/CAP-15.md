# CAP-15: Analysis workers

Board section: Backlog refill (rows CAP-15a and CAP-15b, next to CRED-12).

**Why.** Mark decided (2026-10-11, Ask anything thread, D-099): "Yes to all (seems only additive with no hit to security or UX); helpful also with owners software they have or buy or use to reconstruct it if necessary to be more useful." The toolkit is REA (github.com/morluto/rea, MIT, npm `rea-agents`), an MCP server for reverse engineering. The spec text is CAP-15 in SPEC.md §10, added by the spec-diff PR that carries this stub; this brief is a stub until a package starts.

**What to build (to be expanded).**
- CAP-15a: a worker image variant (CAP-8) with REA at a pinned version, installed at image build, never by `rea-agents setup` or `npx` at run time; Node from the image. Self-update, package fetches and telemetry off; the live website and network-capture modules off. The worker's network namespace has no egress route; refused connection attempts are journaled with destination and the target that made them. Qualification run (LOOP-11, CAP-11): run a new guest or provider-CLI version in the worker and report its connection attempts against its declaration (ADP-10) and its auto-update and telemetry settings. Crash-diagnosis run: a crash dump and the binary in, findings out as a LOOP-4 hypothesis. Ghidra (Apache-2.0) only when RES-2 admits its memory; no proprietary engines.
- CAP-15b: a suspicious mail attachment goes to a fresh `private` analysis worker that is discarded after the run; the verdict reaches the guest as untrusted content.

**Step 0 (before code).**
1. Measure REA's memory and disk cost and list which of its modules work with no network (README lists static JavaScript, ELF, .NET, HAR and others).
2. Confirm REA makes no network call of its own (telemetry, update check, model call) with egress closed; record any it attempts.

**Failure path to test first:** a target binary inside an analysis worker opens a TCP connection and a DNS query; both are refused, journaled, and appear in the qualification report (CAP-15, LOOP-11).

**Limits (Mark, 2026-10-11: "Use should be fine as long as no regulatory/legal issues otherwise arbitrary prohibition"):** legal, not categorical, per CAP-15. A clearly unlawful task is refused; an unclear one goes to the owner and waits for a yes; both are journaled. The build adds the refusal and ask paths and their journal entries; it does not try to encode the law.

**Off-gate.** Not release acceptance. If D-096's scope freeze merges, these rows start after G2.

**Scope:** to be set when the brief is expanded.
