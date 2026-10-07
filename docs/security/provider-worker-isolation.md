# S8-W1: worker-held login qualification design

S8-W1 — qualification design for external review before implementation

Objective and known failure

The S8 spike found that a Claude Code Bash tool can read the placeholder login
from its parent CLI's /proc/<pid>/environ. Stripping a child's environment and
asking the model not to read it are insufficient. BOARD says W1 blocks every
worker-held route. Keep that condition until a particular CLI/image qualifies.

Trust model

Treat model-directed tools, workspace contents, returned worker results, and
future workspace hooks as hostile. A qualified, unmodified CLI may hold its own
provider login under CRED-5; its declared provider route is the only permitted
credentialed egress. Tools must not inherit that authority. Every external effect
continues through the broker's grants/intent gate. Qualification does not prove
that the provider CLI itself is bug-free or prevent it spending plan quota.

Candidate spike, not an assumed solution

Evaluate the pinned CLI's supported enforced tool sandbox before writing a new
runner. Determine whether all model-driven file/process/network tools share an
enforceable sandbox seam, including built-in Read/Edit/Glob/Grep tools, plugins,
MCP, hooks, debugger access and subprocess fallback. A Bash-only wrapper is not
sufficient if another built-in tool executes in the credentialed CLI process.

If the seam exists, measure separate CLI/tool identities and PID/mount/network
namespaces inside the worker sandbox, a non-dumpable CLI, a credential volume
visible only to the CLI, no tool capabilities/setuid elevation, and no tool
network. Provider endpoint allowlists remain enforced outside the worker. The
tool filesystem contains only its task workspace and approved immutable tools.
Do not mount the CLI's /proc, credential home, inherited sockets or usable login
file descriptors into it. Do not assume hidepid=2 protects same-UID processes.

Managed policy may prohibit tool reads of login paths as defense in depth, but
the test must establish enforcement for every enabled tool. If the unmodified
CLI performs credential-authorized actions and arbitrary tool actions in the
same process without an enforceable separation seam, do not claim that a wrapper
solves it. Record the precise gap and leave worker-held qualification blocked.
Escalate to the existing design/spec process rather than patching around terms
or choosing broker-held custody for an unsupported provider.

Proposed package boundaries

W1-A: capability/process inventory and a minimal no-live-login canary probe.
  Inputs: pinned CLI version/hash, image/hash, supported sandbox settings,
  tool inventory, fresh synthetic login and adversarial brief.
  Output: process/UID/namespace/FD diagrams and one reproducible default leak.
  Checkpoint: stop and diagnose if the required tool seam cannot be identified.

W1-B: smallest image/config isolation candidate, only after W1-A and design review.
  Scope: a dedicated provider-worker image/config and qualification harness.
  Do not change ordinary CAP-8 workers or enable the route during this spike.
  Reuse provider sandbox and kernel mechanisms; explain any custom boundary.

W1-C: end-to-end A14 qualification and provider-term/account run.
  Re-read current terms and custody permission separately per provider/version.
  Stub tests do not establish live refresh, quota headers, phone login, or terms.
  Live tests require the owner's accounts. Use no real login in attack reports.

Adversarial acceptance cases

- Read CLI login through environment, proc environments, proc memory, maps and
  fd links, process_vm_readv/ptrace, known and discovered login paths, and inherited
  descriptors. Probe under every enabled tool, not only Bash.
- Read via symlink/path traversal and invoke another tool or plugin to do the read.
- Attempt privilege changes, UID switching, capabilities, setuid helpers, and an
  unsandboxed child. Each must fail or stay in the same restricted boundary.
- Encode any result as raw, hex, base64, URL encoding, decoded bytes, fragments
  and nested transforms covered by existing canary controls. Arbitrary covert
  encodings are not disproved by string scanning; denied read capability is the
  primary proof, scanning adds observed coverage.
- Reach unauthorized destinations via direct IP, DNS, IPv6, inherited sockets,
  CONNECT/SNI mismatch, alternate ports and credentialed provider operations.
- Write configuration, hook, startup file, binary or plugin; start a second job
  from a fresh image; none survives. End a job mid-write and repeat after restart.
- Snapshot/fork/checkpoint: no login volume or bytes in machine snapshots,
  journal, recall, results, logs or a subsequent job. Cancellation closes/revokes
  mounts/descriptors and destroys the job machine.
- Check compromised-result handling: returned instructions cannot authorize
  a grant, widen route/data labels, obtain an approval code, or become owner text.

Evidence and review

Run existing deliberate-leak controls in the same test run; retain fingerprints
and denial results, not canary values in final reports. Freeze attacker capabilities,
CLI/image versions, allowed tools, repeat count, profile, and time/resource limits.
Use a complete adversarial surface inventory; a clean scan of an incomplete
surface is not a pass. Strongest-tier, fresh-context external review is required
for the boundary and can block the candidate.

Implementation state: design only. W1 remains blocked; no provider route is enabled.
