# S8-W1: current tool-seam feasibility

W1-A inventory result

The complete enforced seam has not been demonstrated. Worker-held routes remain
blocked. This is a concrete feasibility result, not a recommendation to treat a
Bash-only sandbox or an instruction classifier as sufficient.

S8 pins Claude Code 2.1.289 and Codex 0.160.1. The locally available Codex is
0.159.0-alpha.3; Claude is unavailable. The local Codex help describes its sandbox
as a policy for model-generated shell commands, which does not establish the
identity/policy for every built-in file tool, plugin, MCP, hook or server-side tool.
No login/configuration files were read and no real-account model runs were made.
The current environment contains bubblewrap, but its presence does not qualify
these pinned CLIs or establish an enforced tool boundary inside gVisor.

provider-worker-surfaces.csv records every surface class that must be accounted
for; enabled tool names and process identities still need observation from each
pinned provider/image. It is a qualification checklist, not a claim that the
inventory of any live CLI is complete. Reuse S8's synthetic backends in an isolated
empty fixture home when running the next probe; never inherit the development
session's configured account, plugins or memory.

Strongest external reviewer decisions: Is the proposed separation seam supported
by each unmodified CLI? Does image-fixed policy cover its in-process file tools?
Which enabled surfaces still share credential authority? If any remain unbounded,
reject W1-B for that CLI and retain API/broker-held qualified alternatives where
supported. Browser consumer routes under the supplied premise have their own
broker-owned executor custody; they do not inherit this worker-held exception.
