# PLAN-claude-optin: Claude plan route as an owner opt-in (worker-held, user-driven)

Board row: work item #1380. Tier A (vm, egress, credentials, localui). Needs: #1314 (merged). **Not buildable as written:** four design points are open and this brief settles what it can and names what Mark must decide before code (D-114).

**Requirements:** CRED-5 owner opt-in and worker-held W1-W9, CAP-11, A14. Failure path: an owner who opts in has their Claude credential read or served by agentOS code, against D-114.

**State.** The built-in `claude` declaration exists (worker-held, verdict `unclear`, refuses `opt-in-required`). Missing: the opt-in record and warning on the Wi-Fi page, install-after-opt-in, the sign-in path, and the containment test.

**Open points (a decision for Mark on each; recommendation first).**
1. **W2 versus "never reads".** Recommend: W2's schema check is dropped for Claude and the login volume is opaque to agentOS; CRED-8 at rest is satisfied by a block-device volume encrypted under a vault key (agentOS holds the key, never opens the file). Cost: no schema defence against a worker writing a hostile file to the volume.
2. **W3 `setup-token`.** Recommend: rule out `claude setup-token`; the route needs the interactive sign-in the CLI keeps itself. If the pinned CLI cannot give an inference-scoped login that way, W3 rules the route out and the row closes without code.
3. **Install after opt-in versus "versions change only through image updates".** Recommend: opt-in triggers an image update to a release-qualified image that already contains Claude Code, disabled until opt-in; nothing is installed at run time.
4. **Sign-in relay.** Recommend: build only if the pinned CLI's sign-in needs no pasted artifact; otherwise the Wi-Fi page relays a code and the "intermediate credentials or session tokens" clause is in the warning text. A finding for #809 to measure.

**Proposed change once decided (split into C1 to C3, each its own PR).** C1: opt-in record and warning page (localui, journal of the opt-in, revocable). C2: image with Claude Code at the qualified version, login volume per provider, the CONNECT-only tunnel with SNI binding (`briefs/S8-W1-tunnel.md`), no memory checkpoint and hidden from all 13 worker tools. C3: the sign-in path and W1 containment test supervised by Mark (D-064).

**Acceptance tests:** none: no code is built from this brief. Each of C1 to C3 gets its own brief, with its tests named, once points 1 to 4 are decided. (`tools/doclint.py` accepts `none: <why>`.)

**Scope:** `briefs/PLAN-claude-optin.md` only. **Guard files:** none.

**Usage estimate:** brief only (small). C1 to C3: 100k each, tier A, strongest model, two reviews.
