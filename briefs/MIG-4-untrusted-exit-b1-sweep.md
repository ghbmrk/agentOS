# MIG-4-untrusted-exit-b1-sweep: sweep leftover sign-in machines after a crash

Board section: Migration to the capability kernel (D-139). Work item #3249, release finding 3 of L3 on #3248 (issuecomment-6421917505). SPEC CAP-8: a sign-in machine is destroyed on every path.

**The gap:** if agentosd crashes during a plan sign-in, `vm.Open` reloads the `pw-signin-*` provider worker as Stopped and nothing destroys it. The issue's second half (the clerk's route directories) is already closed on main: since #3282 agentosd makes every route in `-signin-routes` and empties it at start (`prepareSignInRoutes`); the clerk keeps none.

**Requirement IDs:**
- **CAP-8** (SPEC): once the machine manager opens, before `-signin-sock` is served and whether or not it is, agentosd destroys every machine whose ID starts with `signInPrefix`, and no other; a failed destroy is logged and does not stop the rest.

**Acceptance tests:** CAP-8: `TestSignInSweepDestroysLeftoverSignInMachines` (cmd/agentosd/signinhost_test.go).

**Scope:** `broker/cmd/agentosd/signinhost.go` (`signInMachines`, a new `Sweep`), `broker/cmd/agentosd/main.go` (the call after `vm.Open`), `signinhost_test.go`, `broker/cmd/agentosd/ASSUMPTIONS.md`. Nothing else.

**Gate:** tier A (`tools/risk_tier.py`); L3 on the strongest model. Estimate: under 40k tokens.
