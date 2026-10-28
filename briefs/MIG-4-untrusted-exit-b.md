# MIG-4-untrusted-exit-b: `provagent` out of `cmd/agentosd`, onto the model clerk's plan login

Work item #2780, part (b) (part (a) merged as #2812). Serial `cmd/agentosd` chain (D-111). Tier A. Written 2026-10-26 against main at cedfa22.

**What changed since (b) was parked.** Its blocker, the model clerk's plan login (#3104), merged in four PRs (#3105, #3128, #3147, #3174). `broker/clerk/plan` holds the login sealed and swaps placeholders (CLK-1, CLK-7); `broker/clerk/run` has the guest's endpoint (`ListenPlan`, `ServePlan`), the owner calls (`PlanHost`, `ServePlanOwner`, `PlanOwner`: `planbegin`, `planstate`, `planresume`, `planremove`) and the sign-in flow, which runs the CLI through `SignInWorkers`, an interface it leaves to "the guest host's (#2780(b))".

**Why one session can't do it.** Reading main turned up two gaps besides the agentosd rewire:
1. **Nothing implements `SignInWorkers`.** The sign-in CLI must run in a sandbox whose only route out is that sign-in guest's plan endpoint. The box's one sandbox host is agentosd's `vm.Manager` (gVisor, admission, disk caps), which provagent's runner uses today.
2. **No process hosts the model clerk.** Nothing outside `clerk/run` tests calls `ServePlanOwner`, `ServePlan` or `ServeModel`; there is no binary or unit for it on the image. Until one runs, a page that calls the clerk gets no answer, and the in-image run's guest task (`e2e/boxe2e` `planSignIn`, `providerTask`, run by `image.yml` on every `cmd/agentosd` change) fails.

Deleting provagent first would take "Use my plan" (SPEC §12.1 step 6, ONB-3) off the box and turn `image.yml` red. So the row goes in three slices, in this order.

## Slices

**(b1) MIG-4-untrusted-exit-b1: agentosd hosts the clerk's sign-in workers** (`cmd/agentosd` slot).
- `cmd/agentosd/signinhost.go` (+ test): agentosd serves the model clerk's process, on a socket admitting only `-plan-uid`, three calls: `signinstart {guest, route}`, `signinread {guest}` (printed so far, exited) and `signinstop {guest}`. `route` is the directory the clerk serves that guest's plan endpoint in (`ListenPlan`); agentosd checks it is a directory owned by `-plan-uid` and not group- or world-writable, and the machine's only mount out is it (`vm.Services` keyed by the machine's ID; every other ID falls through to the existing route source). The machine is a provider worker from the plan's image (`Private` label, 1024 MB, `admission.Accepted`), running the declared sign-in argv. One sign-in at a time per guest; a stop or the caller's end destroys the machine; agentosd's shutdown destroys every one.
- `broker/clerk/run/signinsock.go` (+ test): `SignInSock`, the clerk side's `SignInWorkers` over that wire. Its wire test serves agentosd's real handler on a fake host.
- The sign-in guest's image and argv: one table in agentosd (Codex: image `codex`, the argv measured on CLI 0.162.1, #809), copied from `provagent.Builtins`, not imported.
- Not in (b1): the clerk's process, the page rewire, any deletion.

**(b2a) MIG-4-untrusted-exit-b2a: agentosd makes each sign-in route** (`cmd/agentosd` slot; must merge before any unit sets `-signin-sock`). Closes #3248 Security 1 (issuecomment-6421854692): in b1 the clerk named its route, so between agentosd's check and the runtime's mount it could swap the route for a link to any host directory. Now a fourth call, `signinroute {guest}`, has agentosd make `-signin-routes/<guest>` (0700, `chown`ed to `-plan-uid`) in a directory only root or agentosd may write, and answer its path; `signinstart {guest}` mounts only that path, and stop removes it. `SignInSock` loses `Dir` and takes the route from `signinroute`. ASSUMPTIONS MIG-4-untrusted-exit-b1-2 is rewritten. Acceptance: `TestSignInRouteMustBeTheClerks` (CLK-1, PLN-6) as rewritten, and `TestSignInSockStartsOnTheGuestsRoute`.

**(b2b) MIG-4-untrusted-exit-b2b: the model clerk's process** (no `cmd/agentosd`). Its key hand-off merged as MAIL-keys (#3419: the kernel hands each `-clerk-key` clerk its key at every start of its unit). Two slices, since #3560 and #3478 hold `image/` files:
- **b2b-bin** (`broker/cmd/agentos-clerk-model`): opens the plan login's sealed slot, serves `ServePlanOwner` to agentosd's uid, and `PlanHost.Workers` is `SignInSock` on agentosd's socket. Acceptance tests in `main_test.go`: `TestARefusedClerkLeavesItsKeyUnread`, `TestTheKeyMustBeTheModelClerks`, `TestThePlanLoginIsSealedInTheClerksOwnSlot`, `TestPlanBeginRunsTheSignInOnAgentosdsSocket`, `TestTheModelProcessLinksNoMainSideCode`. A guest's model endpoint (`ServePlan` per guest), metering through the kernel's meter socket and `ServeModel` wait for the guest host that names a run's plan, price and window (ASSUMPTIONS MIG-4-untrusted-exit-b2b-3).
- **b2b-unit** (`image/`): its systemd unit (the `agentos-model` user already exists, `agentos-setup.conf`), ordered after the kernel, which gets `-clerk-key model=...`; it sets agentosd's `-signin-sock`, `-signin-routes` (on a tmpfs of its own, #3286) and `-plan-uid`; `ci_boot.sh` checks it listens.

**(b3) MIG-4-untrusted-exit-b3: rewire and delete** (`cmd/agentosd` slot; after b1, b2a and both b2b slices).
- `localsrv/accountsock`: `Plan`, the client of the clerk's plan owner socket (`planbegin`, `planstate`), implementing `localsrv.SignIn` (setup) and `localsrv.PlanSignIn` (Wi-Fi page); the wire is written out and pinned by a test that serves the real `ServePlanOwner`, as `Gmail` is. `-plan-owner` and `-plan-uid` flags, distinct-uid check as `pageAccounts`. `localsrv/setupsignin.go` loses its provagent wording.
- Delete from `cmd/agentosd`: `providerRunner`, `providerTool`, `planSeeder`, `setupsignin.go`, `pagesignin.go`, `imagepin.go`, `planusage.go`, `providerjournal.go`, the provider parts of `planwire.go`, and their tests (`planwire_test.go`, `providerwire_test.go`, `imagepin_test.go`, `pagesignin_test.go`, `providerjournal_test.go`, `setupsignin_test.go`). ONB-9's STATUS line reads `planstate.Stopped`. The worker tools lose `provider_run`.
- `e2e/boxe2e`: `planSignIn` signs in through the page as now, the CLI running in b1's worker and the login landing in the clerk; `providerTask` runs the task as a PLN-5 CLI guest whose endpoint is the clerk's (#2784's guest side, if merged), otherwise it is retired with an E-row naming the row that restores it.
- Done when: no package under `broker/cmd/agentosd` imports `provagent` (direct or test); `go vet ./...` and `go test ./cmd/agentosd/... ./localsrv/...` pass; `tools/trace.py --ratchet` passes; `image.yml` is green; the PR names the docs/migration/cases.md §6c cases it passes or retires.

## Requirements and acceptance tests (b1)

**Acceptance tests:** the four below in `broker/cmd/agentosd/signinhost_test.go` (`REQ: PLN-5, CLK-7, CLK-1, PLN-6`; ARC-2 and CAP-8 are retired, SPEC Appendix A), plus `TestSignInSockStartsOnTheGuestsRoute` in `broker/clerk/run/signinsock_test.go`. `TestSignInSockSpeaksTheHostsWire` lives in cmd/agentosd, not clerk/run: agentosd's handler is in a main package, which clerk/run cannot import (as accountsock's wire test does for the mail clerk).

- PLN-5, CLK-7: `TestSignInWorkerRunsTheCLIOnTheGuestsRoute` (the machine runs the declared argv, from the plan's image, with the given route as its only mount out; `signinread` returns what it printed and when it exits).
- CLK-1, PLN-6: `TestSignInHostAdmitsOnlyTheClerk` (another uid's call is refused before anything starts), `TestSignInRouteMustBeTheClerks` (a route not a directory, owned by another uid, or group- or world-writable starts nothing).
- PLN-6: `TestSignInStopDestroysTheMachine` (stop, the caller's end and shutdown each destroy it; a second start for a running guest is refused).
- `TestSignInSockSpeaksTheHostsWire` (clerk/run): `SignInSock` against agentosd's handler, and `PlanHost.Begin` through it reaches the code.

## Open point for review

The plan endpoint admits one uid (`ListenPlan(path, guestUID)`). A gVisor machine's socket connections are made by agentosd's sandbox host, so for guests agentosd hosts that uid is agentosd's machine host, not the guest's own. The guest is then named by the endpoint's directory, which only that machine mounts. Recommendation: accept this for v1.0, with an ASSUMPTIONS row in b1 and b2, since agentosd already hosts the guest and gets only placeholders through the endpoint; Security should confirm.
