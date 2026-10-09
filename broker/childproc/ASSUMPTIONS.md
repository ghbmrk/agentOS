# childproc: assumptions

What `childproc` rests on (P3-4b-3r-env-r8a; OPERATING §5).

| ID | Assumption | Source | Held by |
|---|---|---|---|
| CP-1 | Linux, and the stdlib `os/exec` semantics `childproc` wraps: a non-nil `exec.Cmd.Env` is the child's whole environment, and `Cancel` and `WaitDelay` behave as documented for Go 1.25 and later. | Go `os/exec` docs | `TestTheChildSeesExactlyTheBuiltEnvironment`, `TestAnEmptyEnvIsEmpty` |
| CP-2 | No code outside `childproc` reaches `os/exec` or names a launcher selector in the non-test graph, apart from the gate's `exempt` map. The gate's graph is the union of `CGO_ENABLED=0` (how shipped binaries are built) and `CGO_ENABLED=1` (CI's race tests). Test files are outside the gate because agentosd links none. The fuzz binaries built with `go test -c` run only as `childproc` children, so whatever they start inherits only the checked pairs. | brief D3 | `TestOnlyChildprocStartsAProcess`, `TestGateCatchesAChildStartedOutsideChildproc` |
| CP-3 | Nothing reaches the handle's unexported `*exec.Cmd` through reflection plus `unsafe`, and nothing starts a child through a raw `SYS_EXECVE`. Both are held by review for now. | LATER P3-4b-3r-env-r8 l1, l2 | review |
| CP-4 | The secrets a child must not see are agentosd's `AGENTOS_*` variables and variables whose names mark a credential (`credentialWords`). A secret under another name is caught only by the key allowlist, which refuses every key not listed. | brief D2 | `TestTheEnvironmentIsDeniedByDefault` |
