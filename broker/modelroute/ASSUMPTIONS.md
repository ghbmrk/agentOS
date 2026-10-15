# Model routes: assumptions

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| M1 | A plan route is a route kind (`plan.go`). `ErrNoPlanLogin` is the no-login sentinel (#1858), and `FallsBack` treats a stalled or contended route (503) as a fallback condition (#1857), so CAP-9 moves to the remaining granted routes. A 503 whose body is not agentos-egress's locked-vault text (`errRouteLocked`, pinned by `TestLockedTextIsTheVaultProcesssOwn`) is also `ErrRouteBusy`, so the plan route can tell the owner's locked vault from a busy route. | CAP-9, CAP-11 | |
| M2 | This package only reports the route control's errors. The stop after a refused login is the provider-agent runner's (provagent P5): it is held across runs until the owner signs in or resumes, not across a broker restart (CRED-5b). | CRED-5 | |
| M3 | **Sign-in routes and plan state (#1264 c4e2).** `SignInFor(id)` marks a worker before it is created, so its `Open` asks `/signin` instead of `/open` until `Close(id)` forgets the mark. `Plan(provider)` reads `/plan`: whether the plan's login is stored and whether the owner allowed it private data, never a login value; a 503 is `ErrVaultLocked` as for every verb, and an unreadable reply is an error with the zero state. | ONB-3, CRED-5, CAP-9 | |
