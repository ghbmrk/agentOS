# Model routes: assumptions

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| M1 | A plan route is a route kind (`plan.go`). `ErrNoPlanLogin` is the no-login sentinel (#1858), and `FallsBack` treats a stalled or contended route (503) as a fallback condition (#1857), so CAP-9 moves to the remaining granted routes. | CAP-9, CAP-11 | |
| M2 | A refused login is not a fallback-and-retry: the route stops and the sign-in line is set once. | CRED-5 | |
