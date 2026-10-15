# Provider-agent route: assumptions

Built for BOARD CAP-11-plan (#1314) on the plan-login chain (#807, #1015, #1014). The route is wired deny-by-default in agentosd: it stays closed until #809 fills the Codex qualification record and CRED-5c, #1264 and #1380 land.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| P1 | The Codex declaration is verdict `allowed` (#1377, D-117) with an empty qualification record, so every run refuses `unqualified` until #809 records the pinned CLI version, evidence pointer, terms URL and date. A record whose CLI version differs from the image's, or `not-allowed`, refuses the same way. | CAP-11, D-114 | #809 changes the built-in under tier A review. |
| P2 | Claude Code is worker-held, verdict `unclear`, and always refuses `opt-in-required` here; #1380 builds the opt-in. `unconfirmed` runs only with the owner's recorded consent (CRED-5c), which agentosd does not yet supply (Consent is false). | CAP-11, CRED-5 | #1380 and CRED-5c provide the grant sources. |
| P3 | The brief reaches the CLI on stdin only, never argv, so `/login` and `!cmd` text is data. Deviation from the brief's "declared result file": stdout is redirected inside the worker to a result file and stderr to /dev/null, so the CLI's own output is the result and no raw stderr is ever journaled. The journal holds metadata only. | CAP-11, CRED-7 | A CLI that writes its own result file needs a declared path. |
| P4 | The command is `env -i` with exactly the launch.json env, then `wrap`, then `argv` (#1850). No login is handled here; the seed is a placeholder via `RouteControl.Seed`. | CRED-5, #1015 | Env or wrap form changes in #1850. |
| P5 | Codex `CreditDraw` and `LoginRefused` signals are provisional; #809 measures them. A credit-draw signal is treated as used-up so no run draws credits unmetered. A refused login calls SignIn once and never retries. | CAP-9, CRED-5b, OP-8 | #809 measurement picks the signal or a credits-off check. |
| P6 | The result is scanned for provider credential formats (CRED-7) and withheld on a match. The scan is a tripwire only; the worker holds placeholders. | CRED-7 | Encodings beyond the tripwire's formats are not detected. |
| P7 | Admission refuses `pool-at-reserve` from the readings the Runner is given. agentosd wires no readings yet (#1856: a control verb carrying quota readings to agentosd is not built), so pools are unread and the route stays closed by P1. | RES-5 | #1856 supplies readings. |
| P8 | A wall-clock cap wraps the Execs; the worker is destroyed on every exit path. A 503 from a stalled or contended route is `route-busy`, a fallback condition (#1857); a missing plan login is `unsigned` (#1858). | CAP-9, CRED-5b | |
