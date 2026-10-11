# Synthetic evidence for the 2026-10-08 UX review

Reviewed code: `c34f2f4b2e9db7ceb8ee71a7a8b8a63a5a7948a1`.

This directory reproduces selected owner-journey observations. It is advisory
evidence, not a release qualification or a test suite asserting desired product
behavior. The observation checker deliberately recognizes defects at the
reviewed revision; a product fix should change the corresponding observation.

## Run

Requires a native Linux or macOS host, Python 3, and an installed Go toolchain
compatible with `broker/go.mod` (the captured run used the supplied Go 1.26.8).
Dependencies come from the repository's vendor directory; the runner does not
download a toolchain or modules.

```sh
GO_BINARY=/path/to/go ./reviews/ux/evidence/2026-10-08/run.sh
```

Omit `GO_BINARY` to use `go` on PATH. The script works from any current directory,
derives the repository path from its own location, and writes copied probes,
generated overlays, cache and all outputs into a new temporary directory. It
prints that directory and leaves it available for inspection. It does not modify
production code, start a web server, contact a provider, or send real messages.
Remove the printed temporary directory when finished.

Sources end in `.go.txt` so the evidence directory cannot become an accidental Go
package. The runner gives each source its own temporary `.go` filename and runs
it from the broker module. There is no local-path `go.mod` or checked-in overlay.

## What runs

| Probe | Actual code exercised | Synthetic fixture and limits |
|---|---|---|
| `probes/setup.go.txt` | `localui.Server.ServeHTTP`, templates and setup state machine | Hooks replace modem/network/provider/vault effects; state starts after identity steps with a synthetic same-phone cookie. Provider code, numbers and network values are synthetic. Direct POST starts the otherwise invisible provider flow solely to inspect its later state. |
| `probes/approvals.go.txt` | `owner.Channel` parsing, held-message behavior, request/MORE rendering, outbound text filter | In-memory carrier, engine, agent and store; fixed time and public synthetic TOTP seed. Approval IDs/texted codes are generated for this fixture and can vary per run. No real SMS or task executes. |
| `probes/status.go.txt` | `clock.Status.Line` and `control.Handler` status composition | Fake authorization always succeeds; engine and exception notes are fixtures. It tests truncation, not real authentication or operational health. |
| `probes/render.go.txt` | `localui.Server.ServeHTTP` and production templates for status, stopped, unlock, approvals, home and long approvals | `source.Call` fabricates status, successful session checks and pending requests. These are rendering fixtures, not proof that a real account or device is signed in. |

The runner also executes four existing localui tests: `TestSetupMinimumPath`,
`TestSetupResumesAfterRestart`, `TestAllSetText`, and
`TestDeviceCodeSignInAloneFinishesSetup`. Their pass alongside a reproduced
missing sign-in control illustrates the gap between direct-handler coverage and
the visible journey. It does not assert that the wider repository tests pass.

## Darwin compilation shims

Some Linux-only functions are referenced by otherwise portable packages/tests.
On Darwin only, a temporary Go overlay adds the two `shims/*.go.txt` files as
virtual files in `broker/sockets` and `broker/localui`. The shim functions contain
only `panic` and **must never execute**. The targeted run invokes no Linux Unix
socket, ownership check or listener helper; successful completion confirms no
placeholder was called. Production files are neither replaced nor edited. On
Linux the overlay is empty and these shims are not used.

Consequently this evidence does **not** qualify Linux service wiring, socket peer
identity, real authentication boundaries, network isolation, credential custody,
real providers, cellular service, hardware boot, captive portals, phone app
handoffs, accessibility, or acceptance gates A1/A14. HTTP requests reach the real
renderer in-process using `httptest`, while the trusted-side effects are fixtures.
The browser review and its metrics are separate evidence.

## Captured observations

`observed/` preserves outputs from the review. Two HTML captures are retained:
`provider-before.html` demonstrates the initial empty provider link/code and
missing start control; `approvals-long.html` is the long-filename layout fixture.
The runner produces all HTML variants in its temporary output directory without
checking redundant captures into the repository.

`setup.json`, `approvals.txt`, and `status.txt` record original probe outputs.
Random request IDs/codes in approval output may differ on replay; compare the
behavior, not those values. HTML hidden request tokens are synthetic. Every
number, email, secret, cookie and provider endpoint here is a public fixture,
not an owner credential.

`check-observations.py` summarizes twelve bounded observations from fresh
outputs. An observation changing or failing is a prompt to inspect the result,
not a reason to restore the old defect. The runner's Go test output and checker
summary are also retained for audit after the portable replay.

`observed/browser.json` records the separate read-only browser measurements:
390px provider/ordinary approval fixtures, 320px long-filename reflow, actual
dark-theme computed colors and their WCAG contrast ratios. These are recorded
observations, not assertions automatically rerun by `run.sh`. View the rendered
HTML in a browser to repeat that portion; preserve full field text when fixing it.
