# broker/browser: assumptions and carry-forward (CRED-4b part 1)

Part 1 is the broker-side gate in front of S5's driver: the closed v0 action protocol (CRED-4), declared-origin checks, and the CRED-10 output filter, all applied outside the driver, which is treated as untrusted because it renders pages written by strangers.

## What the gate guarantees
- **G1** Only the seven v0 verbs exist. Requests with unknown verbs or arguments, wrong JSON types, duplicate keys or trailing data are refused and never reach the driver. The driver receives a canonical re-encoding, never the agent's bytes, so the two sides cannot parse one line differently.
- **G2** `navigate` to an undeclared origin is refused at the gate, in addition to the driver's own routing checks.
- **G3** Every string the driver returns passes the vault's exact-value redactor first, then the CRED-10 detector (ported from S5 `protocol.py`). Fields outside `Result` are dropped.
- **G4** A reply whose page URL is off the declared origins means confinement failed. The gate stops the executor (kills its process group) and relays nothing from that page.
- **G5** Before a screenshot, the gate snapshots the page itself; any match from the driver or the gate withholds the screenshot without taking it.
- **G6** A download whose text carries a vault value or a detector match is removed from the workspace and withheld. Output files must be flat names of regular files in the workspace.
- **G7** The driver starts with a fixed environment (PATH, HOME=workspace, LANG, plus `Config.Env`), never the broker's. A missed reply deadline, malformed output or driver exit stops the executor.

## Known limits (carried to part 2)
- **K1 Sandbox.** The driver is a child process in its own process group, not yet in a broker-owned VM. Part 2 places it in its own sandbox, one account each (CRED-4), through `vm.Manager` (call, not change).
- **K2 Sessions.** There is no session handling yet. Part 2 adds vault-held sessions and the A5 canary sessions. If `broker/vault` cannot hold a browser session in the vault process as it stands, that goes to primary as a `lane:primary` issue before part 2 starts.
- **K3 Driver packaging.** `Config.Driver` points at S5's `executor.py`. Part 2 packages it into the sandbox image with Playwright AI-mode snapshots (S5 measured 1.63) and Chromium's headless shell (S5 finding 5: full Chromium connects to Google on launch).
- **K4 Real-driver test.** `TestFixtureThroughTheGate` skips where Playwright lacks AI-mode snapshots. This build environment has 1.56 and the broker CI job has none, so the real-driver path ran in neither. Part 2's acceptance includes a CI job that runs it together with `tests/test_s5_executor.py`.
- **K5 CRED-6.** Actions that reveal or create secrets are not yet classed as irreversible intents. That needs the adapter's operation map (verb, grants); part 2 or ADP-8.
- **K6 Images.** Screenshots and binary downloads are not inspected as images. A secret drawn in a canvas or image is not detected (same limit as S5).
- **K7 Restart.** After a stop, the caller decides whether to start a fresh executor. The gate never restarts itself.
