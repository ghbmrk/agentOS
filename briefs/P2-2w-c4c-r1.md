# P2-2w c4c r1: the bridge learns the owner's number when setup finishes

Board section: Backlog refill (2026-10-05); work item #1291. Release finding on P2-2w c4c. Serves A1 (§8.1) and CH-1. Tier: A (agentosd setup, the modem bridge's unit). Builder: strongest model. Usage estimate: 90k tokens. **Needs:** P2-2w c4c (merged); before any A1 run.

**Why.** agentos-modem reads the owner's number only from `OWNER_NUMBER` (`-owner-number`, read once into `at.Config.Owner`), and nothing writes it. After the owner finishes setup on the Wi-Fi page and pairs, their first text is, to the bridge, anyone's text: it is deleted as read and offered once (B9), and the owner channel refuses it, so A1's first task never arrives. The G1 e2e works around it with HELP retries (boxe2e E9, `main_linux.go:884`).

**Route (decided here).** agentosd writes `OWNER_NUMBER` into `/etc/agentos/modem.env`, which `agentos-modem.service` already reads after the image's file, and restarts the bridge. Rejected: the bridge asking agentosd for the owner over owner.sock (changes bridgeproto, bridgeclient, modemlink and `at`, and the number is fixed per modem open, so a restart or reopen is needed anyway); writing it into the roles directory (0755, bound into the bridge read-only, so the number would be readable by every local user, and the same reopen problem).

## Requirements

- **P2-2w-c4c-r1-1** (CH-1, ONB-3) When setup's finish is recorded and agentosd runs a modem line (`-modem-roles`, the `modemBridge` branch in `main.go`), agentosd sets `OWNER_NUMBER=<owner>` in `/etc/agentos/modem.env` and then restarts `agentos-modem.service`. The write:
  - accepts only a number `bridgeproto.ValidNumber` passes, so nothing else can be put into the file (no newline, no second variable);
  - is atomic (temporary file in the same directory, fsync, rename), owned by root, mode 0600, and makes `/etc/agentos` (0755) if it is missing;
  - keeps every other line of an existing file as it is (`COUNTRY_CODE`, `BOX_NUMBER`, comments) and replaces any earlier `OWNER_NUMBER` line, so there is exactly one;
  - never puts the number in a log line, an error string or a panic.
- **P2-2w-c4c-r1-2** (CH-1) The restart runs `systemctl --no-block restart agentos-modem.service` under a timeout (reuse the shape of localui's `ExecHost`, `broker/localui/aphost.go`), so finish never waits on the bridge's outbox flush (`FlushWait`, 45 s), which itself needs owner.sock. A failed write or restart is logged without the number and does not stop agentosd: the owner channel still starts.
- **P2-2w-c4c-r1-3** (CH-1) Crash safety, by a done-marker. After the restart call succeeds, agentosd writes a marker in its setup state directory (beside the setup record) naming the owner it was done for, as a hash, never the number. On every start where `rec.Finished` holds and a modem line runs, `setupMode.run` redoes the write and the restart unless the marker matches the recorded owner. So a crash after the record but before the write, or after the write but before the restart (`Requires=` does not restart the bridge when agentosd crashes), ends at the next agentosd start with the bridge restarted on the owner's number, and a normal restart of agentosd restarts the bridge at most once.
- **P2-2w-c4c-r1-4** (CH-12) With no modem line, nothing is written and nothing is restarted. Tests never write the real `/etc/agentos/modem.env` nor run the real `systemctl`: the path and the runner are fields on `setupMode`, set only in `main.go`'s `modemBridge` branch, and nil means off (so `setuptext_test.go` and the other setup tests that set `m.Line` stay as they are).
- **P2-2w-c4c-r1-5** (CH-12) B9 says the bridge gets `OWNER_NUMBER` from agentosd at finish, names the residual window (a text the owner sends between finish and the bridge's restart is still anyone's: deleted and offered once) and why it is accepted; the unit's comment says who writes `/etc/agentos/modem.env`.

**Acceptance tests:**
- P2-2w-c4c-r1-1 `broker/cmd/agentosd/modemenv_test.go::TestFinishWritesTheOwnerNumberToModemEnv` (an existing file with `COUNTRY_CODE` and an old `OWNER_NUMBER` ends with both kept or replaced, one `OWNER_NUMBER`, mode 0600; catches a lost country code or a duplicate line) and `::TestModemEnvRefusesANumberThatIsNotE164` (`+15551234567\nX=1` and the empty string write nothing; catches injection into the unit's environment); `::TestModemEnvNeverLogsTheNumber` (a synthetic canary number on every path, including a failing write, is absent from the log and errors).
- P2-2w-c4c-r1-2 `broker/cmd/agentosd/modemenv_test.go::TestFinishRestartsTheBridgeWithoutWaiting` (the fake runner gets exactly `systemctl --no-block restart agentos-modem.service`, after the rename; a runner that blocks past the timeout and one that fails both leave `run` returning the owner).
- P2-2w-c4c-r1-3 `broker/cmd/agentosd/setup_test.go::TestAFinishedSetupRestartsTheBridgeUntilMarked` (a record finished with no marker: one write and one restart at start, then marked; a second start does neither; a marker for another owner redoes both; catches the crash between record and restart).
- P2-2w-c4c-r1-4 `broker/cmd/agentosd/setup_test.go::TestNoModemLineWritesNoModemEnv` (nil path and runner: setup finishes, no file, no run).
- P2-2w-c4c-r1-5 none: ASSUMPTIONS and unit comment text, checked by the reviewer against B9's revisit column ("Owner number written at finish").

## Acceptance

The tests above (REQ-marked), `go vet` and `go test -race ./cmd/agentosd/...`, `tests/test_image.py` still green (the unit's `EnvironmentFile` list is unchanged); CI green. Tier-A L3 with a threat check: the file is root's and feeds a unit's environment, so the review checks injection, mode and owner, symlinks at the path (the rename replaces a link, never follows it) and that the number reaches no log.

**Guard files:** none

## Scope

`broker/cmd/agentosd/setup.go` (the finished path and the hook after `Finished`), a new `broker/cmd/agentosd/modemenv.go` and `broker/cmd/agentosd/modemenv_test.go`, `broker/cmd/agentosd/setup_test.go`, `broker/cmd/agentosd/main.go` (the `modemBridge` branch only: set the path and the runner), `broker/cmd/agentosd/ASSUMPTIONS.md` (one row: what agentosd writes, where, and the marker), `broker/cmd/agentos-modem/agentos-modem.service` (comment only), `broker/modem/bridge/ASSUMPTIONS.md` (B9), `briefs/P2-2w-c4c-r1.md`. Not `broker/modem/bridge/bridge_test.go` (#2071), `broker/localui/setuphooks.go` (the page needs no change), nor bridgeproto, bridgeclient, modemlink or `at`.

**Sequencing (D-111).** `broker/cmd/agentosd/main.go` is touched by open #2044 and #2015 (hunks far from the setup branch): the build starts when both have merged or closed. `broker/cmd/agentosd/ASSUMPTIONS.md` (#2056, #2033) is an append-only list and exempt; append the row, rebase on conflict.

## Out of scope

Dropping boxe2e E9's HELP retries (a follow-up once a #1688 QEMU run shows the first text lands without them); changing the owner's number after setup; a bridge that rereads its environment without a restart.

## Estimate

About 90k tokens for one session. The figure is a checkpoint, not a cap (docs/OPERATING.md §5).
