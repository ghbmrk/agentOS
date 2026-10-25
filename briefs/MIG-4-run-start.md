# MIG-4-run-start: agentosd reaches the kernel at start

Work item #2682 (MIG-4-run), the start-up slice; head of the serial `cmd/agentosd` chain (D-111: then #2783, #2778, #2779, #2780b, #2790). Tier A. Re-scoped on 2026-10-25 against main at 082b049, under D-154's keeper domain (#2682 comment 6377262816).

**What is already on main.** The four start-up rows in #2682 comment 6373366346 have merged: the unlock step and the kernel's main (STO-2b-1, `cmd/agentos-unlock`, `cmd/agentos-kernel`), the pins on the TPM (STO-pins), the counter-backed anchor (LOG-anchor-tpm), and enrollment with the keeper's units (STO-2c, `agentos-keeper-enroll.service`, `agentos-keeper-kernel.service`). A store with no owner's hardware keys starts a setup-only kernel (#2905 open point 2), which serves `setup`, `setupinfo` and `status`. So on a booted, enrolled image the kernel serves `OwnerSide` on `/run/agentos-kernel/owner.sock`.

**The gap.** The kernel admits only the owner side's uid on that socket (`-owner-uid @uid:agentos-owner`) and refuses root as a peer (`agentos-kernel`'s never-root rule). No process runs as `agentos-owner`; the owner side is `agentosd`, which runs as root. So nothing in production can call the owner seam, and #2783 cannot move STOP onto it.

**This slice.**
1. `broker/owner/kernelsock`: agentosd's dial-only client of the kernel's owner socket. Each call runs on one OS thread whose effective uid alone is the owner side's; the peer must be the kernel's uid; the thread takes root back before the runtime has it again. The wire is written out, as `localsrv/accountsock` does for the mail clerk, since agentosd's control path does not link `kernel/proc`. Only `setupinfo` for now; #2783 adds the seam's actions.
2. `cmd/agentosd`: `-kernel-owner`, `-kernel-uid`, `-kernel-owner-uid` (all or none, no root, distinct uids) and a start-up probe that logs once whether the kernel is reached and whether setup is open. It holds nothing up.
3. `agentosd.service` passes the three flags with the kernel unit's own values and orders itself after `agentos-keeper-kernel.service` without requiring it.
4. The ARC-2 lists (`daemon/arc2_test.go`, `daemon/inference_test.go`) and `core/core.txt` admit the client, as for `localsrv/accountsock`. A CI step runs the root tests as `agentosd.service` runs (root, no_new_privs).

**Design choice (recorded in cmd/agentosd ASSUMPTIONS MIG-4-run-start-a).** The thread-scoped uid keeps D-154 rule 2 (the listener supplies the side; no frame carries a uid) and keeps the kernel's never-root rule, with no new process. Rejected: a `systemd-socket-proxyd` relay under `agentos-owner`, which turns a call never sent into a lost one; admitting root on the kernel's owner socket.

**Scope.** `broker/owner/kernelsock/` (new), `broker/cmd/agentosd/{kernel.go,kernel_test.go,main.go,ASSUMPTIONS.md}`, `broker/daemon/{arc2_test.go,inference_test.go}` (list entries only), `broker/core/core.txt` (one `allow` line), `image/mkosi/mkosi.extra/usr/lib/systemd/system/agentosd.service`, `tests/test_image.py` (one test), `.github/workflows/ci.yml` (one step). Off #3058's files (`kernel/proc`, `cmd/agentos-kernel`, `cmd/agentos-unlock`, the keeper units, `mkosi.finalize`, `tests/test_image_keeper.py`).

**Not in this slice.** The mail clerk's process unit and the Connect page switches (#3059); moving any owner action onto the seam (#2783); a client-only split of `kernel/proc` so agentosd can import its `Owner` (later, once #3058 merges).

**Requirement IDs:** CLK-1, KRN-7, D-154 rules 1 and 2.

**Acceptance tests:**
- `broker/owner/kernelsock/kernelsock_test.go::TestSpeaksTheKernelsWire`: a real setup-only kernel's `OwnerSide`, served to the owner side's uid only, answers `SetupOpen` as open and returns its refusal of `stop` in its own words; the same call made as root is refused. Fails if the call is made as the broker's own uid or the wire drifts from `kernel/proc`.
- `kernelsock_test.go::TestOnlyTheKernelsUIDIsCalled`: a socket under another uid, or none, is `ErrUnreachable` and is never sent the frame.
- `kernelsock_test.go::TestNoThreadKeepsTheOwnerSidesUID`: after 32 concurrent calls every thread of the process has real, effective and saved uid 0. Fails if a thread goes back to the runtime under the owner side's uid.
- `kernelsock_test.go::TestAnOwnerUIDThatCannotBeTakenSendsNothing` (non-root): a uid that cannot be taken runs nothing.
- `broker/cmd/agentosd/kernel_test.go::TestTheBrokerSaysWhenItReachesTheKernel` and `::TestKernelFlags`.
- `tests/test_image.py::ConfigTest::test_broker_calls_the_kernel_as_the_owner_side`: the broker's flags equal the kernel unit's `-owner-sock`, `-owner-uid` and the unlock step's `-uid`; ordered after, never requiring, the kernel's unit.
- CI step "agentosd calls the kernel as the owner side (#2682)": the three root tests ran and passed (`tools/require_ran.py`).
