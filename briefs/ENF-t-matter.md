# ENF-t-matter: the enforcer's Matter controller on the C++ Matter SDK, confined, commissioning only through the BLE process

Board section: Devices, hardware and image (SPEC §13-14). Work item #3702 (ENF-t). The Thread stack merged as #4125, and the Matter stack is what remains (#3702 sweep comment of 2026-11-15). Parent brief: `briefs/ENF.md`, slice ENF-t. Decisions: D-231 (no language runtime, so Matter uses the compiled C++ SDK, and Zigbee goes to #3741) and D-253 (BLE commissioning only through the BLE process, by a custom BTP transport).

**Blocker this brief resolves first: the build path.** The Matter SDK's bootstrap fetches from pigweed.googlesource.com and chrome-infra-packages.appspot.com. Both answer 403 from cloud sessions (#3702 comments of 2026-10-30 and 2026-10-31; rechecked 2026-11-16 with no answer). GitHub-hosted runners can reach them. So the binary is built in CI, the way `tools/build-openthread.sh` builds ot-daemon, and the session that builds this iterates through CI runs. No vendored copy of pigweed or CIPD packages goes into the repository. If CI cannot reach them either, the session stops and reports on #3702.

**Requirements:** NET-2 (Confined radio stacks), NET-6 (locks through Matter), D-253.

## Part a: build pin, launcher and confinement

1. Add `broker/enforcer/radio/matter/connectedhomeip.pin`, holding one commit of project-chip/connectedhomeip. Add `tools/build-matter.sh OUTDIR`, which builds one static, position-independent controller binary (`-static-pie`, as ot-daemon is) with only the clusters the adapter needs: On/Off, Level Control, Door Lock and Boolean State. It has no Python, no chip-tool shell and no BlueZ (D-253). Its BLE layer is the custom transport built in part b. Until then it is built without BLE.
2. In CI, follow the OpenThread pattern in `ci.yml`'s `machines` job (the `otcache` steps), as steps of that job and not a new job. `tests/test_ci_scope.py` pins the job set, and branch protection matches required checks by job id (CIMG-c), so a new job would fail those tests and its failure would not block a merge. Add four steps: a cache restore keyed on `tools/build-matter.sh` and the pin, a build if the cache misses, a cache save on main only, and the root test step through `tools/require_ran.py`.
   **Timeout.** `machines` has `timeout-minutes: 60`, and its existing steps use part of that. The cache is saved only on main, so every push of the building PR builds cold. A cold connectedhomeip bootstrap and build on a hosted 4-core runner is estimated (not measured) at 30 to 60 minutes. Raise `machines` to `timeout-minutes: 120` in the same PR, and record the cold and warm step times from the PR's first CI run in its body. If the cold build alone is over 90 minutes, stop and report on #3702 instead of raising the limit again. Two fallbacks need their own decision: a smaller GN target, or a pinned prebuilt binary checked by hash.
   **Build shape.** connectedhomeip's Linux platform uses GLib by default. If build arguments cannot produce a `-static-pie` controller with no GLib and no BlueZ, stop and report on #3702, as for the network case. Do not ship a dynamic binary into a view that has no loader.
3. Add the launcher, which runs under `confine.Matter` and joins Thread's network namespace and nothing else (radio ASSUMPTIONS ENF-t-2). It sees only its storage directory.
4. Carry two release findings from the ENF-j delta L3 (#3703 comment 6471438160, listed on #3702). First, add `open_tree_attr` to the mount deny list, and build the namespace and mount class from one table that a test checks against the kernel's syscall list. Second, each refusal check must tell the filter apart from the kernel, by running where the call would otherwise succeed or by expecting the filter's own errno. A mutant with each deny line removed must fail it. The same goes for #4125's finding on `probeNet` (#3702 comment of 2026-10-31 07:05Z).

**Scope:** `broker/enforcer/radio/matter/connectedhomeip.pin` (new), `broker/enforcer/radio/matter/matter.go` (new), `broker/enforcer/radio/matter/matter_test.go` (new), `broker/enforcer/radio/matter/ASSUMPTIONS.md` (new), `tools/build-matter.sh` (new), `.github/workflows/ci.yml` (four steps in `machines`, and its `timeout-minutes` line), `tests/test_ci_scope.py` (the `timeout-minutes: 60` entry in `MACHINES_LINES`, which pins the job's timeout, set to the new value), `broker/enforcer/radio/confine/confine.go`, `broker/enforcer/radio/confine/filter.go`, `broker/enforcer/radio/confine/filter_test.go`, `broker/enforcer/radio/stacks_test.go`, `broker/enforcer/radio/ASSUMPTIONS.md`.

**Acceptance tests:**
- NET-2: `radio::TestStacksConfined`, extended to Matter. The process sees only `lo`, `wpan0` and `infra0`, cannot read the policy store, cannot enter a new namespace or mount, and holds the profile's seccomp filter. Catches a controller run unconfined.
- NET-2: `radio::TestSrpReachesController` resolves through the real controller binary, not a stand-in. Catches the spike's one unverified inference.
- NET-2 (#3703 finding 1): `confine::TestDenyTableCoversKernelMountCalls`. Catches a new mount entry point that slips through.
- NET-2 (#3703 finding 2, #4125 point 3): `confine::TestRefusalIsTheFilters`, which fails with any deny line removed. Catches a check the kernel passes on its own.

**Size:** about 120k, with most of it spent waiting on CI.

## Part b: declared ops and BLE commissioning

1. Add `StackMatter` to `radio.Declared` with the closed op set: `read`, `on`, `off`, `level`, `lock`, plus the unlock and keypad-code schedule ops that `locks.Driver` needs, and `commission`. Wire `Request.Check` both on the host and on the stack's server.
2. Add the BTP transport (D-253). The controller's BLE commissioning sends GATT ops to the BLE process over the radio host, and those ops are limited to the Matter service UUID (0xFFF6). The controller holds no Bluetooth capability and no D-Bus access.

**Scope:** `broker/enforcer/radio/radio.go`, `broker/enforcer/radio/radio_test.go`, `broker/enforcer/radio/matter/adapter.go` (new), `broker/enforcer/radio/matter/btp.go` (new), `broker/enforcer/radio/matter/adapter_test.go` (new), `broker/enforcer/radio/matter/btp_test.go` (new), `broker/enforcer/radio/ble/policy.go` (the Matter service only), `broker/enforcer/radio/ble/ble_test.go`, `broker/enforcer/radio/matter/ASSUMPTIONS.md`.

**Acceptance tests:**
- NET-2: `radio::TestStackOnlyDeclaredOps`, for Matter. Catches a wide adapter.
- D-253: `matter::TestCommissionOnlyThroughBLEProcess`. A BTP session that asks for any other service or device is refused by the BLE process, and the controller's profile has no bus socket. Catches the fabric-key process reaching other Bluetooth devices.

**Size:** about 110k.

## Both parts

**Guard files:** `.github/workflows/ci.yml` (part a: four steps in `machines`, and its timeout line) and `tests/test_ci_scope.py` (part a: the timeout entry in `MACHINES_LINES`).

**Dependencies:** ENF-k (#3669) is closed, #3906 (the BLE process) is merged, and Thread (#4125) is merged. Order: part a, then part b. ENF-l-b2 part b starts Matter once part a merges. KERNEL-trim part b (#4094) runs after this row.

**Tier / gate:** tier A. L3 runs on the strongest model, plus the lens screen and a separate Security accept.

**Usage estimate:** two sessions, about 120k and 110k.
