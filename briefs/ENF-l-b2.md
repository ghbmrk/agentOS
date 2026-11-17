# ENF-l-b2: the enforcer daemon's device side (access point, radios, safety devices)

Board section: Devices, hardware and image (SPEC §13-14). Work item #3670 (ENF-l), the part still owed after ENF-l-a (#4754) and ENF-l-b1 (#5020). Parent brief: `briefs/ENF.md`, slice ENF-l and its lifecycle matrix. Split as proposed in #3670 comment 6653490122.

**Problem:** `broker/cmd/agentos-enforcer/main.go` still runs `unwiredNetwork{}` and `noRadio{}`, and the page gets no action, sealed-secret or access-point input (ASSUMPTIONS ENF-l-10). So enrolment enrols nothing, every radio command fails, and the two safety-list lifecycle rows have no test. About 6,000 lines of package code still need wiring: `ap` and `ap/push` (1,125), `radio` with `ble`, `thread` and `confine` (3,629), `devsecret`, `pairseal`, `action` and `locks`. That will not fit one session under 150k, so this brief has three parts. They run in order because they share `main.go`, `enforcer.go` and `lifecycle_test.go`. Each part is its own PR with `Refs #3670`, and the last one says `Closes #3670`.

**Requirements:** NET-2 (Confined radio stacks, Safety devices, Channel), NET-3, NET-4 (Enrolment and recovery), NET-6, STO-4, HW-10.

## Part a: the access point (also closes #4569, ENF-l-ap-stalled)

1. Replace `unwiredNetwork` with a network built on `ap.Keys` and `push.Pusher`. Keep one `push.Pusher` per access point for the whole process lifetime (ENF-g-8), never one per tick. Run `Pusher.Watch` and pass each report to the page.
2. When a report carries `push.ErrStalled`, the page shows the access point as stalled, with the `Result.Abandoned` count, and says that restarting the enforcer clears it once the access point has been checked (#4569).
3. The first-boot and enrolment rows render the grouped Wi-Fi password and the 2.4 GHz note on the page (`Card.Shown`, `Card.Note`, the QR text; ap ASSUMPTIONS ENF-g-6, #3670 comment of 2026-10-31 11:56Z).

**Scope:** `broker/cmd/agentos-enforcer/main.go`, `broker/cmd/agentos-enforcer/enforcer.go`, `broker/cmd/agentos-enforcer/config.go`, `broker/cmd/agentos-enforcer/apnet.go` (new), `broker/cmd/agentos-enforcer/apnet_test.go` (new), `broker/cmd/agentos-enforcer/lifecycle_test.go`, `broker/cmd/agentos-enforcer/ASSUMPTIONS.md`, `broker/enforcer/page/status.go`, `broker/enforcer/page/home.go`, `broker/enforcer/page/templates/home.html`, `broker/enforcer/page/status_test.go`.

**Acceptance tests:**
- NET-3, ENF-g-8: `agentos-enforcer::TestOnePusherPerAccessPoint`. Over many ticks and a policy reload the daemon builds one `Pusher` per access point. Catches a fresh Pusher that resets the stalled count.
- NET-3 (#4569): `agentos-enforcer::TestLifecycle/stalled access point push`. A fake access point drives `push.MaxAbandoned`, and home shows "stalled" with the count. Catches a stall that reaches nobody.
- NET-4, HW-10: `agentos-enforcer::TestLifecycle/first boot` and `/enrolment` are extended so the Wi-Fi card's password and 2.4 GHz note render. Catches a card that never reaches the owner.

**Size:** about 90k.

## Part b: the radio stacks, device secrets and the bulb

1. Replace `noRadio` with `radio.NewHost` and start the BLE and Thread stacks with `confine.BLE` and `confine.Thread`/`ThreadAdapter`. Matter is started only once ENF-t's Matter piece has merged (`briefs/ENF-t-matter.md`). Before a start, lay out each stack's directories: the run directory is 0700 and owned by the Thread user, and the RCP device path is resolved past symlinks (radio ASSUMPTIONS ENF-k2-mnt-2). A stack's writable directory is emptied only through `confine.Empty` (ENF-k2-mnt-d). `Spec.Stderr` goes to a bounded writer that drops, never a pipe that can stall (ENF-k-11). Restart Matter together with Thread (ENF-t-2).
2. Open `devsecret.Store` with the enforcer's `pairseal.Key` from its sealed state, and set `Process` from the radio host's layout. Pass the page its `Secrets` input.
3. Drive the bulb through the radio host. Colours map by name (`alert.Colour` constants, never their numbers; #4305 item 2).
4. Create the Thread user namespace from root, not through an unprivileged `unshare`, because KERNEL-trim part b sets `unprivileged_userns_clone=0` on the enforcer image (#3702 comment 6532233412).

**Scope:** `broker/cmd/agentos-enforcer/main.go`, `broker/cmd/agentos-enforcer/enforcer.go`, `broker/cmd/agentos-enforcer/config.go`, `broker/cmd/agentos-enforcer/radios.go` (new), `broker/cmd/agentos-enforcer/radios_test.go` (new), `broker/cmd/agentos-enforcer/light.go` (new: `logLight` moves here and the bulb driver joins it), `broker/cmd/agentos-enforcer/light_test.go` (new), `broker/cmd/agentos-enforcer/lifecycle_test.go`, `broker/cmd/agentos-enforcer/ASSUMPTIONS.md`, `broker/daemon/arc2_test.go` (its import lines only).

**Acceptance tests:**
- NET-2: `agentos-enforcer::TestLifecycle/safety-list device paired`. The secret is held by the enforcer and released only to that device's stack process, and the core holds no copy. Catches a secret released to the wrong process.
- NET-2: `agentos-enforcer::TestStackDirsEmptiedOnlyByConfine`. A link planted in a stack's run directory is removed, not followed, on restart. Catches an `os.RemoveAll` path.
- KRN-12 (#4305 item 2): `agentos-enforcer::TestBulbMapsColourByName`. It fails if `alert.Red` is renumbered. Catches a driver that maps colours by number.

**Size:** about 110k. Stop at 120k with tests moving and hand the rest to part c.

## Part c: actions and locks

1. Pass the page an `action.Book` whose Actuator is `locks.Gate.Act` over the radio host. The Actuator has its own time limit and never takes the policy lock, because `/do` holds that lock while the act runs (#3670 comment of 2026-10-30). The adapter calls `Host.Send` with the book's context, and `page.Config.Log` and `page.Config.Zone` are set.
2. `locks.Gate` gets its `Codes` from the device-secret store and its `Tick` from every policy load. `Seen` is fed from the stacks' reports.

**Scope:** `broker/cmd/agentos-enforcer/main.go`, `broker/cmd/agentos-enforcer/enforcer.go`, `broker/cmd/agentos-enforcer/safety.go` (new), `broker/cmd/agentos-enforcer/safety_test.go` (new), `broker/cmd/agentos-enforcer/lifecycle_test.go`, `broker/cmd/agentos-enforcer/ASSUMPTIONS.md` (ENF-l-10 is retired here).

**Acceptance tests:**
- NET-6: `agentos-enforcer::TestLifecycle/safety-list turn-on asserted`. The act runs once inside its window, and a replay or a channel request is refused. Catches an unwired or replayable challenge.
- NET-6: `agentos-enforcer::TestActuatorBoundedAndLockFree`. A hung driver releases `/do` within the Actuator's limit, and the Actuator never takes the policy lock. Catches a hung lock that stalls the page.
- NET-6: `agentos-enforcer::TestUnusualUnlockNeedsSecond`, an unlock outside the usual hours, end to end through the daemon. Catches a daemon that bypasses `locks.Gate`.

**Size:** about 90k.

## All parts

**Guard files:** `broker/daemon/arc2_test.go` (part b, import lines only).

**Dependencies:** none open. ENF-a to ENF-s are merged. Part b's Matter start waits on ENF-t's Matter piece and ships without it. Under D-320, overlap with open PRs does not block a build, and no file here is on the hot list.

**Tier / gate:** tier A. L3 runs on the strongest model, plus the lens screen and a separate Security accept.

**Usage estimate:** three sessions, about 90k, 110k and 90k.
