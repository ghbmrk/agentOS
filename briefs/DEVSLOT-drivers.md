# DEVSLOT-drivers: a device-driver slot for vendor protocol code kept in a private repo

Board section: Devices, hardware and image (SPEC §13-14). Work item #3321; SPEC DEV-1, DEV-4, DEV-12, CLK-1, KRN-2, NET-2, HW-10, DEP-4; decision D-189. Tier A (the trusted base gains code that this repo's PRs do not measure). Authority: Mark's tap "Withings private, HomeKit public", 2026-10-26, in the other sub's project; this project has only the coordinator's relay at 23:27Z (#3293 comment 6429769409, #3321 body). The rule it sets: one vendor's protocol goes private; standards stacks and device-agnostic mechanisms stay public.

## Why

The Withings reader (`broker/clerk/withings/`, #3272, #3276) is one vendor's protocol. Under Mark's rule it moves to ghbmrk/agentos-private (#3322), and Whoop (#3273) follows. HomeKit (D-182) is a standard, so it stays public. A public slot is needed so the box can run private driver code under the same rules as public code, without each vendor adding its own hook.

## The premise, corrected

The row says the spec diff "rewords the Withings references under DEV-12 and D-184". That is wrong on both counts:
- **SPEC.md names no vendor here.** It has no "Withings", and DEV-12 is vendor-neutral. Nothing needs rewording.
- **D-184 is already device-agnostic.** `clerk.Secrets.DeviceKey` lends any `device/` slot's key, and it stays public. A decision row is a record, so its "Withings" source text is not rewritten.

So the spec diff adds text rather than rewording it. The text is needed because three clauses assume all trusted code is in this repo:
- KRN-2 says the trusted base "is measured on every PR", which can only mean this repo's PRs.
- HW-10 gives one signed image downloaded from the project's GitHub releases.
- DEV-12 says an encoder the clerk lacks "ships only as a box update (DEP-4) through §8 and its review".

A private driver is all three things: trusted code, part of an image, and an encoder shipped as a box update. The spec has to say how such a driver is named, measured and reviewed. The addition is about 90 words, so it carries `Word-budget: D-189` once Mark's approval is recorded there (point 6), unless the spec builder can retire as many words without changing meaning (see part (s)).

## Design points settled here (recommendations, flagged for the reviews)

1. **A driver is its own clerk process, built in.** Each driver is a separate binary: a `main` that calls the public `devslot.Serve(driver)`, built in the private repo against a pinned commit of this repo. It runs under its own uid and is non-dumpable, like any clerk (CLK-1), and it holds only its own `device/` slot. There are no Go plugins, no dynamic loading and no in-process vendor code in a public host. The slot is the only code that touches the kernel, the sealed store or the link, so a driver can only declare operations, frame bytes and parse replies. Rejected alternative: an in-process library in a shared host. That would put every vendor's parser in one credential domain (risk 19) and would need the host to link private code anyway.
2. **The enforcer loads no driver.** The enforcer's radio (NET-2) offers a generic relay instead: Bluetooth LE GATT to one pinned address and one declared characteristic, carrying writes and notifications. The whole vendor session, its allowlist and its `kl` prover run on the core inside the driver. This keeps vendor code and secrets off the enforcer (NET-2: no shared secret) and gives the enforcer one standards relay instead of a loader. **This changes #3277** (Withings part c), which planned the session on the enforcer (WBS-3). Part c becomes the generic relay, and it is public.
3. **Shipping: drivers are in the image, named in its manifest.** The image build takes an optional drivers directory. Each driver binary goes under `/usr` (verity-covered, read-only), and `agentos_V.release.json` lists each driver as {name, repository, commit, SHA-256}. The public release build lists none, so HW-10's public image is unchanged. Mark's image is the same build with a drivers directory, signed by the same release key and updated under DEP-4 like any image. The host starts only the drivers in the manifest whose hash matches. The kernel logs the list at start, and STATUS names each driver by name and commit (KRN-2). Rejected alternative: a separately signed driver bundle. It would need a second artifact, a second verify path and a second update path, and it would add trusted-base code to replace work the image chain already does.
4. **The residual is stated, not hidden.** An image with drivers can be rebuilt only by someone who holds the private repo. The reproducible-builds mitigation in risk 26 holds for the public image and for holders of both repos. The spec diff says so in one clause.
5. **The review rules carry over by contract, not by trust.**
   - This repo exports `broker/clerk/devslot/conformance`, a test suite every driver must pass. The suite checks that a declaration uses DEV-4 verbs only, that the driver writes nothing but declared shapes, that every parser is fuzzed with bounded buffers, and that a canary secret never leaves the driver. Its source check (plain Go files only, allowlisted standard imports, nothing else from this repo) is a lint, not the boundary: Go code can still corrupt memory through a data race. The boundary is the driver's sealed process (part b).
   - The private repo's CI runs that suite at the pinned commit, plus `go vet`, the race detector and the fuzz targets.
   - Every private PR gets a fresh L3 review, and tier A PRs also get a Security review. Reviewers are sessions with ghbmrk/agentos-private added, using this repo's reviewer skill at the pinned commit.
   - The private repo keeps its own `trusted_base_parsers.txt`, and each parser it adds needs a `Trusted-base: parsers --` line, as here. The image manifest records each driver's parser count, so the KRN-2 measure covers drivers too.
   - Reviewers of public PRs see only the slot and the suite. That is the public contract, and any change to it is tier A here.
6. **D-189 records the rule; Mark's approval of the spec words is still owed.** L3 on #3330 found that the relayed tap supports the policy but not the approval of about 90 SPEC words, so a confirmation card goes to Decisions. Once Mark taps, the row gains that tap and the spec PR's number. `tools/word_budget.py` accepts a waiver only from a row that is active on the base and names the spec PR by number. So: open the spec PR first, then add the tap and its `#number` to D-189 in a one-line tier C PR, merge that, and re-run `word-budget`. If Mark declines, part (s) retires as many words as it adds.

## Spec text for part (s) (a draft; the L1 builder owns the final wording)

- After DEV-1's sentence on mature device stacks: "**Device drivers.** One vendor's protocol code MAY live outside the public repository as a device driver: its own clerk (CLK-1), reached only through the public driver slot, with a declaration of DEV-4 operations only and a link only to its pinned devices (DEV-2, DEV-3). It is reviewed under the same rules as public code and passes the slot's public conformance tests. The image's release manifest names each driver by repository, commit and hash; the log and STATUS name it (KRN-2); the public release ships none."
- At the end of risk 26: "An image with device drivers is reproducible only by holders of their repository."

## Split

- **(s)** L1 spec diff with the text above. It starts once nothing else open touches SPEC.md (#3302 holds it). `Word-budget: D-189` per point 6, unless it retires as many words.
- **(a)** `broker/clerk/devslot/`: the `Driver` interface, `Serve`, the declaration check, the `Link` kinds (GATT through the enforcer relay; TCP to a pinned endpoint), the one-slot `Secrets`, typed event output, the `conformance` suite, and a fixture driver under `testdata/`. Part (a) needs neither the image nor the host.
- **(b)** The host, the sealed driver process, the image and the kernel entries, in five parts settled under "Part (b), settled" below: b1 (image and manifest), b2a (the wire and the host library), b2b (the host process and the units), b3 (the kernel side) and b4 (subscriptions). No driver runs on the box before b2b. The device-agnostic parts of the dropped #3293 land in b2a and b3.
- **(c)** The rewritten #3277: the enforcer's generic GATT relay (point 2). It needs the enforcer hardware.
- **(p)** The private repo's CI and review setup (point 5). It is built in ghbmrk/agentos-private by a session with that repo added, not from this repo.
- Then **#3322** (DEVSLOT-withings-move) runs the former Withings tests through the slot.

## Acceptance tests

Part (a), in `broker/clerk/devslot/`:
- `TestFixtureDriverServes`: the fixture driver serves its declared read through the slot, and its readings come out as typed, private events.
- `TestDeclarationOutsideDEV4IsRefused`: a declaration naming a verb outside DEV-4, an unknown wire-shape kind or an internet host is refused before the driver runs.
- `TestLinkReachesOnlyPinnedDevice`: the link refuses any address or characteristic that is not pinned or declared, and no socket or file reach exists beyond it.
- `TestSecretsOpenOnlyOwnSlot`: the driver's `Secrets` opens only its own `device/` slot, by lending (D-184), and a canary key appears in no log, error, event or written frame.
- `TestConformanceRejectsBadFixtures`: the suite fails a fixture that writes an undeclared shape, one that leaks the canary, and one whose parser panics under fuzzing.
- `TestCheckPathDoesNotLinkDevslot`: the KRN-2 link test shows the kernel's check path does not import `clerk/devslot` or any driver.

Part (b): under "Part (b), settled" below, per part.

**Guard files:** part (a) adds `broker/clerk/devslot/`. It is under `broker/clerk/`, which is on the G2 list, and `tools/risk_tier.py` classes an unnamed broker package tier A, so the package needs no guard edit if it imports only the standard library, `broker/kernel/key` and `broker/clerk`. If it imports anything else, `broker/daemon/arc2_test.go` is pre-approved. Part (b) names its own guard files.

Failure path: private code runs on the box unnamed or unreviewed, a driver gains a verb, a socket or another slot's key, or vendor code or a secret reaches the enforcer.

## Scope

This PR: this brief and the D-189 row in `DECISIONS.md`. Part (a): `broker/clerk/devslot/` (its own `ASSUMPTIONS.md`). Part (b): per part, under "Part (b), settled" below.

## Estimate

Part (a): one session, about 100k tokens, strongest model. Part (b): five sessions, under "Part (b), settled" below.

## Part (b), settled (2026-10-27)

Part (a) (#3356, #3371, #3376) and part (s) (#3385) are on main. This section replaces the earlier one-paragraph part (b) and folds in the part (b) notes from the #3356 reviews: L3 6433450345 point 6, Security 6433469158 points 7 and 8, Security 6433764278 points 2 and 3 (static binary, standard input), and Potency 6433452188 point 1 (subscriptions).

### The premise, corrected

The row said part (b) "waits on the device clerk host". No such row exists. `briefs/DEV-homekit.md` (b2) names DEVSLOT part (b) as that host, so the two rows waited on each other. Part (b) **is** the device clerk host. Its real outside dependency is the per-clerk key hand-off (MAIL-keys, #3419), which only b2b needs. b1 and b2a can start now, subject to the D-111 conflict guard.

### Design points settled here (recommendations, flagged for review)

1. **The driver's process is one socket-activated unit per operation, sandboxed by systemd before exec.** Each driver `<name>` gets `agentos-driver-<name>.socket` (`ListenStream=/run/agentos-drivers/<name>.sock`, `Accept=yes`, `SocketUser=` the host's user, `SocketMode=0600`) and a template service `agentos-driver-<name>@.service`. The host opens one connection per operation, so each operation runs in a fresh process that ends with it. The sandbox has to be applied before exec: Go runs every imported package's `init` before `main`, so a filter that the driver's own `main` installed would come after the driver's code had already run. The template is a fixed set of systemd's own controls:
   - `User=agentos-drv-<name>` (sysusers).
   - `RestrictAddressFamilies=none`, `PrivateNetwork=yes` and `IPAddressDeny=any`: no `socket()`. The connection arrives already open on descriptor 3.
   - `TemporaryFileSystem=/:ro` with `BindReadOnlyPaths=` of the driver's binary only, `ProcSubset=pid` and `ProtectProc=invisible`: file opens are allowed, but nothing is there to open.
   - `NoExecPaths=/` and `ExecPaths=` the binary.
   - `StandardInput=null`, `StandardOutput=null`, `StandardError=null` (the stdin point).
   - `NoNewPrivileges=yes`, an empty `CapabilityBoundingSet=`, `SystemCallFilter=@system-service` minus `@debug @mount @privileged @resources`, `SystemCallArchitectures=native`, `MemoryDenyWriteExecute=yes`, `LockPersonality=yes`, `RestrictNamespaces=yes`, `LimitCORE=0`, and `MemoryMax=`, `TasksMax=` and `CPUQuota=` within RES-2.
   - `MaxConnections=` (a stated per-driver cap, so `MemoryMax=` times the cap stays within RES-2's budget; systemd's default of 64 is never relied on), and `RuntimeMaxSec=` the operation deadline, so PID 1 kills a hung operation (L3 point 6, Security point 7). A panic in a goroutine, `Goexit` or a context-ignoring `Run` ends or hangs only that one process. The host sees the operation fail, and the next operation starts clean.

   The slot's process entry (`devslot.Main`) makes the process non-dumpable and refuses a peer on descriptor 3 whose uid is not the host's. It then serves exactly one operation. A driver binary must be static: the build refuses a dynamically linked ELF, which is Security 6433764278 point 2 (`cgo_import_dynamic`). The template is the reuse case: systemd's sandbox and not a seccomp filter of this repo's own. Rejected alternative: one long-running driver process with an in-process deadline. That process could not be killed by an unprivileged host, and a driver's data race could corrupt the deadline itself.
2. **The host re-checks everything, outside the driver's address space.** The slot (part a) runs inside the driver's process, where a data race in driver code can corrupt it (DEVSLOT-a-7). So the host (`broker/clerk/devhost`, run by `cmd/agentos-devices` under its own uid with no key) holds its own copy of the declaration and makes these checks itself, from the frames it carries:
   - the declaration it reads from the image (point 4) must equal the declaration the driver sends at start, byte for byte in canonical form;
   - every frame must match a running operation's declared shape (the frame's channel, prefix and length range);
   - frame sizes and pins;
   - every reading (a declared kind, an exponent in [-18, 18], UTC, no zone text).

   So the slot's in-process checks are a second layer. The driver reaches the device only through the host: the host owns the transport (a TCP stream whose identity key it checks against the pin, or the enforcer's GATT relay from part c). Until part c, GATT returns a fixed "no relay" error. The host is a parser of hostile bytes (driver wire frames, device frames). It carries `DEV-8`'s per-source rate limit and coalescing, and it is the only process that emits device events (b3).
3. **Each driver's key stays in that driver's process.** Each instance gets two descriptors through `OpenFile=`: the MAIL-keys per-clerk key socket (#3419), as clerk `driver-<name>`, and the driver's own sealed device-key file (`/var/lib/agentos-drivers/<name>/device`, read-only). Slot-side code opens the static slot with that key in-process and lends it through `Env.Lend` (D-184 semantics). The host never holds a driver's key, so no process holds two drivers' keys (CLK-1, risk 19). Writing the key at pairing is a later row and is not needed for b2b's tests, which use a canary. This widens the conformance suite's `slotSide` (public contract, tier A) by the key reader. That reader must link no HTTP or TLS (DEVSLOT-a-5).
4. **Driver classes come from a reviewed class row, never from the declaration (DEV-4; route B of L3 6448338949).** DEV-4 says the class comes from the kernel's table, "never from the declaration", and DEVSLOT-a-2 says the same. Signing a declaration inside the image changes who signs it, not where the class comes from. Route A would class drivers from the table by standard device type. A device with no standard type (the Withings scale) would then fall to DEV-4's conservative class, and its reads, which write request frames over opaque shapes, would land on `actuate-physical`, which defeats the slot's purpose. So:
   - `drivers.json` (in `/usr`, under verity) carries, apart from each driver's canonical declaration, a **class row** keyed by driver and operation: the operation's DEV-4 class. The row is its own reviewed artifact in the private repo, tier A and checked by the Security review (part p), and its diff is read apart from the driver's code.
   - The kernel classes a driver's operation from that row alone. The declaration's `Verb` must equal it. An operation with no row is refused, and so is one whose declared verb differs from the row.
   - **This is a SPEC change.** A one-clause L1 diff to DEV-4 says a device driver's operations are classed by its reviewed class row in the release manifest (DEV-1). The same PR updates DEVSLOT-a-2's wording. The diff is a fixed precondition of b3: b3 does not start before it merges. Whether to make it is Mark's call, on a Decisions card. If he declines, route A applies and b3's test changes to match. b1, b2a and b2b are the same under both routes. b1 carries the class row through as data either way.
5. **KRN-2's measure for drivers (#3386).** Each private PR is measured by this repo's `tools/trusted_base.py` at the pinned commit (part p). The image's manifest carries that measure per driver, so the box's trusted base is named and counted, private code included. #3386 closes when b1 and part (p) have merged. It needs no SPEC words.
6. **Home addresses (Security 6433469158 point 8).** A TCP pin refuses directed-broadcast addresses. It accepts 100.64.0.0/10 and global IPv6 addresses inside the uplink's enclosing /56, which DEV-2 counts as home. The host passes that prefix to `Check`.

### The parts

- **b1, DEVSLOT-image (tier A, one session, about 80k; can start now).**
  - `image/build.sh` takes an optional drivers directory. Each `<name>/` in it holds a static `driver` binary and an `entry.json` (repository, commit, declaration, measure).
  - The build checks each declaration with `devslot.Check`, refuses a dynamically linked binary, writes `drivers.json` (point 4), installs each binary under `/usr/lib/agentos/drivers/<name>/`, and renders the socket unit, the template service and the sysusers line from one public template.
  - `finish_image.py` copies the drivers list into `agentos_V.release.json`.
  - `mkosi.finalize` fails a build where:
    - a file under `drivers/` is not listed in `drivers.json` with its hash;
    - a driver unit differs from the template rendered for its name;
    - a unit outside the template uses `agentos-drv-*` users or the drivers' sockets.
  - Scope: `image/build.sh`, `image/finish_image.py`, `image/mkosi/mkosi.finalize`, the template under `image/mkosi/`, and `tests/test_image_drivers.py` (new). Guard files: `image/mkosi/exec.allow` if the template adds a listed file.
  - **Acceptance tests:**
    - `tests/test_image_drivers.py::test_public_build_lists_no_drivers`: the drivers list in `release.json` is empty, and no driver unit or user ships.
    - `::test_manifest_names_each_driver`: a fixture driver's entry gives its name, repository, commit, hash, declaration and measure.
    - `::test_driver_refused`: each of these fails the build: a hash mismatch, an unlisted file, a declaration that fails `Check`, a name off the alphabet, and a dynamically linked binary.
    - `::test_driver_units_are_the_template`: a rendered unit missing `RestrictAddressFamilies=none` or `MaxConnections=`, or with `StandardInput=` changed, fails the build.
- **b2a, DEVSLOT-host-lib (tier A, one session, about 120k; can start now).**
  - `devslot.Main`, the process entry: a peer-uid check, non-dumpable, one operation, and a wire codec over descriptor 3 with bounded frames.
  - `broker/clerk/devhost`: the host library. It holds the image's declaration, carries the per-operation connection, makes the re-checks (point 2), keeps each operation's deadline, and applies the DEV-8 rate limit and coalescing. Its event sink and its transports are interfaces.
  - The pin's `homeAddr` fix (point 6).
  - Scope: `broker/clerk/devslot/` (`Main`, the wire, `slotSide`, its `ASSUMPTIONS.md`) and `broker/clerk/devhost/` (new, with its own `ASSUMPTIONS.md`). Guard files: `tools/trusted_base_parsers.txt` (a `parser` line for `devhost`, with a `Trusted-base: parsers --` line in the PR).
  - **Acceptance tests:**
    - `TestHostRefusesDeclarationNotInImage`: the driver's declaration differs from the image's, or names an operation the image lacks, and nothing runs.
    - `TestHostRechecksShapes`: a fake driver speaks the wire directly, bypassing its slot, and sends an undeclared frame, an oversize frame and a frame for another channel. Each is refused, nothing reaches the transport, and the operation fails.
    - `TestHostRechecksReadings`: an undeclared kind, an exponent out of range and a zone name are each refused.
    - `TestHostDeadlineFailsOperation`: a driver silent past the deadline fails its operation, the connection is closed, and the next operation opens a new one.
    - `TestMainRefusesWrongPeer`: a peer uid that is not the host's means the process exits before `Declare`.
    - `TestMainNonDumpable`.
    - `FuzzWire`: decode is bounded and never panics.
    - `TestRateLimitCoalesces`: a flood becomes one counted, coalesced event per window (DEV-8).
    - `TestHomeAddr`: directed broadcast is refused; 100.64/10 and an address inside the uplink's /56 are accepted.
- **b2b, DEVSLOT-host-unit (tier A, one session, about 100k; after b1, b2a and MAIL-keys #3419).**
  - `cmd/agentos-devices`: the host process, under its own uid with no key. It reads `drivers.json` and serves the kernel as clerk `devices`.
  - The TCP transport, which checks the device's key against the pin.
  - The template's two `OpenFile=` lines (point 3).
  - The CI boot probe of a fixture driver instance.
  - Serial with the agentosd chain only if it edits `cmd/agentosd` (it should not).
  - Scope: `broker/cmd/agentos-devices/` (new), its unit, the driver template's key lines, and `image/ci_boot.sh` or the health check's probe. Guard files: `broker/core/core.txt` (`wiring cmd/agentos-devices`) and `tools/trusted_base_parsers.txt`.
  - **Acceptance tests:**
    - `TestTCPTransportRefusesWrongKey`.
    - `TestHostStartsOnlyImageDrivers`: an operation for a driver that is not in `drivers.json`, or whose binary hash differs from it, is refused and logged.
    - The CI boot probe: in the fixture instance, `socket()` fails, opening `/etc/passwd` fails, descriptor 0 is `/dev/null`, a hung operation is killed at `RuntimeMaxSec`, and `Lend` yields the canary key and no other slot.
- **b3, DEVSLOT-kernel (tier A, one session, about 100k; after b2a).**
  - **Starts only after the DEV-4 L1 diff (point 4) has merged.** The kernel classes driver operations from the class row in `drivers.json` (point 4).
  - A device-report entry for each event the host emits (DEV-8): private label, the unverified mark when the pin has no key, and no device text. It comes in on a kernel socket side for the host's uid only, with a closed table.
  - A start entry and a STATUS line naming each driver by name and commit (KRN-2).
  - Trusted-core growth under D-159. The approved design is Mark's tap "Retire equal words" for #3321's spec (cmsg_01R91wiieBzMSvPKFsAJVvuK9YJfqRThpR7tJsbErcC32G), whose words say "the log and STATUS name it". Its one-row D-159 PR is owed before merge.
  - Scope: `broker/kernel/`, `broker/clerk/run/` (the socket side) and `broker/cmd/agentos-kernel/` (the `-clerk devices=` flag and the start entry), checked against open kernel PRs under D-111.
  - **Acceptance tests:**
    - `TestDriverOpClassFromClassRow`: the class comes from the class row, whatever the host sends. An operation with no row is refused. A driver that declares `read` where the row says `actuate` (or any other verb that differs from its row) is refused.
    - `TestDeviceReportEntry`: one entry per event, with the private label and the unverified mark, and no zone or device text.
    - `TestDeviceSideTable`: a call outside the host's table is refused and changes nothing.
    - `TestStartEntryNamesDrivers`.
    - `TestStatusNamesDriverCommits`.
- **b4, DEVSLOT-subscribe (tier A, one session, about 60k; after b2a; class release from Potency 6433452188 point 1).**
  - A subscription operation: the instance stays up, up to a longer `RuntimeMaxSec`, after which the host re-subscribes.
  - Each reading is emitted as it arrives, through the same checks in the slot and in the host, under the host's DEV-8 limit.
  - Scope: `broker/clerk/devslot/` and `broker/clerk/devhost/`.
  - **Acceptance tests:**
    - `TestSubscribeEmitsPerReading`.
    - `TestSubscribeFloodCoalesced`.
    - `TestSubscribeEndsAtDeadlineAndResumes`.

Failure path for all five: private code that runs on the box unnamed, that runs outside its sandbox, or whose class comes from itself; a driver that reaches the network, a file, another driver's key or the enforcer; or device text or a flood of events that reaches the bus unchecked.

## Follow-up: DEVSLOT-shapes (#3363)

Release findings from the #3356 reviews (L3 6433450345 point 4, Security 6433469158 point 4, Security 6433764278 points 1-3, L3 6434260250, Security 6434263759 points 1-3). Scope: `broker/clerk/devslot/` only. Tier A (the public contract, point 5).

- **Wide shapes.** The suite fails a shape whose free tail (`Max - len(Prefix)`) is over `MaxFreeTail` (8 bytes, room for an argument or a short tag) unless the driver's tests name it in `Config.Wide`. The private review then sees each wide shape in the diff that adds its name. `Check` still accepts an empty prefix, because length-prefixed TCP framing needs a variable first byte.
- **The listing names the driver.** The suite fails a listing that lacks the driver type's package, an entry with no import path, and an entry go list marked incomplete or in error. DEVSLOT-a-7 says a forged or partial listing still passes, so the private review checks the CI command that makes it.
- **Directives.** The suite fails every `//go:` directive in driver Go files except `//go:build`. That covers `linkname`, `norace` (which hides races from the race detector) and `cgo_import_dynamic` (which loads a system library at exec).
- **Standard input.** DEVSLOT-a-7 says `fmt` can read standard input, and that the sealed process gets none.

Part b notes (L3 6, Security 7 and 8, Potency 1, the stdin point) go into part b's brief update, not this row.

Acceptance tests: `TestConformanceReportsWideShapes`; `TestConformanceRejectsBadFixtures` cases "race detector hidden", "system library at exec", "listing of another package", "listing entry with no path", "null listing", "incomplete listing" and "wide shape".

## Follow-up: DEVSLOT-tails (#3375)

Release findings from the #3371 reviews (L3 6439861920 point 1, Security 6439373630 points 1 and 3). Scope: `broker/clerk/devslot/` only. Tier A.

- **Unprefixed shapes are wide.** The suite fails every shape with no prefix, whatever its `Max`, unless `Config.Wide` names it: it admits any short command (an actuate one under a `read`), and on TCP its writes join into any stream. DEVSLOT-a-4 says the limit is per write.
- **A listing missing a dependency fails.** The suite fails a listing that lacks any import of a listed non-standard package outside the slot, so a listing made without `-deps` reads as a failure.

Acceptance tests: `TestConformanceReportsWideShapes` (the unprefixed `short` shape of `MaxFreeTail` bytes); `TestConformanceRejectsBadFixtures` case "listing without -deps".
