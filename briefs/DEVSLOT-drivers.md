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
   - This repo exports `broker/clerk/devslot/conformance`, a test suite every driver must pass. The suite checks that a declaration uses DEV-4 verbs only, that the driver writes nothing but declared shapes, that every parser is fuzzed with bounded buffers, and that a canary secret never leaves the driver.
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
- **(b)** The host and the image: start only manifest-listed drivers whose hash matches; the build's drivers directory and the `release.json` drivers list (`image/build.sh`, `image/finish_image.py`); the kernel's start-up log entry and the STATUS line. It needs the device clerk host. The device-agnostic parts of the dropped #3293 land here. It is serial with the agentosd chain (D-111), and the kernel log entry needs a `Trusted-core:` decision of its own.
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

Part (b): `TestHostStartsOnlyManifestDrivers` (a binary that is unlisted or has the wrong hash is refused and logged), `TestStatusNamesDriverCommits`, and a `finish_image` test showing that the public build's manifest lists no drivers and a build with one lists its name, repository, commit and hash.

**Guard files:** part (a) adds `broker/clerk/devslot/`. It is under `broker/clerk/`, which is on the G2 list, and `tools/risk_tier.py` classes an unnamed broker package tier A, so the package needs no guard edit if it imports only the standard library, `broker/kernel/key` and `broker/clerk`. If it imports anything else, `broker/daemon/arc2_test.go` is pre-approved. Part (b) names its own guard files.

Failure path: private code runs on the box unnamed or unreviewed, a driver gains a verb, a socket or another slot's key, or vendor code or a secret reaches the enforcer.

## Scope

This PR: this brief and the D-189 row in `DECISIONS.md`. Part (a): `broker/clerk/devslot/` (its own `ASSUMPTIONS.md`). Part (b): the host package, `image/build.sh`, `image/finish_image.py` and its tests, and the kernel start-up entry, as part (b)'s own brief update names them.

## Estimate

Part (a): one session, about 100k tokens, strongest model. Part (b): one session, about 120k tokens, after the device clerk host.
