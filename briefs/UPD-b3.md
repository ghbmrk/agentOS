# UPD-b3: first-boot update, image side: the shipped root, the mirror list and the real activator

Work item #889 (SPEC UPD-3, UPD-1, UPD-1a, UPD-2, UPD-8; `broker/firstboot/ASSUMPTIONS.md` F8). Tier A (`broker/update`, `broker/apply`, `image/`). Written 2026-10-29 against main at fb95c8e.

## Why

UPD-3: before any AI or personal account is connected, the box fetches the latest stable release, verifies it and activates it through A/B with fallback. The gate that holds setup (`broker/firstboot`), the TUF verifier (`broker/update`) and the applier (`broker/apply`) exist and are tested with fakes. Three things the image must supply do not exist (F8):

1. **The root of trust.** `update.InitStore(dir, root, installed)` needs the TUF root metadata and the image's own release version. Nothing ships either, and nothing calls `InitStore` outside tests and `agentos-release`.
2. **Somewhere to fetch from.** The gate takes `Mirrors func() []update.Source`, and the only `Source` is `DirSource` (a drive, DEP-4). There is no network source and no list of mirrors.
3. **A real activator.** `apply.Activator` has only the test fake. `image/ci_boot.sh` (forced-fail fallback) notes that "slot B holds none until an updater writes one".

## What changed since the row was filed

- **D-139.** `broker/apply` and `broker/update` survived the cut. The applier now submits plans to the capability kernel (`broker/kernel`, MIG-4-adapters), and neither directory is in `tools/old_core.txt`. `broker/durable` is old core, though: new code here adds no import of it, and `update.Store` already owns every durable write the seed needs.
- **Wiring moved.** UPD-b2 (#888, wire the gate into agentosd) now waits on the kernel start-up slice #2682, because agentosd is being dismantled. So this brief builds and proves the image-side pieces and does not wire them into a running service. **The integration owner is #888.** It constructs the gate, the applier, the seeded store, the mirror sources and this activator in the kernel start-up, and it owns the running-path matrix (below).
- **#2094 was closed with D-139, but its two findings still bind a real activator.** They are kept in `docs/migration/cases.md` §7 and are part of slice (b). The closure stopped old-core work; it did not settle them.
- **The ARC-2 rule shapes the packages.** `broker/update` is in the control path's dependencies (`change` and `agentosd` import it), and `broker/daemon/arc2_test.go` forbids `net/http`, `crypto/tls` and `os/exec` anywhere in those dependencies. So the network source and the activator are new packages that the control path never imports: `broker/update/mirror` and `broker/apply/bootab`. Only the process that hosts the applier links them (#888).

## Decided here (engineering choices within SPEC; no Mark choice needed)

- **Activator: Go over a cut-checkable disk interface, not `systemd-sysupdate`.** The earlier reuse table (docs/LATER-HISTORY.md, UPD-b) named sysupdate, but it fits poorly. sysupdate downloads and checks bytes on its own trust model (a GPG-signed SHA256SUMS), so `Install` would no longer read "only through `v.Fetch`" (apply A4). Its ESP steps are also a black box, so `activatortest.Check` cannot cut between them (A12(4)). **Reused instead:** systemd-boot's boot counting and `systemd-bless-boot` (already in the image), `veritysetup verify` (as `finish_image.py` uses it), and the Boot Loader Interface EFI variables, read and written by the documented names. The PR states this in a line under Reuse.
- **Version number.** A TUF release version is an `int64` (`update.Manifest.Version`), while `image/build.sh`'s VERSION is `YYYYMMDD.HHMMSS`. The update version is VERSION with the dot removed (`YYYYMMDDHHMMSS`). It fits in an int64 and keeps build.sh's commit-time order. build.sh computes it once and writes it into the seed. `agentos-release add-release -version` takes the same number.
- **The root and the mirror list are build inputs, never committed.** No project TUF repository exists yet (no root keys, so there is no key ceremony to point at; see Outside this brief). `image/build.sh` takes `AGENTOS_UPDATE_ROOT` (a root metadata file) and `AGENTOS_UPDATE_MIRRORS` (a mirror list), and it fails when either is missing or does not parse. CI's image job makes a throwaway repository with `agentos-release init` from keys it generates and then deletes. Its root is the CI image's, and its mirror list names `https://updates.invalid/`, which never resolves. A CI image can therefore never be updated from the network, which is the safe side. The drill in slice (c) updates it from a drive instead.

## Lifecycle: stage by outcome

| Stage | Outcome this brief guarantees | Proved by (slice) | Running-path owner |
|---|---|---|---|
| Image build | `/usr/share/agentos/update/{root.json,seed.json}` present, root verifies against itself, `seed.json` version equals build VERSION's number; build fails without either input | a | — |
| First boot, empty store | `update.Seed` initialises the store once from the shipped files | a | #888 calls it at start |
| Any later boot | `Seed` opens the existing store and never re-initialises it. A store whose `root.json` is missing or does not parse stops the start; it is not overwritten from `/usr` | a | #888 |
| Online check | each mirror in the shipped list is an HTTPS `update.Source`; redirects only to that mirror's listed hosts; no proxy, cookies or credentials | a | #888 passes the netguard dialer |
| Offline / drive | `DirSource` unchanged (DEP-4) | — | firstboot F6 |
| Install N+1 booted on N | inactive slot written, verity-verified against `usr_root_hash`, entry counted `+3`, made next boot; running slot never written | b (model), c (real disk) | #888 via applier |
| Power cut mid-Install | `activatortest.Check` cut cases pass on the real adapter's model | b | — |
| Restart, health passes | slot B boots, `systemd-bless-boot` blesses it, `Booted()` reports N+1 blessed | c | applier `Resume` (#888) |
| Restart, health fails | boot counting falls back to N with no owner action; `Booted()` reports N | c | applier `Resume` (#888) |
| Install N+2 booted on N+1 | overwrites N's slot, never N+1's | b, c | #888 |
| Owner pinned an entry with `d` (EFI `LoaderEntryDefault`) | Install's default write wins or clears the variable (#2094 point 2) | b, c | — |

## Slice (a): the seed and the mirror source (startable)

#3880 (the image-queue PR that edited `image/build.sh`, `image.yml` and the image tests) has merged, so this slice is startable; run the D-111 check at start.

1. **`update.Seed(dir, shipped string) (*Store, error)`** in `broker/update/seed.go`. If `dir/root.json` exists, it returns the store as it is, after checking that `root.json` parses as root metadata. It never writes in that case, and a missing `installed.json` beside an existing root is an error. Otherwise it reads `shipped/root.json` and `shipped/seed.json` (`{"version": N}` with N ≥ 1, unknown fields refused, size bounded like `maxMetadata`) and calls `InitStore`. The shipped files are read with no-follow, as regular files owned by root and not group- or world-writable. Under `/usr` that holds by construction, but tests pin it so that a writable copy is never trusted.
2. **`broker/update/mirror`** (new package). It provides `Parse([]byte) ([]Mirror, error)` and `(Mirror) Source(c *http.Client) update.Source`. Format: one mirror per line, `https://host[:port]/base/` followed optionally by `redirect=host1,host2`. `#` starts a comment. There are at most 16 mirrors; the base must end in `/` and carry no query, fragment or userinfo. An `http:` mirror is refused, and so is anything that does not parse, with the line number. `Open(name)` validates `name` with the store's own path rule (export `update.ValidTargetPath`; do not copy it). It joins the path under the base and issues a GET with no cookies or `Authorization`. It follows at most 3 redirects, each to `https` on the mirror's own host or a listed `redirect=` host; anything else is an error. A non-200 answer is an error that names the status. The caller supplies the client's `DialContext` and roots (#888 passes netguard's policy, as `clerk.guarded` does). The package itself does not import `netguard`, so it stays testable with `httptest`. Size limits stay where they are: the store bounds metadata, and `Verified.Fetch` checks length and hash.
3. **Image.** `image/build.sh` installs the two inputs as `/usr/share/agentos/update/root.json` and `/usr/share/agentos/update/mirrors`, and writes `/usr/share/agentos/update/seed.json` with the version number. It refuses inputs that `agentos-release verify -root` (or a small Go check built beside it) cannot parse. `.github/workflows/image.yml` generates the throwaway repository before the build and deletes the keys. The image ASSUMPTIONS row records the version mapping, and that a CI image's root is throwaway.
4. **The mirror hosts are destinations.** NET-2 lists signed updates among the core's declared destinations. The enforcer's signed list must therefore admit the shipped mirror hosts and their `redirect=` hosts at first boot (§12.1 step 3). That list lives on the enforcer and is outside this scope. Filed as #3925.

**Acceptance tests:** slice (a).
- UPD-3, UPD-8 (seeded once): `broker/update/seed_test.go::TestSeedInitialisesOnceAndNeverOverwrites`. The first call initialises the store from a shipped root and version. A second call with a different shipped root leaves `root.json` byte-equal to the first. A rotated root (via `rotateRoot`) survives a reboot-style re-Seed. Catches a box that re-trusts the shipped root after rotating away from it.
- UPD-8 (refuse damage): `::TestSeedRefusesDamage`. The test covers a store root that does not parse, a missing `installed.json`, a shipped root that does not self-verify, `seed.json` with version 0 or an unknown field, and a shipped file that is a symlink or group-writable. Each is an error, and nothing is written. Catches a silent reinitialisation that would drop a rotation or rollback floor.
- UPD-2 (mirror parse): `broker/update/mirror/mirror_test.go::TestParse`. It accepts the valid forms and refuses `http:`, userinfo, a query, a missing trailing `/`, a 17th mirror and a bad `redirect=` host, each with its line number. Catches a list that sends a box to cleartext or to a credentialed URL.
- UPD-2 (fetch confinement): `::TestSourceFollowsOnlyListedRedirects` (`httptest` TLS servers). The source fetches a file under the base. It follows a redirect to a listed host, and refuses one to an unlisted host, to `http:`, past 3 hops, and a `..` or hidden path name. Catches a mirror that redirects the box to a destination the enforcer list did not declare.
- UPD-2 (whole path): `::TestStoreChecksThroughAMirror`. `updatetest`'s fixture repository is served over `httptest`, and `Store.Check` through `Source` verifies a release. Catches a source that mangles names or bodies.
- UPD-3 (image carries it): `tests/test_image_update_seed.py`. The test checks that `build.sh` installs the three files and fails without either input, that `seed.json`'s number equals VERSION without the dot, and that `image.yml` deletes the throwaway keys. Catches an image with no root, or a CI key left in an artifact.

**Scope (a):** `broker/update/{seed.go,seed_test.go,store.go (export ValidTargetPath only),ASSUMPTIONS.md}`, `broker/update/mirror/` (new), `image/build.sh`, `image/ASSUMPTIONS.md`, `.github/workflows/image.yml`, `tests/test_image_update_seed.py` (new), and `tests/test_image.py` only where it pins the `/usr/share/agentos` tree. **Guard files:** `broker/daemon/arc2_test.go`, only if its package classification needs an entry for `update/mirror` (it must not be added to any control-path import list). Tier and gate list are already covered by the `update` prefix (`tools/risk_tier.py` `parts[1]`, `tools/g1_scope_g2.txt` `allow broker/update/`). Gate-file PR (`image.yml`): it needs the separate Security accept.

**Usage estimate (a):** about 100k tokens, one session. Checkpoint at 70k: `go test ./update/...` green.

## Slice (b): the activator over the model (startable now; disjoint from (a))

1. **activatortest fits a real adapter (#2094).**
   - (1) A slot is whole when its written bytes hash to the release's image digest, compared through `ReadSlot`, not when its bytes equal the `UsrRootHash` string.
   - (2) The model gains the loader's effective default. An EFI `LoaderEntryDefault` value overrides the `loader.conf` default, as systemd-boot does. `SetDefault` must leave the requested entry as the effective selection: it writes the variable, or writes `loader.conf` and clears the variable. A new cut case starts with the variable pinning N-1 and requires that an uncut Install of N+1 leaves N+1 effective. `Disk.SetDefault`'s doc comment says this.
   - (3) A slot is the pair of partitions it is on the disk (data and verity) with their partition UUIDs and labels. Writing either partition, and setting the UUIDs and label, are cut steps. The existing cases keep passing, and wholeness requires both partitions plus UUIDs that match the root hash (see c.2).
2. **`broker/apply/bootab`** (new package): `New(d Disk) apply.Activator`, written against an interface with the extended `activatortest.Disk` method set.
   - **`Install`** runs in A12's order. It finds the inactive slot (not booted, whatever the store says). If that slot's entry is blessed, it removes the entry and makes the running root's entry effective, durably (ESP synced). It then writes the data and verity partitions only from files `v.Fetch` placed in a private staging directory, and syncs them. A `Verifier` hook (`veritysetup verify` in production, (c)) must pass against `UsrRootHash` before the entry is written. The entry is `agentos_<version>+3.conf`, with `usrhash=` equal to the root hash; it is written as the next boot (`LoaderEntryOneShot` is not used; counting is the fallback) and synced.
   - **`Abandon`** makes the running root's entry effective again and removes the counted entry.
   - **`Booted`** reads `LoaderEntrySelected`, the running `usrhash=` from `/proc/cmdline` and whether the selected entry still has a try counter.
   - **`Restart`** is a hook (`systemctl reboot` in production).
   - Blessing stays `systemd-bless-boot`'s (A12(1)); this package never renames an entry to bless it.
3. The fake in `broker/apply`'s tests stays. `bootab` gets its own `activatortest.Check` run.

**Acceptance tests:** slice (b).
- UPD-1, UPD-1a (A12 (3), (4)): `broker/apply/bootab/bootab_test.go::TestCheck` runs `activatortest.Check(t, bootab.New)`. Catches a real activator that writes the booted slot or leaves a torn default.
- UPD-1a (wholeness, #2094 point 1): `broker/apply/activatortest/disk_test.go::TestWholenessIsTheImageDigest`. An activator that writes the root-hash string, or a short image, fails `Violations`. Catches the false pass the finding named.
- UPD-1 (effective default, #2094 point 2): `::TestPinnedEFIDefaultIsOverridden`. An activator that writes only `loader.conf` while `LoaderEntryDefault` names N-1 fails. Catches a box that never boots the release it says it will.
- UPD-1a (no unverified entry, A4): `bootab_test.go::TestNoEntryWithoutVerify`. When the verifier fails, or a fetched file's length or hash differs, no counted entry exists and the inactive slot is not the next boot. Catches a short write that gets a counted entry.
- UPD-1 (`Booted`): `::TestBootedReadsTheLoader`, which reads selected entry, `usrhash` and blessed state from fixture efivars and cmdline. Catches an applier `Resume` that commits a boot that fell back.

**Scope (b):** `broker/apply/activatortest/`, `broker/apply/bootab/` (new), `broker/apply/ASSUMPTIONS.md` (A4 and A12 point at `bootab`). **Guard files:** `broker/daemon/arc2_test.go`, only if it needs an entry; `bootab` is not imported by the control path. No `image/` file, no `cmd/agentosd` file.

**Usage estimate (b):** about 120k tokens, one session. Checkpoint at 80k: `activatortest` changes green against the fake, and `TestCheck` is red only on cases not yet built.

## Slice (c): the disk adapter and the boot drill (after a and b; image queue)

1. **Production adapter** (`broker/apply/bootab/disk_linux.go`). It maps each Disk method to its real operation:
   - ESP files under the mounted ESP, written with temporary file plus rename, and `syncfs` on the ESP for `SyncESP`;
   - EFI variables through efivarfs, clearing the immutable attribute first, as `bootctl` does;
   - slots as the GPT partitions labelled `agentos_*` or `_empty` with the `usr` and `usr-verity` types, written with `O_DIRECT` or `fsync`;
   - partition UUIDs and labels through `sfdisk` or `systemd-repart`, whichever the image already ships (the builder checks; no new package);
   - the verifier as `veritysetup verify`.
   It never follows a symlink, and it refuses a partition that is booted or mounted.
2. **Partition UUIDs.** The builder confirms from systemd's documentation (repart `Verity=` and the Discoverable Partitions Specification) how the initrd finds the `/usr` data and verity partitions for a given `usrhash=`. The expected answer is UUIDs derived from the root hash: the first 128 bits for the data partition and the last 128 bits for verity. The adapter sets them before the entry is written. The image ASSUMPTIONS row cites the source.
3. **Boot drill in CI** (`image/ci_boot.sh`, image job; REQ UPD-1, UPD-1a, UPD-3):
   - The job derives a variant release from the built image: the same `/usr` tree plus one marker file, repacked with `mkfs.erofs` and `veritysetup format` to get a new root hash and entry. It publishes the variant as version N+1 in the throwaway repository and puts that repository on a read-only 9p share (the DEP-4 drive path).
   - A CI-only driver (`broker/apply/bootab/testdata/updatedrill`) runs in the booted image. It calls `update.Seed`, then `Store.Check` against the share as a `DirSource`, then `bootab.Install`, then `Restart`.
   - The next boot must report the variant's root hash, blessed, in `agentos-boot-report`'s line.
   - A second variant whose health check fails (the existing forced-fail hook) must fall back to N+1 with no owner action.
   - This proves the image-side pieces together. It does not stand in for #888's applier path.

**Acceptance tests:** slice (c). `image/ci_boot.sh` step `UPDATE` with `has` lines for the variant's `bless=` and root hash on the second boot, and the fallback root on the third. Static tests in `tests/test_image_update_drill.py` pin the step, the driver build line and the 9p share as read-only. `bootab/disk_linux_test.go` (root, loop device, run in the image job) covers each adapter method against a scratch GPT image, including refusal of the booted partition and of a symlinked ESP path. Each catches the property its row in the matrix names.

**Scope (c):** `broker/apply/bootab/{disk_linux.go,disk_linux_test.go,testdata/updatedrill/}`, `image/ci_boot.sh`, `.github/workflows/image.yml`, `image/ASSUMPTIONS.md`, `tests/test_image_update_drill.py` (new). Gate-file PR: it needs the separate Security accept. **Guard files:** none beyond (a) and (b).

**Usage estimate (c):** about 140k tokens, one session. Checkpoint at 90k: the adapter's loop-device test green. If the drill's variant repack cannot fit, split it into (c1) adapter and (c2) drill before starting.

## Outside this brief (filed; not built here)

- **#3925 (release, enforcer track):** the enforcer's first-boot destination list must admit the shipped mirror hosts and their redirect hosts (NET-2), or the first-boot update can never reach a mirror. Failure path: a preloaded box online behind the enforcer holds at "updating" forever.
- **#3926 (release, publishing):** the project's live TUF repository needs a host, a scheduled snapshot and timestamp refresh, and a production build that passes the real root and mirror list. HW-10 and DEP-2 point at GitHub Releases (the `/usr` image is about 1.1 GiB, under the 2 GiB asset limit). Failure path: every shipped box has a root nobody can sign for.
- **Mark only, before the first public release (not before this build):** custody of the root and targets keys, which is SPEC open risk 6 (UPD-2). This build uses only throwaway CI keys.

## Recurring kinds (reviews/security and reviews/potency READMEs), as acceptance criteria

- **A guard fails open on a missing or invalid value** (security). Every refusal in the matrix and the slice lists has its own test, and an absent input (no seed, no mirror list, an unreadable EFI variable) refuses rather than defaulting.
- **A root-side file operation follows a planted link** (security). The seed reader, the staging directory, the ESP writes and the slot device opens are no-follow, and each has a link test.
- **A defence can be reverted and the suite still passes** (potency). The PR lists a revert mutant for each guard and the test that catches it: redirect host check, Seed's no-overwrite, verify-before-entry, and the running-slot refusal.
- **A brief's declared scope omits the test files the change forces** (potency). If a test file outside the scopes above must change, the builder names it in the PR, and the reviewer judges it against this line rather than as scope creep.
