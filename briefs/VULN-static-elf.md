# VULN-static-elf: every static ELF the image ships is declared, and image-vulncheck scans what it links

Board section: Defects and later findings on surviving packages. SPEC EVL-5. Issue #5885, split from #5873 (VULN-static-check, `briefs/VULN-static-check.md`), which built the half for pinned downloads (`assurance/vulncheck.json` "bundled").

**Sources:** #5873's brief; #5872's Security 6902369509 and L3 6902377665; #5873's Potency item 6902429342 (the DEBIAN-CVE-2026-125709 image record says turning `-infer` on reopens llama-server's static libstdc++ reach).

**Gap.** `image/llamaserver.sh` links `/usr/lib/agentos/infer/llama-server` with `-DCMAKE_EXE_LINKER_FLAGS=-static` against the build runner's Ubuntu 24.04 `libstdc++.a` and `libc.a`, not Debian's. `tools/vulncheck.py image` scans each tree's dpkg status only, so an advisory against that copy passes silently, and no check finds the next static binary that ships unscanned. The guests' bwrap (`guest/codex/build-rootfs.sh`) and `agentos-camdecode` (`image/camdecode.sh`) already close this for themselves: each is linked inside the guest base (`image/guest-base.sh`, the image's pinned Debian sources) with a link map, and every `LOAD` input is recorded as shipped (`image/guest-shipped.sh`, #5572, #5599), so its Debian packages are scanned.

**Design (recommendation, taken as the brief's choice).** Reuse that pattern rather than teach the scan a second ecosystem. Rejected: recording the runner's Ubuntu packages and querying OSV's `Ubuntu:24.04` ecosystem, which adds an os-release per declaration, a second advisory source and a toolchain that moves weekly with the runner image, for one binary.

## Two parts, one session each, in order

### Part a: llama-server is linked from the image's Debian toolchain and scanned in the main tree

- **SEL-1:** `image/llamaserver.sh` builds inside a base root from `image/guest-base.sh` by chroot with a clean environment, as `image/camdecode.sh` does: compiler, `libstdc++.a`, `libc.a` and cmake are the base's, never the build host's (the base's `--include` gains `g++` and `cmake`, and whatever else the build needs; its `dpkg-query` line names them). The link writes a map (`-Wl,-Map=…`); every `LOAD` input from outside the build directory is recorded with `guest-shipped.sh BASE PATH…` into a list of its own (`GUEST_SHIPPED` set to the main tree's list, not the guests'), and the build stops on an input no package owns or a map that loads nothing. The existing checks stay: static (no `INTERP`), CPU only, nothing fetched, build info from the pins.
- **SEL-2:** `image/build.sh` writes that list's status with `guest-shipped.sh --status BASE OUT/linked` (`agentos.dpkg-status` and `agentos.os-release`), and image.yml's Release record copies `out/linked` into `rec`. `vulncheck.py image` scans `rec/linked` as part of tree `image` (records with `where` "image" apply, findings carry `where` "image"); a missing or empty `linked` status fails closed (exit 2), as a missing guest status does.
- **SEL-3:** the DEBIAN-CVE-2026-125709 image record's `why` is rewritten to the new fact (llama-server's libstdc++ is now Debian's gcc-14 `libstdc++-14-dev`, scanned), and `tests/test_image_infer.py`'s leaves-infer-off test names DEBIAN-CVE-2026-125709 in its message, so turning `-infer` on points at the record to redo (Potency 6902429342).
- **SEL-4:** `.github/workflows/infer-real.yml` builds the same way (guest-base.sh first, then llamaserver.sh with the base), so its real test still runs the build the image ships.

### Part b: a check that finds every static ELF in every tree and holds it to a declaration

- **SEL-5:** a new `image/static_elf.py OUT VERSION` (as root; reuse `image/import_sweep.py`'s tree walk by import: `run_build`, `tree_files`, `initrd_place`, without editing it, since #5889 holds that file) lists every ELF in the main tree (root and `/usr`, the guests' roots under `/usr/lib/agentos/images/` included) and in each initrd that is static (no `PT_INTERP` and no `DT_NEEDED`; `finish_image.static_refusal` reads the first), or dynamic but carrying a static libstdc++ (it defines libstdc++'s code, such as `__cxa_throw` or `_ZNSt…` in `.text`, and no `DT_NEEDED` names `libstdc++`).
- **SEL-6:** each listed file matches exactly one entry of `image/static_elf.allow` (glob, kind, argument); an unlisted file, a file matching two entries and an entry matching nothing each fail. Kinds:
  - `go`: a Go binary whose build info says `CGO_ENABLED=0` (read from the file, not assumed): links no C library. A Go binary with cgo on is not `go`.
  - `linked LIST`: a build step recorded the file's link inputs (SEL-1's main-tree list, or the guests' `GUEST_SHIPPED`); the build writes, per file, the packages its map loaded, and the check fails unless each is in the status the scan reads for that list. bwrap, `agentos-camdecode` and llama-server are this kind, so `guest/codex/build-rootfs.sh` and `image/camdecode.sh` also write their per-file input lists.
  - `package`: owned by a package in its tree's dpkg status (from the build's `agentos.dpkg-md5sums` or file lists), such as libc-bin's `ldconfig`; the scan also queries each source the package's `Built-Using` field names, as part of the same tree.
  - `bundled HOLDER`: a pinned download's binary that `assurance/vulncheck.json` "bundled" names by holder (the codex guest's two musl binaries). Their static musl libc: the builder checks whether a version string is recoverable; if so it becomes a bundled `copy` with an upstream in `vulncheck.py`'s table, if not that is a release finding.
- **SEL-7:** control: the check fails when the main tree yields none of llama-server, `runsc`, `agentos-camdecode` or `ldconfig`, so a clean result is not a walk that read nothing; it fails on an ELF it cannot read.
- **SEL-8:** image.yml runs it in the build job (matrix run a, beside the import sweep), and fails the build on any SEL-6 or SEL-7 failure.

**Acceptance tests:**
- SEL-1: `tests/test_image_infer.py::TestInferImage::test_the_server_is_linked_in_the_base_and_records_its_inputs` (new): the script chroots into the base with a clean environment, links with a map, records every outside `LOAD` line through guest-shipped.sh, and stops on an empty map; plus the existing `test_the_server_is_static_cpu_only_and_fetches_nothing` and `test_the_build_info_comes_from_the_pins_never_from_git` kept green. `tests/test_image_repro.py` guest-base test updated for the include list.
- SEL-2: `tests/test_vulncheck.py` (new case in the image scan tests): a planted advisory on a package only in `linked` fails under `where` "image"; the image record accepts it; a missing or empty `linked` status raises ScanError; the control's `CONTROL_FAILS` gains the plant.
- SEL-3: `tests/test_image_infer.py::TestInferImage::test_the_unit_names_the_pinned_model_and_leaves_infer_off` names the CVE; `vulncheck.py run --check-issues` passes with the rewritten record.
- SEL-4: `infer-real.yml`'s run, and a test pinning that it runs guest-base.sh before llamaserver.sh (`tests/test_image_infer.py`, new).
- SEL-5, SEL-6, SEL-7: `tests/test_image_static_elf.py` (new), on fixture trees built in the test (a tiny static C program, a dynamic one, a Go binary with cgo off and one with cgo on, a dynamic C++ program with `-static-libstdc++`): each is listed or not as SEL-5 says; each SEL-6 failure (unlisted, two matches, unmatched glob, `go` on a cgo binary, `linked` with a package missing from the status, `bundled` naming no holder) is named; the control fails on a tree missing a required file.
- SEL-6 `package` `Built-Using`: `tests/test_vulncheck.py`: a planted advisory on a `Built-Using` source fails in that tree.
- SEL-8: the build job's step on the real image (CI), and a test that image.yml runs the step in run a (`tests/test_image_static_elf.py`).
- EVL-5: image.yml's image-vulncheck job on the built image with the live records.

**Scope:**
- Part a: `image/llamaserver.sh`, `image/infer.sh`, `image/build.sh`, `image/guest-base.sh` (include and dpkg-query lines only), `.github/workflows/image.yml` (Release record step), `.github/workflows/infer-real.yml`, `tools/vulncheck.py`, `tests/test_vulncheck.py`, `tests/fixtures/vulncheck/`, `assurance/vulncheck.json` (the DEBIAN-CVE-2026-125709 image record only), `tests/test_image_infer.py`, `tests/test_image_repro.py`, one row in `image/ASSUMPTIONS.md`, this brief.
- Part b: `image/static_elf.py`, `image/static_elf.allow`, `tests/test_image_static_elf.py`, `.github/workflows/image.yml` (one new step), `image/camdecode.sh` and `guest/codex/build-rootfs.sh` (per-file input lists only), `tests/test_camdecode_build.py`, `tests/test_guest_bundled.py`, `tools/vulncheck.py`, `tests/test_vulncheck.py`, `tests/fixtures/vulncheck/`, `assurance/vulncheck.json` (bundled `copy` only, if SEL-6 finds a musl version), one row in `image/ASSUMPTIONS.md`.

**Guard files:** none (no broker package added or linked).

**Dependencies and order (D-111):** both parts touch `image.yml`, and part a `image/build.sh` and `image/guest-base.sh`, which open PR #5932 (IMG-keyring-pin) changes: part a starts after #5932 merges. #5889 (VULN-cipher-sweep-tidy-2) also edits `image.yml` (its path filters) and holds `image/import_sweep.py`: whichever of #5889 and this row starts first runs alone on `image.yml`; part b imports `import_sweep.py` and never edits it. Part b starts after part a merges.

**Lifecycle:** build time only; nothing runs on the device at boot, update or removal. Integration owner: part a (the build path and the scan); part b adds the gate.

**Recurring kinds:** Security "a guard fails open on a missing or invalid value": a missing `linked` status, an empty link map, an unreadable ELF and an empty walk each fail closed with a test. Potency "a brief's declared scope omits the test files the change forces": the test files are listed above.

**Gate:** tier A (`image/`, `tools/vulncheck`, `assurance/`, `.github/`; `tools/risk_tier.py`). Gate files `image.yml`, `infer-real.yml`: `premerge.py --needs-mark` prints `mark`, so each part needs L3 on the strongest model, Potency, and a separate Security accept. Builder on Opus.

**Estimate:** part a under 130k tokens; part b under 130k.
