# VULN-static-elf-tighten: guest-root and initrd package files bound to their bytes; Go read from section headers; .syso C code seen

Board section: Defects and later findings on surviving packages. SPEC EVL-5. Issue #6482, release findings from #6437 (VULN-static-elf part b, `briefs/VULN-static-elf.md` SEL-5 to SEL-8).

**Sources:** #6437's Potency 7068815856 point 4 and L3 7068815628 points 4a and 4b.

## Requirements

- **SET-1 (`package` bytes, guests' roots):** `image/guest-userland.sh` records, for every file it copies from the base, the package whose dpkg md5sum equals the copied bytes (`image/guest-shipped.sh` with `SHIPPED_BYTES=1`: "MD5 PACKAGE" lines, moved by `--status` to `OUT/guest/agentos.md5sums`); the copy fails when no owner's md5sums list those bytes at that path. `image/static_elf.py` refuses a guest-root file declared `package PKG` unless its shipped bytes' MD5 is recorded for PKG; a missing record refuses.
- **SET-2 (`package` bytes, initrds):** an initrd member declared `package PKG` must have the main tree's dpkg md5sum at its path, and PKG must be at the same version in the initrd's status as in the main tree's (both are installed from the image's one set of pinned sources); a differing or missing version refuses. No file is added to the initrd.
- **SET-3 (Go from section headers):** a file is Go only when its section header table names `.gopclntab`; build info is read only from the `.go.buildinfo` section's start. A table the check cannot read is an unreadable file (SEL-7). A C binary holding the bytes `\0.gopclntab\0` or the build-info magic elsewhere is not Go.
- **SET-4 (.syso C code):** a Go binary whose function table (`.gopclntab`, Go 1.18 and later formats) lists a function with no line table, other than the linker's own `go:` markers, holds C code linked without runtime/cgo, and `go` refuses it. Externally linked C still needs cgo (Go refuses `-linkmode=external` with cgo off), which `CGO_MARK` keeps catching. Checked on the pinned releases: gVisor release-20260928.0's four Go binaries and esbuild 0.28.2 list no such function.

**Acceptance tests:**
- SET-1: `tests/test_guest_userland.py` (staged base with md5sums: a recorded copy, a copy whose bytes differ from dpkg's failing); `tests/test_image_static_elf.py::StaticElfTest::test_guest_and_initrd_package_files_are_held_to_their_bytes` (new).
- SET-2: the same new test (initrd member with other bytes, other version, missing version).
- SET-3, SET-4: `tests/test_image_static_elf.py::StaticElfTest::test_go_is_read_from_section_headers_and_syso_c_code_is_seen` (new): a C binary carrying both marker strings is not Go; a Go binary with a `.syso` C function and cgo off is refused by `go`; a truncated section table is unread.
- EVL-5: image.yml's build job (run a) runs `static_elf.py` on the real image with no refusal.

**Scope:** `image/static_elf.py`, `image/guest-userland.sh`, `image/guest-shipped.sh`, `tests/test_image_static_elf.py`, `tests/test_guest_userland.py`, `image/ASSUMPTIONS.md` (row VULN-static-elf-2), this brief.

**Guard files:** none.

**Dependencies (D-111):** open #6382 edits `image/static_elf.py`'s docstring line 16 and `classify`'s `read_elf` call; this row leaves those lines alone, so whichever merges second takes a clean textual merge.

**Recurring kinds:** Security "a guard fails open on a missing or invalid value": a missing md5 record, a missing initrd version, an unreadable section table or function table each refuse. A Go PIE (no `.gopclntab` section) is not read as Go, so `go` refuses it.

**Gate:** tier A (`image/`). Not a gate file unless `premerge.py --needs-mark` says so. L3 on the strongest model, Potency, and Security.

**Estimate:** under 120k tokens.
