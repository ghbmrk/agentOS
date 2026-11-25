# VULN-static-elf-go-entry: a `go` file runs only code its function table lists

Board section: Defects and later findings on surviving packages. SPEC EVL-5. Issue #6563, release findings from #6554 (VULN-static-elf-tighten, `briefs/VULN-static-elf-tighten.md` SET-3, SET-4), Security 7091899582 items 1 to 3.

## Requirements

- **SGE-1 (external link, item 1):** `cmd/link` takes `-linkmode=external` with cgo off (a warning; only `go build` refuses), so glibc's crt and C from a `.syso` reach a Go binary outside its function table and with no `CGO_MARK`. `image/static_elf.py` `go_outside` refuses a `go` file unless `.text` is its only executable section, every executable `PT_LOAD` segment ends at `.text`'s end and starts at or before its start, the table starts at `.text`'s start and ends within `TEXT_SLACK` of its end (the stored text start, where Go before 1.26 stores one, equal to `.text`'s address), and the entry point lies in a listed function with a line table. The `CGO_MARK` comment and the `go` kind's docstring no longer say Go refuses that link.
- **SGE-2 (forged table, item 2):** a table listing no function refuses; a `.gopclntab` added to a static C binary fails SGE-1's checks.
- **SGE-3 (markers, item 3):** `no_line_funcs` exempts exactly `GO_MARKERS` (`go:textfipsstart`, `go:textfipsend`: the only `go:` text symbols cmd/link of go1.22.12 to go1.26.8 gives a static executable), not every `go:` name.

Checked on the pinned releases: gVisor release-20260928.0's five Go binaries (`runsc`, `gvisor_sentry`, `checkpointgofer`, `runsc-metric-server`, `containerd-shim-runsc-v1`) and esbuild 0.28.2 read "none"; plain binaries from go1.22.12, 1.24.7, 1.25.5 and 1.26.8, and `agentosd` from the broker's go1.26.11, read "0". Each table ends 16 bytes (1 in go1.22) before `.text`'s end, and lists `GO_MARKERS` as its only functions without a line table.

**Acceptance tests** (`tests/test_image_static_elf.py::StaticElfTest`):
- SGE-1: `test_a_go_file_runs_only_code_its_function_table_lists` (a cgo-off `.syso` package linked externally through `-toolexec`: "0-o" with `no_line_funcs` empty and no `CGO_MARK`; the same with `.init`, `.plt`, `.fini` flagged as data; the tree check's refusal; an entry point past the table or on a marker; an executable segment past `.text`).
- SGE-2: `test_a_forged_function_table_is_not_go` (objcopy-added 1.20 header with nfunc 0 on static glibc C reads "o"; a real table edited to nfunc 0 reads "0-o").
- SGE-3: `test_only_the_linkers_own_markers_are_exempt` (a `.syso` function named `go:x` is listed).
- EVL-5: image.yml's build job (run a) runs `static_elf.py` on the real image with no refusal.

**Scope:** `image/static_elf.py`, `tests/test_image_static_elf.py`, `image/ASSUMPTIONS.md` (row VULN-static-elf-2), this brief.

**Guard files:** none.

**Dependencies (D-320):** open #6382 edits `image/static_elf.py`'s docstring line 16 and `classify`'s `read_elf` call; this row leaves those lines alone.

**Recurring kinds:** Security "a guard fails open on a missing or invalid value": no function, no executable segment, unreadable program headers or an out-of-order table each refuse or read as unread.

**Gate:** tier A (`image/`). L3 on the strongest model, Potency, and Security.

**Estimate:** under 100k tokens.
