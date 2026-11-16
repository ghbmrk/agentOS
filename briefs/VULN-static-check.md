# VULN-static-check: vulncheck queries advisories for the bundled copies of pinned downloads

Board section: Defects and later findings on surviving packages. SPEC EVL-5. Issue #5873; the image half (static ELFs such as llama-server, and the Potency item 6902429342) moved to #5885, since it needs image build steps and `.github/workflows/image.yml`, which draft #5816 holds.

**Sources:** #5873 (from #5872's Security 6902369509 and L3 6902377665); #5879 added `assurance/vulncheck.json` "bundled" (node's OpenSSL 3.5.9, codex's OpenSSL 3.6.4), whose `_doc` says "#5873 makes the scan read them", and whose codex record says "no build step checks this record yet (#5873)".

**Requirement IDs** (the builder writes the failing test first):
- **EVL-5** (SPEC): a known vulnerability in a statically linked copy a guest ships fails the scan or carries a record.
- **BUN-1:** `vulncheck.py run` queries OSV for each bundled copy by its upstream repository and release tag (OSV's GIT ecosystem; `openssl@3.5.9` is `https://github.com/openssl/openssl` at tag `openssl-3.5.9`) and reports each advisory as a finding in `where` "bundled", failing unless the entry's `ids` names its ID or an alias. Paged answers are followed.
- **BUN-2:** the copy's upstream release branch's notes (`openssl-X.Y/CHANGES.md`) are a second source: every CVE id in a section newer than the copy's release is an advisory of the copy, unioned with OSV's by ID and alias; a notes file with no section for the release, or one that cannot be read, fails closed (exit 2). An entry id that neither source lists is reported as info, not a failure (#5888: OSV's GIT data missed 5 of the 13 OpenSSL 3.6.5 fixes; a reviewed branch-only fix keeps its record).
- **BUN-3:** shape: exactly the keys holder, copy, build, issue, ids, why; holder and copy are `name@version`; the copy's library has a known upstream (a table in vulncheck.py; a new library fails until it is added); build names an existing file; issue a positive integer; ids a list of distinct non-empty strings (may be empty); no two entries share holder and copy.
- **BUN-4:** fails closed (exit 2): a query error, an answer count unlike the query count, or a canary (OpenSSL 1.0.1f, a release with many advisories) answered with none.
- **BUN-5:** `run --check-issues` checks each bundled entry's issue like a record's: open, an issue, naming each of its ids; `cited`, `reopen` and the close guard hook count the entry as citing its issue.
- **BUN-6:** `vulncheck.py control` plants GIT advisories offline (`tests/fixtures/vulncheck/osvdb/GIT`): with no ids, the advisories at the planted tag fail and one at another tag is not reported; with ids, one accepted by ID and one by alias clear.
- **BUN-7:** `guest/codex/build-rootfs.sh` fails unless each of the two CLI binaries holds exactly one OpenSSL version string (`OpenSSL X.Y.Z DD Mon YYYY`) and a bundled record names `@openai/codex@$CODEX_VERSION-linux-x64` with that copy.

**Design constraints:** the bundled scan runs in `run` (vulncheck.yml, every PR and daily), not `image`; it uses OSV's API directly as `advised_names` does, offline from the fixture's database as the control does. No change to image.yml, the image scan or the inlined scan.

**Acceptance tests:**
- BUN-1, BUN-2, BUN-4: `tests/test_vulncheck.py::BundledTest` (new): a stubbed OSV opener answering per tag; unaccepted advisory fails, ID and alias accepted, unlisted id info, page token followed, query error / short answer / empty canary raise ScanError; release notes read after the copy's section, unioned with OSV, and a missing section or failed read raise ScanError.
- BUN-3: `tests/test_vulncheck.py::BundledTest::test_shape_problems` (each bad shape named).
- BUN-5: `tests/test_vulncheck.py::BundledTest::test_issue_records_include_bundled_ids`.
- BUN-6: `tests/test_vulncheck.py` control test (existing `control()` run) with CONTROL_FAILS extended by the bundled plants.
- BUN-7: `tests/test_guest_bundled.py::Bundled::test_the_codex_check_passes_only_for_the_recorded_openssl` (fake binaries: recorded version passes; another version, two versions, none, and an unrecorded CLI version fail).
- EVL-5: CI's `vulncheck` job, `run` against OSV with the live records.

**Scope:** `tools/vulncheck.py`, `tests/test_vulncheck.py`, `tests/fixtures/vulncheck/osvdb/GIT/`, `tests/fixtures/vulncheck/changelog/` (#5888), `assurance/vulncheck.json` (`_doc` and bundled entries only), `guest/codex/build-rootfs.sh`, `tests/test_guest_bundled.py`, `.claude/hooks/close_guard.py` and `tests/test_close_guard_hook.py` (a bundled entry's issue is cited, so its close is denied as a record's is), one new row in `tools/ASSUMPTIONS.md`, this brief.

**Guard files:** none.

**Recurring kinds:** Security "a guard fails open on a missing or invalid value": the canary, answer count and shape checks fail closed, each with a test.

**Gate:** tier A (`tools/vulncheck`, `assurance/`, `guest/codex/build-rootfs.sh`; risk_tier.py:157). L3 on the strongest model, Potency, and a separate Security accept (`premerge.py --needs-mark` prints `mark`).

**Estimate:** under 120k tokens.
