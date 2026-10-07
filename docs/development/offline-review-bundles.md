# Offline review bundle consistency

H7 lets an external reviewer independently compare exported source and metadata
with pinned Git objects, without network access or rebuilding the author's paths.
This is development tooling: no product requirement marker, new acceptance gate,
qualification assertion, test runner or runtime policy change.

After inspecting the script, clone the supplied Git bundle **outside** the review
package directory and run:

```sh
git clone review-stack.bundle ../review-checkout
python3 tools/review_stack.py --package /path/to/package --checkout ../review-checkout
```

A standalone copy of the script may accompany an export. It uses Python's standard
library and Git. It reads committed objects directly; it does not check out a
branch, edit the checkout, execute commands named by a manifest, invoke tests,
contact GitHub or enable Git text conversions/external diff programs. A dirty
checkout does not change the pinned objects it reads. Use a normal reviewed Git
checkout; this tool is not a sandbox for malicious Git configuration or software.

The package format contains `stack.json`, `SHA256SUMS`, `pr-bodies/` and
`source/<candidate>/`. Every regular file except `SHA256SUMS` must appear exactly
once in the checksum inventory. Added files, missing files, symlinks, noncanonical
paths, path traversal and artifacts over 32 MiB are refused. Keep checkout clones,
new reviewer notes and publication output outside this immutable package until
verification finishes. The checksum list cannot authenticate itself.

Each candidate needs a unique key and `pkg/` branch, full head/base/tree hashes,
`draft: true`, an exact sorted changed-file list, its PR body, and copies of every
changed file. The auditor checks object existence, ancestry, tree equality, diff
whitespace and source bytes. This version supports added/modified regular files;
deleted-file exports need an explicit representation before use. File modes are
pinned by the Git tree; the source copies check bytes only.

Independent proposals target `main`. A directly stacked proposal identifies one
preceding dependency and must use that dependency's exact head as its source base
and its branch as the PR base. Logical prerequisites are described in PR bodies;
multiple prerequisites do not create an implicit merge base. This version does
not assert all independent base commits are the latest upstream main.

Successful output asserts internal content consistency only. Editable manifests
and hashes are not signatures or trusted producer attestations. Patch files are
checksummed, not independently applied by this tool; the Git objects are the
review source of truth. Requirement coverage, actual test execution, environment
claims, business benefit and security qualification still require independent
review. Review the proposed diff before running any candidate tests or publisher.
