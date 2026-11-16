# REV-LOW-tools-c: srclint GO_CMD anchoring and continuation lines

Board row: #5866 (tier C, lane:primary, class:release). Source: the two L3 release items on PR #5855 (#5846), https://github.com/ghbmrk/agentOS/pull/5855#issuecomment-6898503791. Usage estimate: 30k tokens.

## Requirement
- **c1 anchoring:** a go verb counts as a build only at a command position, so `echo "run go build -tags staletag"` authorizes no tag (a lint-tag false pass today).
- **c2 continuation:** a `-tags` on a backslash-continuation line, and one held in a shell variable that a go command expands (`TAGS="-tags x"` then `go build $TAGS`), still count (a false fail today).

## Design
- Join backslash-continued lines into one logical line before matching.
- Split each logical line into command segments at unquoted `&&`, `||`, `;`, `|`, `(`, `)`, `$(` and backticks. A segment is a build when it opens, after an optional YAML `- ` or `run:`, any env assignments and any wrapper word (`env exec command time nice nohup sudo export if then do else elif while until ! {` and the repo's `jail` from image/camdecode.sh), with `go build|test|vet|run|install|list|generate` or a `GOFLAGS=` assignment. Only `-tags` inside a build segment counts.
- An assignment segment whose value holds `-tags` is remembered per file; a later build segment's `$NAME` or `${NAME}` is expanded with it before matching.
- Not a shell parser: quoting is tracked only to find separators. Unknown wrappers fail closed (the tag is not authorized, the lint reports it).

## Scope (files)
- In scope: `tools/srclint.py`, `tests/test_srclint.py`, this brief.
- Out of scope: the other `build_tags` signals (`-race`, `CGO_ENABLED`, `GOOS`/`GOARCH`, `runs-on`), which stay line-wide; `tools/ASSUMPTIONS.md`.

## Acceptance tests
**Acceptance tests:** `test_go_verb_counts_only_at_a_command_position` (echo, message and after-separator cases), `test_tags_on_continuation_lines_and_in_variables_count`, and the existing `test_tag_set_comes_from_the_builds` and `test_main_is_clean`.
