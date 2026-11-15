# REV-LOW-tools: three review-tool false passes (findings 19, 21, 23)

Work item #4400. Written 2026-11-15 against main f97dd399. Findings 16, 17, 20 and 22 of the same issue moved to #5846 (REV-LOW-tools-b, tier C) at claim: none of them lets a gate pass on a real violation. This package builds the three that can. Source: Mark's 23-Low review, cmsg_01R91wiieBzMSvPKFsAJVvuKGzpVhVhSFNMJuM4ZAmLuTq; finding text in #4400's body.

**Scope:** `tools/netguardcheck.py`, `tests/test_netguardcheck.py`, `tools/word_budget.py`, `tests/test_word_budget.py`, `tools/doclint.py`, `tests/test_doclint.py`, `tests/test_workflows.py`, `tests/requirements.txt` (new) and one install step in `.github/workflows/ci.yml` (added in review, below), this brief. Not `tools/ASSUMPTIONS.md` (open in #5838; the assumptions below go there in a later PR). Tier A (`tests/test_workflows.py`); `premerge.py --needs-mark` decides the Security accept.
**Guard files:** none (no broker package added).
**Requirement IDs:** DEV-2 (19: every broker dialer is hooked into the address guard). 21 and 23: none, assurance tooling (D-086).
**Dependencies:** none. D-111: no open PR touches the scope (dispatch pass 2026-11-15 16:30Z).

## 19. netguardcheck: a guard path in non-import text counts as a hook

`hooked()` tests `'"…/broker/netguard"' in text`, so the quoted path in a comment, a string literal or any non-import text suppresses the missing-guard finding, and the SIP check reads the same substring (and `DialerCreate` anywhere). The existing comment test uses an unquoted path, so it passes without exercising the predicate.
**Do:** parse the Go import declarations (after stripping comments while respecting interpreted, raw and rune literals): single and grouped forms, named and dot aliases. A blank import (`_`) is not a hook, since it cannot use the guard. A file whose comments or literals do not terminate, or whose import block does not parse, is not hooked (fail closed). The SIP check uses the same predicate and looks for `DialerCreate` outside comments. Unix-socket exemptions and the stale-debt allowlist checks stay as they are.
**Acceptance tests (`tests/test_netguardcheck.py`):** `::test_hooked_reads_only_imports` (production `hooked()` on a quoted path in a line comment, a block comment, a string and a raw string each returns false; single, grouped, aliased and dot imports return true; a blank import returns false), `::test_a_comment_naming_the_guard_is_not_a_hook` (now with the quoted path, through `check()`), `::test_parse_error_is_not_hooked` (an unterminated block comment or import group fails closed), `::test_sip_needs_a_real_import_and_dialer` (guard named only in a comment, or `DialerCreate` only in a comment, still fails), and `::test_the_repository_is_clean` (unchanged, positive control).

## 21. word_budget and doclint: quoted Git paths are skipped

`git ls-tree --name-only` and `git ls-files` quote a path holding a non-ASCII byte, quote or backslash (`core.quotePath`), so `word_budget.git_counts` drops a `.claude/skills/<name>/SKILL.md` whose name needs quoting and the set can grow unchecked; `doclint.markdown_files` drops such Markdown files; `doclint.lens_files` also splits on whitespace, so a review record whose name holds a space is never checked.
**Do:** `-z` on all three listings, split on NUL, decode strictly as UTF-8 (a name that is not UTF-8 raises rather than being dropped). Scope, tracked-only and non-git fallbacks stay as they are.
**Acceptance tests:** `tests/test_word_budget.py::test_quoted_skill_path_is_counted` (a committed skill under a non-ASCII directory name grows the process set and `--git` exits 1), `tests/test_doclint.py::test_tracked_names_needing_quotes_are_listed` (a lens record with a space and one with a non-ASCII name are each flagged; a Markdown brief under a non-ASCII name is listed by `markdown_files`), `::test_untracked_scratch_record_is_not_checked_in_a_git_repo` (unchanged control).

## 23. test_workflows: steps not starting with `uses` are skipped

`steps()` matches only `- uses:` lines, so a step written `- name: …` then `uses: …` escapes the full-SHA pin check and the checkout persist-credentials check. Today about 15 such steps exist (cache restore/save, create-github-app-token); all are pinned.
**Do:** collect every step mapping (a list item and its indented body) and find `uses:` at the step's own key column, regardless of key order. Yield the whole step text so step-local `with:` settings are read. Local actions (`./…`) stay exempt in the pin test.
**Acceptance tests (`tests/test_workflows.py`):** `::test_steps_finds_steps` (extended: `uses`-first, `name`-first, `id`-first and `if`-first forms of the same step each yield the same action and full step text; a `uses:` inside a `run: |` body deeper than the key column, or in a nested `with:` value, is not a step), `::test_step_order_does_not_hide_an_unpinned_action` (a synthetic name-first unpinned step fails the pin predicate; a name-first tokenless checkout passes and a persisting one fails), and the existing pin and checkout tests over the real workflows (positive control).

## Assumptions (for tools/ASSUMPTIONS.md after #5838)

- netguardcheck still trusts a file that imports the guard to use it for every dial (unchanged; review holds use).
- Git's `-z` output is the only listing form these tools read in a git checkout.
- PyYAML (6.0.2, one hash-pinned wheel) reads workflows as GitHub's runner does for the keys checked (`uses`, `with.persist-credentials`); a duplicate key is refused.

**Review change (three fix-lists on #5850):** the hand step parser kept missing text forms (bare `-`, quoted and spaced keys, comments, flow mappings, `run: |` decoys, multi-line quoted values). The pin and token checks now read steps through PyYAML with a duplicate-key-refusing loader; `steps()` stays for the step text other tests read, and `test_hand_parser_agrees_with_the_loader` fails if it disagrees with the loader. CI installs the wheel by hash (`tests/requirements.txt`); a missing loader fails the module rather than skipping it.

**Size:** S. **Model:** Opus 5.5 (tier A).
