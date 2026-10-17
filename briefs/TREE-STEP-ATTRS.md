# TREE-STEP-ATTRS: hold tmpfiles z/Z/a/d/e/C lines, non-root group write and a link's own directory to the step rules

Board row: issue #1829 (tier A, class:release). Follow-up of #1803 (PR #1826 Security R1 findings 2-4, L3 R1 points 2-3). Requirement IDs: HW-1, DEV-2.

**Scope:** `image/mkosi/mkosi.finalize`, `tests/test_image.py`, `image/ASSUMPTIONS.md` (I23). No other file. No open PR touches these (D-111); all three are under `tools/g1_scope.txt` allow lines.

**Gate:** tier A: L3 and security lens on the strongest model, with an explicit threat check.

**Invariant (I23, #1803).** A link the box holds goes only through steps that root alone can write. That holds for what the box does to a step after the build, not only for the step as the tree ships it, and for the directories the link itself sits in.

## Gaps and fixes

1. **tmpfiles lines that change a held step (gap 2).** `link_refusal` asks `tmpfiles_makers` only about steps the tree lacks. A `z`, `Z`, `a`, `a+`, `A`, `d`, `D`, `e` (or `L+`) line, or a glob, naming a step the tree holds can give it a mode, owner or ACL that lets someone else write it. Fix: `step_refusal` asks the same makers about every held step. Every step of the path is asked, so a `Z` or `A` line on an ancestor is caught at the ancestor. An `L` line's last component is not resolved through a link the tree holds there (the line replaces that link; resolving it refused Debian's stock `var/lib/dbus/machine-id`).
2. **Group write by a non-root gid (gap 3).** A held step at 0775 with gid 1000 passes. Fix: `step_refusal` refuses g+w on a held step whose gid is not `TREE_GROUP` (0). Default picked: no named exceptions. The rule applies only to steps of a link, and no stock link goes through `var/mail` or `var/local` (2775, gid mail/staff), so an exception would only open a hole. The tree-wide group-write rule stays absent, as I23 says.
3. **`C` lines make steps (gap 4).** `C /opt/nope - - - - /var/tmp/u` makes `/opt/nope` with contents a local user chose. Fix: `tmpfiles_makers` counts every `C` line, whatever its source: the tree check never chased what the copy holds.
4. **The directory a link sits in (gap 5).** A link in `etc/foo.d`, where uid 1000 owns `etc/foo.d`, passes, and that user can replace the link on the box. Fix: `link_refusal` holds each tree directory holding the link (its parent chain, as far as the tree holds it without a link) to `step_refusal`, before the mask and `BOX_LINKS` pass, since replacing a link does not depend on its target. This covers tree links and the links tmpfiles.d `L` lines make.
5. **Cost.** `tmpfiles_makers` is now asked about every held step of every link, so `violations()` reads it once per check (a cache that lives only inside one `violations()` call; direct calls stay uncached).

## Acceptance tests

**Acceptance tests:** HW-1, DEV-2, in `tests/test_image.py`, `TreeLinkTmpfilesTest`, section (g):

- `test_a_tmpfiles_line_that_changes_a_held_step_is_refused`: the issue's three examples, plus `Z`/`A+` on an ancestor, `D`, `e`, a glob and `L+`.
- `test_a_tmpfiles_line_that_keeps_a_held_step_root_only_passes`
- `test_without_the_held_step_tmpfiles_rule_those_links_pass` (mutant)
- `test_a_held_step_a_non_root_group_can_write_is_refused`
- `test_without_the_group_write_rule_the_link_passes` (mutant)
- `test_a_tree_link_through_a_step_a_copy_line_makes_is_refused`
- `test_without_the_copy_rule_the_link_passes` (mutant)
- `test_a_link_in_a_directory_someone_else_can_write_is_refused`: tree link and tmpfiles `L` link, owner, group, ACL and a `z` line on the holder.
- `test_without_the_holder_rule_those_links_pass` (mutant)
- `test_violations_reads_the_makers_once`

Every existing `TreeLinkTmpfilesTest`, `TmpfilesTest`, `TmpfilesAllowTest`, `CredstoreTest` and `TreeAccessTest` case still passes.

## Not in scope

- A user making an entry writable after the build (I23 "Not covered" keeps it).
- Holder directories of a tmpfiles `L` link that the tree lacks or reaches only through a link (named in I23 "Not covered").

**Usage estimate:** ~120k tokens, one session. Checkpoint at 150k.
