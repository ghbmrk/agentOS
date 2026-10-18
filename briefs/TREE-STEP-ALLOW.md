# TREE-STEP-ALLOW: weigh tmpfiles line types by allowlist in the link-step check

Board row: issue #2174 (tier A, class:release). Follow-up of TREE-STEP-ATTRS (#1829; PR #2141 combined delta 3). Requirement IDs: HW-1, DEV-2.

**Scope:** `image/mkosi/mkosi.finalize`, `tests/test_image.py`, `image/ASSUMPTIONS.md` (I23) and this brief. No other file. No open PR touches these (D-111); `image/` is allowed under the G1 freeze.

**Gate:** tier A: L3 and security lens on the strongest model, with an explicit threat check.

**Invariant (I23).** A link the box holds goes only through steps that root alone can write, including after the box runs its `tmpfiles.d` lines.

## Gap and fix

`tmpfiles_makers` counted a line only if its type was one the check knew could change a step (`L`, `C`, `a`/`A`, or a mode, user or group field that grants someone else write); every other type passed. That is a denylist, and four review rounds on #2141 each found a type it missed. The last was `t`/`T`, which set any xattr, `system.posix_acl_access` included, so they grant a user write as an `a` line does.

Fix: an allowlist. A line reaching a step counts unless both of these hold:

- Its type is in `TMPFILES_STEP_TYPES`: `f w d D e v q Q z Z` (weighed by their mode, user and group fields, as before) and `x X r R` (they grant nothing; `r`, `R` stay with the remover rule).
- Its modifiers are in `TMPFILES_STEP_MODIFIERS`: `+ ! - ~ $`.

`L`, `C`, `a` and `A` keep their own texts. Everything else counts as making the step writable by someone other than root. That covers `t`, `T`, `h`, `H`, `p`, `c`, `b`, any letter a later systemd adds, the `=` modifier (it replaces a path of another type) and the `^` modifier (its content comes from a credential, not the tree). The refusal reads `type <T> (off the step check's allowlist, #2174)`.

A refused type matches a step as the other non-group lines do: at that step, with its globs. A recursive `T` or `H` on an ancestor is caught at the ancestor, which is itself a step.

Default picked: `f` and `w` stay on the list. They write content, not the step's attributes, and their mode, user and group are weighed as before.

**Stock check.** `tmpfiles.allow` holds no `t`, `T`, `H`, `p`, `c` or `b` line. Its newly counted lines are `h` on `/var/log/journal…` and `f^` on `/etc/motd.d`, `/etc/issue.d`, `/etc/hosts` and `/root/.ssh/authorized_keys`. None of them is a step of a stock link, so CI's build (a) must still print `image check: clean`.

## Acceptance tests

**Acceptance tests:** HW-1, DEV-2, in `tests/test_image.py`, `TreeLinkTmpfilesTest`, section (g):

- `test_a_tmpfiles_line_of_a_type_off_the_allowlist_is_refused` covers:
  - `t` (an ACL xattr), `T` on an ancestor, `t+`, `h`, `H`, `p`, `c+`, `b`, a made-up `Y`, `f^`, `d=` and an unknown modifier, on a held step;
  - `t` on a step the tree lacks.
- `test_a_tmpfiles_line_of_an_allowlisted_type_keeping_a_step_root_only_passes` covers:
  - every listed type and modifier with root-only fields;
  - a `t` line on a path off the link's steps.
- `test_without_the_type_allowlist_a_t_line_passes` (mutant of the default-refuse branch).

Every existing `TreeLinkTmpfilesTest`, `TmpfilesTest`, `TmpfilesAllowTest` and `TreeAccessTest` case still passes.

## Not in scope

The rest of I23 "Not covered" is unchanged, and so is the exec channels work (IMG-exec-channels-2, #2176).

**Usage estimate:** ~60k tokens, one session. Checkpoint at 100k.
