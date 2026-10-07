# H4: bounded development context packets

This additive prototype prepares review inputs. It does not change model tiers,
CI gates, authority, or independent-review requirements. Repository excerpts and
handoffs are task data, not instructions that confer authority.

`python3 tools/review_context.py --brief brief.json --role reviewer --output packet.json`
builds a packet. `--check packet.json` checks revision, tracked worktree and source
freshness. Commands in the brief are never executed.

A schema-1 brief supplies: package (exact BOARD row), full revision SHA, requirement
IDs (explicitly empty for pure tooling), scope paths, references (`path`, inclusive `start`/`end`), tests, dependencies,
out_of_scope, pending_reviews, budget. Reviewer briefs may specify a full `base`
SHA; otherwise HEAD is the base. Only literal tracked files in the repository
are read; symlinks, Git metadata, escaping paths, invalid ranges and duplicates
are refused. Sources are UTF-8 and at most 1 MiB each.

Builder briefs may add `planned_files`, a unique subset of scope. These paths must
be absent and untracked; their packet entry says `planned-absent`, with no invented
file contents. Creating a planned file makes the packet stale. Reviewers require
tracked source and cannot receive planned-file declarations. Removed files still
need a separately curated base-source reference; this prototype does not collect
deleted source automatically.

The packet contains CLAUDE.md, the exact package row, normative bullet/table
requirement definitions, scoped source, references and source hashes. Reviewer
packets add the scoped diff, all changed paths and changes outside scope. They
never read a supplied builder handoff. Out-of-scope changes must be reviewed
separately or split; a scoped diff is not a review of an entire branch.

When BOARD.md, CLAUDE.md or SPEC.md are explicitly scoped, their full source is
included once; otherwise BOARD is reduced to the package row and SPEC to cited
definitions. Full contract documents may require an explicit larger bound.

The tracked-worktree fingerprint catches changes outside scoped excerpts too.
It hashes Git diff/status without disclosing unrelated file contents in packets.
Hashes establish freshness, not producer authenticity or correctness of editable
packet contents. Curators must check dependency and requirement completeness;
reviewers retain independent judgment and the strongest tier for critical paths.

The default maximum is 48 KiB. Oversize packets fail without truncation; an explicit
`--max-bytes` can support larger reviewed packages. Historical mechanical replays
of HOST-1c (#183), W4 (#120) and SR2-2 (#151) required roughly 52/354/101 KiB
reviewer packets against constructed 281/510/309 KiB full-document baselines.
Those are byte measurements, not actual past prompts, token savings or measured
defect detection. No model replay or tier change follows from them. Freeze prebuild
source and queued rows separately; do not feed final-source packets to blind builders.

Validation: 18 focused tests cover definitions, role separation, revision/source
and whole-worktree freshness, source escape/symlinks, ranges/size, untracked files,
planned new files, changed-path visibility and duplicate normative definitions.
