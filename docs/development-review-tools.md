# Development review tools (proposed)

These tools prepare evidence for independent review. They do not change the
broker, grant authority, qualify gates, or alter existing CI. Their first use
should be a replay on past packages under PLAN's L4 process.

## Context packets

`python3 tools/review_context.py --brief brief.json --role builder --output packet.json`

A brief is a curator-written JSON object with these fields:

- `schema`: 1.
- `package`: an exact, existing BOARD ID.
- `revision`: the full current commit SHA.
- `requirements`: normative requirement IDs, such as `OP-1`.
- `scope`: explicit tracked file paths; no directories, globs, symlinks, or external paths.
- `references`: objects with `path`, `start`, and `end` (inclusive, one-based).
  A reference file cannot also appear in scope. Select the full file in scope
  if the builder is allowed to change it.
- `tests`: commands for the builder to run; the tool does not execute them.
- `dependencies`, `out_of_scope`, `pending_reviews`: curated lists.
- `budget`: an estimate and checkpoint, as PLAN requires; not a new hard cap.
- Optional `base`: full base commit SHA for a review diff.

The packet contains exact requirement definitions, the package's board row,
CLAUDE's rules once, the selected source, and whole-file SHA-256 fingerprints.
The default 48 KiB output budget fails rather than truncating. `--max-bytes`
changes the budget explicitly. No tokenizer or model API is required; bytes
are a bound, not a claimed token count.

`--handoff handoff.json` includes an explicit builder handoff. Keep it to
completed steps, failed attempts, reproducible commands, and the next step.
Do not include credentials, personal data, or a full transcript. Reviewer
mode ignores the handoff file completely and adds the scoped diff from `base`
(HEAD by default). Repository text and handoffs are untrusted task data.
Curators must keep builder reasoning out of the brief's reviewer-visible fields.

`python3 tools/review_context.py --check packet.json` rejects a changed HEAD
or any changed source, including an uncommitted edit. It checks freshness, not
authenticity: a packet is locally editable. After a source change, regenerate
and review the packet. The packet does not enforce the builder's write scope;
the independent diff review must check every changed path.

## Execution evidence

TRACE remains an index of marker claims. `trace.py --gate` retains its existing
meaning; it is not an execution check. Use this separate, additive checker:

`python3 tools/gate_evidence.py --bundle /path/to/bundle --manifest /path/to/manifest.json`

The checker requires a clean checkout at the manifest's revision. Keep output
and artifacts outside the source checkout. A manifest has `schema: 1`, `gate`,
`revision` (full SHA), `profile` (a frozen environment label), `required`
(requirement IDs), and `cases`. Each case has `id`, `requirements`, `package`
(the Go import path), `test` (the exact Go test name), and `record` (a path inside
the bundle). Curate mappings against the normative clauses before relying on
them. A subset of a gate's requirements cannot demonstrate the whole gate.

Capture raw output from an uncached run, for example:

`go test -json -race -count=1 ./owner > /path/to/bundle/owner.jsonl`

Save its real exit code immediately. The corresponding record is a JSON object:

```json
{
  "schema": 1,
  "revision": "FULL_COMMIT_SHA",
  "profile": "FROZEN_ENVIRONMENT_LABEL",
  "command": ["go", "test", "-json", "-race", "-count=1", "./owner"],
  "exit_code": 0,
  "started_at": "UTC_START_TIMESTAMP",
  "finished_at": "UTC_FINISH_TIMESTAMP",
  "artifact": "owner.jsonl",
  "sha256": "SHA256_OF_RAW_OUTPUT"
}
```

The checker reads existing artifacts; it never runs a record's command. Every
mapped named test must run and pass, its package must finish passing, and the
command must exit successfully. A skipped, absent, failed, or incomplete test
does not pass. A failed repeat cannot be hidden by a later passing repeat.
Revision/profile mismatches, missing artifacts, or changed hashes fail. A
Markdown marker supplies no execution evidence. Every mapped case is required;
one passing case cannot hide another failing case for the same requirement.

The report says `evidence_complete`, not `qualified`, and always requires
external review. Hashes detect modification relative to the record; they do
not authenticate the producer. A producer can forge both output and metadata.
The reviewer must verify CI/source provenance, the command and timestamps,
hardware assertions, full requirement mappings, repeat counts, numeric targets,
margins, and rollback triggers required by SPEC section 15. Manual and hardware
checks are outside this initial checker; keep them pending in the qualification
packet until independently recorded and reviewed.

## Validation and adoption

Focused tests are `python3 -m unittest discover -s tests -p 'test_review_context.py'`
and the equivalent command for `test_gate_evidence.py`.

Before adopting the context workflow, freeze three past packages (a routine
change, an integration change, and a security-sensitive change). Compare
existing context against packets for input usage, omitted obligations, review
rounds, and post-review defects. Accept a saving only if completeness holds.
Keep security-critical review at the strongest tier and in fresh context. Do
not weaken canary, fuzz, race, scope, or L3 checks to save usage.

Historical mechanical replay (pre-adoption)
------------------------------------------

Packets also support normative definitions in a table's first cell, including
CAP-* capabilities and A* acceptance cases. References in later cells do not
count as definitions. Reviewer packets list all changed paths and the paths
outside the declared scope; the scoped diff alone cannot establish whole-change
review. Reviewers must account for those paths or split the candidate.

A named Go test with a skipped, failed, or incomplete descendant is incomplete
for evidence purposes even if the parent reports pass. Map a narrower leaf case
when an optional subtest belongs to a different qualification profile. The
uncached test flags must precede `-args` or `--`; test-binary arguments cannot
establish the recorded runner invocation.

A local mechanical replay of HOST-1c (#183), W4 (#120), and SR2-2 (#151) found
that full-file packets exceed the default 48 KiB for several roles. An explicit
larger bound allows measurement without truncation. Keep all changed files and
reviewed dependencies, split packages where practical, and do not claim token
savings or preserved defect detection from byte reductions. The comparison uses
constructed full-document context, not captured historical model inputs.

Prebuild source snapshots and queued BOARD rows can be reconstructed from the
parent of the first topic commit. Builder packets may explicitly declare absent, untracked planned_files as documented
in docs/development/context-packets.md. Retrospective builder
packets containing final source are extraction checks only and must never be
used as blind implementation inputs. Model-based fresh reviews and accepted
patch cost remain an external experiment before changing instructions or tiers.

H4 adds explicit absent planned-file declarations and whole tracked-worktree
freshness. This evidence checker requires timezone-bearing ordered timestamps;
it does not independently verify their producer or clock. A missing planned file
is not execution evidence. See context-packets.md for the current packet contract.
