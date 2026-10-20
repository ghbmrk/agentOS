# Lanes

Live record of who owns which paths. The rules for parallel teams are docs/OPERATING.md §7, and the migration steps that set directory owners are PLAN.md §3; this file is the state they act on.

Mark's two Claude subscriptions are equal peers (D-099): neither is primary, and either reviews and merges under the same rules (OPERATING §7). From migration step 1 until step 5 deletes the old core, D-139 suspends D-099's "no lane restriction between them": the directory owners below bind both subscriptions, and after step 5 D-099 applies in full again. A lane binds a team that is not one of those two subscriptions.

## Directory owners

One owner per directory at a time (PLAN.md §3). A change another owner's directory needs goes to that owner as an issue; nobody else writes there.

- **Steps 1 to 3 (D-139):** sub A runs the freeze, this spec, the kernel and the slice; `broker/kernel`, `broker/clerk` and `broker/sim` belong to its step-2 kernel builder, then to its step-3 slice builders, and the step-2 simulator replaces `broker/sim` in place (PLAN.md §3). Sub B runs only the hardware track and the eval set, and owns `evals/slice-inbox/`, which no kernel PR touches. Nobody else writes these.
- **Step 4:** sub A owns the trusted side (the kernel, clerks, modem, enforcer), sub B the untrusted side (planner, reader, guests, owner channel and UI), and the Codex lane the adapters and evals. The PR that starts step 4 lists each directory and its owner here, one bullet each, and re-onboards the Codex lane (below); each port PR names the directories it owns and the old ones it deletes.
- **Everything else** (docs, tools, tests, image, CI) has no fixed owner: the conflict guard (OPERATING §5) keeps two builds off one file.

## Lanes

| Lane | Team | Label | Prefix | Paths |
|---|---|---|---|---|
| none | peers (Mark's two Claude subscriptions, D-099) | none | none (`D-NNN`) | all paths, split by directory owners above |

A lane is added by an onboarding PR for each other team (another vendor's agent, a teammate), naming its directories and the frozen kernel and clerk interfaces it may call. The earlier claude2 lane (lifted 2026-10-10) and codex lane named old-core interfaces; their onboarding records are in git history before MIG-1. D-126 retired the codex lane; D-139, which is later, gives it the adapters and evals at step 4, so the PR that starts step 4 re-onboards it: a `codex` row in the table above with its label (`lane:codex`), its directories, the frozen kernel and clerk interfaces it may call, and AGENTS.md as its entry point. Until then it has no lane and no row.
