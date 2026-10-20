# Lanes

Live record of who owns which paths. The rules for parallel teams are docs/OPERATING.md §7, and the migration steps that set directory owners are PLAN.md §3; this file is the state they act on.

Mark's two Claude subscriptions are equal peers (2026-10-10): neither is primary, and either builds, reviews and merges under the same rules (OPERATING §7). What keeps them from building the same thing twice is directory ownership below, not a lane. A lane binds only a team that is not one of those two subscriptions.

## Directory owners

One owner per directory at a time (PLAN.md §3). A change another owner's directory needs goes to that owner as an issue; nobody else writes there.

- **Steps 2 and 3:** `broker/kernel`, `broker/clerk` and `broker/sim` belong to the step-2 kernel builder, then to the step-3 slice builders. Nobody else writes them.
- **Step 4:** sub A owns the trusted side (the clerks, modem, enforcer) and sub B the untrusted side (planner, reader, adapters, guests, owner channel and UI). The PR that starts step 4 lists each directory and its owner here, one bullet each, and each port PR names the directories it owns and the old ones it deletes.
- **Everything else** (docs, tools, tests, image, CI) has no fixed owner: the conflict guard (OPERATING §5) keeps two builds off one file.

## Lanes

| Lane | Team | Label | Prefix | Paths |
|---|---|---|---|---|
| none | peers (Mark's two Claude subscriptions, D-099) | none | none (`D-NNN`) | all paths, split by directory owners above |

A lane is added by an onboarding PR for each other team (another vendor's agent, a teammate), naming its directories and the frozen kernel and clerk interfaces it may call. The earlier claude2 lane (lifted 2026-10-10) and codex lane (retired by D-126) named old-core interfaces; their onboarding records are in git history before MIG-1.
