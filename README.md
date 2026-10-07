# AgentOS

A computer for delegated work. Frontier AI the owner already pays for does the reasoning; a drive you plug into any PC does the executing, remembering, and improving, under the owner's sole control. Direction is by text or phone call.

**Status:** pre-alpha. The broker under `broker/` builds and its tests run. There is no bootable drive image yet. Spike results for agent machines, the OpenClaw guest, and the host image are in `spikes/`. Screenless boot (S1) and the USB modem (S2) are waiting on hardware. Most open packages are `in review`. No license has been chosen yet; all rights reserved until one is (spec OSS-12).

## Working on it

Read [CLAUDE.md](CLAUDE.md) before editing. Build only from a package on [BOARD.md](BOARD.md). Do not edit [SPEC.md](SPEC.md) except as an L1 spec diff that Mark approves, and do not commit TRACE.md.

`python3 tools/next.py` prints the uncovered requirement IDs and the queued packages that are not blocked or deferred. Prefer finishing a package already `in review` over starting a new one. P3-4b (LOOP-7, in-sandbox adversarial tests) is deferred.

A package branch is `pkg/<id>-<slug>-<suffix>`. Tests first. In the PR's trace table, every requirement ID must have a `REQ:` marker in a file the PR changes, unless that ID is already covered on main.

| File | What it is |
|---|---|
| [SPEC.md](SPEC.md) | The system specification (v0.12). Requirement IDs like `CRED-1` are normative. |
| [PLAN.md](PLAN.md) | How it gets built: phases, nested build loops, budget. |
| [BOARD.md](BOARD.md) | Current work packages and their states. |
| [LEDGER.md](LEDGER.md) | Model-usage budget, allocated vs spent. |
| [DECISIONS.md](DECISIONS.md) | Decisions with dates and evidence. |
| [TRACE.md](TRACE.md) | Generated on main after each merge: which tests cover which requirement IDs. |
| [CLAUDE.md](CLAUDE.md) | Rules for the AI agents that build this repository. |
| [tools/next.py](tools/next.py) | Uncovered IDs and queued, unblocked packages. |
