# Lanes

Live record of who owns which paths. The rules for parallel teams are docs/OPERATING.md §7, and the migration steps that set directory owners are PLAN.md §3; this file is the state they act on.

Mark's two Claude subscriptions are equal peers (D-099): neither is primary, and either reviews and merges under the same rules (OPERATING §7). From migration step 1 until step 5 deletes the old core, D-139 suspends D-099's "no lane restriction between them": the directory owners below bind both subscriptions, and after step 5 D-099 applies in full again. A lane binds a team that is not one of those two subscriptions.

## Directory owners

One owner per directory at a time (PLAN.md §3). A change another owner's directory needs goes to that owner as an issue; nobody else writes there.

- **Steps 1 to 3 (D-139):** sub A runs the freeze, this spec, the kernel and the slice; `broker/kernel` (with `key` and `sim`) and `broker/clerk` belong to its step-2 kernel builder, then to its step-3 slice builders. Sub B runs only the hardware track and the eval set, and owns `evals/slice-inbox/`, which no kernel PR touches. Nobody else writes these.
- **Step 4:** sub A owns the trusted side, sub B the untrusted side, and the Codex lane only what its tier limit allows. Each port PR names the directories it owns and the old ones it deletes.
  Port map (2026-10-20; `broker/` directories, one owner each, every directory named). Two rules decide it:
  - **Ownership follows trust.** A directory that holds keys or secrets, scrubs credentials, writes the event or log store, holds verdict or claim code, or scores reviewers belongs to sub A. Sub B gets only the untrusted side. The Codex lane gets only what its tier limit C allows (below).
  - **Deleting waits on importers.** A row that deletes a directory waits until no other owner's directory imports it. The importer table below is generated, not hand-kept; regenerate it with the command under it before changing a row.
  - **Sub A, trusted core:** `kernel`, `clerk`, `core`, `vendor`, `third_party`, `cmd/agentos-a8scan`, `cmd/agentos-builder`.
  - **Sub A, ported onto the kernel (each deleted by its row):** `grants` (keys, `broker/kernel/key`), `vault`, `egress`, `holder` and `checker` (the clerk exit and its sealed secrets, `broker/clerk`; one row, #2571), `verb` and `meter` (spend and verb caveats, #2572), `mail` (clerk, waits on the inbox slice #2566, #2574), `browser` (clerk, #2573), `recall` and `recalltool` (the private-data read side, #2579), `replay` (sim and replay are one path in `broker/kernel/sim`, #2575), `provagent` (#2579 ports and deletes it), `journal` and `durable` (the log and its stores; deleted last, once every other row that imports them has merged), `projection` (deleted by #2568; nothing imported it).
  - **Sub A, trusted-side directories moved off the other lanes (rewired onto `Kernel.Submit` and the clerk interfaces in #2579):** `events`, `e2e`, `route`, `routerule`, `modelroute`, `infer`, `photo`, `test`, `pubid`, `maintain`, `cmd/agentos-photo`, `cmd/agentos-infer`, and `evals/review/` (it scores reviewers).
  - **Sub A, trusted host and hardware (each rewires its old-core imports in its own row; the imports are in the table below):** `modem`, `modemlink`, `firstboot`, `recovery`, `update`, `apply`, `follow`, `apnet`, `clock`, `vm`, `reversible`, and the `cmd/` mains `agentos-holder`, `-egress`, `-checker`, `-ap`. These need no rewiring: `tpmseal`, `hostdisk`, `claim`, `card`, `netguard`, `netjoin`, `sipsign`, `smsapi`, `sendrules`, `sockets`, `procguard`, `childproc`, `cgroup`, `attest`, `boxname`, `bridgeclient`, `bridgeproto`, `quota`, `admission`, `accel`, `budget`, `inflight`, `floor`, `hostchange`, and the `cmd/` mains `agentos-modem`, `-hostdisk`, `-release`, `-netjoin`, `-clock-boot`, `-seller`.
  - **Sub B, untrusted side:** `owner`, `localui`, `localsrv`, `localapi`, `control`, `question`, `attention`, `guest`, `guesterr`, `cmd/agentos-guest-bridge`, `workers`, `change`, `compile`, `corpus`, `skill`, `loops`, `loop7`, `loopbuild`, `machprobe`, `probecmd`, `sockprobe`, `fold`, `hint`, `cleanroom`, `pubsend`, `voice`, `daemon` and `cmd/agentosd` (the wiring; sub B's ports unhook it, step 5 deletes it), `cmd/agentos-localui`, and `evals/slice-inbox/` until it is handed over.
  - **Codex lane, tier C only:** the lane gate fails a Codex PR whose tier is above C (`tools/risk_tier.py`), and every `broker/` and `evals/` directory is tier B or A, so the lane owns no `broker/` directory. Its rows change only files under `docs/` and `tests/` that are not gate files, claimed by issue; it changes nothing under `tools/` or `.github/` (sub A owns all of them). It writes through `Kernel.Submit` (`broker/kernel/kernel.go`, which runs `Admit`), never raw `Log.Append`, and imports no old-core directory.
  - **Importers of each directory a row deletes** (direct and test imports; sub B importers are the cross-owner waits, sub A importers port first or in the same row; `cmd/agentosd` is sub B everywhere):

    | Deleted | Importers |
    |---|---|
    | `grants` | sub B: `attention`, `daemon`, `localui`, `cmd/agentosd`; sub A: `follow`, `mail`, `recalltool`, `vm` |
    | `vault` | sub B: `cmd/agentosd`; sub A: `browser`, `e2e`, `egress`, `firstboot`, `holder`, `provagent`, `recovery`, `route`, `cmd/agentos-a8scan`, `cmd/agentos-egress` |
    | `egress` | sub B: `cmd/agentosd`; sub A: `e2e`, `holder`, `provagent`, `route`, `cmd/agentos-egress`, `cmd/agentos-holder` |
    | `holder` | sub B: `cmd/agentosd`; sub A: `cmd/agentos-egress`, `cmd/agentos-holder` |
    | `checker` | sub B: `cmd/agentosd`; sub A: `holder`, `cmd/agentos-checker`, `cmd/agentos-egress`, `cmd/agentos-holder` |
    | `verb` | sub B: `attention`, `change`, `localui`, `cmd/agentosd`; sub A: `egress`, `grants`, `holder`, `mail`, `reversible` |
    | `meter` | sub B: `cleanroom`, `guest`, `loopbuild`, `loops`, `cmd/agentosd`; sub A: `e2e`, `grants`, `maintain`, `modelroute`, `replay`, `route`, `cmd/agentos-egress` |
    | `mail` | sub B: `corpus`, `cmd/agentosd`; sub A: `vm`, `cmd/agentos-egress` |
    | `browser` | none |
    | `recall` | sub B: `cmd/agentosd`; sub A: `events`, `mail`, `photo`, `recalltool`, `vault` |
    | `recalltool` | sub B: `cmd/agentosd`; sub A: `recall` |
    | `replay` | sub B: `cmd/agentosd` |
    | `provagent` | sub B: `cmd/agentosd`; sub A: `e2e` |
    | `journal` | sub B: `change`, `compile`, `control`, `daemon`, `guest`, `localsrv`, `localui`, `loop7`, `loopbuild`, `loops`, `owner`, `cmd/agentosd`, `cmd/agentos-guest-bridge`; sub A: the rest, listed by the command |
    | `durable` | sub B: `change`, `cleanroom`, `guest`, `localsrv`, `localui`, `loops`, `owner`, `pubsend`, `question`, `cmd/agentosd`; sub A: the rest, listed by the command |

    `browser` imports `vault`, so it ports before the `vault` row deletes `vault`, and waits on nothing itself. Of the kept host directories only these import an old-core directory: `firstboot` (`vault`), `recovery` (`durable`, `journal`, `vault`), `update` and `apnet` and `clock` (`durable`), `apply` and `modem` and `modemlink` (`journal`), `follow` (`durable`, `grants`, `journal`), `vm` (`durable`, `grants`, `journal`, `mail`), `reversible` (`journal`, `verb`), `cmd/agentos-ap` (`durable`), and the `cmd/` mains `-holder`, `-egress`, `-checker` (the exit and `mail`, `meter`, `durable`, `journal`).

    Regenerate from `broker/` (Go 1.26.8; the rows above are this output reduced to top-level directories):

    ```
    go list -e -f '{{.ImportPath}} {{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}' ./... | awk '{p=$1; sub(".*/broker/","",p); for(i=2;i<=NF;i++) if($i ~ /agentos\/broker\//){d=$i; sub(".*/broker/","",d); if(d!=p) print d" "p}}' | sort -u
    ```
- **Everything else** has a fixed owner: sub A owns all of `tools/`, `.github/` and every gate file. The Codex lane may change only `docs/` and `tests/` files that are not gate files. The conflict guard (OPERATING §5) still keeps two builds off one file.

## Lanes

| Lane | Team | Label | Prefix | Paths |
|---|---|---|---|---|
| none | peers (Mark's two Claude subscriptions, D-099) | none | none (`D-NNN`) | all paths, split by directory owners above |
| codex | codex (OpenAI Codex, D-139) | `lane:codex` | rows `CX-`, decisions `D-codex-NNN` | `docs/` and `tests/` files that are not gate files (port map above); entry point AGENTS.md |

A lane is added by an onboarding PR for each other team (another vendor's agent, a teammate), naming its directories and the frozen kernel and clerk interfaces it may call. The earlier claude2 lane (lifted 2026-10-10) and codex lane named old-core interfaces; their onboarding records are in git history before MIG-1. D-126 retired the codex lane; D-139, which is later, brings it back at step 4: the `codex` row in the table above gives its label (`lane:codex`), its tier limit, the frozen kernel and clerk interfaces it may call, and AGENTS.md as its entry point. The Codex lane may call only the frozen kernel and clerk interfaces: `kernel.Request`, `kernel.View` and `Kernel.Submit` in `broker/kernel`, `key.Step` and `key.Refusal` in `broker/kernel/key`, `clerk.Check`, `clerk.Facts` and the `Effect` type in `broker/clerk`, and the simulator in `broker/kernel/sim`. It never imports an old-core directory (`tools/old_core.txt`), and it claims a row by its issue's `state:building` label before building (CLAUDE.md).
