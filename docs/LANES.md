# Lanes

Live record of who owns which paths. The rules for parallel teams are docs/OPERATING.md §7, and the migration steps that set directory owners are PLAN.md §3; this file is the state they act on.

Mark's two Claude subscriptions are equal peers (D-099): neither is primary, and either reviews and merges under the same rules (OPERATING §7). From migration step 1 until step 5 deletes the old core, D-139 suspends D-099's "no lane restriction between them": the directory owners below bind both subscriptions, and after step 5 D-099 applies in full again. A lane binds a team that is not one of those two subscriptions.

## Directory owners

One owner per directory at a time (PLAN.md §3). A change another owner's directory needs goes to that owner as an issue; nobody else writes there.

- **Steps 1 to 3 (D-139):** sub A runs the freeze, this spec, the kernel and the slice; `broker/kernel` (with `key` and `sim`) and `broker/clerk` belong to its step-2 kernel builder, then to its step-3 slice builders. Sub B runs only the hardware track and the eval set, and owns `evals/slice-inbox/`, which no kernel PR touches. Nobody else writes these.
- **Step 4:** sub A owns the trusted side, sub B the untrusted side, and the Codex lane only what its tier limit allows. Each port PR names the directories it owns and the old ones it deletes.
  Port map (2026-10-20; `broker/` directories, one owner each, every directory named). Two rules decide it:
  - **Ownership follows trust.** A directory that holds keys or secrets, scrubs credentials, writes the event or log store, holds verdict or claim code, or scores reviewers belongs to sub A. Sub B gets only the untrusted side. The Codex lane gets only directories its tier limit C allows (below).
  - **Deleting waits on importers.** A row that deletes a directory waits until no other owner's directory imports it.
  - **Sub A, trusted core:** `kernel`, `clerk`, `core`, `vendor`, `third_party`, `cmd/agentos-a8scan`, `cmd/agentos-builder`.
  - **Sub A, ported onto the kernel (each deleted by its row):**
    - `grants` (keys, `broker/kernel/key`). Waits on sub B's `attention`, `localui` and `daemon`, and on `vm`, `follow`, `recalltool` and `mail`.
    - `vault`, `egress`, `holder` and `checker` (the clerk exit and its sealed secrets, `broker/clerk`; one row). Waits on the ports of their importers `browser`, `route`, `e2e`, `provagent`, `recovery`, `firstboot`, `smsapi` and the `cmd/` mains that import them.
    - `verb` and `meter` (spend and verb caveats). Waits on sub B's `attention`, `change`, `localui`, `guest`, `loopbuild`, `loops` and `cleanroom`, and on `grants`, `egress`, `holder`, `mail`, `reversible`, `maintain`, `modelroute`, `replay` and `route`.
    - `mail` (clerk; waits on the inbox slice #2566 and on sub B's `corpus` and `localui`) and `browser` (a vault importer with no importers of its own, so it waits on nothing and ports before the `vault` row deletes `vault`).
    - `recall` and `recalltool` (the private-data read side; their importers `events`, `photo`, `mail`, `vault` and `cmd/` are all sub A, so the row waits only on those ports).
    - `replay` (sim and replay are one path in `broker/kernel/sim`; only `cmd/agentosd` imports it, so the row waits on sub B's unhooking of `loops`).
    - `journal` and `durable` (the log and its stores; deleted last, once every other row that imports them has merged).
    - `projection` (deleted by #2568; nothing imported it).
  - **Sub A, trusted-side directories moved off the other lanes:** `events`, `e2e`, `route`, `routerule`, `modelroute`, `infer`, `photo`, `test`, `pubid`, `maintain`, `provagent`, `cmd/agentos-photo`, `cmd/agentos-infer`, and `evals/review/` (it scores reviewers). Each is rewired onto `kernel.Submit` and the clerk interfaces in its own row (see the issue rows); `provagent` is deleted with step 5.
  - **Sub A, trusted host and hardware (kept, D-139 keep list; each only rewires its `journal`, `durable` and `grants` imports onto the kernel log and keys in its own row):** `modem`, `modemlink`, `tpmseal`, `hostdisk`, `firstboot`, `claim`, `card`, `recovery`, `update`, `apply`, `follow`, `netguard`, `netjoin`, `apnet`, `sipsign`, `smsapi`, `sendrules`, `sockets`, `procguard`, `childproc`, `cgroup`, `clock`, `attest`, `boxname`, `bridgeclient`, `bridgeproto`, `vm`, `quota`, `admission`, `accel`, `budget`, `inflight`, `floor`, `hostchange`, `reversible`, and the host-side `cmd/` binaries (`agentos-modem`, `-holder`, `-egress`, `-checker`, `-hostdisk`, `-release`, `-ap`, `-netjoin`, `-clock-boot`, `-seller`).
  - **Sub B, untrusted side:** `owner`, `localui`, `localsrv`, `localapi`, `control`, `question`, `attention`, `guest`, `guesterr`, `cmd/agentos-guest-bridge`, `workers`, `change`, `compile`, `corpus`, `skill`, `loops`, `loop7`, `loopbuild`, `machprobe`, `probecmd`, `sockprobe`, `fold`, `hint`, `cleanroom`, `pubsend`, `voice`, `daemon` and `cmd/agentosd` (the wiring; sub B's ports unhook it, step 5 deletes it), `cmd/agentos-localui`, and `evals/slice-inbox/` until it is handed over.
  - **Codex lane, tier C only:** the lane gate fails a Codex PR whose tier is above C (`tools/risk_tier.py`), and every `broker/` directory and `evals/` directory is tier B or A. The lane therefore owns no `broker/` directory; its rows touch only tier C paths (`docs/`, `tools/`, `tests/`) and are claimed by issue. A Codex row that needs a tier B path is built by the peers, unless a gate-file PR with a Security accept raises the limit in `tools/risk_tier.py`. It writes through `Kernel.Submit` (`broker/kernel/kernel.go`, which runs `Admit`), never raw `Log.Append`, and imports no old-core directory.
- **Everything else** (docs, tools, tests, image, CI) has no fixed owner: the conflict guard (OPERATING §5) keeps two builds off one file.

## Lanes

| Lane | Team | Label | Prefix | Paths |
|---|---|---|---|---|
| none | peers (Mark's two Claude subscriptions, D-099) | none | none (`D-NNN`) | all paths, split by directory owners above |
| codex | codex (OpenAI Codex, D-139) | `lane:codex` | rows `CX-`, decisions `D-codex-NNN` | tier C paths only (port map above); entry point AGENTS.md |

A lane is added by an onboarding PR for each other team (another vendor's agent, a teammate), naming its directories and the frozen kernel and clerk interfaces it may call. The earlier claude2 lane (lifted 2026-10-10) and codex lane named old-core interfaces; their onboarding records are in git history before MIG-1. D-126 retired the codex lane; D-139, which is later, brings it back at step 4: the `codex` row in the table above gives its label (`lane:codex`), its tier limit, the frozen kernel and clerk interfaces it may call, and AGENTS.md as its entry point. The Codex lane may call only the frozen kernel and clerk interfaces: `kernel.Request`, `kernel.View` and `Kernel.Submit` in `broker/kernel`, `key.Step` and `key.Refusal` in `broker/kernel/key`, `clerk.Check`, `clerk.Facts` and the `Effect` type in `broker/clerk`, and the simulator in `broker/kernel/sim`. It never imports an old-core directory (`tools/old_core.txt`), and it claims a row by its issue's `state:building` label before building (CLAUDE.md).
