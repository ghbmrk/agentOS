# Hand-off: resume from here

Read this first, on either subscription (both are equal peers, OPERATING §7; D-098). GitHub is the live handoff; this file is the durable map and holds no dated state. Read order: README.md role list, this file, then only the PR or brief you act on.

## 1. Rebuild in-flight state from GitHub alone
1. List open PRs (`list_pull_requests`, state open, newest first). Titles carry the package ID; drafts are reference only.
2. For each PR you may act on, read its latest verdict comment. Every verdict comment ends with the PR's next step and the reviews still owed (OPERATING §5, §7), so that line says what happens next without any chat history.
3. Read the PR's check runs on the current head: green CI plus all required reviews accepting that head plus a clean merge means merge.
4. Read BOARD.md rows for state and owner; a row `building` with an owner belongs to that team (OPERATING §7).
5. Read `briefs/SIM.md` for the plan and wave order, and DECISIONS.md for anything newer than the list below.
6. Verify before acting: any thread or status label can be stale.

## 2. Standing decisions and rules
- **D-095** Simplification: the journal is the only durable state, owner messages are intents, one revisable outcome, forget once, a named trusted core. Plan and packages: `briefs/SIM.md`.
- **D-096** Includes SPEC one log (SIM-sd) and the scope freeze and PR cap (off-gate scope frozen until G2 passes; open PRs capped at about 10 per lane).
- **D-097** Pull-first (STATUS is the primary owner view, only urgent classes pushed, daily digest removed) and key erasure.
- **D-098** Both subscriptions are equal peers; no main one, no lane restriction between them.
- Merge when every required review accepts the current head, CI is green and it merges cleanly; asks to Mark are cards, never typed phrases.
- Chat layout: standing threads Decisions, Questions, PR updates, Alerts; finished threads are resolved at once. Project memory may be off, so durable state lives in the repo.

Edit this file only when a standing decision changes. Where DECISIONS.md and this list differ, DECISIONS.md wins.
