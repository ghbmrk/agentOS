# ENV-session-hooks-unloaded: a loud check that the close guard runs in this session

Work item #6413 (release finding from #6412). Tier C.

**What main has.** `tools/session_hooks.py` copies `.claude/hooks/close_guard.py`'s PreToolUse entry into `~/.claude/settings.json`, and TN-vulncheck-11 rests on the environment's setup script running it. Checked 2026-11-21: the environment has no setup script, the session process is a preloaded `claude --preload` started in /home/user, and `~/.claude/settings.json` does not exist, so the guard loads in no project-thread or coordinator session and nothing says so.

**Work.**
1. Each command `session_hooks.py` installs marks the session it runs in (`/tmp/agentos-close-guard/<CLAUDE_CODE_SESSION_ID>`), without changing the guard's verdict or fail-closed exit.
2. `session_hooks.py --check` exits 0 only when the guard ran in this session (its mark exists) or the session started in the checkout; 1, naming the setup-script fix, when the entry is missing, stale or edited, or installed but not loaded this session; 2 when there is no session id.
3. TN-vulncheck-11 states what was observed and the preload risk.

**Not in this row.** Adding the setup-script line is an environment setting only Mark can approve (a Decisions card via the coordinator); a session after that runs `--check` to confirm the guard loads.

**Requirement IDs:** EVL-5.

**Scope:** `tools/session_hooks.py`, `tests/test_session_hooks.py`, `tools/ASSUMPTIONS.md`, this brief.

**Acceptance tests** (`tests/test_session_hooks.py`):
- `test_check_fails_loudly_until_the_guard_has_run_in_this_session`
- `test_check_reads_a_stale_or_edited_entry_as_not_installed`
- `test_check_passes_a_session_started_in_the_checkout`
- `test_cli_check_exit_codes`
- the existing install and deny tests, updated for the mark.
