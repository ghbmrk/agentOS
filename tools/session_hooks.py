#!/usr/bin/env python3
"""Copy this checkout's close guard hook into the user's Claude Code settings (#5692).

Claude Code reads a project's hooks only from the `.claude/settings.json` of the directory a
session starts in. This project's sessions start in /home/user with the checkout below it, so
`.claude/hooks/close_guard.py` never loads there (#5702 L3). The cloud environment's setup script
runs `python3 /home/user/agentOS/tools/session_hooks.py`, which writes the checkout's PreToolUse
entries for the hooks in HOOKS into ~/.claude/settings.json with `$CLAUDE_PROJECT_DIR` replaced by
the checkout's absolute path, so every session in the environment loads them wherever it starts.
`gh_shape.py` is left out: it narrows settings.json's allow rules, which load only where it does.
Each command first passes when its hook file is missing (a checkout older than the hook,
or none), so a stale container never blocks every Bash call; once the file is there it fails
closed exactly as the project entry does. Entries this wrote before are replaced, others are
kept, and running it twice changes nothing. tests/test_session_hooks.py pins it.

The copy alone passes silently when it never loads (#6413): the environment may have no setup
script, or a session preloaded before it ran reads its settings first. So each installed command
also marks the session it runs in (MARKS/<CLAUDE_CODE_SESSION_ID>), and `--check`, run as a Bash
call, which the hook sees first, exits 0 only when the guard ran in this session or the session
started in the checkout, 1 (naming the fix) when it is not installed or not loaded, and 2 when
the session has no id to tell by.
"""
import argparse
import json
import os
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
HOOKS = ("close_guard",)
MARKS = pathlib.Path("/tmp/agentos-close-guard")
_HOOK_PATH = re.compile(r'"\$CLAUDE_PROJECT_DIR/(\.claude/hooks/[A-Za-z0-9_]+\.py)"')


def user_entries(root=ROOT, marks=MARKS):
    """The checkout's PreToolUse entries for HOOKS, rewritten to run from any starting directory."""
    project = json.loads((root / ".claude/settings.json").read_text())
    entries = []
    for entry in project["hooks"]["PreToolUse"]:
        hooks = []
        for hook in entry["hooks"]:
            command = hook["command"]
            paths = _HOOK_PATH.findall(command)
            if len(paths) != 1:
                raise ValueError(f"cannot place hook command: {command}")
            if pathlib.PurePath(paths[0]).stem not in HOOKS:
                continue
            path = f"{root}/{paths[0]}"
            command = command.replace("$CLAUDE_PROJECT_DIR", str(root))
            mark = f'{{ mkdir -p "{marks}" && : > "{marks}/${{CLAUDE_CODE_SESSION_ID:-unknown}}"; }} 2>/dev/null; '
            hooks.append({**hook, "command": f'[ -f "{path}" ] || exit 0; {mark}{command}'})
        if hooks:
            entries.append({**entry, "hooks": hooks})
    return entries


def ours(entry, root):
    return any(f"{root}/.claude/hooks/" in h.get("command", "") for h in entry.get("hooks", []))


def install(settings_path, root=ROOT, marks=MARKS):
    """Merge the entries into settings_path; return the merged settings."""
    try:
        settings = json.loads(settings_path.read_text())
    except FileNotFoundError:
        settings = {}
    pre = settings.setdefault("hooks", {}).setdefault("PreToolUse", [])
    pre[:] = [e for e in pre if not ours(e, root)] + user_entries(root, marks)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=settings_path.parent, prefix=".settings.")
    with os.fdopen(fd, "w") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")
    os.replace(tmp, settings_path)
    return settings


FIX = ("the cloud environment's setup script must run `python3 {root}/tools/session_hooks.py` "
       "before the session starts (an environment setting; #6413)")


def check(settings_path, root=ROOT, marks=MARKS, session="", start=""):
    """(exit code, message): whether the close guard runs in this session."""
    if start and pathlib.Path(start).resolve() == pathlib.Path(root).resolve():
        return 0, f"session_hooks: this session started in {root}; its .claude/settings.json loads close_guard"
    try:
        pre = json.loads(settings_path.read_text())["hooks"]["PreToolUse"]
    except (OSError, ValueError, KeyError, TypeError):
        pre = None
    want = user_entries(root, marks)
    if not isinstance(pre, list) or [e for e in pre if isinstance(e, dict) and ours(e, root)] != want:
        return 1, f"session_hooks: close_guard is not installed in {settings_path}: " + FIX.format(root=root)
    if not session:
        return 2, "session_hooks: no CLAUDE_CODE_SESSION_ID, so whether close_guard loaded cannot be told"
    if not (pathlib.Path(marks) / session).exists():
        return 1, (f"session_hooks: close_guard is in {settings_path} but not loaded in this session "
                   "(written after it started): " + FIX.format(root=root))
    return 0, "session_hooks: close_guard ran in this session"


def start_dir():
    try:
        return os.readlink(f"/proc/{int(os.environ.get('CLAUDE_PID', ''))}/cwd")
    except (OSError, ValueError):
        return ""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--settings", default=str(pathlib.Path.home() / ".claude/settings.json"))
    ap.add_argument("--marks", default=str(MARKS), help=argparse.SUPPRESS)
    ap.add_argument("--check", action="store_true", help="exit 0 only if close_guard runs in this session")
    a = ap.parse_args(argv)
    if a.check:
        code, says = check(pathlib.Path(a.settings), ROOT, pathlib.Path(a.marks),
                           os.environ.get("CLAUDE_CODE_SESSION_ID", ""), start_dir())
        print(says, file=sys.stdout if code == 0 else sys.stderr)
        return code
    install(pathlib.Path(a.settings), ROOT, pathlib.Path(a.marks))
    print(f"session_hooks: {ROOT}'s {', '.join(HOOKS)} hook is in {a.settings}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
