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
_HOOK_PATH = re.compile(r'"\$CLAUDE_PROJECT_DIR/(\.claude/hooks/[A-Za-z0-9_]+\.py)"')


def user_entries(root=ROOT):
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
            hooks.append({**hook, "command": f'[ -f "{path}" ] || exit 0; {command}'})
        if hooks:
            entries.append({**entry, "hooks": hooks})
    return entries


def ours(entry, root):
    return any(f"{root}/.claude/hooks/" in h.get("command", "") for h in entry.get("hooks", []))


def install(settings_path, root=ROOT):
    """Merge the entries into settings_path; return the merged settings."""
    try:
        settings = json.loads(settings_path.read_text())
    except FileNotFoundError:
        settings = {}
    pre = settings.setdefault("hooks", {}).setdefault("PreToolUse", [])
    pre[:] = [e for e in pre if not ours(e, root)] + user_entries(root)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=settings_path.parent, prefix=".settings.")
    with os.fdopen(fd, "w") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")
    os.replace(tmp, settings_path)
    return settings


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--settings", default=str(pathlib.Path.home() / ".claude/settings.json"))
    a = ap.parse_args(argv)
    install(pathlib.Path(a.settings))
    print(f"session_hooks: {ROOT}'s {', '.join(HOOKS)} hook is in {a.settings}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
