#!/usr/bin/env python3
"""PreToolUse hook: a session's close of an issue that `assurance/vulncheck.json` cites is denied
(VULN-accept-close-guard, #5692).

A closed issue withdraws every acceptance record that cites it, so every vulncheck scan that
applies one fails until the `acceptance` workflow reopens it, and that reopen waits on the shared
runner queue: #5660 was closed by a merge cleanup at 05:05:44Z on 2026-11-14 and #5664's
image-vulncheck failed eleven seconds later. GitHub cannot block a close, so this stops the close
where a session makes it. A cited issue stays open with `state:merged` (tools/vulncheck.py
REOPEN_NOTE); `acceptance.yml` stays the backstop for every other close path.

Closes it sees: the GitHub MCP issue tools with `state: closed` on ghbmrk/agentOS, and a Bash
command that runs `gh issue close` or carries `state=closed` beside an `issues/N` path. The records are the
union of the working tree's file and `origin/main`'s, so a checkout older than a new record
still guards it. A cited issue is denied with the reason; a close whose issue number it cannot
read, or whose records it cannot load, goes to the permission ask. Every other call passes.
tests/test_close_guard_hook.py pins the decisions and the settings.json wiring.
"""
import json
import pathlib
import re
import shlex
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG = "assurance/vulncheck.json"
REPO = ("ghbmrk", "agentos")
MCP_TOOLS = {"mcp__github__issue_write", "mcp__github__update_issue"}
_GH_CLOSE = re.compile(r"\bgh\s+issue\s+close\b", re.I)
_STATE_CLOSED = re.compile(r"""\bstate["']?\s*[:=]\s*["']?closed\b""", re.I)
_CLOSE_ARG = re.compile(r"#?([1-9][0-9]{0,6})|https://github\.com/[^/]+/[^/]+/issues/([1-9][0-9]{0,6})")
_ISSUE_PATH = re.compile(r"\bissues/([1-9][0-9]{0,6})\b")


def bash_closes(command):
    """The issue numbers a Bash command closes: [] when it closes none, None when it runs
    `gh issue close` on an issue it names in a way this cannot read (a variable). `state=closed`
    counts only beside an `issues/N` path, the only form an API close takes; a search or list
    filter such as `issues?state=closed` names no issue and passes."""
    closes = list(_GH_CLOSE.finditer(command))
    nums = [int(n) for n in _ISSUE_PATH.findall(command)] if _STATE_CLOSED.search(command) else []
    if not closes and not nums:
        return []
    for closing in closes:
        try:
            lex = shlex.shlex(command[closing.end():], posix=True, punctuation_chars=True)
            lex.whitespace_split = True
            tokens = list(lex)
        except ValueError:
            return None
        args = []
        for t in tokens:  # up to the end of this command; every number-shaped argument counts
            if t and set(t) <= set(";&|()"):
                break
            m = _CLOSE_ARG.fullmatch(t)
            if m:
                args.append(int(m.group(1) or m.group(2)))
        if not args:
            return None
        nums += args
    return sorted(set(nums)) or None


def mcp_closes(tool_input):
    """The issue an MCP issue call closes on ghbmrk/agentOS, as a one-item list, else []."""
    if str(tool_input.get("state", "")).lower() != "closed":
        return []
    if (str(tool_input.get("owner", "")).lower(), str(tool_input.get("repo", "")).lower()) != REPO:
        return []
    num = tool_input.get("issue_number")
    return [int(num)] if isinstance(num, (int, float)) and int(num) == num and num > 0 else None


def records(root=ROOT):
    """Acceptance records from the working tree and from origin/main, if it is there."""
    texts = [(root / CONFIG).read_text()]
    shown = subprocess.run(["git", "-C", str(root), "show", f"origin/main:{CONFIG}"],
                           capture_output=True, text=True, timeout=10)
    if shown.returncode == 0:
        texts.append(shown.stdout)
    return [r for t in texts for r in json.loads(t).get("accepted", [])]


def cited(recs, num):
    """tools/vulncheck.py's `cited`, which this does not import: that module loads the image
    tooling at import, too slow and too wide for a hook that runs on every Bash call."""
    return sum(1 for r in recs if r.get("issue") == num)


def decide(event, root=ROOT):
    """None lets the call go on; otherwise (decision, reason) with decision "deny" or "ask"."""
    tool, tool_input = event.get("tool_name"), event.get("tool_input") or {}
    if tool == "Bash":
        command = tool_input.get("command", "")
        nums = bash_closes(command) if isinstance(command, str) else None
    elif tool in MCP_TOOLS:
        nums = mcp_closes(tool_input)
    else:
        return None
    if nums == []:
        return None
    if nums is None:
        return ("ask", "close_guard hook: this closes an issue whose number it cannot read; check "
                "`python3 tools/vulncheck.py cited N` first (a cited issue stays open)")
    recs = records(root)
    hits = {n: cited(recs, n) for n in nums if cited(recs, n)}
    if not hits:
        return None
    named = ", ".join(f"#{n} ({c} record(s))" for n, c in sorted(hits.items()))
    return ("deny", f"close_guard hook: {CONFIG} cites {named}. Closing a cited issue withdraws its "
            "acceptance and fails image-vulncheck on every PR until the queued reopen runs (#5692). "
            "Leave it open with `state:merged`; close it only after its last record is removed or "
            "moved to another open issue.")


def main():
    try:
        verdict = decide(json.load(sys.stdin))
    except Exception as e:  # a hook error must not let a close of a cited issue through unasked
        verdict = ("ask", f"close_guard hook error: {type(e).__name__}")
    if verdict:
        json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                          "permissionDecision": verdict[0],
                                          "permissionDecisionReason": verdict[1]}}, sys.stdout)


if __name__ == "__main__":
    main()
