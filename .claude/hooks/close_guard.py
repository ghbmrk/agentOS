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
command that runs `gh issue [-R repo] close` or carries `state=closed` beside an `issues/N` path;
an `issues/N` call with `--input`, or `closeIssue`, goes to the ask. The records are the
union of the working tree's file and `origin/main`'s, so a checkout older than a new record
still guards it. The hook loads in a session rooted at this checkout through settings.json, and
in a session rooted elsewhere (a project thread starts in /home/user) once tools/session_hooks.py
has copied the hook block into the user's settings. A cited issue is denied with the reason; a close whose issue number it cannot
read, or whose records it cannot load, goes to the permission ask, wherever the words stand: the
hook does not parse the shell, so it cannot tell run text from data, and it fails closed (#5714).
The one exemption is a commit message whose text provably runs nowhere (`inert_spans`), so a
message that mentions `gh issue close N` does not stall an unattended session (#5705). Every
other call passes. tests/test_close_guard_hook.py pins the decisions and the settings.json wiring.
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
# `gh issue close`, with the repository flag (gh's one flag that goes before the subcommand) between.
_GH_CLOSE = re.compile(r"gh\s+issue\s+(?:(?:-R\s*|--repo(?:\s+|=))\S+\s+)*close\b", re.I)
_STATE_CLOSED = re.compile(r"""\bstate["']?\s*[:=]\s*["']?closed\b""", re.I)
_CLOSE_ARG = re.compile(r"#?([1-9][0-9]{0,6})|https://github\.com/[^/]+/[^/]+/issues/([1-9][0-9]{0,6})")
_ISSUE_PATH = re.compile(r"\bissues/([1-9][0-9]{0,6})\b")
# A close whose state this cannot read: an API call on an issue itself (no sub-path) whose body
# comes from --input, or GraphQL's closeIssue mutation.
_OPAQUE = re.compile(r"\bcloseIssue\b|\bissues/[1-9][0-9]{0,6}(?![/0-9]).*--input\b"
                     r"|--input\b.*\bissues/[1-9][0-9]{0,6}(?![/0-9])", re.I | re.S)


# A commit message whose text reaches only git: `git [-C dir] commit` at the start of a command
# (string start, newline, `;`, `&&`, `||`), then words with no quoting or expansion, then `-m`,
# `-am` or `--message` with a single-quoted string, a double-quoted string with no `$`, backtick
# or backslash, or `"$(cat <<'D' ... D\n)"`; or `-F -` / `--file=-` fed by `<<'D'` (a quoted
# delimiter: the body is not expanded). A body line equal to the delimiter ends it, as in bash.
_CMD_START = r"(?:^|(?<=\n)|(?<=;)|(?<=&&)|(?<=\|\|))[ \t]*"
_PLAIN = r"[^'\"`$\\\n;&|<>(){}#]"
_GIT_COMMIT = _CMD_START + r"git(?:[ \t]+-C[ \t]+" + _PLAIN + r"+)?[ \t]+commit\b" + _PLAIN + r"*?[ \t]"
_BODY = r"[ \t]*\n(?P<{b}>(?:(?!(?P={d})(?:\n|$))[^\n]*\n)*)(?P={d})"
_INERT = re.compile(
    _GIT_COMMIT + r"(?:(?:-[a-zA-Z]*m[ \t]*|--message(?:=|[ \t]+))(?P<m1>"
    r"'(?P<sq>[^']*)'|\"(?P<dq>[^\"$`\\]*)\""
    r"|\"\$\(cat[ \t]+<<[ \t]*'(?P<d1>\w+)'" + _BODY.format(b="b1", d="d1") + r"\n[ \t]*\)\")"
    r"|(?:-F[ \t]*|--file(?:=|[ \t]+))-[ \t]+(?P<m2><<[ \t]*'(?P<d2>\w+)'" + _BODY.format(b="b2", d="d2")
    + r"(?=\n|$)))")
# After the messages are masked, the rest of the command must hold nothing that could run git's
# output (which echoes the subject line) or change the quoting around a message: no quote,
# backslash, substitution, brace, comment, pipe or redirection other than `2>&1` and `>/dev/null`.
_SAFE_REDIRECT = re.compile(r"[ \t][12]?>(?:&[12]|[ \t]*/dev/null)(?=[ \t;&|\n]|$)")
_UNSAFE_REST = re.compile(r"['\"`\\{}()<>#]|(?<!\|)\|(?!\|)")


def inert_spans(command):
    """The command with every inert commit message replaced by `_`, and the messages' texts; None
    when the masked command could still run or requote a message, or holds no message."""
    texts, masked = [], command
    while True:
        m = _INERT.search(masked)
        if not m:
            break
        texts.append(next(t for t in m.group("sq", "dq", "b1", "b2") if t is not None))
        span = "m1" if m.group("m1") is not None else "m2"
        masked = masked[:m.start(span)] + "_" + masked[m.end(span):]
    if not texts or _UNSAFE_REST.search(_SAFE_REDIRECT.sub(" ", masked)):
        return None
    return masked, texts


def bash_closes(command):
    """The issue numbers a Bash command closes: main's reading (`_bash_closes`), except that an
    unreadable close only inside inert commit messages passes; a literal number there still counts."""
    nums = _bash_closes(command)
    if nums is not None:
        return nums
    spans = inert_spans(command)
    if spans is None:
        return None
    nums = _bash_closes(spans[0])
    if nums is None:
        return None
    for text in spans[1]:
        nums += loose_numbers(text)
    return sorted(set(nums))


def loose_numbers(command):
    """Every number on the rest of a line after `gh issue close`, quotes ignored: used only to turn
    an ask into a deny, so reading too many numbers cannot let a close through."""
    return {int(a or b) for m in _GH_CLOSE.finditer(command)
            for a, b in _CLOSE_ARG.findall(command[m.end():].split("\n", 1)[0])}


def _bash_closes(command):
    """The issue numbers a Bash command closes: [] when it closes none, None when it runs
    `gh issue close` on an issue it names in a way this cannot read (a variable), or may close
    one through `--input` or GraphQL's `closeIssue`. `state=closed`
    counts only beside an `issues/N` path, the only form an API close takes; a search or list
    filter such as `issues?state=closed` names no issue and passes."""
    if _OPAQUE.search(command):
        return None
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
    """Acceptance records from the working tree and from origin/main, if it is there; a record in
    both counts once."""
    texts = [(root / CONFIG).read_text()]
    shown = subprocess.run(["git", "-C", str(root), "show", f"origin/main:{CONFIG}"],
                           capture_output=True, text=True, timeout=10)
    if shown.returncode == 0:
        texts.append(shown.stdout)
    unique = {json.dumps(r, sort_keys=True): r for t in texts for r in json.loads(t).get("accepted", [])}
    return list(unique.values())


def cited(recs, num):
    """tools/vulncheck.py's `cited`, which this does not import: that module loads the image
    tooling at import, too slow and too wide for a hook that runs on every Bash call."""
    return sum(1 for r in recs if r.get("issue") == num)


def decide(event, root=ROOT):
    """None lets the call go on; otherwise (decision, reason) with decision "deny" or "ask"."""
    tool, tool_input = event.get("tool_name"), event.get("tool_input") or {}
    command = tool_input.get("command", "")
    if tool == "Bash":
        nums = bash_closes(command) if isinstance(command, str) else None
    elif tool in MCP_TOOLS:
        nums = mcp_closes(tool_input)
    else:
        return None
    if nums == []:
        return None
    if nums is None:
        # An unreadable close may still name a cited number in words this could not split (an
        # unterminated quote, a nested shell): a cited number anywhere on such a line denies.
        recs = records(root)
        loose = loose_numbers(command) if tool == "Bash" and isinstance(command, str) else ()
        hits = {n: cited(recs, n) for n in loose if cited(recs, n)}
        if hits:
            return _deny(hits)
        return ("ask", "close_guard hook: this closes an issue whose number it cannot read; check "
                "`python3 tools/vulncheck.py cited N` first (a cited issue stays open)")
    recs = records(root)
    hits = {n: cited(recs, n) for n in nums if cited(recs, n)}
    if not hits:
        return None
    return _deny(hits)


def _deny(hits):
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
