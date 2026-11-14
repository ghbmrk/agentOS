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
command that holds `gh issue [-R repo] close N` (a target it cannot read goes to the ask only at
a command position of text that is run, so a commit message naming the command passes, #5705) or
carries `state=closed` beside an `issues/N` path;
an `issues/N` call with `--input`, or `closeIssue`, goes to the ask. The records are the
union of the working tree's file and `origin/main`'s, so a checkout older than a new record
still guards it. The hook loads in a session rooted at this checkout through settings.json, and
in a session rooted elsewhere (a project thread starts in /home/user) once tools/session_hooks.py
has copied the hook block into the user's settings. A cited issue is denied with the reason; a close whose issue number it cannot
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
_STATE_CLOSED = re.compile(r"""\bstate["']?\s*[:=]\s*["']?closed\b""", re.I)
_CLOSE_ARG = re.compile(r"#?([1-9][0-9]{0,6})|https://github\.com/[^/]+/[^/]+/issues/([1-9][0-9]{0,6})")
_ISSUE_PATH = re.compile(r"\bissues/([1-9][0-9]{0,6})\b")
# A close whose state this cannot read: an API call on an issue itself (no sub-path) whose body
# comes from --input, or GraphQL's closeIssue mutation.
_OPAQUE = re.compile(r"\bcloseIssue\b|\bissues/[1-9][0-9]{0,6}(?![/0-9]).*--input\b"
                     r"|--input\b.*\bissues/[1-9][0-9]{0,6}(?![/0-9])", re.I | re.S)


# Shell lexing for `gh issue close` (#5705). A close of a literal issue number counts wherever the
# words `gh issue close N` stand, in the command or in any string or here-document in it, so a
# cited number is denied even inside text that `bash -c`, `ssh` or `eval` may run. A close whose
# number is unreadable (a variable) asks only where the text is surely run: at a command position
# (after the start, a separator `;`, `&`, `|`, `(`, `)`, a newline, a backtick or `$(`, environment
# assignments, redirections, or anywhere after a wrapper such as `sudo` or `xargs`), in the command
# itself or in a string or here-document given to a shell runner. Elsewhere it is data, such as a
# commit message or grep pattern, and passes. An unterminated quote runs to the end.
_SEPS = set(";|()\n`")
_NESTED = re.compile(r"[\s;&|()`]")
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")
_REDIR = re.compile(r"[0-9]*(?:<<<|&>>|&>|>>|<>|>\||<&|>&|<|>)(.*)", re.S)
# Runners take a string they may run as shell code; a wrapper's later words stay command positions.
_RUNNERS = {"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "busybox", "ssh", "su", "eval",
            "watch", "script", "tmux", "screen", "parallel", "xargs", "flock", "nix-shell", "docker", "podman",
            "kubectl"}
_WRAPPERS = _RUNNERS | {"sudo", "doas", "env", "command", "builtin", "exec", "nohup", "time", "nice", "ionice",
                        "timeout", "stdbuf", "setsid", "chronic", "unbuffer", "strace", "find", "!", "{", "if",
                        "then", "elif", "else", "while", "until", "do"}
_ANSI = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f",
         "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _ansi(body):
    """The text of a $'...' string."""
    def one(m):
        e = m.group(1)
        if e[0] in "xu":
            return chr(int(e[1:], 16)) if len(e) > 1 else m.group(0)
        if e[0] in "01234567":
            return chr(int(e, 8) & 0xFF)
        return _ANSI.get(e, m.group(0))
    return re.sub(r"\\(x[0-9a-fA-F]{0,2}|u[0-9a-fA-F]{0,4}|[0-7]{1,3}|.)", one, body, flags=re.S)


def _word(s, i):
    """One shell word from s[i]: (its text with quoting removed, next index)."""
    out, n = [], len(s)
    while i < n:
        c = s[i]
        if c in " \t" or c in _SEPS or s.startswith("$(", i):
            break
        if c == "&" and not (out and out[-1] in "<>"):
            break
        if s.startswith("<<", i) and not s.startswith("<<<", i) and not (out and out[-1] == "<"):
            break
        if c == "\\":
            if s[i + 1:i + 2] not in ("", "\n"):
                out.append(s[i + 1])
            i += 2
        elif c == "'" or s.startswith("$'", i):
            ansi = c == "$"
            i += 1 + ansi
            j = i
            while j < n and s[j] != "'":
                j += 2 if ansi and s[j] == "\\" else 1
            out.append(_ansi(s[i:j]) if ansi else s[i:j])
            i = j + 1
        elif c == '"':
            i += 1
            while i < n and s[i] != '"':
                if s[i] == "\\" and s[i + 1:i + 2] in ("$", "`", '"', "\\", "\n"):
                    out.append(s[i + 1] if s[i + 1] != "\n" else "")
                    i += 2
                else:
                    out.append(s[i])
                    i += 1
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out), i


def _lex(s):
    """(simple commands as word lists, here-document bodies as (text, index of their command))."""
    cmds, bodies, pending, i, n = [[]], [], [], 0, len(s)
    while i < n:
        c = s[i]
        if c in " \t":
            i += 1
        elif s.startswith("\\\n", i):
            i += 2
        elif c in _SEPS or c == "&" or s.startswith("$(", i):
            if cmds[-1]:
                cmds.append([])
            i += 1 + s.startswith("$(", i)
            if c == "\n":
                for delim, strip, owner in pending:  # each body runs to its delimiter line
                    start = i
                    while i < n:
                        j = s.find("\n", i)
                        j = n if j < 0 else j
                        line = s[i:j].lstrip("\t") if strip else s[i:j]
                        i = j + 1
                        if line == delim:
                            break
                    bodies.append((s[start:i], owner))
                pending = []
        elif s.startswith("<<", i) and not s.startswith("<<<", i):
            i += 2
            strip = s.startswith("-", i)
            i += strip
            while i < n and s[i] in " \t":
                i += 1
            delim, i = _word(s, i)
            pending.append((delim, strip, len(cmds) - 1))
        else:
            w, i = _word(s, i)
            cmds[-1].append(w)
    return cmds, bodies


def _gh_close(rest):
    """The issues the arguments after a `gh` command name close: [] for no close, None if unread."""
    if not rest or rest[0].lower() != "issue":
        return []
    i = 1
    while i < len(rest):  # gh's repository flag, its one flag that goes before the subcommand
        if rest[i] in ("-R", "--repo"):
            i += 2
        elif rest[i].startswith(("-R", "--repo=")):
            i += 1
        else:
            break
    if i >= len(rest) or rest[i].lower() != "close":
        return []
    args = [m for t in rest[i + 1:] if (m := _CLOSE_ARG.fullmatch(t))]  # every number-shaped argument
    return [int(m.group(1) or m.group(2)) for m in args] or None


def _command_closes(words, run):
    """The issues one simple command closes; None for an unreadable close at its command position."""
    nums, position, skip = [], True, False  # position: True, False, or "wrapped" (stays a position)
    for k, w in enumerate(words):
        name = w.rsplit("/", 1)[-1].lower()
        if name == "gh":
            found = _gh_close(words[k + 1:])
            if found is None and run and position and not skip:
                return None
            nums += found or []
        if skip:
            skip = False
        elif position is True:
            redirect = _REDIR.fullmatch(w)
            if name in _WRAPPERS:
                position = "wrapped"
            elif redirect:
                skip = not redirect.group(1)
            elif not _ASSIGN.match(w):
                position = False
    return nums


def _runs(words):
    return any(w.rsplit("/", 1)[-1].lower() in _RUNNERS for w in words)


def _closes(s, run=True, depth=0):
    """The issues s closes, or None for an unreadable close where `run` says s is surely run, or
    for strings nested past depth 8."""
    if depth > 8:
        return None
    cmds, bodies = _lex(s)
    parts = [(w, run and _runs(c[:k])) for c in cmds for k, w in enumerate(c) if w != s and _NESTED.search(w)]
    parts += [(text, run and _runs(cmds[owner])) for text, owner in bodies]
    found = [_closes(text, runs, depth + 1) for text, runs in parts]
    found += [_command_closes(c, run) for c in cmds]
    if None in found:
        return None
    return [n for f in found for n in f]


def bash_closes(command):
    """The issue numbers a Bash command closes: [] when it closes none, None when it runs
    `gh issue close` on an issue it names in a way this cannot read (a variable), or may close
    one through `--input` or GraphQL's `closeIssue`; an unreadable `gh issue close` asks only at a
    command position of text that is run (#5705). `state=closed` counts only beside an `issues/N` path, the only form an API
    close takes; a search or list filter such as `issues?state=closed` names no issue and passes."""
    if _OPAQUE.search(command):
        return None
    closes = _closes(command)
    if closes is None:
        return None
    nums = [int(n) for n in _ISSUE_PATH.findall(command)] if _STATE_CLOSED.search(command) else []
    return sorted(set(closes + nums))


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
