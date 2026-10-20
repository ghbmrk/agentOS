#!/usr/bin/env python3
"""PreToolUse hook: a Bash call that a gh allow rule in .claude/settings.json would let skip
the permission ask skips it only in its exact shape (OPERATING §7).

An allow rule's `*` also matches spaces, so without this hook a call could carry another
method, field, `--input` or `@file` on the same endpoint. Any command in which one of RULES
matches anywhere (a compound command included), as written or with quotes and backslashes
removed, whitespace collapsed and case ignored, must be, as a whole, one of SHAPES; anything
else goes to the permission ask. Commands no rule matches pass through to the normal
permission flow. tests/test_gh_shape_hook.py pins RULES to settings.json and every shape to
its rule.
"""
import json
import re
import shlex
import sys

REPO = "repos/ghbmrk/agentOS"
NUM = r"[1-9][0-9]{0,6}"
SHA = r"[0-9a-f]{40}"
LABEL = r"[a-z][a-z0-9-]*(?::[a-z][a-z0-9-]*)?"

# The gh allow rules in .claude/settings.json, without the Bash( ) wrapper.
RULES = [
    f"gh api -X PUT {REPO}/pulls/*/ccr/auto_merge -f merge_method=merge",
    f"gh api -X DELETE {REPO}/pulls/*/ccr/auto_merge",
    f"gh api -X PUT {REPO}/pulls/*/merge -f merge_method=merge -f sha=*",
    f"gh api -X POST {REPO}/issues/*/labels -f labels[]=*",
    f"gh api -X DELETE {REPO}/issues/*/labels/*",
]

# The only commands those rules may let through: arm, disarm, pinned merge, label add, label remove.
SHAPES = [
    ["gh", "api", "-X", "PUT", f"{REPO}/pulls/{NUM}/ccr/auto_merge", "-f", "merge_method=merge"],
    ["gh", "api", "-X", "DELETE", f"{REPO}/pulls/{NUM}/ccr/auto_merge"],
    ["gh", "api", "-X", "PUT", f"{REPO}/pulls/{NUM}/merge", "-f", "merge_method=merge", "-f", f"sha={SHA}"],
    ["gh", "api", "-X", "POST", f"{REPO}/issues/{NUM}/labels", "-f", rf"labels\[\]={LABEL}"],
    ["gh", "api", "-X", "DELETE", f"{REPO}/issues/{NUM}/labels/{LABEL}"],
]

# A space in a rule matches any run of whitespace, in case the matcher normalizes it.
_RULE_RES = [re.compile(".*".join(r"\s+".join(map(re.escape, p.split(" "))) for p in r.split("*")),
                        re.S | re.I)
             for r in RULES]
# Characters a shell gives meaning to; none appears in any shape.
_SHELL = set(";&|<>()$`\\\"'{}*?!#~\n\r\t")


def normalized(command):
    """The command with line continuations, quotes and backslashes removed and whitespace collapsed."""
    return " ".join(re.sub(r"['\"\\]", "", command.replace("\\\n", "")).split())


def guarded(command):
    return any(r.search(c) for c in (command, normalized(command)) for r in _RULE_RES)


def exact(command):
    if _SHELL & set(command) or command != command.strip() or "  " in command:
        return False
    tokens = shlex.split(command)
    return any(len(s) == len(tokens) and all(re.fullmatch(p, t) for p, t in zip(s, tokens))
               for s in SHAPES)


def decide(command):
    """None lets the call go on; a string is the reason it goes to the permission ask."""
    if guarded(command) and not exact(command):
        return ("gh allow rule matched but the call is not one of the exact shapes in "
                ".claude/hooks/gh_shape.py (arm, disarm, pinned merge, label add or remove: "
                "numeric number, 40-hex sha, plain lowercase label, no other flags or shell syntax)")
    return None


def main():
    try:
        event = json.load(sys.stdin)
        command = event.get("tool_input", {}).get("command", "") if event.get("tool_name") == "Bash" else ""
        reason = decide(command) if isinstance(command, str) else "command is not a string"
    except Exception as e:  # a hook error must not let a call skip its shape check
        reason = f"gh_shape hook error: {type(e).__name__}"
    if reason:
        json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                          "permissionDecision": "ask",
                                          "permissionDecisionReason": reason}}, sys.stdout)


if __name__ == "__main__":
    main()
