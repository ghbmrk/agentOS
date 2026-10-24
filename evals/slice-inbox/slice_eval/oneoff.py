"""Counts one-off irreversible approvals in a kernel log export (MET-oneoff, #2964).

A one-off is an irreversible step that no standing key (KEY-5), nor any key
narrowed from one, covered, so the owner approved it alone. The reader adds no
log entry or field: it reads only what the kernel already writes (broker/kernel
state.go and task.go), and a split those entries do not record is reported as
not recorded, never inferred.

- An accepted plan under a bare root (a key with no links) is a passkey's own
  tap (KEY-4, D-146): one approval, its irreversible steps listed by verb. A
  co-signed one carries the second passkey (factor "passkey+second").
- A task approval (task.approved, CLK-3, D-147) is one passkey approval of a
  task's submits on one site; its entry lists no verb or steps.
- Texted-code approvals (CH-10 low tier) have no log entry yet, so that factor
  is reported as not recorded.

Conversion reads key.issued: a verb converted when, after its first one-off,
the log issued a clerk key (a root with at least one link) for the same clerk
whose verbs include it.

The output is one line beside OWN-19's decisions component, never summed into
it. Input: a JSON array, or JSON lines, of entries as kernel.Entry marshals
them ({seq, prev, at, type, v, body}).

    python3 evals/slice-inbox/slice_eval/oneoff.py LOG.json
"""
import datetime
import json
import sys

# key.ClassOf: these are reversible, and every other verb, unknown ones too, is
# irreversible (it fails closed, as ClassOf does).
REVERSIBLE = frozenset({"read", "fetch", "draft", "organize", "trash", "present"})

UNRECORDED = "-"


def load(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    s = text.lstrip()
    if s.startswith("["):
        return json.loads(s)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def week(at_ms):
    y, w, _ = datetime.datetime.fromtimestamp(at_ms / 1000, datetime.timezone.utc).isocalendar()
    return f"{y}-W{w:02d}"


def verbs(k):
    """The verbs a key reaches: its root's, narrowed by every link's verbs caveat."""
    out = set(k["root"].get("verbs") or [])
    for link in k.get("links") or []:
        for c in link.get("caveats") or []:
            if c.get("kind") == "verbs":
                out &= set(c.get("set") or [])
    return out


def approvals(entries):
    """Each one-off approval in log order: {at, factor, clerk, steps: [verb, ...] or None}."""
    submitted = {}
    out = []
    for e in entries:
        t, b = e["type"], e.get("body") or {}
        if t == "plan.submitted":
            submitted[e["seq"]] = b
        elif t == "plan.accepted":
            p = submitted.get(b.get("cause"))
            if p is None or p.get("key", {}).get("links"):
                continue
            steps = [s["verb"] for s in p.get("steps") or [] if s.get("verb") not in REVERSIBLE]
            if steps:
                out.append({"at": e["at"], "factor": "passkey+second" if p.get("cosigns") else "passkey",
                            "clerk": p["key"]["root"].get("clerk", ""), "steps": steps})
        elif t == "task.approved":
            out.append({"at": e["at"], "factor": "passkey", "clerk": UNRECORDED, "steps": None})
    return out


def report(entries):
    found = approvals(entries)
    rows = {}
    for a in found:
        for v in sorted(set(a["steps"])) if a["steps"] is not None else [UNRECORDED]:
            r = rows.setdefault((week(a["at"]), a["factor"], v), {"approvals": 0, "steps": 0})
            r["approvals"] += 1
            r["steps"] = UNRECORDED if a["steps"] is None else r["steps"] + a["steps"].count(v)
    first = {}
    for a in found:
        for v in a["steps"] or []:
            first.setdefault((a["clerk"], v), a["at"])
    keyed = set()
    for e in entries:
        if e["type"] != "key.issued":
            continue
        for k in (e.get("body") or {}).get("Keys") or []:
            if not k.get("links"):
                continue
            for v in verbs(k):
                cv = (k["root"].get("clerk", ""), v)
                if cv in first and e["at"] > first[cv]:
                    keyed.add(cv)
    return {
        "approvals": len(found),
        "steps": sum(len(a["steps"]) for a in found if a["steps"] is not None),
        "rows": [{"week": w, "factor": f, "verb": v, **r} for (w, f, v), r in sorted(rows.items())],
        "verbs": sorted(f"{c}/{v}" for c, v in first),
        "keyed_later": sorted(f"{c}/{v}" for c, v in keyed),
    }


def render(r):
    lines = [f"one-offs (OWN-19, not in decisions): {r['approvals']} approvals, {r['steps']} steps; "
             f"texted code: not recorded"]
    if r["rows"]:
        lines.append("week      factor          verb             approvals  steps")
        lines += [f"{x['week']:<9} {x['factor']:<15} {x['verb']:<16} {x['approvals']:>9}  {x['steps']:>5}" for x in r["rows"]]
    lines.append(f"later keyed: {len(r['keyed_later'])} of {len(r['verbs'])} verbs"
                 + (f" ({', '.join(r['keyed_later'])})" if r["keyed_later"] else ""))
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: oneoff.py LOG.json")
    print(render(report(load(sys.argv[1]))))
