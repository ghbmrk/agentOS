# MET-oneoff (#2964): the one-off approval reader in evals/slice-inbox/slice_eval/oneoff.py.
# Tests that it counts only bare-root accepted plans with irreversible steps and task
# approvals, splits them by ISO week, factor and verb, counts approvals and steps apart,
# reads conversion from later clerk keys, and that the names it reads still match the
# kernel's (broker/kernel). Makes no SPEC coverage claim: the issue is class later.
import json
import pathlib
import re
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "evals" / "slice-inbox"))
from slice_eval import oneoff  # noqa: E402

KERNEL = ROOT / "broker" / "kernel"
DAY = 86_400_000
MON = 1_792_368_000_000  # 2026-10-19T00:00Z, a Monday (ISO 2026-W43)


def root(clerk, verbs):
    return {"owner": "AA==", "clerk": clerk, "verbs": verbs, "serial": "s", "sig": "AA=="}


def link(verbs=None):
    cav = [{"kind": "verbs", "set": verbs}] if verbs is not None else [{"kind": "spend-day", "n": 5}]
    return {"caveats": cav, "holder": "AA==", "sig": "AA=="}


class Log:
    def __init__(self):
        self.entries = []

    def add(self, at, typ, body):
        self.entries.append({"seq": len(self.entries) + 1, "prev": "00", "at": at, "type": typ, "v": 1, "body": body})
        return len(self.entries)

    def plan(self, at, pid, key, verbs, cosigns=None, accept=True):
        p = {"id": pid, "key": key, "steps": [{"verb": v, "clerk": key["root"]["clerk"], "args": {}} for v in verbs],
             "sig": "AA=="}
        if cosigns:
            p["cosigns"] = cosigns
        seq = self.add(at, "plan.submitted", p)
        if accept:
            self.add(at, "plan.accepted", {"plan": pid, "cause": seq, "root": "00", "scopes": []})
        else:
            self.add(at, "plan.rejected", {"plan": pid, "cause": seq, "code": "key", "detail": ""})

    def grant(self, at, *keys):
        self.add(at, "key.issued", {"Keys": list(keys)})


class Count(unittest.TestCase):
    def test_only_uncovered_irreversible_steps_count(self):
        log = Log()
        bare = {"root": root("mail", ["send", "trash", "unsubscribe"]), "links": []}
        log.plan(MON, "p1", bare, ["send", "send", "trash"])  # one approval, two irreversible steps
        log.plan(MON + 1, "p2", bare, ["trash", "organize"])  # reversible only: not an irreversible one-off
        log.plan(MON + 2, "p3", bare, ["unsubscribe"], accept=False)  # refused: never took effect
        log.plan(MON + 3, "p4", {"root": root("mail", ["send"]), "links": [link()]}, ["send"])  # key-covered
        r = oneoff.report(log.entries)
        self.assertEqual((r["approvals"], r["steps"]), (1, 2))
        self.assertEqual(r["rows"], [{"week": "2026-W43", "factor": "passkey", "verb": "send", "approvals": 1, "steps": 2}])

    def test_weeks_factors_and_verbs_split(self):
        log = Log()
        bare = {"root": root("pay", ["buy", "share"]), "links": []}
        log.plan(MON, "a", bare, ["buy", "share"])
        log.plan(MON + 6 * DAY, "b", bare, ["buy"], cosigns=[{"by": "AA==", "sig": "AA=="}])
        log.plan(MON + 7 * DAY, "c", bare, ["buy", "buy", "buy"])  # next ISO week
        r = oneoff.report(log.entries)
        self.assertEqual((r["approvals"], r["steps"]), (3, 6))
        self.assertEqual([(x["week"], x["factor"], x["verb"], x["approvals"], x["steps"]) for x in r["rows"]], [
            ("2026-W43", "passkey", "buy", 1, 1),
            ("2026-W43", "passkey", "share", 1, 1),
            ("2026-W43", "passkey+second", "buy", 1, 1),
            ("2026-W44", "passkey", "buy", 1, 3),
        ])

    def test_task_approval_counts_with_steps_unrecorded(self):
        log = Log()
        log.add(MON, "task.opened", {"id": "t1"})
        log.add(MON, "task.approved", {"task": "t1", "approval": {"site": "shop.test", "first": "x", "n": 0,
                                                                  "by": {"by": "AA==", "sig": "AA=="}}})
        r = oneoff.report(log.entries)
        self.assertEqual((r["approvals"], r["steps"]), (1, 0))
        self.assertEqual(r["rows"], [{"week": "2026-W43", "factor": "passkey", "verb": "-", "approvals": 1, "steps": "-"}])

    def test_conversion_reads_later_clerk_keys(self):
        log = Log()
        bare = {"root": root("mail", ["send", "unsubscribe"]), "links": []}
        log.grant(MON - DAY, {"root": root("mail", ["send"]), "links": [link()]})  # before: not a conversion
        log.plan(MON, "p1", bare, ["send", "unsubscribe"])
        log.plan(MON, "p2", {"root": root("web", ["post"]), "links": []}, ["post"])
        log.grant(MON + DAY, {"root": root("mail", ["send", "unsubscribe"]), "links": []})  # a bare root: no standing key
        log.grant(MON + DAY, {"root": root("mail", ["send", "unsubscribe"]), "links": [link(["unsubscribe"])]})
        log.grant(MON + DAY, {"root": root("other", ["post"]), "links": [link()]})  # another clerk
        r = oneoff.report(log.entries)
        self.assertEqual(r["verbs"], ["mail/send", "mail/unsubscribe", "web/post"])
        self.assertEqual(r["keyed_later"], ["mail/unsubscribe"])

    def test_render_and_load(self):
        log = Log()
        log.plan(MON, "p1", {"root": root("mail", ["send"]), "links": []}, ["send"])
        with tempfile.TemporaryDirectory() as d:
            arr, jl = pathlib.Path(d, "a.json"), pathlib.Path(d, "b.jsonl")
            arr.write_text(json.dumps(log.entries))
            jl.write_text("\n".join(json.dumps(e) for e in log.entries) + "\n")
            self.assertEqual(oneoff.load(arr), oneoff.load(jl))
        out = oneoff.render(oneoff.report(log.entries))
        self.assertTrue(out.startswith("one-offs (OWN-19, not in decisions): 1 approvals, 1 steps"), out)
        self.assertIn("later keyed: 0 of 1 verbs", out)
        self.assertEqual(oneoff.render(oneoff.report([])).splitlines()[-1], "later keyed: 0 of 0 verbs")


class KernelNames(unittest.TestCase):
    """The reader reads the kernel's own names; these fail if the kernel renames one."""

    def test_reversible_verbs_match_classof(self):
        src = (KERNEL / "key" / "verbs.go").read_text()
        consts = dict(re.findall(r'^\t(\w+)\s+Verb = "([^"]+)"', src, re.M))
        table = re.search(r"var classes = map\[Verb\]Class\{(.*?)\n\}", src, re.S).group(1)
        rev = {consts[n] for n, c in re.findall(r"(\w+): (\w+)", table) if c == "Reversible"}
        self.assertEqual(rev, set(oneoff.REVERSIBLE))

    def test_entry_names_match_the_kernel(self):
        src = (KERNEL / "state.go").read_text() + (KERNEL / "task.go").read_text()
        for t in ("plan.submitted", "plan.accepted", "key.issued", "task.approved"):
            self.assertIn(f'"{t}"', src)
        for tag in ('json:"cause"', 'json:"cosigns,omitempty"', 'json:"steps"', 'json:"key"'):
            self.assertIn(tag, src)
        self.assertRegex(src, r"grantBatch struct \{\s*\n\s*Keys\s+\[\]key\.Key\n")
        ksrc = (KERNEL / "key" / "key.go").read_text()
        for tag in ('json:"links"', 'json:"verbs"', 'json:"clerk"', 'json:"caveats"', 'json:"set"', 'KVerbs         = "verbs"'):
            self.assertIn(tag, ksrc)


if __name__ == "__main__":
    unittest.main()
