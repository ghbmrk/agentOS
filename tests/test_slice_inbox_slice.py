"""The inbox slice ("Sort my inbox and unsubscribe from and delete the spam", #2526)
against the held-out eval set evals/slice-inbox/ (EVL-2, VRB-2).

The adapter hands each case to broker/clerk/inbox/cmd/slice, which runs the real kernel,
planner and mail clerk over the case's synthetic mailbox and prints the outcome as JSON.
The set itself is read only; this file is the one that claims EVL-2.
"""
# REQ: EVL-2, VRB-2
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "evals" / "slice-inbox"))
from slice_eval import harness  # noqa: E402


class SliceBinary:
    """go build once per test run; each case then costs one process."""

    exe = None
    tmp = None

    @classmethod
    def build(cls):
        if cls.exe is None:
            cls.tmp = tempfile.mkdtemp(prefix="slice-inbox-")
            cls.exe = os.path.join(cls.tmp, "slice")
            subprocess.run(["go", "build", "-o", cls.exe, "./clerk/inbox/cmd/slice"],
                           cwd=ROOT / "broker", check=True,
                           env=dict(os.environ, GOCACHE=os.path.join(cls.tmp, "gc")))
        return cls.exe


def request(case, world, mailbox=""):
    """What the adapter hands the slice binary for one run of case on mailbox."""
    ids, classes = harness.mailbox(case, world)
    by_id = harness.by_id(world)
    standing = harness.later_run_key(case)
    return {
        "world": {k: world[k] for k in ("dkim_keys", "provider_table", "history", "contacts",
                                        "known_senders", "today", "last_opened",
                                        "unsubscribe_unopened_days", "authserv", "alert_senders")},
        "mails": [{"id": i, "raw": base64.b64encode(by_id[i]["raw"]).decode(), "class": classes[i]}
                  for i in ids],
        "owner": world["owner"],
        "one_click_body": world["one_click_body"],
        "trash_retention_days": harness.account(case, world)["trash_retention_days"],
        "prior_unsubscribes": world["prior_unsubscribes"],
        "script": case.get("variant", {}).get("script", []),
        "standing": standing,
        "mailbox": mailbox,
    }


def adapter(case, world, mailbox=""):
    done = subprocess.run([SliceBinary.build()],
                          input=json.dumps(request(case, world, mailbox)).encode(),
                          capture_output=True, check=False)
    if done.returncode:
        raise RuntimeError(done.stderr.decode())
    return json.loads(done.stdout)


class SliceInbox(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        if SliceBinary.tmp:
            shutil.rmtree(SliceBinary.tmp, ignore_errors=True)

    def test_every_case_passes(self):
        failures = {c: f for c, f in harness.run_suite(adapter).items() if f}
        self.assertEqual(failures, {})

    def test_every_case_passes_on_both_mailboxes(self):
        """A21 on IMAP and on the Gmail API (#2851): each case's effects land on a fake
        account through the clerk's real mailbox for it, which the binary checks, and
        the outcome is the synthetic run's."""
        for mailbox in ("imap", "gmail"):
            with self.subTest(mailbox=mailbox):
                run = lambda case, world, m=mailbox: adapter(case, world, m)  # noqa: E731
                failures = {c: f for c, f in harness.run_suite(run).items() if f}
                self.assertEqual(failures, {})


if __name__ == "__main__":
    unittest.main()
