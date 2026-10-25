#!/usr/bin/env python3
"""A21 in QEMU (#3117, broker/clerk/inbox/ASSUMPTIONS.md MIG-3-1): the inbox slice's eval run
inside the booted image, checked on the host.

  slice_boot.py requests DIR   write every request the eval hands cmd/slice, on each mailbox, one
                               file per distinct request, named by the SHA-256 of its bytes
  slice_boot.py check DIR      run the eval harness over the guest's outcomes in DIR

ci_boot.sh's slice boot runs cmd/slice twice over each request file inside the guest and writes
DIGEST.1.json and DIGEST.2.json. The check's adapter builds each case's request again, exactly as
tests/test_slice_inbox_slice.py does, and answers the harness's two runs of it with those two
files, so a guest outcome counts only for the request the host built. The guest's files are
untrusted: they are read as JSON and nothing else, and a missing or unreadable one fails its case.
"""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import test_slice_inbox_slice as native  # noqa: E402

harness = native.harness

# "" is the synthetic mailbox; imap and gmail run each case on a fake account through the clerk's
# real mailbox for it (broker/clerk/inbox/ASSUMPTIONS.md TN-gmail-api-8).
MAILBOXES = ("", "imap", "gmail")


def encode(req):
    return json.dumps(req, sort_keys=True, separators=(",", ":")).encode()


def requests(out, mailboxes=MAILBOXES):
    """Writes each distinct request once; returns how many."""
    world, cases = harness.load()
    seen = set()
    for mailbox in mailboxes:
        for case in cases:
            body = encode(native.request(case, world, mailbox))
            d = hashlib.sha256(body).hexdigest()
            if d not in seen:
                seen.add(d)
                with open(os.path.join(out, d + ".json"), "wb") as f:
                    f.write(body)
    return len(seen)


def guest(out, mailbox):
    """An adapter answering each run with the guest's outcome for its request, and the list of
    guest files it could not read. The harness runs each case twice; two cases with one request
    (variants the slice never sees) read the same pair, which the slice's determinism makes the
    same outcome."""
    runs, unread = {}, []

    def adapter(case, world):
        d = hashlib.sha256(encode(native.request(case, world, mailbox))).hexdigest()
        runs[d] = runs.get(d, 0) + 1
        name = "%s.%d.json" % (d, (runs[d] - 1) % 2 + 1)
        try:
            with open(os.path.join(out, name), "rb") as f:
                got = json.load(f)
        except (OSError, ValueError) as e:
            got = "%s: %s" % (name, type(e).__name__)
        if isinstance(got, dict):
            return got
        unread.append("%s: %s" % (case["id"], got if isinstance(got, str) else name + ": not an object"))
        return {}

    return adapter, unread


def check(out, mailboxes=MAILBOXES):
    """{mailbox: {case id: failures}} with only the failing cases; empty means A21's cases pass."""
    bad = {}
    for mailbox in mailboxes:
        adapter, unread = guest(out, mailbox)
        try:
            results = harness.run_suite(adapter)
        except Exception as e:  # an outcome the checks cannot read fails the run, not the script
            results = {"*": ["the harness could not read the guest's outcomes: %s" % type(e).__name__]}
        failing = {c: f for c, f in results.items() if f}
        if unread:
            failing["*"] = failing.get("*", []) + ["unread guest outcome " + u for u in unread]
        if failing:
            bad[mailbox or "synthetic"] = failing
    return bad


def printable(v):
    """A failure can quote the guest's text; one line, so none of it starts a workflow command."""
    return "".join(c if c.isprintable() else "?" for c in str(v))


def main(argv):
    if len(argv) != 3 or argv[1] not in ("requests", "check"):
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "requests":
        print("slice_boot: %d requests" % requests(argv[2]))
        return 0
    bad = check(argv[2])
    for mailbox, failing in sorted(bad.items()):
        for case, failures in sorted(failing.items()):
            for f in failures:
                print("slice_boot: FAIL %s %s: %s" % (mailbox, printable(case), printable(f)))
    n = len(harness.load()[1])
    print("slice_boot: %s, %d cases on %d mailboxes" % ("FAIL" if bad else "PASS", n, len(MAILBOXES)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
