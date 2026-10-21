# The vault process's memory ceiling (SR3-mail-k18e, #1676; release r1 of Security 4a on #1658).
# A hostile mail or model host costs one call, not the vault process or the host (CRED-8, egress
# K18): agentos-egress.service caps the unit's memory, so a runaway the parser bounds miss ends
# the vault (it fails closed and restarts) inside its own cgroup instead of the kernel OOM killer
# picking another process. The cap is derived from what the bounded paths can legitimately hold
# at once; the figures are read from the source where they live, so a change there fails here.
# REQ: CRED-8
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
UNIT = ROOT / "image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-egress.service"
BROKER = ROOT / "broker"

KiB, MiB, GiB = 1 << 10, 1 << 20, 1 << 30

# Mail M21 (#1658): one IMAP response stopped at the field bound peaks near 60 MB of heap, and the
# bound binds before the 16 MiB read budget does. Rounded up to 64 MiB.
RESPONSE_PEAK = 64 * MiB
# A Fetch asks for at most 100 messages (agentosd's batches; Security l1 on #1658).
FETCH_BATCH = 100
# What the proxy's requests in flight may hold at once is DefaultInFlightBytes in egress/proxy.go
# (egress K18, SR3-mail-k18f), read below: each request reserves what its body costs to read and
# check before it holds it, a cost egress TestBodyCostBoundsApply measures. Provider worker routes
# (#1014 part c, egress K28) add their own process-wide cap, routeCalls in
# cmd/agentos-egress/workerroute.go, also read below; each holds at most one body, counted on top.
# HW-4's floor has 8 GB; the vault may take at most a quarter of it.
FLOOR_RAM = 8 * GiB


def settings(unit):
    out = {}
    section = None
    for l in unit.read_text().replace("\\\n", " ").splitlines():
        l = l.strip()
        if l.startswith("["):
            section = l
        elif l and not l.startswith("#") and section == "[Service]":
            k, _, v = l.partition("=")
            out.setdefault(k, []).append(v)
    return out


def go_int(path, name):
    """The value of `name = <a> << <b>` or `name = <a>` in a Go file."""
    m = re.search(r"\b%s\s*=\s*(\d+)(?:\s*<<\s*(\d+))?\s*$" % re.escape(name),
                  (BROKER / path).read_text(), re.M)
    if not m:
        raise AssertionError("%s not found in %s" % (name, path))
    return int(m.group(1)) << int(m.group(2) or 0)


def kdf_memory():
    """defaultKDF's MemoryKiB, in bytes: what one unlock spends."""
    m = re.search(r"var defaultKDF = KDF\{[^}]*MemoryKiB:\s*(\d+)\s*<<\s*(\d+)",
                  (BROKER / "vault/keyslot.go").read_text())
    return (int(m.group(1)) << int(m.group(2))) * KiB


def size(v):
    """A systemd byte value (K, M, G suffixes are base 1024)."""
    m = re.fullmatch(r"(\d+)([KMG]?)", v)
    if not m:
        raise AssertionError("not a byte size: %r" % v)
    return int(m.group(1)) * {"": 1, "K": KiB, "M": MiB, "G": GiB}[m.group(2)]


def gomem(v):
    """A GOMEMLIMIT value (KiB, MiB, GiB suffixes)."""
    m = re.fullmatch(r"(\d+)(B|KiB|MiB|GiB)?", v)
    if not m:
        raise AssertionError("not a GOMEMLIMIT: %r" % v)
    return int(m.group(1)) * {None: 1, "B": 1, "KiB": KiB, "MiB": MiB, "GiB": GiB}[m.group(2)]


def legitimate_peak():
    """What the bounded paths can hold live at once: every mail call at its worst (one response
    at the field bound, plus a full Fetch's read budget of kept bodies), one unlock's Argon2id,
    the proxy's in-flight budget and the provider worker routes' request bodies."""
    fetch_budget = 16 * MiB + FETCH_BATCH * (go_int("clerk/inbox/imapsmtp/imapsmtp.go", "cfg.MaxFetch") + 8 * KiB)
    mail = go_int("cmd/agentos-egress/mailaccount.go", "mailConns") * (RESPONSE_PEAK + fetch_budget)
    routes = go_int("cmd/agentos-egress/workerroute.go", "routeCalls") * go_int("egress/proxy.go", "DefaultMaxBody")
    return mail + kdf_memory() + go_int("egress/proxy.go", "DefaultInFlightBytes") + routes


def seen_peak():
    """What one Store.Seen call can hold (#2685): the search's UIDs at the field bound (M21, about a
    million, 4 bytes each) and one batch session's fixed read budget. What Live.Opened keeps is the
    mail clerk's own memory (openedMax, #2684), never the vault's: see
    test_the_vault_never_reads_who_was_opened."""
    imap = "clerk/inbox/imapsmtp/imapsmtp.go"
    batch = 16 * MiB + go_int(imap, "seenBatch") * (go_int(imap, "headMax") + 8 * KiB)
    return 4 * MiB + batch


class VaultMemoryCeiling(unittest.TestCase):
    def setUp(self):
        self.s = settings(UNIT)

    def one(self, key):
        self.assertEqual(len(self.s.get(key, [])), 1, "%s= set once in [Service]" % key)
        return self.s[key][0]

    def test_reading_who_was_opened_costs_no_more_than_a_fetch(self):
        fetch = 16 * MiB + FETCH_BATCH * (go_int("clerk/inbox/imapsmtp/imapsmtp.go", "cfg.MaxFetch") + 8 * KiB)
        self.assertLessEqual(seen_peak(), fetch)

    def test_the_clerks_read_log_bound_is_one_search(self):
        # Live.Opened keeps as many read mails as one UID SEARCH can name (clerk/inbox MIG-3-R10b).
        self.assertEqual(go_int("clerk/inbox/mailbox.go", "searchMax"), go_int("third_party/go-imap/read.go", "maxRespFields"))

    def test_the_vault_never_reads_who_was_opened(self):
        # The vault's mail store wraps the transport without Seen, and nothing outside the mail
        # clerk's package links Live, so neither Seen nor openedMax counts in the vault's ceiling.
        self.assertNotIn(".Seen(", (BROKER / "mail/imapsmtp/imapsmtp.go").read_text())
        inbox = BROKER / "clerk/inbox"
        for f in BROKER.rglob("*.go"):
            if inbox not in f.parents and "/vendor/" not in str(f):
                self.assertNotIn('broker/clerk/inbox"', f.read_text(), f)

    def test_memory_max_is_set_within_the_derived_range(self):
        cap = size(self.one("MemoryMax"))
        self.assertGreaterEqual(cap, legitimate_peak())
        self.assertLessEqual(cap, FLOOR_RAM // 4)

    def test_memory_high_sits_between_the_peak_and_the_cap(self):
        high = size(self.one("MemoryHigh"))
        self.assertGreaterEqual(high, legitimate_peak())
        self.assertLess(high, size(self.one("MemoryMax")))

    def test_go_heap_limit_sits_under_memory_high(self):
        # Without a soft limit the Go heap can reach twice its live size before collecting, so the
        # cgroup would kill a process whose live heap is well under the cap.
        envs = dict(e.partition("=")[::2] for v in self.s.get("Environment", []) for e in v.split())
        self.assertIn("GOMEMLIMIT", envs)
        limit = gomem(envs["GOMEMLIMIT"])
        self.assertGreaterEqual(limit, legitimate_peak())
        self.assertLess(limit, size(self.one("MemoryHigh")))

    def test_a_kill_restarts_the_vault(self):
        # A cgroup OOM kill is a failure, so on-failure restarts the unit; the vault comes back
        # locked (fail closed). OOMPolicy=continue would leave a half-dead process serving.
        self.assertIn(self.one("Restart"), ("on-failure", "always"))
        self.assertNotIn("continue", self.s.get("OOMPolicy", []))

    def test_the_derivation_reads_real_figures(self):
        # Guards the regexes: a figure that stops parsing must not pass as zero.
        self.assertEqual(go_int("cmd/agentos-egress/mailaccount.go", "mailConns"), 8)
        self.assertEqual(go_int("clerk/inbox/imapsmtp/imapsmtp.go", "cfg.MaxFetch"), 256 * KiB)
        self.assertEqual(kdf_memory(), 256 * MiB)
        self.assertEqual(go_int("egress/proxy.go", "DefaultMaxBody"), 8 * MiB)
        self.assertEqual(go_int("cmd/agentos-egress/workerroute.go", "routeCalls"), 8)
        self.assertEqual(go_int("egress/proxy.go", "DefaultInFlightBytes"), 320 * MiB)

    def test_the_proxy_budget_is_global(self):
        # The figure above bounds the whole process only if admit counts it across machines: a
        # per-machine bound alone lets every machine hold its own bodies (#1771).
        src = (BROKER / "egress/proxy.go").read_text()
        admit = re.search(r"func \(p \*Proxy\) admit\(.*?\n}\n", src, re.S)
        self.assertIsNotNone(admit, "Proxy.admit not found")
        self.assertRegex(admit.group(0), r"p\.reserved\s*\+\s*n\s*>\s*p\.budget")
        self.assertRegex(src, r"p\.budget\s*=\s*DefaultInFlightBytes")


if __name__ == "__main__":
    unittest.main()
