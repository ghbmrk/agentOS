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
# Model calls through the proxy at once; each holds at most one request body in memory.
PROXY_CALLS = 16
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
    and the proxy's request bodies."""
    fetch_budget = 16 * MiB + FETCH_BATCH * (go_int("mail/imapsmtp/imapsmtp.go", "cfg.MaxFetch") + 8 * KiB)
    mail = go_int("cmd/agentos-egress/mailaccount.go", "mailConns") * (RESPONSE_PEAK + fetch_budget)
    proxy = PROXY_CALLS * go_int("egress/proxy.go", "DefaultMaxBody")
    return mail + kdf_memory() + proxy


class VaultMemoryCeiling(unittest.TestCase):
    def setUp(self):
        self.s = settings(UNIT)

    def one(self, key):
        self.assertEqual(len(self.s.get(key, [])), 1, "%s= set once in [Service]" % key)
        return self.s[key][0]

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
        self.assertEqual(go_int("mail/imapsmtp/imapsmtp.go", "cfg.MaxFetch"), 256 * KiB)
        self.assertEqual(kdf_memory(), 256 * MiB)
        self.assertEqual(go_int("egress/proxy.go", "DefaultMaxBody"), 8 * MiB)


if __name__ == "__main__":
    unittest.main()
