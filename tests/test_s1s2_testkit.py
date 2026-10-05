# Unit tests for the S1/S2 test kit's pure logic. No coverage claims: a spike measures, it does not
# implement requirements. The image itself is checked end to end by .github/workflows/testkit.yml.
import importlib.util
import pathlib
import random
import sys
import unittest

K = pathlib.Path(__file__).resolve().parent.parent / "spikes" / "S1S2-testkit"
sys.path.insert(0, str(K / "mkosi" / "mkosi.extra" / "usr" / "lib" / "testkit"))
import dtmf  # noqa: E402
import s2  # noqa: E402
import testkit as tk  # noqa: E402

spec = importlib.util.spec_from_file_location("finish_image", K / "finish_image.py")
fi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fi)


def keys(s):
    out = []
    for k in s:
        out.extend(dtmf.tone(k))
    return out


class DtmfTest(unittest.TestCase):
    def test_all_keys(self):
        self.assertEqual(dtmf.decode(keys("123A456B789C*0#D")), "123A456B789C*0#D")

    def test_repeated_key_needs_a_gap(self):
        self.assertEqual(dtmf.decode(keys("4477")), "4477")

    def test_noise_and_attenuation(self):
        rnd = random.Random(7)
        sig = [int(v * 0.25 + rnd.gauss(0, 300)) for v in keys("9183")]
        self.assertEqual(dtmf.decode(sig), "9183")

    def test_rejects_noise_and_single_tones(self):
        rnd = random.Random(3)
        self.assertEqual(dtmf.decode([int(rnd.gauss(0, 4000)) for _ in range(16000)]), "")
        import math
        self.assertEqual(dtmf.decode([int(6000 * math.sin(2 * math.pi * 770 * t / 8000)) for t in range(8000)]), "")


class StateMachineTest(unittest.TestCase):
    def run_boots(self, seq, st=None, machine="m1"):
        st, log = st or {}, []
        for entry in seq:
            st, acts = tk.decide(entry, st, machine)
            log.append(acts)
        return st, log

    def test_full_sequence_on_a_new_pc(self):
        st, log = self.run_boots(["rollback", "rollback", "good"])
        self.assertEqual(log[0], ["new_run", "probe", "reboot"])
        self.assertEqual(log[1], ["reboot"])
        self.assertEqual(log[2], ["verdict", "s2", "rearm", "poweroff"])
        self.assertTrue(tk.verdict(st).startswith("PASS"))

    def test_next_pc_starts_a_new_run(self):
        st, _ = self.run_boots(["rollback", "rollback", "good"])
        st, log = self.run_boots(["rollback"], st, machine="m2")
        self.assertEqual(log[0], ["new_run", "probe", "reboot"])
        self.assertEqual(st["rb_boots"], 1)

    def test_same_pc_again_is_a_new_run(self):
        st, _ = self.run_boots(["rollback", "rollback", "good"])
        _, log = self.run_boots(["rollback"], st)
        self.assertIn("new_run", log[0])

    def test_spent_counters_are_rearmed_once(self):
        st, log = self.run_boots(["good", "rollback", "rollback", "good"])
        self.assertEqual(log[0], ["new_run", "probe", "rearm", "reboot"])
        self.assertEqual(log[1], ["reboot"])  # already probed in this run
        self.assertIn("poweroff", log[3])
        self.assertTrue(tk.verdict(st).startswith("PASS"))

    def test_rollback_never_selected_still_finishes(self):
        st, log = self.run_boots(["good", "good"])
        self.assertIn("poweroff", log[1])
        self.assertTrue(tk.verdict(st).startswith("FAIL"))

    def test_rearm_names(self):
        self.assertEqual(tk.rearm_names(["agentos-tk-good.conf", "agentos-tk-rollback+0-2.conf", "x.conf"]),
                         {"agentos-tk-good.conf": "agentos-tk-good+3.conf",
                          "agentos-tk-rollback+0-2.conf": "agentos-tk-rollback+2.conf"})
        self.assertEqual(tk.rearm_names(["agentos-tk-good+3.conf"]), {})

    def test_valid_number(self):
        self.assertTrue(tk.valid_number("+15550100199"))
        for bad in ("", "5550100199", "+1 555 010 0199", "+1555'; reboot", "+123456"):
            self.assertFalse(tk.valid_number(bad), bad)

    def test_entry_mode(self):
        self.assertEqual(tk.entry_mode("quiet agentos.tk=rollback systemd.mask=x"), "rollback")
        self.assertEqual(tk.entry_mode("quiet"), "good")


class FinishImageTest(unittest.TestCase):
    SRC = ("title agentos-tk 6.12.48-amd64\nversion 6.12.48-amd64\n"
           "linux /agentos-tk/6.12.48-amd64/vmlinuz\noptions usrhash=ab12 console=tty0 rw\n"
           "initrd /agentos-tk/initrd\n")

    def test_two_counted_entries(self):
        e = fi.entries_for(self.SRC)
        self.assertEqual(sorted(e), ["agentos-tk-good+3.conf", "agentos-tk-rollback+2.conf"])
        rb, good = e["agentos-tk-rollback+2.conf"], e["agentos-tk-good+3.conf"]
        self.assertIn("version 2\n", rb)
        self.assertIn("version 1\n", good)
        self.assertIn("usrhash=ab12 console=tty0 rw agentos.tk=rollback systemd.mask=systemd-bless-boot.service", rb)
        self.assertIn("rw agentos.tk=good\n", good)
        for t in e.values():
            self.assertEqual(t.count("version "), 1)
            self.assertIn("initrd /agentos-tk/initrd", t)


class FloorFitTest(unittest.TestCase):
    # PE2: on the N95, the agent machine and one replay machine fit in the pool left after the
    # RES-2 floor budget (host, inference, browser, headroom).
    def test_n95_fits(self):
        out = tk.floor_fit("MemTotal:        7864320 kB\nMemAvailable:    7340032 kB\n")
        self.assertTrue(out.startswith("PASS"), out)
        self.assertIn("pool 3496 MiB", out)
        self.assertIn("agent 1536 + one replay 1024 = 2560", out)
        self.assertIn("-capacity-mb 4096", out)

    def test_small_pc_fails(self):
        out = tk.floor_fit("MemTotal:        6291456 kB\n")
        self.assertTrue(out.startswith("FAIL"), out)
        self.assertIn("pool 1960 MiB", out)

    def test_unreadable(self):
        self.assertTrue(tk.floor_fit("").startswith("unknown"))


class S2HelpersTest(unittest.TestCase):
    def test_same_number(self):
        self.assertTrue(s2.same_number("+1 (555) 010-0199", "5550100199"))
        self.assertFalse(s2.same_number("+15550100199", "+15550100198"))
        self.assertFalse(s2.same_number("", ""))


if __name__ == "__main__":
    unittest.main()
