# CTRL-spike scoring: the stick-boot spike (A1) and the USB4 spike (CTRL-usb4, A17).
# REQ: HW-13, HW-12
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "spikes" / "CTRL-spike"))
import check  # noqa: E402

class BootTests(unittest.TestCase):
    def test_no_key_press_passes(self):  # HW-13
        self.assertTrue(check.score({"spike": "boot", "key_presses": 0, "boot_marker_seen": True})[0])

    def test_key_press_or_missing_marker_fails(self):  # HW-13
        self.assertFalse(check.score({"spike": "boot", "key_presses": 1, "boot_marker_seen": True})[0])
        self.assertFalse(check.score({"spike": "boot", "key_presses": 0, "boot_marker_seen": False})[0])


class Usb4Tests(unittest.TestCase):
    def test_line_rate_60s_passes(self):  # HW-12
        self.assertTrue(check.score({"spike": "usb4", "duration_s": 60, "mbit_per_s": 2400, "stalls": 0})[0])

    def test_short_slow_or_stalled_fails(self):  # HW-12
        for m in ({"duration_s": 59, "mbit_per_s": 2400, "stalls": 0},
                  {"duration_s": 60, "mbit_per_s": 900, "stalls": 0},
                  {"duration_s": 60, "mbit_per_s": 2400, "stalls": 3}):
            self.assertFalse(check.score(dict(m, spike="usb4"))[0])


class ScoreTests(unittest.TestCase):
    def test_unknown_spike_and_empty_run_fail(self):
        self.assertFalse(check.score({"spike": "x"})[0])
        self.assertFalse(check.score({"spike": "ap", "ap_mode_listed": True})[0])  # retired by D-178
        self.assertEqual(check.main([]), 1)


if __name__ == "__main__":
    unittest.main()
