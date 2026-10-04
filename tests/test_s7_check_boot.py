import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "spikes" / "S7-host-image"))
import check_boot  # noqa: E402

GOOD = """[  80.1] s7-probe.sh[1]: S7: version=1
S7: secureboot=SecureBoot enabled
S7: usr=/dev/mapper/usr
S7: usr_ro=ro
S7: bootdisk=usb
S7: tpm=/dev/tpmrm0
S7: mm=/usr/sbin/ModemManager nm=/usr/sbin/NetworkManager
S7: done
"""


class CheckBoot(unittest.TestCase):
    def test_passes_when_all_facts_hold(self):
        _, failures = check_boot.check(GOOD)
        self.assertEqual(failures, [])

    def test_fails_on_secure_boot_off_and_non_usb_disk(self):
        bad = GOOD.replace("SecureBoot enabled", "SecureBoot disabled").replace("bootdisk=usb", "bootdisk=sata")
        _, failures = check_boot.check(bad)
        self.assertEqual(sorted(failures), ["bootdisk", "secureboot"])

    def test_missing_probe_output_fails_everything(self):
        _, failures = check_boot.check("Kernel panic")
        self.assertEqual(len(failures), len(check_boot.REQUIRED))


if __name__ == "__main__":
    unittest.main()
