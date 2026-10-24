"""TN-drill (#2932): the monthly restore drill on the weekly reboot (UPD-10).

Once a month reboot-weekly reads every block of the booted /usr through dm-verity against the signed
boot entry's usrhash=, records the result, and reboots as before; drill-report, on the first healthy
boot after, reports the time to a clean core and writes the record STATUS will read. The backup and
the kernel's log are not on the box yet and always read none. CI's reboot boot runs a drill end to
end (image/ci_boot.sh, agentos-drill lines)."""
# REQ: UPD-10
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import MK, ROOT, ini, stub, write  # noqa: E402

AG = MK / "mkosi.extra/usr/lib/agentos"
UNITS = MK / "mkosi.extra/usr/lib/systemd/system"
HASH = "ab" * 32
STATUS = ("/dev/mapper/usr is active and is in use.\n  type:        VERITY\n  status:      verified\n"
          "  data device: /dev/vda2\n  hash device: /dev/vda3\n  root hash:   %s\n" % HASH)


class DrillTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(self.tmp.name)
        self.bin, self.root, self.log, self.clock = t / "bin", t / "root", t / "calls.log", t / "clock"
        self.drill = self.root / "var/lib/agentos/drill"
        write(self.root, "proc/uptime", "3600.42 12.00\n")
        write(self.root, "proc/cmdline", "console=ttyS0 usrhash=%s rw\n" % HASH)
        self.clock.write_text("1000000\n")
        self.verify_rc = 0
        # date +%s reads the clock file; sleep moves it and uptime on; a verify takes 40 s.
        stub(self.bin, "date", 'cat "%s"' % self.clock)
        stub(self.bin, "sleep", 'echo "sleep $*" >>"{l}"\nc=$(cat "{c}"); echo $((c + $1)) >"{c}"\n'
             'u=$(cut -d. -f1 "{u}"); echo "$((u + $1)).00 0.00" >"{u}"'
             .format(l=self.log, c=self.clock, u=self.root / "proc/uptime"))
        self.inhibit = t / "inhibit"
        self.inhibit.write_text("0\n")
        stub(self.bin, "systemctl", 'echo "systemctl $*" >>"%s"\n'
             'case "$*" in *--check-inhibitors=no*) exit 0 ;; esac\n'
             'n=$(cat "%s"); [ "$n" -gt 0 ] || exit 0; echo $((n - 1)) >"%s"; exit 1'
             % (self.log, self.inhibit, self.inhibit))
        stub(self.bin, "ionice", '[ "$1 $2" = "-c 3" ] || exit 9; shift 2; exec "$@"')
        stub(self.bin, "nice", '[ "$1 $2" = "-n 19" ] || exit 9; shift 2; exec "$@"')
        self.status = STATUS
        (t / "status").write_text(self.status)
        stub(self.bin, "veritysetup", 'case $1 in status) [ "$2" = usr ] && cat "{s}" ;;\n'
             'verify) echo "veritysetup $*" >>"{l}"; c=$(cat "{c}"); echo $((c + 40)) >"{c}"; exit $(cat "{rc}") ;;\n'
             'esac'.format(s=t / "status", l=self.log, c=self.clock, rc=t / "rc"))
        self.rc = t / "rc"
        self.rc.write_text("0\n")
        self.statusf = t / "status"

    def tearDown(self):
        self.tmp.cleanup()

    def env(self):
        return dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]), AGENTOS_HEALTH_ROOT=str(self.root))

    def reboot(self):
        r = subprocess.run(["sh", str(AG / "reboot-weekly")], env=self.env(), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        calls = self.log.read_text().splitlines() if self.log.exists() else []
        return r.stdout, calls

    def report(self):
        r = subprocess.run(["sh", str(AG / "drill-report")], env=self.env(), capture_output=True, text=True)
        return r.returncode, r.stdout.strip()

    def pending(self):
        return dict(w.split("=", 1) for w in (self.drill / "pending").read_text().split())

    def last(self):
        return json.loads((self.drill / "last.json").read_text())

    def test_a_drill_is_due_with_no_record(self):
        out, calls = self.reboot()
        self.assertEqual(calls, ["veritysetup verify /dev/vda2 /dev/vda3 " + HASH,
                                 "systemctl reboot --check-inhibitors=yes"])
        self.assertIn("agentos-reboot: drill image=verified in 40s", out)
        self.assertEqual(self.pending(), {"image": "verified", "image_seconds": "40", "reboot_at": "1000040"})
        self.assertEqual((self.drill.stat().st_mode & 0o777), 0o700)

    def test_no_drill_within_27_days_of_the_last(self):
        write(self.root, "var/lib/agentos/drill/last.json", "{}\n")
        out, calls = self.reboot()
        self.assertEqual(calls, ["systemctl reboot --check-inhibitors=yes"])
        self.assertNotIn("drill", out)
        self.assertFalse((self.drill / "pending").exists())

    def test_a_drill_is_due_after_27_days(self):
        f = write(self.root, "var/lib/agentos/drill/last.json", "{}\n")
        old = time.time() - 28 * 86400
        os.utime(f, (old, old))
        _, calls = self.reboot()
        self.assertEqual(calls[0], "veritysetup verify /dev/vda2 /dev/vda3 " + HASH)

    def test_the_last_usrhash_is_the_one_verified(self):
        write(self.root, "proc/cmdline", "usrhash=%s usrhash=%s\n" % ("cd" * 32, HASH))
        _, calls = self.reboot()
        self.assertEqual(calls[0], "veritysetup verify /dev/vda2 /dev/vda3 " + HASH)

    def test_a_failed_verify_still_reboots(self):
        self.rc.write_text("1\n")
        out, calls = self.reboot()
        self.assertEqual(calls[-1], "systemctl reboot --check-inhibitors=yes")
        self.assertIn("drill image=failed", out)
        self.assertEqual(self.pending()["image"], "failed")

    def test_nothing_to_verify_against_fails_without_a_verify(self):
        for cmdline, status in (("console=ttyS0 rw\n", STATUS), ("usrhash=%s\n" % HASH, "")):
            with self.subTest(cmdline=cmdline, status=bool(status)):
                write(self.root, "proc/cmdline", cmdline)
                self.statusf.write_text(status)
                for f in (self.log, self.drill / "pending"):
                    if f.exists():
                        f.unlink()
                out, calls = self.reboot()
                self.assertEqual(calls, ["systemctl reboot --check-inhibitors=yes"])
                self.assertEqual(self.pending()["image"], "failed")

    def test_a_wait_on_an_inhibitor_is_not_counted(self):
        self.inhibit.write_text("2\n")
        self.reboot()
        # Two waits of 300 s after the 40 s verify: the record holds the moment the reboot was asked for.
        self.assertEqual(self.pending()["reboot_at"], "1000640")
        self.assertEqual(self.pending()["image_seconds"], "40")

    def test_the_week_bound_holds_through_a_drill(self):
        write(self.root, "proc/uptime", "604800.00 1.00\n")
        self.inhibit.write_text("1000000\n")
        _, calls = self.reboot()
        self.assertEqual(calls, ["veritysetup verify /dev/vda2 /dev/vda3 " + HASH,
                                 "systemctl reboot --check-inhibitors=no"])
        self.assertEqual(self.pending()["image"], "verified")

    def test_the_report_after_the_reboot(self):
        self.reboot()
        self.clock.write_text("1000095\n")  # healthy 55 s after the reboot was asked for
        rc, out = self.report()
        self.assertEqual(rc, 0, out)
        self.assertEqual(out, "agentos-drill: pass image=verified clean_core_seconds=95 image_seconds=40 "
                              "restart_seconds=55 backup=none log=none (no backup: this drive is the only copy)")
        self.assertEqual(self.last(), {"at": 1000095, "result": "pass", "image": "verified", "image_seconds": 40,
                                       "restart_seconds": 55, "clean_core_seconds": 95,
                                       "backup": "none", "log": "none"})
        self.assertFalse((self.drill / "pending").exists())
        # The record resets the month: the next weekly reboot is no drill.
        self.log.unlink()
        _, calls = self.reboot()
        self.assertEqual(calls, ["systemctl reboot --check-inhibitors=yes"])

    def test_a_failed_image_fails_the_report(self):
        self.rc.write_text("1\n")
        self.reboot()
        rc, out = self.report()
        self.assertEqual(rc, 1)
        self.assertTrue(out.startswith("agentos-drill: FAIL image=failed "), out)
        self.assertEqual(self.last()["result"], "fail")

    def test_a_damaged_record_or_a_clock_gone_back_fails(self):
        for pending in ("image=verified image_seconds=40;reboot reboot_at=1000000",
                        "image=verified reboot_at=1000000", "image=verified image_seconds=40",
                        "image=verified image_seconds=40 reboot_at=2000000", "", None):
            with self.subTest(pending=pending):
                if pending is None:
                    (self.drill / "pending").unlink(missing_ok=True)
                else:
                    write(self.root, "var/lib/agentos/drill/pending", pending + "\n")
                rc, out = self.report()
                self.assertEqual(rc, 1, out)
                self.assertIn("agentos-drill: FAIL ", out)
                self.assertIn("clean_core_seconds=none", out)
                last = self.last()
                self.assertEqual((last["result"], last["clean_core_seconds"]), ("fail", None))

    def test_a_record_that_cannot_be_written_fails(self):
        self.reboot()
        self.clock.write_text("1000095\n")
        (self.drill / "last.json").mkdir()  # in the way: mv -T cannot replace a directory with a file
        rc, out = self.report()
        self.assertEqual(rc, 1, out)
        self.assertTrue(out.startswith("agentos-drill: FAIL image=verified "), out)
        self.assertTrue((self.drill / "pending").exists())

    def test_the_report_unit(self):
        u = ini(UNITS / "agentos-drill-report.service")
        self.assertEqual(u["Unit"]["ConditionPathExists"], "/var/lib/agentos/drill/pending")
        # Requires= as well as After=: ordering alone would start the report on a boot whose health
        # check failed, and record that boot's drill as a pass (#2958 L3 1).
        self.assertEqual(u["Unit"]["Requires"], "boot-complete.target")
        self.assertEqual(u["Unit"]["After"], "boot-complete.target")
        self.assertEqual(u["Unit"]["Before"], "agentos-boot-report.service")
        self.assertEqual(u["Service"]["ExecStart"], "/usr/lib/agentos/drill-report")
        self.assertEqual(u["Install"]["WantedBy"], "multi-user.target")
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text().splitlines()
        self.assertIn("enable agentos-drill-report.service", preset)
        for f in ("reboot-weekly", "drill-report"):
            self.assertTrue(os.access(AG / f, os.X_OK), f)

    def test_ci_boot_runs_a_drill(self):
        sh = (ROOT / "image/ci_boot.sh").read_text()
        self.assertIn("systemctl start --no-block agentos-reboot.service", sh)
        self.assertIn('UNTIL="agentos-drill: \\|agentos-health: FAIL"', sh)
        for want in ('has "$W/console-reboot.log" "agentos-reboot: drill image=verified"',
                     'has "$W/console-reboot.log" "agentos-drill: pass image=verified clean_core_seconds="',
                     'hasnt "$W/console-reboot.log" "agentos-drill: FAIL"'):
            self.assertIn(want, sh)
        m = re.search(r"^DRILL_EXTRA=.*$", sh, re.M)
        self.assertIsNotNone(m)


if __name__ == "__main__":
    unittest.main()
