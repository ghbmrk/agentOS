"""P2-1 MOR (#4794): an orderly shutdown wipes the image's secrets, then clears the memory-overwrite
request the kernel's EFI stub set at boot, so the host's next start does not wipe memory and its
MemoryOverwriteRequestControl is as it was (HW-8).

The wipe is the kernel's init_on_free=1 (mkosi.conf, allowed by finish_image.py); the clear is
agentos-mor.service's ExecStop, ordered to run after every secret-holding unit has stopped
(broker/cmd/agentos-mor tests the program itself). Kept apart from tests/test_image.py; the helpers
come from there."""
# REQ: HW-8
import pathlib
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import ENTRY, H, MK, ROOT, check, finish, ini, settings  # noqa: E402

UNITS = MK / "mkosi.extra/usr/lib/systemd/system"
UNIT = UNITS / "agentos-mor.service"
# Units the image ships without default dependencies, so not ordered after sysinit.target: each is
# stopped in no known order against agentos-mor.service, so none may hold a secret.
NO_DEFAULT_DEPS = {
    "agentos-inbound.service": "loads the inbound nftables ruleset; holds no secret",
    "agentos-mor.service": "this unit",
}


def words(s, key):
    return " ".join(s.get(key, [])).split()


class MorUnitTest(unittest.TestCase):
    def test_clear_runs_at_stop_after_the_secret_holders(self):
        s = settings(UNIT)
        self.assertEqual(s["DefaultDependencies"], ["no"])
        # Started before sysinit.target, so stopped after every unit ordered after it; before
        # tmp.mount, so stopped after /tmp is unmounted and its pages freed.
        self.assertTrue({"sysinit.target", "shutdown.target", "tmp.mount"} <= set(words(s, "Before")))
        self.assertEqual(words(s, "Conflicts"), ["shutdown.target"])
        self.assertNotIn("sysinit.target", words(s, "After"))
        self.assertNotIn("local-fs.target", words(s, "After"))
        # A manual stop would run the clear while the secret holders still run (Security on #5009, 3).
        self.assertEqual(s["RefuseManualStop"], ["yes"])
        self.assertEqual(s["Type"], ["oneshot"])
        self.assertEqual(s["RemainAfterExit"], ["yes"])
        self.assertEqual(s["ExecStop"], ["/usr/lib/agentos/agentos-mor clear"])
        self.assertEqual(s["ExecStart"], ["/usr/lib/agentos/agentos-mor status"])
        self.assertEqual(ini(UNIT)["Install"]["WantedBy"], "sysinit.target")
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text()
        self.assertIn("\nenable agentos-mor.service\n", preset)

    def test_no_ordering_cycle_with_tmp_mount(self):
        # L3 on #5009: agentos-.service.d/50-main-side.conf orders every agentos unit after
        # systemd-tmpfiles-setup.service, which is after local-fs.target and so after tmp.mount; with
        # this unit before tmp.mount, systemd broke the cycle by skipping this unit or tmp.mount. This
        # unit's own file of the same name replaces that drop-in and adds no ordering.
        shared, own = UNITS / "agentos-.service.d/50-main-side.conf", UNITS / "agentos-mor.service.d/50-main-side.conf"
        self.assertIn("systemd-tmpfiles-setup.service", words(settings(shared), "After"))
        self.assertEqual(sorted(UNITS.glob("agentos-mor.service.d/*")), [own])
        self.assertEqual({k for k in settings(own)}, {"InaccessiblePaths"})
        self.assertEqual(words(settings(UNIT), "After"), ["sys-firmware-efi-efivars.mount"])
        for key in ("Requires", "Wants", "BindsTo", "Requisite", "Upholds"):
            self.assertNotIn(key, settings(UNIT))

    def test_the_clear_sees_the_dirs_it_lists(self):
        # agentos-mor's holdDirs on /run are what the unit leaves unmasked (mkosi.finalize MOR_LISTED).
        src = (ROOT / "broker/cmd/agentos-mor/main.go").read_text()
        held = re.findall(r'"([^"]+)"', re.search(r"var holdDirs = \[\]string\{([^}]*)\}", src).group(1))
        self.assertEqual(tuple("/" + d for d in held if d.startswith("run/")), check.MOR_LISTED)
        hidden = [w.lstrip("-") for w in settings(UNITS / "agentos-mor.service.d/50-main-side.conf")["InaccessiblePaths"][0].split()]
        for d in check.MOR_LISTED:
            self.assertNotIn(d, hidden)

    def test_every_other_unit_stops_first(self):
        # A unit with DefaultDependencies=no is not ordered after sysinit.target, so it could still
        # run when MOR is cleared. Each one is listed with why it holds no secret.
        found = {u.name for u in UNITS.iterdir()
                 if u.is_file() and u.suffix in (".service", ".socket", ".mount", ".path", ".timer")
                 and (settings(u).get("DefaultDependencies") or ["yes"])[-1].lower() in ("no", "false", "0", "off")}
        for d in UNITS.glob("*.d"):
            for f in d.glob("*.conf"):
                if "DefaultDependencies" in settings(f):
                    found.add(d.name[:-2])
        self.assertEqual(found, set(NO_DEFAULT_DEPS))

    def test_build_installs_the_program(self):
        build = (ROOT / "image/build.sh").read_text()
        loop = re.search(r"for cmd in ([^;]+); do", build, re.S).group(1).split()
        self.assertIn("agentos-mor", loop)


class WipeOnTest(unittest.TestCase):
    def test_kernel_zeroes_freed_memory(self):
        args = ini(MK / "mkosi.conf")["Content"]["KernelCommandLine"].split()
        self.assertEqual([w for w in args if w.startswith("init_on_free")], ["init_on_free=1"])

    def test_finish_allows_only_that_word(self):
        conf = MK / "mkosi.conf"
        entry = (ENTRY % H).replace("rw quiet", "rw quiet init_on_free=1")
        self.assertEqual(finish.cmdline_violations(entry, conf), [])
        # The exemption is the one parameter's name: init= and lookalikes are still refused, and the
        # word itself must still be in mkosi.conf.
        for bad in ("init=/bin/sh", "init_on_freex=1", "initx=1", "rdinit=/bin/sh", "Init=/bin/sh",
                    "init_on_alloc=0", "rd.init=/bin/sh"):
            with self.subTest(bad=bad):
                self.assertNotEqual(finish.cmdline_violations(entry.replace("quiet", "quiet " + bad), conf), [])
        with tempfile.TemporaryDirectory() as d:
            other = pathlib.Path(d) / "mkosi.conf"
            other.write_text("[Content]\nKernelCommandLine=console=tty0 console=ttyS0 rw quiet\n")
            v = finish.cmdline_violations((ENTRY % H).replace("rw quiet", "rw quiet init_on_free=0"), other)
            self.assertEqual(len(v), 1, v)
            self.assertIn("not in mkosi.conf", v[0])


if __name__ == "__main__":
    unittest.main()
