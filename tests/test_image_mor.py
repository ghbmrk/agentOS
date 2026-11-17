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
from test_image import ENTRY, H, MK, ROOT, check, exec_args, finish, ini, settings  # noqa: E402

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


# Where systemd puts a system unit's directory settings, and the specifiers that name those bases.
DIR_BASES = {"RuntimeDirectory": "/run", "StateDirectory": "/var/lib", "CacheDirectory": "/var/cache",
             "LogsDirectory": "/var/log", "ConfigurationDirectory": "/etc"}
SPECIFIERS = {"%t": "/run", "%S": "/var/lib", "%C": "/var/cache", "%L": "/var/log", "%E": "/etc"}


def names_held_dir(text, dirs):
    """Whether a unit file's text names one of dirs, or a path under it: the path ending at a
    separator, a quote or the end of a line, through a specifier, or as a directory setting."""
    for spec, base in SPECIFIERS.items():
        text = text.replace(spec, base)
    if any(re.search(re.escape(d) + r"""(?=[/\s"':;\\]|$)""", text) for d in dirs):
        return True
    keys = "|".join(DIR_BASES)
    for key, value in re.findall(r"^[ \t]*(%s)[ \t]*=(.*)$" % keys, text, re.M):
        for name in value.replace(":", " ").split():
            path = DIR_BASES[key] + "/" + name.strip("\"'").strip("/")
            if any(path == d or path.startswith(d + "/") for d in dirs):
                return True
    return False


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

    def test_the_staged_page_authority_goes_at_stop(self):
        # MOR-setup-hold (#5836): before enrollment the page authority's sealed pair sits in
        # /run/agentos-setup, a holdDirs entry, so the clear refused on every orderly shutdown. The
        # staging unit's stop removes exactly the pair and certificate its start made; it keeps default
        # dependencies (test_every_other_unit_stops_first), so it stops before this unit's clear. A
        # manual stop is refused, so a card printed this boot keeps its fingerprint until shutdown.
        unit = UNITS / "agentos-keeper-pageca.service"
        p, s = exec_args(unit), settings(unit)
        made = [p[p.index("-page-ca-file") + 1], p[p.index("-page-ca-cert") + 1]]
        self.assertEqual(s["ExecStopPost"], ["/usr/bin/rm -f " + " ".join(made)])
        self.assertEqual(made[0].rsplit("/", 1)[0], check.MOR_LISTED[0])
        self.assertEqual(s["RefuseManualStop"], ["yes"])
        self.assertNotIn("DefaultDependencies", s)
        for key in ("ExecStop", "ExecStopPre"):
            self.assertNotIn(key, s)

    def test_every_held_file_goes_at_stop(self):
        # MOR-setup-factors (#5843): the card's factors, and the first edge's capture, sit in holdDirs
        # entries from the confirm until a successful enrollment, and on a failure for a retry, with no
        # stop of their own, so an orderly shutdown then left MOR set. The wipe's stop empties every
        # holdDirs entry on /run. It keeps default dependencies, so it stops before this unit's clear
        # (test_every_other_unit_stops_first); it is ordered before every unit whose commands name a
        # holdDirs path, so it stops after each; nothing but shutdown stops it. /dev/shm: no unit names it.
        name = "agentos-keeper-wipe.service"
        wipe = UNITS / name
        s = settings(wipe)
        self.assertEqual(s["ExecStop"], ["/usr/bin/find %s -xdev -mindepth 1 -delete" % " ".join(check.MOR_LISTED)])
        self.assertEqual((s["Type"], s["RemainAfterExit"]), (["oneshot"], ["yes"]))
        self.assertEqual((s["IgnoreOnIsolate"], s["RefuseManualStop"]), (["yes"], ["yes"]))
        for key in ("DefaultDependencies", "ExecStart", "ExecStopPost", "Conflicts", "BindsTo", "PartOf",
                    "Requires", "Requisite", "StopPropagatedFrom", "After"):
            self.assertNotIn(key, s)
        self.assertFalse([k for k in s if k.startswith(("Condition", "Assert"))])
        self.assertEqual(sorted(UNITS.glob(name + ".d/*")), [])
        before, wanted = set(words(s, "Before")), set(ini(wipe)["Install"]["WantedBy"].split())
        self.assertEqual(wanted, before | {"multi-user.target"})
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text()
        self.assertIn("\nenable %s\n" % name, preset)
        files = [u for u in UNITS.iterdir() if u.is_file()] + list(UNITS.glob("*.d/*.conf"))
        writers = set()
        for f in files:
            t = f.read_text()
            self.assertNotIn("/dev/shm", t, f.name)
            if f.name != name and names_held_dir(t, check.MOR_LISTED):
                writers.add(f.name)
            for key in ("Conflicts", "PropagatesStopTo"):
                self.assertNotIn(name, words(settings(f), key), f.name)
        # The writers, each found by its own text: the mor unit's drop-in names the dirs only to leave
        # them unmasked, the main side's only to mask them.
        self.assertEqual(writers - {"50-main-side.conf"}, {
            "agentos-keeper-pageca.service", "agentos-keeper-enroll.service", "agentos-keeper-enroll.path",
            "agentos-keeper-setup@.service", "agentos-keeper-link-capture.service"})
        for w in writers - {"50-main-side.conf"}:
            with self.subTest(w):
                if w.endswith(".path"):
                    continue  # writes nothing; it starts enrollment, which is listed
                ordered = w in before or name in words(settings(UNITS / w), "After")
                self.assertTrue(ordered, w)
                self.assertNotIn("DefaultDependencies", settings(UNITS / w))

    def test_every_writer_spelling_is_counted(self):
        # MOR-writer-match (#6043): test_every_held_file_goes_at_stop finds a writer by its text, so
        # each way a unit can name a holdDirs path counts, and a sibling path does not.
        dirs = check.MOR_LISTED
        named = [
            "ExecStart=/usr/bin/x /run/agentos-setup/passphrase\n",
            "ExecStart=/usr/bin/x /run/agentos-setup -y\n",
            "ReadWritePaths=/run/agentos-link-capture\n",
            "ReadWritePaths=/run/agentos-link-capture",
            "ReadWritePaths=-/run/agentos-setup\n",
            'Environment="DIR=/run/agentos-setup"\n',
            "Environment='DIR=/run/agentos-link-capture'\n",
            "BindPaths=/run/agentos-setup:/mnt\n",
            "ExecStart=/usr/bin/x %t/agentos-setup\n",
            "RuntimeDirectory=agentos-setup\n",
            "RuntimeDirectory=agentos-x agentos-link-capture/first\n",
            "  RuntimeDirectory = agentos-setup\n",
            "ExecStart=/usr/bin/x /run/agentos-setup\\\n  -y\n",
        ]
        for t in named:
            with self.subTest(t):
                self.assertTrue(names_held_dir(t, dirs))
        apart = [
            "ExecStart=/usr/bin/x /run/agentos-setupx\n",
            "ReadWritePaths=/run/agentos-link-capture-old\n",
            "ExecStart=/usr/bin/x /run/agentos-setup.bak/f\n",
            "RuntimeDirectory=agentos-setupx\n",
            "StateDirectory=agentos-setup\n",
            "CacheDirectory=agentos-link-capture\n",
            "# Not RuntimeDirectory=agentos-setup: a comment writes nothing\n",
        ]
        for t in apart:
            with self.subTest(t):
                self.assertFalse(names_held_dir(t, dirs))

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
