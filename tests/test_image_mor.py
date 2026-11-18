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
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import ENTRY, H, MK, ROOT, check, exec_args, finish, ini, nodump, settings, write  # noqa: E402

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


def unit_specifiers(unit):
    """A unit's name specifiers as regexes: %n, %N, %p, %j and %J literal; %i and %I any instance
    when the unit is a template (no instance in its name), so a template's directory may be any."""
    n = re.escape(unit)
    stem = unit.rsplit(".", 1)[0]
    prefix, at, inst = stem.partition("@")
    j = prefix.rsplit("-", 1)[-1]
    wild = at and not inst
    return {"%n": n, "%N": re.escape(stem), "%p": re.escape(prefix), "%j": re.escape(j),
            "%J": re.escape(j), "%i": "[^/]*" if wild else re.escape(inst),
            "%I": ".*" if wild else re.escape(inst)}


def unit_lines(text):
    """A unit file's text as systemd reads it: a comment line ("#" or ";" first) dropped, inside a
    continued line too, and a line ending in a backslash joined to the next. A comment line never
    continues here (systemd's would take the next line with it), so a write after one still counts."""
    out, cont = [], ""
    for line in text.split("\n"):
        if line.lstrip()[:1] in ("#", ";"):
            continue
        if line.endswith("\\"):
            cont += line[:-1] + " "
            continue
        out.append(cont + line)
        cont = ""
    return "\n".join(out + [cont])


def names_held_dir(text, dirs, unit=""):
    """Whether a unit file's text names one of dirs, or a path under it: the path not followed by a
    character that continues a name, through a base specifier, or as a directory setting (comments
    dropped, continued lines joined, the unit's name specifiers resolved). An InaccessiblePaths= line
    masks the paths it lists, so it names none: the main side's drop-ins (#5818) list every hold dir
    there."""
    text = re.sub(r"^[ \t]*InaccessiblePaths[ \t]*=.*$", "", unit_lines(text), flags=re.M)
    for spec, base in SPECIFIERS.items():
        text = text.replace(spec, base)
    if any(re.search(re.escape(d) + r"(?![\w.@+~-])", text) for d in dirs):
        return True
    names = unit_specifiers(unit) if unit else {}
    keys = "|".join(DIR_BASES)
    for key, value in re.findall(r"^[ \t]*(%s)[ \t]*=(.*)$" % keys, text, re.M):
        for name in value.replace(":", " ").split():
            parts = (DIR_BASES[key] + "/" + name.strip("\"'").strip("/")).split("/")
            for k in range(2, len(parts) + 1):
                pat = "".join(names.get(w, re.escape(w)) for w in re.split(r"(%[a-zA-Z])", "/".join(parts[:k])))
                if any(re.fullmatch(pat, d) for d in dirs):
                    return True
    return False


WIPE = "agentos-keeper-wipe.service"
# The clear's only commands (test_clear_runs_at_stop_after_the_secret_holders). It reaches the hold
# dirs only through agentos-mor's holdDirs, which it lists and never writes in
# (test_the_clear_sees_the_dirs_it_lists), so its unit names none and is counted like any other.
CLEAR_EXEC = {"ExecStart": ["/usr/lib/agentos/agentos-mor status"],
              "ExecStop": ["/usr/lib/agentos/agentos-mor clear"]}
COMMANDS = ("ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop",
            "ExecStopPost")


def hold_writers(units):
    """Every unit but the wipe whose file or drop-in names a holdDirs path, by unit name."""
    writers = set()
    for f in [u for u in units.iterdir() if u.is_file()] + list(units.glob("*.d/*.conf")):
        unit = f.parent.name[:-2] if f.parent.name.endswith(".d") else f.name
        if unit != WIPE and names_held_dir(f.read_text(), check.MOR_LISTED, unit):
            writers.add(unit)
    return writers


def unordered_writers(units):
    """The writers whose stop is not ordered before the wipe's: each must be in the wipe's Before= or
    name it in After=, and keep default dependencies so it also stops before the clear. A .path unit
    writes nothing; it starts enrollment, which is a writer of its own."""
    before = set(words(settings(units / WIPE), "Before"))
    bad = set()
    for w in hold_writers(units):
        if w.endswith(".path"):
            continue
        s = settings(units / w)
        if not (w in before or WIPE in words(s, "After")) or "DefaultDependencies" in s:
            bad.add(w)
    return bad


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
        # MOR-wipe-console (#6042): a failed find leaves MOR set; its error goes to the journal only.
        self.assertEqual((s["StandardError"], s.get("StandardOutput")), (["journal"], None))
        # MOR-wipe-owner (#6094): the stop's result is recorded for STATUS, in the unit's own directory
        # (broker/cmd/agentosd/wipenote_test.go runs the step and reads the line it drives).
        self.assertEqual((s["StateDirectory"], s["StateDirectoryMode"]), (["agentos-wipe"], ["0700"]))
        self.assertEqual(len(s["ExecStopPost"]), 1)
        self.assertTrue(s["ExecStopPost"][0].startswith("/usr/bin/sh -c "), s["ExecStopPost"])
        self.assertIn("MOR-wipe-journal", wipe.read_text())
        for key in ("DefaultDependencies", "ExecStart", "Conflicts", "BindsTo", "PartOf",
                    "Requires", "Requisite", "StopPropagatedFrom", "After"):
            self.assertNotIn(key, s)
        self.assertFalse([k for k in s if k.startswith(("Condition", "Assert"))])
        self.assertEqual(sorted(UNITS.glob(name + ".d/*")), [])
        before, wanted = set(words(s, "Before")), set(ini(wipe)["Install"]["WantedBy"].split())
        self.assertEqual(wanted, before | {"multi-user.target"})
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text()
        self.assertIn("\nenable %s\n" % name, preset)
        files = [u for u in UNITS.iterdir() if u.is_file()] + list(UNITS.glob("*.d/*.conf"))
        for f in files:
            self.assertNotIn("/dev/shm", f.read_text(), f.name)
            for key in ("Conflicts", "PropagatesStopTo"):
                self.assertNotIn(name, words(settings(f), key), f.name)
        # The writers, each found by its own text; a mask or a comment names none. The clear's own unit
        # is counted too (MOR-writer-match-fu, #6083): its commands are the clear's and nothing else.
        clear = [UNIT] + sorted(UNITS.glob("agentos-mor.service.d/*.conf"))
        cmds = {}
        for f in clear:
            for k, v in settings(f).items():
                if k in COMMANDS:
                    cmds.setdefault(k, []).extend(v)
        self.assertEqual(cmds, CLEAR_EXEC)
        self.assertEqual(hold_writers(UNITS), {
            "agentos-keeper-pageca.service", "agentos-keeper-enroll.service", "agentos-keeper-enroll.path",
            "agentos-keeper-setup@.service", "agentos-keeper-link-capture.service"})
        self.assertEqual(unordered_writers(UNITS), set())

    def test_the_clear_counts_as_a_writer_beyond_its_clear(self):
        # MOR-writer-match-fu (#6083): the clear's own unit is no longer skipped by name, so a write it
        # gains beside the clear is counted and fails the ordering (it stops after the wipe), whether in
        # the unit, in a drop-in, or folded into the clear's own command line.
        exec_stop = "ExecStop=/usr/lib/agentos/agentos-mor clear\n"
        self.assertIn(exec_stop, UNIT.read_text())
        writes = {
            "unit": ("agentos-mor.service", exec_stop, exec_stop + "ExecStopPost=/usr/bin/rm -f /run/agentos-setup/x\n"),
            "drop-in": ("agentos-mor.service.d/60-x.conf", None, "[Service]\nExecStopPost=/usr/bin/touch %t/agentos-link-capture/x\n"),
            "clear": ("agentos-mor.service", exec_stop, "ExecStop=/usr/lib/agentos/agentos-mor clear /run/agentos-setup\n"),
        }
        for case, (path, old, new) in writes.items():
            with self.subTest(case), tempfile.TemporaryDirectory() as tmp:
                units = pathlib.Path(tmp) / "system"
                shutil.copytree(UNITS, units, symlinks=True)
                f = units / path
                f.write_text(new if old is None else f.read_text().replace(old, new, 1))
                self.assertIn("agentos-mor.service", hold_writers(units))
                self.assertIn("agentos-mor.service", unordered_writers(units))

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
            'ExecStart=/bin/sh -c "test -d /run/agentos-setup&&touch x"\n',
            "ExecStart=/bin/sh -c 'ls /run/agentos-setup|wc'\n",
            "Environment=DIRS=/run/agentos-setup,/tmp\n",
            'ExecStart=/bin/sh -c "x=$(ls /run/agentos-setup)"\n',
            "ExecStart=/bin/sh -c 'echo /run/agentos-setup>/dev/null'\n",
            "ExecStart=/bin/sh -c 'cat /run/agentos-setup*'\n",
            'ExecStart=/bin/sh -c "d=${D:-/run/agentos-setup}"\n',
            "RuntimeDirectory=agentos-x \\\n  agentos-setup\n",
            "InaccessiblePaths=/var/lib/x\nReadWritePaths=/run/agentos-setup\n",
            "# a comment ends here \\\nExecStart=/usr/bin/x /run/agentos-setup\n",
            "RuntimeDirectory=agentos-x \\\n# a comment\n  agentos-setup\n",
            "ExecStart=/usr/bin/x #/run/agentos-setup\n",
        ]
        for t in named:
            with self.subTest(t):
                self.assertTrue(names_held_dir(t, dirs))
        # A directory setting through the unit's own name: the template's instance may be any name.
        for t, unit in [("RuntimeDirectory=%p\n", "agentos-setup.service"),
                        ("RuntimeDirectory=%N/x\n", "agentos-link-capture.service"),
                        ("RuntimeDirectory=%n\n", "agentos-setup"),
                        ("RuntimeDirectory=agentos-%j\n", "x-setup.service"),
                        ("RuntimeDirectory=agentos-%i\n", "agentos-keeper-setup@.service"),
                        ("RuntimeDirectory=%I\n", "agentos-keeper-setup@.service"),
                        ("RuntimeDirectory=agentos-%i\n", "agentos-keeper-setup@setup.service")]:
            with self.subTest(t, unit=unit):
                self.assertTrue(names_held_dir(t, dirs, unit))
        for t, unit in [("RuntimeDirectory=%p\n", "agentos-setupx.service"),
                        ("RuntimeDirectory=agentos-%i\n", "agentos-keeper-setup@other.service"),
                        ("RuntimeDirectory=%i-x\n", "agentos-keeper-setup@.service")]:
            with self.subTest(t, unit=unit):
                self.assertFalse(names_held_dir(t, dirs, unit))
        apart = [
            "ExecStart=/usr/bin/x /run/agentos-setupx\n",
            "ReadWritePaths=/run/agentos-link-capture-old\n",
            "ExecStart=/usr/bin/x /run/agentos-setup.bak/f\n",
            "RuntimeDirectory=agentos-setupx\n",
            "StateDirectory=agentos-setup\n",
            "CacheDirectory=agentos-link-capture\n",
            "# Not RuntimeDirectory=agentos-setup: a comment writes nothing\n",
            "InaccessiblePaths=/run/agentos-setup\n",
            "InaccessiblePaths=-/var/lib/x /run/agentos-setup /run/agentos-link-capture\n",
            "  InaccessiblePaths = /var/lib/x \\\n  /run/agentos-setup\n",
            "# Leaves /run/agentos-setup unmasked\n",
            "  ; ExecStart=/usr/bin/x /run/agentos-link-capture\n",
            "ExecStart=/usr/bin/x \\\n# /run/agentos-setup\n  -y\n",
        ]
        for t in apart:
            with self.subTest(t):
                self.assertFalse(names_held_dir(t, dirs))

    def test_an_isolate_keeps_the_staged_page_authority(self):
        # MOR-setup-isolate (#5858, HW-1, CH-9): RefuseManualStop= does not cover an isolate, so
        # "systemctl isolate rescue.target" stopped the staging unit, its stop removed the pair, and
        # the next confirm staged a new authority under a card already printed. An isolate now leaves
        # the unit active. Shutdown still stops it through Conflicts=shutdown.target (default
        # dependencies kept), so the pair goes before the clear. No other unit may stop it through a
        # dependency: the staging names none that would, and no image unit names it in one that would.
        name = "agentos-keeper-pageca.service"
        unit = UNITS / name
        self.assertEqual(ini(unit)["Unit"]["IgnoreOnIsolate"], "yes")
        s = settings(unit)
        self.assertNotIn("DefaultDependencies", s)
        for key in ("Conflicts", "BindsTo", "PartOf", "Requires", "Requisite", "StopPropagatedFrom"):
            self.assertNotIn(key, s)
        self.assertEqual(sorted(UNITS.glob(name + ".d/*")), [])
        for f in [u for u in UNITS.iterdir() if u.is_file()] + list(UNITS.glob("*.d/*.conf")):
            for key in ("Conflicts", "PropagatesStopTo"):
                with self.subTest(f.name, key=key):
                    self.assertNotIn(name, words(settings(f), key))

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


class WipeJournalTest(unittest.TestCase):
    """MOR-wipe-journal (#6078): the wipe's error goes to the journal only (#6042), and a failed wipe is
    a shutdown, so the journal keeps it only on disk. Debian's postinst makes /var/log/journal, which
    Storage=auto needs; the image's drop-in sets persistent instead, and the tree check holds it."""
    # REQ: HW-8
    DROPIN = "usr/lib/systemd/journald.conf.d/50-agentos-persist.conf"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        write(self.root, "etc/machine-id", "uninitialized\n")
        nodump(self.root)

    def v(self):
        return " | ".join(check.violations(self.root))

    def test_the_image_keeps_the_journal_on_disk(self):
        self.assertEqual(dict(ini(MK / "mkosi.extra" / self.DROPIN)["Journal"]), {"Storage": "persistent"})
        self.assertEqual(sorted(p.name for p in MK.glob("mkosi.extra/**/journald.conf*")), ["journald.conf.d"])
        self.assertNotIn("journald", ini(MK / "mkosi.conf")["Content"]["KernelCommandLine"])
        self.assertNotIn("journald", self.v())

    def test_the_tree_check_refuses_a_journal_that_forgets(self):
        # UX on #6086: each refusal names the file whose line decides, or says the shipped drop-in is missing.
        zz, lib = "etc/systemd/journald.conf.d/zz.conf", "usr/lib/systemd/journald.conf.d/zz.conf"
        must = "; must be persistent (change or remove that line)"
        level = "; must store info, a unit's stderr (set info or debug, or remove that line)"
        ignored = ", keeping the one before it (set a valid one or remove that line)"
        for rel, text, want in (
                (self.DROPIN, None, "journald Storage is not set (auto); must be persistent "
                                    "(usr/lib/systemd/journald.conf.d/50-agentos-persist.conf is missing)"),
                (zz, "[Journal]\nStorage=volatile\n", zz + ": journald Storage is volatile" + must),
                (zz, "[Journal]\nStorage=auto\n", zz + ": journald Storage is auto" + must),
                (zz, "[Journal]\nStorage=\n", zz + ": journald Storage= is a value journald ignores" + ignored),
                (zz, "[Journal]\nStorage=Persistent\n", zz + ": journald Storage=Persistent is a value journald ignores"
                 + ignored),
                (self.DROPIN, "[Journal]\nStorage=none\n", self.DROPIN + ": journald Storage is none" + must),
                (lib, "[Journal]\nMaxLevelStore=notice\n", lib + ": journald MaxLevelStore is notice" + level),
                (lib, "[Journal]\nMaxLevelStore=5\n", lib + ": journald MaxLevelStore is 5" + level),
                (lib, "[Journal]\nMaxLevelStore=x\n", lib + ": journald MaxLevelStore=x is a value journald ignores"
                 + ignored),
                (lib, "[Journal]\nMaxLevelStore=8\n", lib + ": journald MaxLevelStore=8 is a value journald ignores"
                 + ignored),
                (zz, b"[Journal]\nX=\xff\n", zz + ": unreadable ("),
                ("run/systemd/journald.conf.d/a.conf", "[Journal]\nStorage=persistent\n", "/run is a tmpfs")):
            with self.subTest(rel=rel, text=text):
                saved = (self.root / self.DROPIN).read_text()
                if text is None:
                    (self.root / rel).unlink()
                elif isinstance(text, bytes):
                    (self.root / rel).write_bytes(text)
                else:
                    write(self.root, rel, text)
                self.assertIn(want, self.v())
                if rel != self.DROPIN:
                    (self.root / rel).unlink()
                write(self.root, self.DROPIN, saved)
                self.assertNotIn("journald", self.v())
        # The later file decides (drop-ins in name order, whatever their directory), and is the one named.
        early = "usr/lib/systemd/journald.conf.d/40-a.conf"
        write(self.root, early, "[Journal]\nStorage=volatile\n")
        self.assertNotIn("journald", self.v())  # the shipped 50- drop-in is read after it
        write(self.root, zz, "[Journal]\nStorage=volatile\n")
        self.assertEqual([v for v in check.violations(self.root) if "journald" in v],
                         [zz + ": journald Storage is volatile" + must])
        (self.root / zz).unlink()
        (self.root / early).unlink()
        # Security on #6086: an empty value is ignored, not a reset, so notice still holds after it.
        write(self.root, early, "[Journal]\nMaxLevelStore=notice\n")
        write(self.root, zz, "[Journal]\nMaxLevelStore=\n")
        self.assertEqual([v for v in check.violations(self.root) if "journald" in v],
                         [zz + ": journald MaxLevelStore= is a value journald ignores" + ignored,
                          early + ": journald MaxLevelStore is notice" + level])
        (self.root / zz).unlink()
        (self.root / early).unlink()
        for kept in ("info", "debug", "6", "7"):
            with self.subTest(kept=kept):
                write(self.root, zz, "[Journal]\nMaxLevelStore=%s\n" % kept)
                self.assertNotIn("journald", self.v())


if __name__ == "__main__":
    unittest.main()
