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
from test_image import ENTRY, H, MK, ROOT, check, exec_args, finish, flush_unit, ini, nodump, settings, write  # noqa: E402

UNITS = MK / "mkosi.extra/usr/lib/systemd/system"
UNIT = UNITS / "agentos-mor.service"
# Units the image ships without default dependencies, so not ordered after sysinit.target: each is
# stopped in no known order against agentos-mor.service, so none may hold a secret.
NO_DEFAULT_DEPS = {
    "agentos-inbound.service": "loads the inbound nftables ruleset; holds no secret",
    "agentos-mor.service": "this unit",
}
# Units that drop the default dependencies only to leave out their Requires=sysinit.target, which an
# emergency isolate stops through sysinit.target's Conflicts=emergency.target (MOR-pageca-emergency, #6178):
# each states the rest of them, and its stop is ordered before this unit's clear (STATED_DEPS).
STATED = {
    "agentos-keeper-pageca.service": "the page authority a printed Owner Card names",
    "agentos-keeper-wipe.service": "its stop empties /run/agentos-setup, the staged authority's pair included",
}
STOP_LINKS = ("BindsTo", "PartOf", "Requires", "Requisite", "StopPropagatedFrom", "StopWhenUnneeded",
              "RequiresMountsFor")


def words(s, key):
    return " ".join(s.get(key, [])).split()


def stated_deps(s):
    """Whether settings S keep the default dependencies (After=sysinit.target, so the stop comes before
    the clear's), or drop them and state each but Requires=sysinit.target: After=sysinit.target and
    basic.target, Conflicts= and Before=shutdown.target, and After= this unit, so the stop is before the
    clear's in a shutdown transaction directly."""
    if "DefaultDependencies" not in s:
        return True
    return (s["DefaultDependencies"] == ["no"] and words(s, "Conflicts") == ["shutdown.target"]
            and {"sysinit.target", "basic.target", UNIT.name} <= set(words(s, "After"))
            and "shutdown.target" in words(s, "Before") and UNIT.name not in words(s, "Before"))


def applied_dropins(units, name):
    """The drop-ins systemd applies to service NAME from UNITS: NAME.d's, then each "-" prefix's, then
    service.d's, a file named as one already taken being replaced by it (the more specific directory)."""
    stem = name.rsplit(".", 1)[0]
    dirs = [name + ".d"] + ["%s-.service.d" % stem[:i] for i in range(len(stem) - 1, 0, -1)
                             if stem[i] == "-"] + ["service.d"]
    seen, out = set(), []
    for d in dirs:
        for f in sorted((units / d).glob("*.conf")):
            if f.name not in seen:
                seen.add(f.name)
                out.append(f)
    return out


def isolate_pin(units):
    """Why agentos-mor.service, read from UNITS with every drop-in applied to it, could be stopped by an
    isolate or with another unit (MOR-emergency-isolate, #5947; L3 and Security on #6159): IgnoreOnIsolate=
    not set once to yes, a STOP_LINKS key, or any drop-in that has a [Unit] section."""
    unit, dropins = units / UNIT.name, applied_dropins(units, UNIT.name)
    out = []
    every = {}
    for f in [unit] + dropins:
        for k, v in settings(f).items():
            every.setdefault(k, []).extend(v)
    if every.get("IgnoreOnIsolate") != ["yes"]:
        out.append("IgnoreOnIsolate=%s" % every.get("IgnoreOnIsolate"))
    out += ["%s=%s" % (k, every[k]) for k in STOP_LINKS if k in every]
    out += ["[Unit] in %s" % f.name for f in dropins if re.search(r"^\s*\[Unit\]", f.read_text(), re.M)]
    return out


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
# (test_the_clear_sees_the_dirs_it_lists), so its unit names none and is counted like any other. Its
# record step (MOR-clear-owner, test_a_refused_clear_is_recorded_on_root) writes on root only.
CLEAR_RECORD = ("/usr/bin/sh -c 'if [ \"$$SERVICE_RESULT\" = success ]; then exec /usr/bin/rm -f -- "
                "/var/lib/agentos-mor/refused; fi; /usr/bin/mkdir -p -m 0700 /var/lib/agentos-mor && "
                "echo \"$$SERVICE_RESULT $$EXIT_CODE $$EXIT_STATUS\" >/var/lib/agentos-mor/refused && "
                "exec /usr/bin/sync -f /var/lib/agentos-mor/refused'")
CLEAR_EXEC = {"ExecStart": ["/usr/lib/agentos/agentos-mor status"],
              "ExecStop": ["/usr/lib/agentos/agentos-mor clear"],
              "ExecStopPost": [CLEAR_RECORD]}
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
    name it in After=, and keep default dependencies or state them (stated_deps), so it also stops
    before the clear. A .path unit
    writes nothing; it starts enrollment, which is a writer of its own."""
    before = set(words(settings(units / WIPE), "Before"))
    bad = set()
    for w in hold_writers(units):
        if w.endswith(".path"):
            continue
        s = settings(units / w)
        if not (w in before or WIPE in words(s, "After")) or not stated_deps(s):
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

    def test_a_refused_clear_is_recorded_on_root(self):
        # MOR-clear-owner (#6111): the stop's result is recorded for STATUS whatever it is
        # (broker/cmd/agentos-mor/record_test.go drives each refusal through the step, and
        # broker/cmd/agentosd/wipenote_test.go the record to the line). The directory is made by the
        # step, not by StateDirectory=, which systemd makes at this unit's early-boot start.
        s = settings(UNIT)
        self.assertEqual(len(s["ExecStopPost"]), 1)
        stop = s["ExecStopPost"][0]
        self.assertTrue(stop.startswith("/usr/bin/sh -c "), stop)
        self.assertIn("/var/lib/agentos-mor/refused", stop)
        for key in list(DIR_BASES) + ["ProtectSystem", "ReadOnlyPaths", "ReadWritePaths", "TemporaryFileSystem",
                                      "BindPaths", "BindReadOnlyPaths", "RootDirectory", "RootImage"]:
            self.assertNotIn(key, s)
        # It runs after every other unit has stopped and after tmp.mount, so the record must sit on a
        # file system that is still mounted and writable then: the root partition, which systemd never
        # unmounts (systemd-shutdown syncs and remounts it read-only after the last unit). Nothing the
        # image ships mounts another file system at /var or below.
        rec = pathlib.PurePosixPath("/var/lib/agentos-mor/refused")
        repart = list((MK / "mkosi.repart").glob("*.conf")) + list((MK / "mkosi.extra/usr/lib/repart.d").glob("*.conf"))
        self.assertEqual({t for f in repart for t in settings(f).get("Type", [])},
                         {"esp", "usr", "usr-verity", "root"})
        fstab = [l.split() for l in (MK / "mkosi.extra/etc/fstab").read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
        self.assertEqual([m for _, m, *_ in fstab if rec.is_relative_to(m) and m != "/"], [])
        self.assertEqual(sorted(u.name for u in UNITS.iterdir() if u.suffix in (".mount", ".automount")
                                and u.name.startswith("var")), [])
        hidden = [w.lstrip("-") for w in settings(UNITS / "agentos-mor.service.d/50-main-side.conf")["InaccessiblePaths"][0].split()]
        self.assertFalse([h for h in hidden if rec.is_relative_to(h)], hidden)
        # The root is mounted read-write from the start (the boot entry's rw), so the step can write it.
        self.assertIn("rw", words(settings(MK / "mkosi.conf"), "KernelCommandLine"))

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
        # run when MOR is cleared. Each one is listed with why it holds no secret, or states the default
        # dependencies but Requires=sysinit.target and is ordered after this unit (STATED, #6178).
        found = {u.name for u in UNITS.iterdir()
                 if u.is_file() and u.suffix in (".service", ".socket", ".mount", ".path", ".timer")
                 and (settings(u).get("DefaultDependencies") or ["yes"])[-1].lower() in ("no", "false", "0", "off")}
        for d in UNITS.glob("*.d"):
            for f in d.glob("*.conf"):
                if "DefaultDependencies" in settings(f):
                    found.add(d.name[:-2])
        self.assertEqual(found, set(NO_DEFAULT_DEPS) | set(STATED))
        for name in STATED:
            s = settings(UNITS / name)
            self.assertTrue(stated_deps(s), name)
            self.assertEqual(sorted(UNITS.glob(name + ".d/*")), [])
        # Each part of the stated order is needed: drop one and the unit no longer stops before the clear.
        s = settings(UNITS / "agentos-keeper-pageca.service")
        for key, word in (("After", "sysinit.target"), ("After", "basic.target"), ("After", UNIT.name),
                          ("Conflicts", "shutdown.target"), ("Before", "shutdown.target")):
            with self.subTest(key=key, word=word):
                cut = dict(s, **{key: [" ".join(w for w in words(s, key) if w != word)]})
                self.assertFalse(stated_deps(cut))
        self.assertFalse(stated_deps(dict(s, Before=s["Before"] + [UNIT.name])))
        self.assertFalse(stated_deps(dict(s, Conflicts=["shutdown.target emergency.target"])))

    def test_the_staged_page_authority_goes_at_stop(self):
        # MOR-setup-hold (#5836): before enrollment the page authority's sealed pair sits in
        # /run/agentos-setup, a holdDirs entry, so the clear refused on every orderly shutdown. The
        # staging unit's stop removes exactly the pair and certificate its start made; it keeps default
        # dependencies (test_every_other_unit_stops_first), so it stops before this unit's clear. A
        # manual stop is refused, so a card printed this boot keeps its fingerprint until shutdown. Its
        # stated dependencies order that stop before the clear (#6178).
        unit = UNITS / "agentos-keeper-pageca.service"
        p, s = exec_args(unit), settings(unit)
        made = [p[p.index("-page-ca-file") + 1], p[p.index("-page-ca-cert") + 1]]
        self.assertEqual(s["ExecStopPost"], ["/usr/bin/rm -f " + " ".join(made)])
        self.assertEqual(made[0].rsplit("/", 1)[0], check.MOR_LISTED[0])
        self.assertEqual(s["RefuseManualStop"], ["yes"])
        self.assertEqual(s["DefaultDependencies"], ["no"])
        self.assertTrue(stated_deps(s))
        for key in ("ExecStop", "ExecStopPre"):
            self.assertNotIn(key, s)

    def test_every_held_file_goes_at_stop(self):
        # MOR-setup-factors (#5843): the card's factors, and the first edge's capture, sit in holdDirs
        # entries from the confirm until a successful enrollment, and on a failure for a retry, with no
        # stop of their own, so an orderly shutdown then left MOR set. The wipe's stop empties every
        # holdDirs entry on /run. Its stated dependencies order it before this unit's clear
        # (test_every_other_unit_stops_first, #6178); it is ordered before every unit whose commands name a
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
        self.assertTrue(stated_deps(s))
        self.assertEqual(set(words(s, "After")), {"sysinit.target", "basic.target", UNIT.name})
        for key in ("ExecStart",) + STOP_LINKS:
            self.assertNotIn(key, s)
        self.assertFalse([k for k in s if k.startswith(("Condition", "Assert"))])
        self.assertEqual(sorted(UNITS.glob(name + ".d/*")), [])
        before, wanted = set(words(s, "Before")), set(ini(wipe)["Install"]["WantedBy"].split())
        self.assertEqual(wanted, before - {"shutdown.target"} | {"multi-user.target"})
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
        # the unit active. MOR-pageca-emergency (#6178): default dependencies add Requires=sysinit.target,
        # which conflicts with emergency.target, so an emergency isolate still stopped it; the staging and
        # the wipe (whose stop empties the pair's directory) drop them and state the rest (stated_deps), so
        # shutdown alone stops them, before the clear. No other unit may stop either through a dependency:
        # neither names one that would, and no image unit names either in one that would.
        for name in STATED:
            unit = UNITS / name
            self.assertEqual(ini(unit)["Unit"]["IgnoreOnIsolate"], "yes")
            s = settings(unit)
            self.assertEqual((s["IgnoreOnIsolate"], s["DefaultDependencies"]), (["yes"], ["no"]))
            self.assertTrue(stated_deps(s))
            for key in STOP_LINKS:
                self.assertNotIn(key, s)
            self.assertEqual(sorted(UNITS.glob(name + ".d/*")), [])
            for f in [u for u in UNITS.iterdir() if u.is_file()] + list(UNITS.glob("*.d/*.conf")):
                for key in ("Conflicts", "PropagatesStopTo"):
                    with self.subTest(f.name, name=name, key=key):
                        self.assertNotIn(name, words(settings(f), key))

    def test_an_isolate_leaves_the_clear_alone(self):
        # MOR-emergency-isolate (#5947): this unit is WantedBy=sysinit.target, which emergency.target does
        # not pull in, so "systemctl isolate emergency.target" stopped it: its stop cleared MOR (or held on
        # the staged pair), and "systemctl default" then restarted the secret holders with MOR clear, as
        # its start only reads MOR. An isolate now leaves it active, so only the shutdown transaction stops
        # it (Conflicts=shutdown.target). No other stop path: it needs no unit (test_no_ordering_cycle_with
        # _tmp_mount), nothing stops it when unneeded, and no image unit names it in a stop dependency.
        # tests/test_hostcheck.py's test_an_isolate_keeps_mor_set boots the image through both isolates.
        # Its drop-ins are read with it, and none may have a [Unit] section (L3 and Security on #6159): each
        # stop key, or a second IgnoreOnIsolate=, in a drop-in fails the pin.
        self.assertEqual(ini(UNIT)["Unit"]["IgnoreOnIsolate"], "yes")
        self.assertEqual(isolate_pin(UNITS), [])
        self.assertEqual([f.name for f in applied_dropins(UNITS, UNIT.name)], ["50-main-side.conf"])
        cases = {key: "[Unit]\n%s=%s\n" % (key, "yes" if key == "StopWhenUnneeded" else "/run" if key ==
                                            "RequiresMountsFor" else "x.service") for key in STOP_LINKS}
        cases.update({"IgnoreOnIsolate=no": "[Unit]\nIgnoreOnIsolate=no\n",
                      "IgnoreOnIsolate=yes twice": "[Unit]\nIgnoreOnIsolate=yes\n",
                      "a [Unit] section": "[Unit]\nDescription=x\n"})
        for case, text in cases.items():
            for d in ("agentos-mor.service.d", "agentos-.service.d", "service.d"):
                with self.subTest(case, d=d), tempfile.TemporaryDirectory() as tmp:
                    units = pathlib.Path(tmp) / "system"
                    shutil.copytree(UNITS, units, symlinks=True)
                    write(units, d + "/60-x.conf", text)
                    self.assertNotEqual(isolate_pin(units), [])
        for f in [u for u in UNITS.iterdir() if u.is_file()] + list(UNITS.glob("*.d/*.conf")):
            for key in ("Conflicts", "PropagatesStopTo"):
                with self.subTest(f.name, key=key):
                    self.assertNotIn(UNIT.name, words(settings(f), key))

    def test_build_installs_the_program(self):
        build = (ROOT / "image/build.sh").read_text()
        loop = re.search(r"for cmd in ([^;]+); do", build, re.S).group(1).split()
        self.assertIn("agentos-mor", loop)


class IsolateKeptTest(unittest.TestCase):
    """MOR-pageca-emergency (#6178; Security on #6159): mkosi.finalize's isolate_violations reads the built
    tree, so a later layer's unit or drop-in that lets an isolate stop the MOR clear, the page authority's
    staging or the wipe fails the build, which the source-tree tests above cannot see."""
    # REQ: HW-8
    SYSTEM = "usr/lib/systemd/system/"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        shutil.copytree(UNITS, self.root / self.SYSTEM, symlinks=True)

    def v(self):
        return check.isolate_violations(self.root)

    def test_the_image_passes(self):
        self.assertEqual(check.ISOLATE_KEPT, (UNIT.name,) + tuple(STATED))
        self.assertEqual(set(check.STOP_LINKS), set(STOP_LINKS))
        self.assertEqual(self.v(), [])

    def test_a_drop_in_that_lets_an_isolate_stop_one_is_refused(self):
        once = "%s: IgnoreOnIsolate= is %s; must be set once, to exactly yes, so an isolate leaves it running (#6178)"
        for name in check.ISOLATE_KEPT:
            unit = self.SYSTEM + name
            for value in ("no", "true", "1", "yes", ""):
                for d in ("etc/systemd/system/%s.d" % name, "usr/local/lib/systemd/system/agentos-.service.d"):
                    with self.subTest(name, value=value, d=d):
                        f = write(self.root, d + "/zz.conf", "[Unit]\nIgnoreOnIsolate=%s\n" % value)
                        got = self.v()
                        f.unlink()
                        self.assertIn(once % (name, "'yes' in %s, %r in %s" % (unit, value, d + "/zz.conf")), got)
                        # agentos-.service.d applies to all three.
                        self.assertEqual(len(got), 1 if d.startswith("etc") else len(check.ISOLATE_KEPT), got)
            with self.subTest(name, case="dropped"):
                saved = (self.root / unit).read_text()
                write(self.root, unit, saved.replace("IgnoreOnIsolate=yes\n", ""))
                self.assertEqual(self.v(), [once % (name, "unset")])
                write(self.root, unit, saved)
            with self.subTest(name, case="default dependencies"):
                f = write(self.root, "etc/systemd/system/%s.d/zz.conf" % name, "[Unit]\nDefaultDependencies=yes\n")
                got = self.v()
                f.unlink()
                self.assertEqual(got, ["%s: DefaultDependencies= is 'no' in %s, 'yes' in %s; must be set once, to "
                                            "exactly no, so an isolate leaves it running (#6178)"
                                            % (name, unit, f.relative_to(self.root))])
            for key in check.STOP_LINKS:
                with self.subTest(name, key=key):
                    rel = "etc/systemd/system/%s.d/zz.conf" % name
                    f = write(self.root, rel, "[Unit]\n%s=sysinit.target\n" % key)
                    got = self.v()
                    f.unlink()
                    self.assertEqual(got, ["%s: %s=sysinit.target in %s; another unit's stop would stop it, "
                                                "whatever IgnoreOnIsolate= says (#6178)" % (name, key, rel)])
            with self.subTest(name, case="conflict"):
                f = write(self.root, "etc/systemd/system/%s.d/zz.conf" % name, "[Unit]\nConflicts=emergency.target\n")
                got = self.v()
                f.unlink()
                self.assertEqual(len(got), 1, got)
                self.assertIn("must conflict with shutdown.target alone", got[0])
        self.assertEqual(self.v(), [])

    def test_each_holder_stops_before_the_clear(self):
        for name in STATED:
            for text in ("[Unit]\nBefore=agentos-mor.service\n", None):
                with self.subTest(name, text=text):
                    unit, zz = self.root / self.SYSTEM / name, self.root / ("etc/systemd/system/%s.d/zz.conf" % name)
                    saved = unit.read_text()
                    if text is None:
                        self.assertIn(" agentos-mor.service\n", saved)
                        unit.write_text(saved.replace(" agentos-mor.service\n", "\n", 1))
                    else:
                        write(self.root, str(zz.relative_to(self.root)), text)
                    got = self.v()
                    unit.write_text(saved)
                    zz.unlink(missing_ok=True)
                    self.assertEqual(len(got), 1, got)
                    self.assertTrue(got[0].startswith(name + ": After="), got)
                    self.assertIn("so shutdown stops it before the MOR clear (#6178)", got[0])

    def test_a_mask_passes_and_an_alias_is_refused(self):
        # A masked or missing unit never runs: MOR stays set, or no card is staged.
        for name in check.ISOLATE_KEPT:
            m = self.root / "etc/systemd/system" / name
            m.parent.mkdir(parents=True, exist_ok=True)
            m.symlink_to("/dev/null")
            self.assertEqual(self.v(), [], name)
            m.unlink()
        alias = self.root / self.SYSTEM / "foo.service"
        alias.symlink_to("agentos-keeper-pageca.service")
        self.assertEqual(self.v(), ["%sfoo.service: an alias of agentos-keeper-pageca.service; the tree check does not "
                                    "model unit aliases" % self.SYSTEM])


class SoftRebootTest(unittest.TestCase):
    """MOR-soft-reboot (#6182): an orderly soft reboot stops agentos-mor.service through shutdown.target, so
    its clear runs while the kernel keeps its memory, and the next userspace's start only reads MOR. The
    image removes the unit soft-reboot.target requires, and mkosi.finalize's ram_kept_violations
    refuses a built tree where it can load again. tests/test_hostcheck.py test_an_isolate_keeps_mor_set
    boots the image and runs the soft reboot."""
    # REQ: HW-8
    SYSTEM = "usr/lib/systemd/system/"
    DEBIAN = "[Unit]\nRequires=shutdown.target umount.target final.target\n[Service]\nType=oneshot\n" \
             "ExecStart=systemctl --force soft-reboot\n"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        shutil.copytree(UNITS, self.root / self.SYSTEM, symlinks=True)

    def v(self):
        return check.ram_kept_violations(self.root)

    def test_the_image_removes_the_unit(self):
        self.assertEqual(check.SOFT_REBOOT, "systemd-soft-reboot.service")
        removed = ini(MK / "mkosi.conf")["Content"]["RemoveFiles"].split()
        self.assertIn("/" + self.SYSTEM + check.SOFT_REBOOT, removed)
        self.assertFalse((UNITS / check.SOFT_REBOOT).exists())
        self.assertEqual(self.v(), [])
        self.assertIn("ram_kept_violations(root)", (MK / "mkosi.finalize").read_text())

    def test_the_unit_coming_back_is_refused(self):
        why = ("%s: present; an orderly soft reboot stops agentos-mor.service, whose stop clears MOR, while the "
               "kernel keeps its memory, so the holders after it run with MOR clear (remove it or mask it, #6182)")
        for d in check.UNIT_PATHS:
            rel = "%s/%s" % (d, check.SOFT_REBOOT)
            for text in (self.DEBIAN, "\n"):
                with self.subTest(d=d, text=text):
                    f = write(self.root, rel, text)
                    got = self.v()
                    f.unlink()
                    self.assertEqual(got, [why % rel])

    def test_a_mask_first_passes_and_a_mask_after_the_unit_does_not(self):
        write(self.root, self.SYSTEM + check.SOFT_REBOOT, self.DEBIAN)
        for kind in ("link", "empty"):
            with self.subTest(kind=kind):
                m = self.root / "etc/systemd/system" / check.SOFT_REBOOT
                m.parent.mkdir(parents=True, exist_ok=True)
                if kind == "link":
                    m.symlink_to("/dev/null")
                else:
                    m.write_text("")
                self.assertEqual(self.v(), [])
                m.unlink()
        (self.root / self.SYSTEM / check.SOFT_REBOOT).unlink()
        # The first entry decides: a unit in /etc wins over a mask lower in the search path.
        write(self.root, "etc/systemd/system/" + check.SOFT_REBOOT, self.DEBIAN)
        (self.root / self.SYSTEM / check.SOFT_REBOOT).symlink_to("/dev/null")
        got = self.v()
        self.assertEqual(len(got), 1, got)
        self.assertTrue(got[0].startswith("etc/systemd/system/%s: present;" % check.SOFT_REBOOT), got)

    def test_a_link_of_its_name_is_refused(self):
        # An alias (a link of its name to another unit) loads that unit under the name, so it is refused
        # unread, as is any link but a mask.
        link = self.root / self.SYSTEM / check.SOFT_REBOOT
        for target in ("agentos-mor.service", "/usr/lib/systemd/system/agentos-mor.service", "/dev/zero"):
            with self.subTest(target=target):
                link.symlink_to(target)
                got = self.v()
                link.unlink()
                self.assertEqual(len(got), 1, got)
                self.assertTrue(got[0].startswith(self.SYSTEM + check.SOFT_REBOOT + ": unreadable ("), got)



class KexecClassTest(unittest.TestCase):
    """MOR-kexec-class (#6311): Debian's kernel has CONFIG_KEXEC=y and CONFIG_KEXEC_FILE=y, so an orderly kexec
    (kexec.target requires systemd-kexec.service, which requires shutdown.target) would stop
    agentos-mor.service, clearing MOR, and boot the next kernel on memory the firmware never wiped. The image
    removes the unit as it does the soft reboot's, ram_kept_violations refuses it coming back, and
    kexec_loader_violations refuses a loader, so no kernel is ever loaded for a kexec or a crash kernel.
    tests/test_hostcheck.py test_an_isolate_keeps_mor_set boots the image and runs the kexec."""
    # REQ: HW-8
    SYSTEM = "usr/lib/systemd/system/"
    DEBIAN = "[Unit]\nRequires=shutdown.target umount.target final.target\nSuccessAction=kexec-force\n"
    WHY = ("a kexec loader; with a kernel loaded, a kexec or a crash kernel runs the next kernel on memory the "
           "firmware never wiped (remove it, #6311)")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        shutil.copytree(UNITS, self.root / self.SYSTEM, symlinks=True)

    def test_the_image_removes_the_unit_and_runs_both_checks(self):
        self.assertEqual(check.KEXEC, "systemd-kexec.service")
        self.assertEqual([u for u, _, _ in check.RAM_KEPT], [check.SOFT_REBOOT, check.KEXEC])
        removed = ini(MK / "mkosi.conf")["Content"]["RemoveFiles"].split()
        self.assertIn("/" + self.SYSTEM + check.KEXEC, removed)
        self.assertFalse((UNITS / check.KEXEC).exists())
        self.assertEqual(check.ram_kept_violations(self.root), [])
        self.assertEqual(check.kexec_loader_violations(self.root), [])
        text = (MK / "mkosi.finalize").read_text()
        self.assertIn("kexec_loader_violations(root)", text)
        self.assertIn("ram_kept_violations(root)", text)

    def test_the_unit_coming_back_is_refused(self):
        why = ("%s: present; an orderly kexec stops agentos-mor.service, whose stop clears MOR, while the kernel "
               "keeps its memory, so the holders after it run with MOR clear (remove it or mask it, #6311)")
        for d in check.UNIT_PATHS:
            rel = "%s/%s" % (d, check.KEXEC)
            for text in (self.DEBIAN, "\n"):
                with self.subTest(d=d, text=text):
                    f = write(self.root, rel, text)
                    got = check.ram_kept_violations(self.root)
                    f.unlink()
                    self.assertEqual(got, [why % rel])

    def test_a_mask_passes_and_both_units_are_reported(self):
        m = self.root / "etc/systemd/system" / check.KEXEC
        m.parent.mkdir(parents=True, exist_ok=True)
        m.symlink_to("/dev/null")
        write(self.root, self.SYSTEM + check.KEXEC, self.DEBIAN)
        self.assertEqual(check.ram_kept_violations(self.root), [])
        m.unlink()
        write(self.root, self.SYSTEM + check.SOFT_REBOOT, self.DEBIAN)
        got = check.ram_kept_violations(self.root)
        self.assertEqual([g.split(":", 1)[0] for g in got], [self.SYSTEM + check.SOFT_REBOOT, self.SYSTEM + check.KEXEC])

    def test_a_loader_anywhere_the_box_runs_it_is_refused(self):
        for d in ("usr/sbin", "usr/bin", "usr/local/sbin", "usr/local/bin"):
            for kind in ("file", "empty", "link"):
                with self.subTest(d=d, kind=kind):
                    p = self.root / d / "kexec"
                    p.parent.mkdir(parents=True, exist_ok=True)
                    if kind == "link":
                        (self.root / "usr/lib/kexec-tools").parent.mkdir(parents=True, exist_ok=True)
                        (self.root / "usr/lib/kexec-tools").write_bytes(b"\x7fELF")
                        p.symlink_to("/usr/lib/kexec-tools")
                    else:
                        p.write_bytes(b"\x7fELF" if kind == "file" else b"")
                    got = check.kexec_loader_violations(self.root)
                    p.unlink()
                    self.assertEqual(got, ["%s/kexec: %s" % (d, self.WHY)])
        # The core's merged /usr: /sbin is a link to usr/sbin, so a loader there is the one in usr/sbin.
        (self.root / "sbin").symlink_to("usr/sbin")
        write(self.root, "sbin/kexec", "x")
        self.assertEqual(check.kexec_loader_violations(self.root), ["usr/sbin/kexec: %s" % self.WHY])
        self.assertIn("kexec_loader_violations(root)", (MK / "mkosi.finalize").read_text())

    def test_a_loader_package_is_refused_and_a_removed_one_is_not(self):
        status = check.DPKG_STATUS
        stanza = "Package: %s\nStatus: install ok %s\nArchitecture: amd64\nVersion: 1\n"
        for pkg in ("kexec-tools", "kdump-tools"):
            for state, refused in (("installed", True), ("unpacked", True), ("half-configured", True),
                                   ("config-files", False), ("not-installed", False)):
                with self.subTest(pkg=pkg, state=state):
                    write(self.root, status, "Package: systemd\nStatus: install ok installed\n\n" + stanza % (pkg, state))
                    want = ["%s: %s is installed; %s" % (status, pkg, self.WHY)] if refused else []
                    self.assertEqual(check.kexec_loader_violations(self.root), want)
        write(self.root, status, stanza % ("kexec-tools-doc", "installed"))
        self.assertEqual(check.kexec_loader_violations(self.root), [])

    def test_an_unreadable_status_is_refused(self):
        (self.root / check.DPKG_STATUS).parent.mkdir(parents=True)
        (self.root / check.DPKG_STATUS).symlink_to("/proc/self/environ")
        got = check.kexec_loader_violations(self.root)
        self.assertEqual(len(got), 1, got)
        self.assertTrue(got[0].startswith(check.DPKG_STATUS + ": unreadable ("), got)
        self.assertTrue(got[0].endswith(self.WHY), got)


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
        alone = " (set a valid one or remove that line)"  # UX on #6086: no value before it to keep
        for rel, text, want in (
                (self.DROPIN, None, "journald Storage is not set (auto); must be persistent "
                                    "(usr/lib/systemd/journald.conf.d/50-agentos-persist.conf is missing or masked)"),
                (zz, "[Journal]\nStorage=volatile\n", zz + ": journald Storage is volatile" + must),
                (zz, "[Journal]\nStorage=auto\n", zz + ": journald Storage is auto" + must),
                (zz, "[Journal]\nStorage=\n", zz + ": journald Storage= is a value journald ignores" + ignored),
                (zz, "[Journal]\nStorage=Persistent\n", zz + ": journald Storage=Persistent is a value journald ignores"
                 + ignored),
                (self.DROPIN, "[Journal]\nStorage=none\n", self.DROPIN + ": journald Storage is none" + must),
                (lib, "[Journal]\nMaxLevelStore=notice\n", lib + ": journald MaxLevelStore is notice" + level),
                (lib, "[Journal]\nMaxLevelStore=5\n", lib + ": journald MaxLevelStore is 5" + level),
                (lib, "[Journal]\nMaxLevelStore=x\n", lib + ": journald MaxLevelStore=x is a value journald ignores"
                 + alone),
                (lib, "[Journal]\nMaxLevelStore=8\n", lib + ": journald MaxLevelStore=8 is a value journald ignores"
                 + alone),
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

    def journald(self):
        return [v for v in check.violations(self.root) if "journal" in v]

    def test_the_messages_point_at_the_fix(self):
        # UX on #6086 (items 3 and 4), whole messages: an empty same-named file in /etc masks the shipped
        # drop-in, and the shipped drop-in with an invalid Storage= is there but sets nothing.
        write(self.root, "etc/systemd/journald.conf.d/50-agentos-persist.conf", "")
        self.assertEqual(self.journald(), ["journald Storage is not set (auto); must be persistent "
                                           "(usr/lib/systemd/journald.conf.d/50-agentos-persist.conf is missing or masked)"])
        (self.root / "etc/systemd/journald.conf.d/50-agentos-persist.conf").unlink()
        write(self.root, self.DROPIN, "[Journal]\nStorage=bogus\n")
        self.assertEqual(self.journald(), [
            self.DROPIN + ": journald Storage=bogus is a value journald ignores (set a valid one or remove that line)",
            "journald has no valid Storage= in the chain, so it is auto; must be persistent"])

    def test_the_tree_check_keeps_journald_defaults(self):
        # #6095 (Potency on #6086): no setting that deletes or drops stored entries early.
        zz = "etc/systemd/journald.conf.d/zz.conf"
        for key in check.JOURNAL_DEFAULTS:
            with self.subTest(key=key):
                write(self.root, zz, "[Journal]\n%s=1\n" % key)
                self.assertEqual(self.journald(), ["%s: journald %s=1; the image keeps journald's default, so no "
                                                   "entry goes early (remove that line)" % (zz, key)])
        self.assertEqual(sorted(check.JOURNAL_DEFAULTS), sorted(
            ("SystemMaxUse", "SystemKeepFree", "SystemMaxFileSize", "SystemMaxFiles", "MaxRetentionSec",
             "RateLimitIntervalSec", "RateLimitInterval", "RateLimitBurst")))

    def test_the_tree_check_holds_the_flush(self):
        # #6095 (R1): until systemd-journal-flush.service runs, journald writes to /run only.
        unit, link = "usr/lib/systemd/system/systemd-journal-flush.service", \
            self.root / "usr/lib/systemd/system/sysinit.target.wants/systemd-journal-flush.service"
        why = "journald keeps the journal in /run until it runs, so a reboot loses it"
        masked = "systemd-journal-flush.service: missing or masked; " + why
        self.assertEqual(self.journald(), [])
        # L3 and Security on #6130: a mask, an empty file or a whole copy in any other unit directory replaces
        # Debian's unit, so it is refused, whatever it holds.
        for d in ("etc/systemd/system.control", "etc/systemd/system", "etc/systemd/system.attached",
                  "usr/local/lib/systemd/system"):
            other = self.root / d / "systemd-journal-flush.service"
            replaced = ("%s/systemd-journal-flush.service: replaces %s; the tree check does not model a change to "
                        "it (remove it)" % (d, unit))
            for body in (None, "", "[Unit]\nDescription=x\n[Service]\nType=oneshot\nExecStart=/bin/true\n",
                         (self.root / unit).read_text()):
                with self.subTest(d=d, body=body):
                    other.parent.mkdir(parents=True, exist_ok=True)
                    if body is None:
                        other.symlink_to("/dev/null")
                    else:
                        write(self.root, str(other.relative_to(self.root)), body)
                    self.assertIn(replaced, self.journald())
                    other.unlink()
        # Debian's own file: every line as Debian's systemd 257.13 ships it (Security on #6130).
        saved = (self.root / unit).read_text()
        self.assertEqual(saved, flush_unit())
        changed = "%s: not Debian systemd 257.13's unit (first difference: %%s); the tree check does not model a " \
            "change to it (restore it, or after a Debian systemd update read the new unit into JOURNAL_FLUSH_LINES)" % unit
        for body, first in (
                ("", None),
                (flush_unit((("Unit", "ConditionPathExists", "/nonexistent"),)), ("Unit", "ConditionPathExists", "/nonexistent")),
                (flush_unit((("Service", "ExecStartPre", "/bin/false"),)), ("Service", "ExecStartPre", "/bin/false")),
                (flush_unit((("Service", "ExecStart", "/bin/true"),)), ("Service", "ExecStart", "/bin/true")),
                (saved.replace("ExecStart=journalctl --flush", "ExecStart=/bin/true"), ("Service", "ExecStart", "/bin/true")),
                (saved.replace("TimeoutSec=90s\n", ""), ("Service", "TimeoutSec", "90s"))):
            with self.subTest(body=body):
                write(self.root, unit, body)
                self.assertIn(masked if first is None else changed % (first,), self.journald())
        write(self.root, unit, saved)
        # An alias's drop-ins apply to the unit too, so the alias is refused.
        alias = self.root / "usr/lib/systemd/system/foo.service"
        alias.symlink_to("systemd-journal-flush.service")
        self.assertIn("usr/lib/systemd/system/foo.service: an alias of systemd-journal-flush.service; the tree "
                      "check does not model unit aliases", self.journald())
        alias.unlink()
        self.assertEqual(self.journald(), [])
        saved = (self.root / unit).read_text()
        (self.root / unit).unlink()
        self.assertIn(masked, self.journald())  # and #5167 refuses the link it leaves dangling
        write(self.root, unit, saved)
        link.unlink()
        self.assertEqual(self.journald(), ["systemd-journal-flush.service: not in sysinit.target.wants; " + why])
        link.symlink_to("../systemd-journal-flush.service")
        # Security on #6128: every directory whose drop-ins systemd applies to the unit, prefixes and service.d too.
        for d in ("systemd-journal-flush.service.d", "systemd-journal-.service.d", "systemd-.service.d", "service.d"):
            with self.subTest(d=d):
                dropin = "etc/systemd/system/%s/x.conf" % d
                write(self.root, dropin, "[Service]\nExecStart=\nExecStart=/bin/true\n")
                self.assertIn(dropin + ": a drop-in for systemd-journal-flush.service; the tree check "
                              "does not model a change to it (remove it)", self.journald())
                (self.root / dropin).unlink()


class ExactFormsTest(unittest.TestCase):
    """MOR-wipe-journal-fu2 (#6158): two tree checks the L3 reviews of #6130 found read a value in a form
    systemd may not read as written, or held one by no test."""
    # REQ: HW-8

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.n = 0

    def files(self, *texts):
        out = []
        for t in texts:
            self.n += 1
            write(self.root, "u/%d.conf" % self.n, t)
            out.append(check.Conf(str(self.root), "u/%d.conf" % self.n))
        return out

    def test_a_path_unit_skips_a_first_unit_systemd_ignores(self):
        # config_parse_trigger_unit (257): a value with no unit type is ignored, so the next one is the unit the
        # path starts. Both ways: a keeper unit after it passes, any other unit after it is refused.
        path, enroll = "agentos-keeper-enroll.path", "agentos-keeper-enroll.service"
        watch = "PathExists=/run/agentos-setup/x\n"
        for first in ("", "agentos-x", "agentos-keeper-enroll"):
            with self.subTest(first=first):
                got = check.keeper_path_violations(path, self.files(
                    "[Path]\nUnit=%s\n%s" % (first, watch), "[Path]\nUnit=%s\n" % enroll))
                self.assertEqual(got, [])
                got = check.keeper_path_violations(path, self.files(
                    "[Path]\nUnit=%s\n%s" % (first, watch), "[Path]\nUnit=agentos-x.service\n"))
                self.assertEqual(got, [path + ": starts agentos-x.service, not one of the keeper's units (D-154)"])

    def test_default_dependencies_take_only_their_exact_forms(self):
        # config_parse_bool ignores a value it cannot parse and keeps the one before it, so "no" then "x" is no.
        for texts, early in ((("[Unit]\nDefaultDependencies=no\n",), True),
                             (("[Unit]\nDefaultDependencies=yes\n", "[Unit]\nDefaultDependencies=no\n"), True),
                             (("[Unit]\nDefaultDependencies=no\n", "[Unit]\nDefaultDependencies=yes\n"), False),
                             (("[Unit]\nDescription=x\n",), False),
                             (("[Unit]\nDefaultDependencies=no\nAfter=basic.target\n",), False)):
            with self.subTest(texts=texts):
                self.assertIs(check.starts_early(self.files(*texts)), early)
        for later in ("x", "", "false", "No", "0"):
            with self.subTest(later=later):
                files = self.files("[Unit]\nDefaultDependencies=no\n", "[Unit]\nDefaultDependencies=%s\n" % later)
                with self.assertRaisesRegex(ValueError, r"^DefaultDependencies=%s in u/%d\.conf is a form the tree "
                                            r"check does not read \(use yes or no\)$" % (re.escape(later), self.n)):
                    check.starts_early(files)
                # The service check names the line, read through the tree check's refusal of what it cannot read.
                with self.assertRaises(ValueError):
                    check.bus_unit_violations("agentos-x.service", files + self.files(
                        "[Service]\nInaccessiblePaths=-/run/dbus\n"))


if __name__ == "__main__":
    unittest.main()
