"""IMG-dbus-reach (#5818): the system bus is out of reach of every agentos unit that makes no bus call,
and dbus-daemon's start-up command line is pinned.

dbus-daemon is a long-lived process, and stock system.conf lets any local uid connect to
/run/dbus/system_bus_socket. Every agentos service but BUS_UNITS (whose `systemctl reboot` asks logind
over the bus) masks /run/dbus, so a unit compromised through its peer has no second stage through a
future bus flaw. dbus.service and dbus.socket, with every drop-in systemd would merge into them, are held
to exec.allow by hash, and their merged lines, read as systemd runs them, to one listener (dbus.socket,
--address=systemd:), which assurance/vulncheck.json's CVE-2026-128886 record rests on (#6037). Each refusal test is a mutant of the shipped
tree (or of Debian's stock units) that mkosi.finalize must refuse; its control is the tree that passes."""
# REQ: EVL-5, STO-2
import hashlib
import json
import os
import pathlib
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import MK, ROOT, check, clean_tree, write  # noqa: E402
from test_image_keeper import KEEPER_FILES, SYSUSERS  # noqa: E402
from test_image_noexec import STOCK_TMP, SYSTEM, shipped_units, stage_binaries  # noqa: E402

UNITS = MK / "mkosi.extra/usr/lib/systemd/system"
SCRIPTS = MK / "mkosi.extra/usr/lib/agentos"
# The non-root, network-facing units the brief names: each must lose the bus.
NETWORK_FACING = ("agentos-link.service", "agentos-egress.service", "agentos-keeper-mail.service",
                  "agentos-keeper-camera.service", "agentos-keeper-homekit.service",
                  "agentos-keeper-link-capture.service")
# Units whose own empty root or /run leaves /run/dbus out of view: a mask there fails the unit.
OUT_OF_VIEW = ("agentos-camdecode@.service", "agentos-imapconn@.service")
# Units with DefaultDependencies=no and no order after basic.target: they may start before dbus.socket makes
# /run/dbus. The page authority's staging and the wipe drop the default dependencies but keep that order (#6178).
EARLY = ("agentos-inbound.service", "agentos-mor.service")
LATE_NO_DEFAULTS = ("agentos-keeper-pageca.service", "agentos-keeper-wipe.service")
# #6037: the exact bytes the image ships, so exec.allow's two pins can be reviewed here: dbus.service from
# Debian's dbus_1.16.2-2_amd64.deb and dbus.socket from dbus-system-bus-common_1.16.2-2_all.deb (trixie,
# the image's snapshot; the .deb sha256s are f5c47639...e6f50f274 and 262e9ec8...4a1120a, as the archive's
# Packages index lists them). test_the_fixtures_are_the_pinned_bytes holds them to the pins.
STOCK_SERVICE = """[Unit]
Description=D-Bus System Message Bus
Documentation=man:dbus-daemon(1)
Requires=dbus.socket

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
ExecReload=/usr/bin/dbus-send --print-reply --system --type=method_call --dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig
OOMScoreAdjust=-900
User=messagebus
Group=messagebus
AmbientCapabilities=CAP_AUDIT_WRITE
"""
STOCK_SOCKET = """[Unit]
Description=D-Bus System Message Bus Socket

[Socket]
ListenStream=/run/dbus/system_bus_socket
"""
BUS_TOOLS = re.compile(r"(?<![\w-])(busctl|dbus-send|gdbus|loginctl|hostnamectl|timedatectl|localectl|networkctl|"
                       r"resolvectl|systemctl\s+(?:\S+\s+)*(?:reboot|poweroff|halt|suspend|hibernate|kexec))(?![\w-])")


def scripts_units(names):
    """The BUS_UNITS the image ships as files (the transient one has only its drop-in)."""
    return [n for n in names if (UNITS / n).is_file()]


class BusMaskTest(unittest.TestCase):
    """Every agentos service's effective InaccessiblePaths=, read from the image's own units and drop-ins."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = clean_tree(pathlib.Path(self.tmp.name))
        for rel, src in shipped_units().items():
            write(self.root, rel, src.read_text())
        for rel in KEEPER_FILES:
            write(self.root, rel, (MK / "mkosi.extra" / rel).read_text())
        write(self.root, SYSTEM + "tmp.mount", STOCK_TMP)
        write(self.root, "usr/lib/sysusers.d/agentos-setup.conf", SYSUSERS.read_text())
        stage_binaries(self.root)
        self.dirs = check.unit_dirs(str(self.root))[0]

    def v(self):
        return check.keeper_violations(self.root)

    def services(self):
        return sorted(p.name for p in (self.root / SYSTEM).iterdir()
                      if check.NOEXEC_UNITS.match(p.name) and p.is_file())

    def hidden(self, name):
        files = check.unit_with_dropins(str(self.root), self.dirs, name)
        return check.ini_paths(files, "Service", "InaccessiblePaths")

    def edit(self, rel, old, new):
        f = self.root / SYSTEM / rel
        s = f.read_text()
        self.assertIn(old, s)
        f.write_text(s.replace(old, new, 1))

    def test_every_unit_that_makes_no_bus_call_masks_the_bus(self):
        self.assertEqual(self.v(), [])
        names = self.services()
        for n in NETWORK_FACING + tuple(scripts_units(check.BUS_UNITS)) + EARLY + OUT_OF_VIEW:
            self.assertIn(n, names)
        files = {n: check.unit_with_dropins(str(self.root), self.dirs, n) for n in names}
        early = [n for n in names if check.starts_early(files[n])]
        self.assertEqual(early, list(EARLY))
        self.assertEqual([n for n in names if check.ini_last(files[n], "Unit", "DefaultDependencies") == "no"],
                         sorted(EARLY + LATE_NO_DEFAULTS))
        masked = [n for n in names if n not in check.BUS_UNITS + check.NOEXEC_EXEMPT + OUT_OF_VIEW]
        for n in masked:
            self.assertIn(check.BUS_DIR, self.hidden(n), n)
        # The keeper's reset (90-keeper.conf) and the decoder's (90-empty-run.conf) are covered: the keeper
        # units keep the bus masked, and the decoder's empty /run holds no /run/dbus.
        for n in check.KEEPER_UNITS:
            self.assertIn(n, masked)
        for n in OUT_OF_VIEW:
            files = check.unit_with_dropins(str(self.root), self.dirs, n)
            self.assertTrue(check.driver_root(n, files) or check.tmpfs_hides(files, check.BUS_DIR), n)
        # The units that keep it keep the rest of the main side's mask.
        for n in scripts_units(check.BUS_UNITS):
            self.assertNotIn(check.BUS_DIR, self.hidden(n), n)
            self.assertEqual(self.hidden(n), list(check.KEEPER_PATHS), n)

    def test_removing_the_entry_from_one_unit_is_refused(self):
        want = "agentos-link.service: InaccessiblePaths does not hold /run/dbus; a unit that makes no bus call " \
               "never sees the system bus (#5818)"
        write(self.root, SYSTEM + "agentos-link.service.d/99-x.conf",
              "[Service]\nInaccessiblePaths=\nInaccessiblePaths=%s\n" % " ".join(check.KEEPER_PATHS))
        self.assertEqual(self.v(), [want])

    def test_the_shared_entry_covers_the_main_side(self):
        self.edit("agentos-.service.d/50-main-side.conf", " /run/dbus\n", "\n")
        got = self.v()
        names = [n for n in self.services() if n not in check.BUS_UNITS + check.NOEXEC_EXEMPT + OUT_OF_VIEW
                 + check.KEEPER_UNITS + EARLY]
        self.assertEqual(got, ["%s: InaccessiblePaths does not hold /run/dbus; a unit that makes no bus call never "
                               "sees the system bus (#5818)" % n for n in names])
        self.assertIn("agentos-link.service", names)

    def test_the_keeper_reset_re_adds_it(self):
        self.edit("agentos-keeper-.service.d/90-keeper.conf", "InaccessiblePaths=/run/dbus\n", "")
        got = self.v()
        self.assertEqual(sorted(l.split(":")[0] for l in got), sorted(check.KEEPER_UNITS))
        self.assertTrue(all("does not hold /run/dbus" in l for l in got), got)

    def test_a_dash_entry_is_refused_after_sockets_target(self):
        self.edit("agentos-keeper-.service.d/90-keeper.conf", "InaccessiblePaths=/run/dbus\n",
                  "InaccessiblePaths=-/run/dbus\n")
        got = self.v()
        self.assertEqual(len(got), len(check.KEEPER_UNITS), got)
        self.assertTrue(all("InaccessiblePaths=-/run/dbus gives no mask while the directory is missing" in l
                            for l in got), got)

    def test_an_early_unit_takes_a_dash(self):
        # 226/NAMESPACE: agentos-inbound and agentos-mor start before dbus.socket makes /run/dbus.
        self.edit("agentos-inbound.service.d/90-early-bus.conf", " -/run/dbus\n", " /run/dbus\n")
        self.edit("agentos-mor.service.d/50-main-side.conf", " -/run/dbus\n", " /run/dbus\n")
        self.assertEqual(self.v(), [self.early_msg(n) for n in EARLY])

    @staticmethod
    def early_msg(n):
        return ("%s: InaccessiblePaths=/run/dbus fails the unit (226/NAMESPACE): with DefaultDependencies=no it may "
                "start before dbus.socket makes the directory, so the entry takes \"-\" (#5818)" % n)

    def test_early_is_read_from_the_unit(self):
        # #6037: any unit that drops the default dependencies may start before sockets.target, so it takes
        # the "-", whatever list it is on; told so, not told to drop it.
        for word in ("no", "false", "0", "off"):
            with self.subTest(word):
                f = write(self.root, SYSTEM + "agentos-link.service.d/99-x.conf", "[Unit]\nDefaultDependencies=%s\n"
                          % word)
                got = self.v()
                f.unlink()
                self.assertEqual(got, [self.early_msg("agentos-link.service")])
        # Control: the same unit with the "-" passes; and back to default dependencies, an early unit's "-"
        # is refused.
        write(self.root, SYSTEM + "agentos-link.service.d/99-x.conf", "[Unit]\nDefaultDependencies=no\n"
              "[Service]\nInaccessiblePaths=\nInaccessiblePaths=%s -/run/dbus\n"
              % " ".join(check.KEEPER_PATHS))
        self.assertEqual(self.v(), [])
        write(self.root, SYSTEM + "agentos-inbound.service.d/99-x.conf", "[Unit]\nDefaultDependencies=yes\n")
        self.assertEqual(self.v(), ["agentos-inbound.service: InaccessiblePaths=-/run/dbus gives no mask while the "
                                    "directory is missing; with default dependencies the unit starts after "
                                    "dbus.socket makes it (#5818)"])

    def test_an_order_after_basic_target_is_not_early(self):
        # #6178: a unit that drops the default dependencies but is ordered after basic.target or sockets.target
        # starts after dbus.socket, so its entry takes no "-"; without that order it takes one.
        for after in ("basic.target", "sockets.target", "x.service sockets.target"):
            with self.subTest(after):
                f = write(self.root, SYSTEM + "agentos-link.service.d/99-x.conf",
                          "[Unit]\nDefaultDependencies=no\nAfter=%s\n" % after)
                got = self.v()
                f.unlink()
                self.assertEqual(got, [])
        for name in LATE_NO_DEFAULTS:
            with self.subTest(name):
                f = self.root / SYSTEM / name
                saved = f.read_text()
                self.assertIn(" basic.target ", saved)
                f.write_text(saved.replace(" basic.target ", " ", 1))
                got = self.v()
                f.write_text(saved)
                self.assertEqual(got, [self.early_msg(name)])

    def test_a_bus_unit_keeps_the_rest_of_the_mask(self):
        # #6037: the transient kernel-reboot unit has only drop-ins; its keeper list is weighed like the
        # two unit files'.
        conf = "agentos-kernel-reboot.service.d/90-bus.conf"
        rel = SYSTEM + conf
        write(self.root, rel, (UNITS / conf).read_text())
        self.assertEqual(self.v(), [])
        stock = (self.root / rel).read_text()
        want = " ".join(check.KEEPER_PATHS)
        for text, got in ((stock.replace(" /var/lib/agentos-homekit", ""), want.replace(" /var/lib/agentos-homekit", "")),
                          (stock.replace("/var/lib/agentos-homekit", "/var/lib/agentos-homekit /run/dbus"),
                           " ".join(sorted(check.KEEPER_PATHS + ("/run/dbus",)))),
                          ("", " ".join(sorted(check.KEEPER_PATHS + ("/run/dbus",))))):
            with self.subTest(text):
                (self.root / rel).write_text(text)
                self.assertEqual(self.v(), ["agentos-kernel-reboot.service: InaccessiblePaths=%s; a unit that keeps "
                                            "the bus masks the rest of the keeper's state, %s (#6037)"
                                            % (" ".join(sorted(got.split())), want)])
        (self.root / rel).write_text(stock)
        self.edit("agentos-reboot.service.d/90-bus.conf", "/var/lib/agentos-homekit", "/var/lib/agentos-homekit /tmp")
        self.assertEqual(len(self.v()), 1)
        self.assertTrue(self.v()[0].startswith("agentos-reboot.service: InaccessiblePaths="), self.v())

    def test_the_bus_units_are_the_ones_that_call_logind(self):
        # #5818: a unit keeps the bus only if its commands call a tool that goes over it. Root's other
        # systemctl verbs (show, is-active, try-restart) reach PID 1 on /run/systemd/private instead.
        scripts = {"agentos-fallback.service": "fallback", "agentos-reboot.service": "reboot-weekly"}
        transient = "agentos-kernel-reboot.service"
        self.assertEqual(sorted(list(scripts) + [transient]), sorted(check.BUS_UNITS))
        # The kernel's ExecStopPost= reaches PID 1 (systemd-run as root); the reboot runs in the transient
        # unit, which a drop-in of its name lifts the mask for.
        self.assertIn("--unit=%s " % transient[:-len(".service")], check.KERNEL_REBOOT)
        self.assertTrue((UNITS / (transient + ".d/90-bus.conf")).is_file())
        for unit, script in scripts.items():
            self.assertRegex((SCRIPTS / script).read_text(), r"systemctl reboot")
            self.assertIn("/usr/lib/agentos/" + script, (UNITS / unit).read_text())
        for n in self.services():
            if n in check.BUS_UNITS:
                continue
            text = (self.root / SYSTEM / n).read_text().replace(check.KERNEL_REBOOT, "")
            self.assertIsNone(BUS_TOOLS.search(text), n)
            for prog in re.findall(r"/usr/lib/agentos/([\w.-]+)", text):
                f = SCRIPTS / prog
                if f.is_file() and f.read_bytes()[:2] == b"#!":
                    self.assertIsNone(BUS_TOOLS.search(f.read_text()), (n, prog))


class BusDaemonTest(unittest.TestCase):
    """dbus.service and dbus.socket as Debian ships them pass; any drop-in, override or second listener fails."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        write(self.root, SYSTEM + "dbus.service", STOCK_SERVICE)
        write(self.root, SYSTEM + "dbus.socket", STOCK_SOCKET)
        self.allowed = self.reviewed()

    def reviewed(self):
        return {(rel, value) for rel, value, err in check.exec_entries(str(self.root)) if value is not None}

    def v(self):
        return check.exec_allow_violations(str(self.root), self.allowed) + check.bus_daemon_violations(str(self.root))

    def test_the_stock_units_pass(self):
        self.assertEqual(sorted(r for r, _ in self.allowed), [SYSTEM + "dbus.service", SYSTEM + "dbus.socket"])
        self.assertEqual(self.v(), [])

    def test_a_drop_in_fails_the_build(self):
        for rel in (SYSTEM + "dbus.service.d/50-x.conf", "etc/systemd/system/dbus.service.d/50-x.conf",
                    "usr/local/lib/systemd/system/dbus.service.d/50-x.conf", SYSTEM + "service.d/50-x.conf",
                    SYSTEM + "dbus.socket.d/50-x.conf", SYSTEM + "socket.d/50-x.conf"):
            with self.subTest(rel):
                f = write(self.root, rel, "[Service]\nNice=1\n")
                got = self.v()
                f.unlink()
                self.assertEqual(len(got), 1, got)
                self.assertTrue(got[0].startswith(rel + ": not on the boot-code allowlist"), got)

    def test_a_changed_or_overridden_unit_fails_the_build(self):
        f = self.root / SYSTEM / "dbus.service"
        f.write_text(STOCK_SERVICE.replace("--syslog-only", "--syslog"))
        got = self.v()
        self.assertEqual(len(got), 1, got)
        self.assertTrue(got[0].startswith(SYSTEM + "dbus.service: not on the boot-code allowlist"), got)
        f.write_text(STOCK_SERVICE)
        write(self.root, "etc/systemd/system/dbus.service", STOCK_SERVICE)
        got = self.v()
        self.assertEqual(len(got), 1, got)
        self.assertTrue(got[0].startswith("etc/systemd/system/dbus.service: not on the boot-code allowlist"), got)

    def test_a_reviewed_hash_cannot_carry_another_listener(self):
        # Even a drop-in someone listed on exec.allow cannot move the bus off dbus.socket.
        for name, text in (
                ("dbus.service", "[Service]\nExecStart=\nExecStart=/usr/bin/dbus-daemon --system "
                                 "--address=nonce-tcp:host=127.0.0.1 --nofork\n"),
                ("dbus.service", "[Service]\nExecStart=\nExecStart=/usr/bin/dbus-daemon --system --address=systemd: "
                                 "--config-file=/tmp/x.conf\n"),
                ("dbus.service", "[Service]\nExecStart=\nExecStart=/usr/bin/dbus-daemon --system --address=systemd: "
                                 "--address=tcp:host=0.0.0.0\n"),
                ("dbus.service", "[Service]\nExecStart=\nExecStart=/usr/bin/dbus-broker-launch --scope system\n"),
                # #6037: what systemd rewrites or splits.
                ("dbus.service", "[Service]\nExecStart=\nExecStart=/usr/bin/dbus-daemon --system --address=systemd: "
                                 "--nofork $EXTRA\n"),
                ("dbus.service", "[Service]\nExecStart=\nExecStart=/usr/bin/dbus-daemon --system --address=systemd: "
                                 "--nofork ${EXTRA}\n"),
                ("dbus.service", "[Service]\nExecStart=\nExecStart=/usr/bin/dbus-daemon --system --address=systemd: "
                                 "--nofork %E\n"),
                ("dbus.service", "[Service]\nExecStart=\nExecStart=/usr/bin/dbus-daemon --system --address=systemd: "
                                 "\"--nofork --address=tcp:host=0.0.0.0\"\n"),
                ("dbus.service", "[Service]\nExecStart=\nExecStart=/usr/bin/dbus-daemon --system --address=systemd: "
                                 "--nofork\\x20--address=tcp:host=0.0.0.0\n"),
                ("dbus.service", "[Service]\nExecStart=\nExecStart=+/usr/bin/dbus-daemon --system --address=systemd: "
                                 "--nofork\n"),
                ("dbus.service", "[Service]\nExecStart=\nExecStart=/tmp/dbus-daemon --system --address=systemd: "
                                 "--nofork\n"),
                ("dbus.service", "[Service]\nExecReload=\nExecReload=/tmp/dbus-send\n"),
                ("dbus.service", "[Service]\nExecReload=\nExecReload=/usr/bin/dbus-send --system ; "
                                 "/usr/bin/socat TCP-LISTEN:1 -\n"),
                ("dbus.service", "[Service]\nExecReload=\nExecReload=-/usr/bin/dbus-send --system\n"),
                ("dbus.service", "[Service]\nExecSearchPath=/tmp\n"),
                ("dbus.service", "[Service]\nSockets=dbus.socket evil.socket\n"),
                ("dbus.socket", "[Socket]\nService=evil.service\n"),
                ("dbus.service", "[Service]\nExecStart=\n"),
                ("dbus.service", "[Service]\nExecStartPost=/usr/bin/dbus-daemon --system "
                                 "--address=nonce-tcp:host=127.0.0.1 --fork\n"),
                ("dbus.service", "[Service]\nExecStartPre=/bin/sh -c 'true'\n"),
                ("dbus.service", "[Service]\nExecStopPost=/usr/bin/socat TCP-LISTEN:1 -\n"),
                ("dbus.service", "[Service]\nExecReload=\nExecReload=/usr/bin/dbus-daemon --system\n"),
                ("dbus.service", "[Service]\nExecStart=/usr/bin/dbus-daemon --system --address=systemd:\n"),
                ("dbus.socket", "[Socket]\nExecStartPre=/usr/bin/true\n"),
                ("dbus.socket", "[Socket]\nListenStream=127.0.0.1:5555\n"),
                ("dbus.socket", "[Socket]\nListenStream=\nListenStream=/run/dbus/other\n"),
                ("dbus.socket", "[Socket]\nListenSequentialPacket=/run/x\n")):
            with self.subTest(text):
                f = write(self.root, SYSTEM + name + ".d/50-x.conf", text)
                self.allowed = self.reviewed()
                got = self.v()
                f.unlink()
                self.assertEqual(len(got), 1, got)
                self.assertTrue(got[0].startswith(name + ": "), got)
                self.assertRegex(got[0], r"\(#(5818|6037)\)$")

    def test_no_other_unit_reaches_the_bus(self):
        # #6037: a second socket that starts dbus.service is a second listener, and a second service that
        # takes dbus.socket holds the bus's own socket.
        for rel, text in (
                ("foo.socket", "[Socket]\nListenStream=127.0.0.1:5555\nService=dbus.service\n"),
                ("foo.socket", "[Socket]\nListenStream=127.0.0.1:5555\nService=%p.service\n"),
                ("dbus@.socket", "[Socket]\nListenStream=127.0.0.1:5555\nService=dbus${X}.service\n"),
                ("socket.d/50-x.conf", "[Socket]\nService=dbus.service\n"),
                ("foo-.socket.d/50-x.conf", "[Socket]\nService=dbus.service\n"),
                # #6109: another unit's drop-in that names the bus unit is not the bus unit's own, so the
                # exemption is the exact dbus.socket.d / dbus.service.d directory, not a "dbus" prefix.
                ("dbusx.socket.d/50-x.conf", "[Socket]\nService=dbus.service\n"),
                ("dbusx.service.d/50-x.conf", "[Service]\nSockets=dbus.socket\n"),
                ("foo.service", "[Service]\nExecStart=/usr/bin/true\nSockets=dbus.socket\n"),
                ("service.d/50-x.conf", "[Service]\nSockets=foo.socket %N.socket\n")):
            with self.subTest(rel):
                f = write(self.root, SYSTEM + rel, text)
                got = check.bus_daemon_violations(str(self.root))
                f.unlink()
                # A generic service.d drop-in is dbus.service's too, so its Sockets= is refused there as well.
                self.assertEqual(len(got), 2 if rel.startswith("service.d/") else 1, got)
                self.assertTrue(got[-1].startswith(SYSTEM + rel + ": ["), got)
                self.assertIn("is the system bus's", got[-1])
        # Control: a socket that starts its own service, and a service that takes its own socket, pass.
        write(self.root, SYSTEM + "foo.socket", "[Socket]\nListenStream=127.0.0.1:5555\nService=foo.service\n")
        write(self.root, SYSTEM + "foo.service", "[Service]\nExecStart=/usr/bin/true\nSockets=foo.socket\n")
        self.assertEqual(check.bus_daemon_violations(str(self.root)), [])

    def test_the_fixtures_are_the_pinned_bytes(self):
        # #6037: exec.allow pins the bytes the image ships; these fixtures are those bytes, so the reviewed
        # unit text is here in the repository.
        pins = dict(check.exec_allowed())
        for name, text in (("dbus.service", STOCK_SERVICE), ("dbus.socket", STOCK_SOCKET)):
            self.assertEqual(pins[SYSTEM + name], "sha256:" + hashlib.sha256(text.encode()).hexdigest(), name)

    def test_an_alias_is_refused(self):
        os.symlink("dbus.service", str(self.root / SYSTEM / "messagebus.service"))
        got = check.exec_allow_violations(str(self.root), self.reviewed())
        self.assertEqual(len(got), 1, got)
        self.assertIn("merged files are unknown", got[0])

    def test_the_record_argues_from_the_pinned_units(self):
        rec = {r["id"]: r for r in json.loads((ROOT / "assurance/vulncheck.json").read_text())["accepted"]}
        why = rec["DEBIAN-CVE-2026-128886"]["why"]
        for word in (check.BUS_ADDRESS, "ListenStream=" + check.BUS_SOCKET, "bus_daemon_violations", "exec.allow"):
            self.assertIn(word, why)
        self.assertLess(why.index(check.BUS_ADDRESS), why.index("As a fallback only, the image's system.conf"))

    def test_the_image_pins_both_units(self):
        allowed = {r for r, _ in check.exec_allowed()}
        for n in check.BUS_DAEMON_UNITS:
            self.assertIn(SYSTEM + n, allowed)
        self.assertFalse([r for r in allowed if re.match(r"(etc|usr/local/lib|usr/lib)/systemd/system/"
                                                         r"(dbus\.(service|socket)|service|socket)\.d/", r)])


if __name__ == "__main__":
    unittest.main()
