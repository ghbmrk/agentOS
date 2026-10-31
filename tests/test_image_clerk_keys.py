"""KEYS-route-by-cgroup (#4210, from the #4166 step-back): mkosi.finalize's clerk_key_violations.

The kernel hands each clerk key only to that entry's own keeper unit (broker/cmd/agentos-kernel
clerkCgroup), so a key's route does not rest on reading the kernel's command line. The tree check pins
that line instead of parsing it, keeps every socket the service manager opens away from a keyed clerk,
keeps each clerk's user its own, and holds the home-only clerks to the home ranges, each read with every
drop-in (#4212 L3 6540162186, Security 6540126812). Each refusal is a mutant of the shipped tree."""
# REQ: CLK-1, NET-2
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import check, write  # noqa: E402
import test_image_keeper as keeper  # noqa: E402
from test_image import exec_args  # noqa: E402
from test_image_noexec import SYSTEM  # noqa: E402

HOMEKIT = "agentos-keeper-homekit.service"
CAMERA = "agentos-keeper-camera.service"
MAIL = "agentos-keeper-mail.service"


class ClerkKeyTreeTest(unittest.TestCase):
    """clerk_key_violations on a tree holding the image's own units (KeeperTreeTest's)."""

    setUp = keeper.KeeperTreeTest.setUp
    unit = keeper.KeeperTreeTest.unit
    edit = keeper.KeeperTreeTest.edit
    add = keeper.KeeperTreeTest.add

    def v(self):
        return check.clerk_key_violations(self.root)

    def dropin(self, unit, text, name="99-x.conf"):
        write(self.root, SYSTEM + unit + ".d/" + name, text)

    # REQ: CLK-1
    def test_the_image_passes_and_the_pin_is_the_shipped_line(self):
        self.assertEqual(self.v(), [])
        self.assertEqual(check.KERNEL_EXEC.split()[1:], exec_args(keeper.KERNEL))
        self.assertIn(check.KERNEL_EXEC_TEXT, keeper.KERNEL.read_bytes())
        self.assertEqual(check.KEYED_CLERKS, (MAIL, CAMERA, HOMEKIT))
        self.assertEqual(set(check.HOME_ONLY_CLERKS), {CAMERA, HOMEKIT})

    # REQ: CLK-1
    def test_any_change_to_the_kernel_s_line_is_refused(self):
        refused = ["agentos-keeper-kernel.service: ExecStart= is not the pinned kernel line (KERNEL_EXEC); the "
                   "kernel's line and every -clerk-key entry change only with it (#4210)"]
        good = self.unit("agentos-keeper-kernel.service").read_text()
        for old, new in (
                # One byte, an extra flag, another exec, an entry whose spelling systemd rewrites.
                ("-up /run/agentos-kernel/up", "-up /run/agentos-kernel/uq"),
                ("-up /run/agentos-kernel/up", "-up /run/agentos-kernel/up -clerk-key x=/k,/x.service"),
                ("-exec /usr/lib/agentos/agentos-kernel", "-exec /usr/lib/agentos/agentos-kernel2"),
                ("-exec /usr/lib/agentos/agentos-kernel --", "-exec /usr/bin/sh -- /usr/lib/agentos/agentos-kernel"),
                ("agentos-keeper-mail.service \\", "agentos-keeper-mail.servic\\x65 \\"),
                ("agentos-keeper-mail.service \\", "agentos-keeper-%N.service \\"),
                ("agentos-keeper-mail.service \\", "agentos-keeper-mail.service $X \\"),
                ("ExecStart=/usr", "ExecStart=-/usr"),
                ("-store /var/lib/agentos-store/store \\", "-store /var/lib/agentos-store/store  \\"),
        ):
            with self.subTest(new):
                self.edit("agentos-keeper-kernel.service", old, new)
                self.assertEqual(self.v(), refused)
                self.unit("agentos-keeper-kernel.service").write_text(good)
        # A drop-in that replaces the line, or adds a second ExecStart=.
        for text in ("[Service]\nExecStart=\nExecStart=" + check.KERNEL_EXEC + " -tick 2s\n",
                     "[Service]\nExecStart=/usr/lib/agentos/agentos-kernel\n"):
            with self.subTest(text):
                self.dropin("agentos-keeper-kernel.service", text)
                self.assertEqual(self.v(), refused)
        # The pin itself read back through a drop-in passes: it is what systemd reads, not how it is spelt.
        self.dropin("agentos-keeper-kernel.service", "[Service]\nExecStart=\nExecStart=" + check.KERNEL_EXEC + "\n")
        self.assertEqual(self.v(), [])

    # REQ: CLK-1, NET-2
    def test_no_socket_the_manager_opens_reaches_a_keyed_clerk(self):
        for clerk in check.KEYED_CLERKS:
            stem = clerk[:-len(".service")]
            with self.subTest(clerk):
                # In the unit and in a drop-in, which the static tests do not read.
                self.dropin(clerk, "[Service]\nSockets=x.socket\n")
                self.assertEqual(self.v(), ["%s: Sockets=x.socket; a keyed clerk is handed no socket and has no alias "
                                            "(#4210)" % clerk])
                (self.root / SYSTEM / (clerk + ".d/99-x.conf")).unlink()
                write(self.root, SYSTEM + stem + ".socket", "[Socket]\nListenStream=0.0.0.0:80\n")
                write(self.root, SYSTEM + "other.socket", "[Socket]\nListenStream=1.2.3.4:1\nService=%s\n" % clerk)
                why = "starts %s with its sockets; a keyed clerk is handed no socket, which its IP list would not filter (#4210)"
                self.assertEqual(self.v(), ["usr/lib/systemd/system/%s.socket: %s" % (stem, why % clerk),
                                            "usr/lib/systemd/system/other.socket: %s" % (why % clerk)])
                for n in (stem + ".socket", "other.socket"):
                    (self.root / SYSTEM / n).unlink()
                self.assertEqual(self.v(), [])

    # REQ: CLK-1
    def test_a_socket_unit_s_drop_in_naming_a_clerk_is_refused(self):
        write(self.root, "etc/systemd/system/later.socket", "[Socket]\nListenStream=::\n")
        write(self.root, "etc/systemd/system/later.socket.d/99-x.conf", "[Socket]\nService=%s\n" % HOMEKIT)
        self.assertEqual(self.v(), ["etc/systemd/system/later.socket: starts %s with its sockets; a keyed clerk is "
                                    "handed no socket, which its IP list would not filter (#4210)" % HOMEKIT])

    # REQ: CLK-1
    def test_an_alias_of_a_keyed_clerk_is_refused(self):
        (self.root / "etc/systemd/system").mkdir(parents=True, exist_ok=True)
        (self.root / "etc/systemd/system/hk.service").symlink_to("/usr/lib/systemd/system/" + HOMEKIT)
        self.assertEqual(self.v(), ["etc/systemd/system/hk.service: an alias of %s; the tree check does not model a "
                                    "keyed clerk's aliases (#4210)" % HOMEKIT])
        (self.root / "etc/systemd/system/hk.service").unlink()
        self.add(HOMEKIT, "Install", "Alias=hk.service")
        self.assertEqual(self.v(), ["%s: Alias=hk.service; a keyed clerk is handed no socket and has no alias (#4210)"
                                    % HOMEKIT])

    # REQ: CLK-1
    def test_a_keyed_clerk_s_user_is_its_own(self):
        other = "%s: User=agentos-homekit is %s's; no other unit runs as a keyed clerk's user (#4210)"
        # Another unit, its drop-in, a drop-in for a "-" prefix or a type, a socket unit, a linked unit file.
        for rel, text in (
                (SYSTEM + CAMERA + ".d/99-x.conf", "[Service]\nUser=agentos-homekit\n"),
                (SYSTEM + "agentos-keeper-.service.d/99-x.conf", "[Service]\nUser=agentos-homekit\n"),
                (SYSTEM + "service.d/99-x.conf", "[Service]\nUser=agentos-homekit\n"),
                ("etc/systemd/system/x.service", "[Service]\nExecStart=/usr/bin/true\nUser=agentos-homekit\n"),
                ("etc/systemd/system/x.socket", "[Socket]\nListenFIFO=/run/x\nUser=agentos-homekit\n"),
                ("opt/x.service", "[Service]\nUser=agentos-homekit\n"),
        ):
            with self.subTest(rel):
                write(self.root, rel, text)
                link = self.root / "etc/systemd/system/x.service"
                if rel.startswith("opt/"):
                    link.parent.mkdir(parents=True, exist_ok=True)
                    link.symlink_to("/" + rel)
                try:
                    # A drop-in that reaches another keyed clerk gives it a user two clerks share, refused as such.
                    got = self.v()
                    self.assertTrue(other % (rel, HOMEKIT) in got or
                                    any(" User=agentos-homekit is also " in g for g in got), got)
                finally:
                    (self.root / rel).unlink()
                    if rel.startswith("opt/"):
                        link.unlink()
                self.assertEqual(self.v(), [])
        # The clerk's own drop-in may restate it.
        self.dropin(HOMEKIT, "[Service]\nUser=agentos-homekit\n")
        self.assertEqual(self.v(), [])

    # REQ: CLK-1
    def test_a_user_that_may_be_a_clerk_s_is_refused(self):
        for value, why in (("995", "a number may be a keyed clerk's uid, which sysusers allocates at boot"),
                           ("agentos-%i", "may expand to a keyed clerk's user or a number"),
                           ("%I", "may expand to a keyed clerk's user or a number"),
                           ("${U}", "may expand to a keyed clerk's user or a number")):
            with self.subTest(value):
                rel = "etc/systemd/system/x@.service"
                write(self.root, rel, "[Service]\nUser=%s\n" % value)
                self.assertEqual(self.v(), ["%s: User=%s; %s (#4210)" % (rel, value, why) if value.isdigit()
                                            else "%s: User=%s %s (#4210)" % (rel, value, why)])
                (self.root / rel).unlink()
        # A fixed prefix no clerk's user has, root, and systemd's per-user manager pass.
        for rel, value in (("etc/systemd/system/capsule@.service", "c-%i"), ("etc/systemd/system/y.service", "0"),
                           ("etc/systemd/system/user@.service", "%i")):
            write(self.root, rel, "[Service]\nUser=%s\n" % value)
        self.assertEqual(self.v(), [])

    # REQ: CLK-1
    def test_a_keyed_clerk_runs_under_a_named_user(self):
        for line in ("User=root", "User=0", "User=", "User=%i", "DynamicUser=yes", "User=agentos-mail"):
            with self.subTest(line):
                self.dropin(HOMEKIT, "[Service]\n%s\n" % line)
                got = self.v()
                if line == "User=agentos-mail":
                    self.assertEqual(got, [
                        "%s: User=agentos-mail is also %s's; a keyed clerk's user is its own (#4210)" % (HOMEKIT, MAIL),
                        "usr/lib/systemd/system/%s.d/99-x.conf: User=agentos-mail is %s's; no other unit runs as a keyed "
                        "clerk's user (#4210)" % (HOMEKIT, MAIL)])
                else:
                    self.assertEqual(got[0], "%s: User=%s; a keyed clerk runs under a named user of its own (#4210)"
                                     % (HOMEKIT, "agentos-homekit" if line.startswith("Dynamic") else line[5:]))

    # REQ: NET-2
    def test_a_home_only_clerk_s_addresses_are_read_with_its_drop_ins(self):
        for clerk in check.HOME_ONLY_CLERKS:
            for text in ("[Service]\nIPAddressAllow=any\n", "[Service]\nIPAddressDeny=\n",
                         "[Service]\nIPAddressAllow=\nIPAddressAllow=localhost 8.8.8.8/32\n",
                         "[Service]\nIPAddressDeny=\nIPAddressDeny=8.8.8.8\n"):
                with self.subTest((clerk, text)):
                    self.dropin(clerk, text)
                    got = self.v()
                    self.assertEqual(len(got), 1, got)
                    self.assertRegex(got[0], r"^%s: IPAddressDeny=.* a home-only clerk denies any and allows the "
                                     r"home ranges alone \(NET-2, #4210\)$" % clerk)
            # Narrowing to fewer home ranges passes.
            self.dropin(clerk, "[Service]\nIPAddressAllow=\nIPAddressAllow=192.168.0.0/16\n")
            self.assertEqual(self.v(), [])
            (self.root / SYSTEM / (clerk + ".d/99-x.conf")).unlink()

    # REQ: CLK-1
    def test_what_it_cannot_read_is_refused(self):
        self.dropin(HOMEKIT, "[Service]\nUser=agentos-homekit\x00\n")
        self.assertTrue(any("never passes what it cannot read" in v for v in self.v()), self.v())

    # REQ: NET-2
    def test_an_allow_on_a_slice_above_a_home_only_clerk_is_refused(self):
        # systemd applies every parent slice's allow list, and an allow beats the unit's deny (#4264 Security 6543099224).
        for rel in ("agentos-keeper.slice.d/99-x.conf", "agentos.slice.d/99-x.conf", "-.slice.d/99-x.conf",
                    "slice.d/99-x.conf", "agentos-.slice.d/99-x.conf"):
            with self.subTest(rel):
                write(self.root, "etc/systemd/system/" + rel, "[Slice]\nIPAddressAllow=any\n")
                try:
                    got = self.v()
                    self.assertTrue(got and all("a home-only clerk's slices allow nothing (NET-2, #4210)" in g
                                                for g in got), got)
                    self.assertTrue(any(HOMEKIT in g for g in got) and any(CAMERA in g for g in got), got)
                finally:
                    (self.root / "etc/systemd/system" / rel).unlink()
        self.assertEqual(self.v(), [])
        self.assertEqual(check.parent_slices("agentos-keeper.slice"), ["-.slice", "agentos.slice", "agentos-keeper.slice"])

    # REQ: CLK-1
    def test_a_socket_whose_service_has_a_specifier_is_refused(self):
        # Service=agentos-keeper-%N.service in mail.socket would start the mail clerk (#4264 Security 6543099224).
        write(self.root, "etc/systemd/system/mail.socket", "[Socket]\nListenStream=/run/x\nService=agentos-keeper-%N.service\n")
        why = "starts %s with its sockets; a keyed clerk is handed no socket, which its IP list would not filter (#4210)"
        self.assertEqual(self.v(), ["etc/systemd/system/mail.socket: " + why % c for c in check.KEYED_CLERKS])
        # A stock template socket's specifier that can name no keeper unit passes both rules (trixie's journald).
        write(self.root, "etc/systemd/system/mail.socket", "[Socket]\nListenStream=/run/x\nAccept=yes\n"
              "Service=systemd-journald@%i.service\n")
        self.assertEqual(self.v(), [])
        self.assertEqual(check.keeper_violations(self.root), [])
        # The unlock unit's own socket rule refuses it too.
        write(self.root, "etc/systemd/system/mail.socket", "[Socket]\nListenStream=/run/x\nService=agentos-keeper-%i.service\n")
        self.assertIn("mail.socket: starts agentos-keeper-%i.service with its sockets; nothing reaches the unlock step "
                      "past descriptor 2 (#2899)", check.keeper_violations(self.root))

    # REQ: CLK-1
    def test_a_user_manager_instance_is_refused(self):
        # user@.service's %i passes as a login's manager; an instance under a number the tree starts does not
        # (#4264 L3 6543012125).
        sysdir = self.root / "etc/systemd/system"
        (sysdir / "multi-user.target.wants").mkdir(parents=True, exist_ok=True)
        (sysdir / "multi-user.target.wants/user@998.service").symlink_to("/usr/lib/systemd/system/user@.service")
        self.assertEqual(self.v(), ["etc/systemd/system/multi-user.target.wants/user@998.service: starts a per-user "
                                    "manager, whose user may be a keyed clerk's (#4210)"])
        (sysdir / "multi-user.target.wants/user@998.service").unlink()
        write(self.root, "etc/systemd/system/x.service", "[Unit]\nWants=user@998.service\n")
        self.assertEqual(self.v(), ["etc/systemd/system/x.service: Wants=user@998.service starts a per-user manager, "
                                    "whose user may be a keyed clerk's (#4210)"])
        (sysdir / "x.service").unlink()
        for name in ("agentos-homekit", "998", "%i"):
            with self.subTest(name):
                write(self.root, "etc/systemd/system/x.service", "[Unit]\nWants=user@%s.service\n" % name)
                self.assertEqual(len(self.v()), 1, self.v())
                (sysdir / "x.service").unlink()
        write(self.root, "var/lib/systemd/linger/agentos-homekit")
        self.assertEqual(self.v(), ["var/lib/systemd/linger: lingering users; logind would start a per-user manager "
                                    "under each at boot, which may be a keyed clerk's (#4210)"])
        (self.root / "var/lib/systemd/linger/agentos-homekit").unlink()
        self.assertEqual(self.v(), [])
        write(self.root, "etc/systemd/system/user@998.service", "[Service]\n")
        self.assertEqual(self.v(), ["etc/systemd/system/user@998.service: a per-user manager, whose user may be "
                                    "a keyed clerk's (#4210)"])

    def test_a_driver_entry_is_no_keeper_clerk(self):
        # The kernel sends driver-<d> to the driver's template (clerkCgroup); the keeper's list follows it.
        self.assertFalse([c for c in check.KEYED_CLERKS if "driver" in c])

    def test_the_whole_check_runs_it(self):
        self.dropin(HOMEKIT, "[Service]\nSockets=x.socket\n")
        self.assertIn("%s: Sockets=x.socket; a keyed clerk is handed no socket and has no alias (#4210)" % HOMEKIT,
                      check.violations(self.root))


if __name__ == "__main__":
    unittest.main()
