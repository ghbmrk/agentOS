"""STO-2c slice ii-b (#2905): the keeper's units under image/, and mkosi.finalize's checks on them.

The keeper (D-154) is enrollment (agentos-keeper-enroll.service) and the unlock step that becomes the
kernel (agentos-keeper-kernel.service), in agentos-keeper.slice. Every other agentos unit is main side:
it cannot see the keeper's state, and only the keeper's units (and the old core's vault process until
it is deleted) reach the TPM. The unlock unit gets no descriptor past 2 and no privilege past its drop
(#2899), and its restarts are bounded so a crash loop cannot wear the TPM counter (#2897); a kernel
that came up and then failed reboots the box, at most twice an hour (#2998). Each test
of a refusal is a mutant of the shipped tree that mkosi.finalize must refuse. CI's boot test enrolls
on the first boot with synthetic factors (image/ci_boot.sh, agentos-keeper lines)."""
# REQ: STO-2, STO-1, HW-5a, CLK-1, UPD-10
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import MK, ROOT, check, clean_tree, exec_args, arg, ini, write  # noqa: E402
from test_image_noexec import STOCK_TMP, SYSTEM, shipped_units  # noqa: E402

UNITS = MK / "mkosi.extra/usr/lib/systemd/system"
# The keeper's files beside its units, which shipped_units (agentos* regular files) leaves out.
KEEPER_FILES = tuple("usr/lib/systemd/system/" + n for n in (
    "agentos-keeper.slice", "agentos-.service.d/50-main-side.conf", "agentos-keeper-.service.d/90-keeper.conf"))
ENROLL = UNITS / "agentos-keeper-enroll.service"
KERNEL = UNITS / "agentos-keeper-kernel.service"
SYSUSERS = MK / "mkosi.extra/usr/lib/sysusers.d/agentos-setup.conf"
WITH_UIDS = MK / "mkosi.extra/usr/lib/agentos/with-uids"
TMPFILES = MK / "mkosi.extra/usr/lib/tmpfiles.d/agentos.conf"
BOOT_REPORT = MK / "mkosi.extra/usr/lib/agentos/boot-report"
CI_BOOT = ROOT / "image/ci_boot.sh"


def exec_lines(path, key):
    # Every KEY= line of PATH, in order: ini() keeps only the last of a repeated key.
    return re.findall(r"(?m)^%s=(.*)$" % key, path.read_text())


def go_flags(cmd):
    """The flag names cmd's main.go defines (fs.StringVar(&x, "name", ...) and the like)."""
    src = (ROOT / "broker/cmd" / cmd / "main.go").read_text()
    return set(re.findall(r'fs\.(?:String|Bool|Int|Duration|Uint)?(?:Var)?\((?:[^,]+, )?"([a-z-]+)"', src))


class KeeperTreeTest(unittest.TestCase):
    """mkosi.finalize's keeper check on a tree holding the image's own units."""

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

    def v(self):
        return check.keeper_violations(self.root)

    def unit(self, name):
        return self.root / SYSTEM / name

    def edit(self, name, old, new):
        f = self.unit(name)
        s = f.read_text()
        self.assertIn(old, s)
        f.write_text(s.replace(old, new, 1))

    def add(self, name, section, line):
        self.edit(name, "[%s]\n" % section, "[%s]\n%s\n" % (section, line))

    def test_the_image_passes(self):
        self.assertEqual(self.v(), [])
        self.assertEqual(check.violations(self.root), [])

    def test_the_keeper_is_listed_once(self):
        self.assertEqual(check.KEEPER_UNITS, ("agentos-keeper-enroll.service", "agentos-keeper-kernel.service"))
        self.assertEqual(check.UNLOCK_UNITS, ("agentos-keeper-kernel.service",))
        self.assertEqual(check.TPM_UNITS, check.KEEPER_UNITS + ("agentos-egress.service",))
        for rel in KEEPER_FILES + tuple(SYSTEM + n for n in check.KEEPER_UNITS):
            self.assertTrue((MK / "mkosi.extra" / rel).is_file(), rel)
        drop = ini(UNITS / "agentos-keeper-.service.d/90-keeper.conf")["Service"]
        self.assertEqual(drop["Slice"], check.KEEPER_SLICE)
        self.assertEqual(drop["InaccessiblePaths"], "")
        main = ini(UNITS / "agentos-.service.d/50-main-side.conf")["Service"]["InaccessiblePaths"].split()
        self.assertEqual(main, list(check.KEEPER_PATHS))
        # The main side's mask sorts before the keeper's reset, so the reset wins for the keeper only.
        self.assertLess("50-main-side.conf", "90-keeper.conf")

    # The keeper boundary (D-154).

    def test_every_main_side_unit_is_masked_from_the_keeper(self):
        names = sorted(n for n in (p.name for p in (self.root / SYSTEM).iterdir())
                       if check.NOEXEC_UNITS.match(n) and n not in check.KEEPER_UNITS + check.NOEXEC_EXEMPT)
        self.assertIn("agentos-localui.service", names)
        self.assertIn("agentos-ap-exempt@.service", names)
        (self.root / SYSTEM / "agentos-.service.d/50-main-side.conf").unlink()
        want = ["%s: InaccessiblePaths does not hold %s; the main side never sees the keeper's state (D-154)" % (n, p)
                for n in names for p in check.KEEPER_PATHS]
        self.assertEqual(self.v(), want)

    def test_a_unit_that_lifts_the_mask_is_refused(self):
        write(self.root, SYSTEM + "agentos-localui.service.d/99-x.conf", "[Service]\nInaccessiblePaths=\n")
        self.assertEqual(len(self.v()), len(check.KEEPER_PATHS))
        self.assertTrue(all(l.startswith("agentos-localui.service: InaccessiblePaths does not hold") for l in self.v()))

    def test_a_mount_from_the_keeper_s_state_is_refused(self):
        for key, w in (("BindReadOnlyPaths", "/var/lib/agentos-kernel/log:/tmp/log"),
                       ("BindPaths", "-/var/lib/agentos-store"), ("ReadWritePaths", "/var/lib/agentos-kernel"),
                       ("BindReadOnlyPaths", "/var/lib/agentos/../agentos-store:/x")):
            with self.subTest(key):
                good = self.unit("agentos-modem.service").read_text()
                self.add("agentos-modem.service", "Service", "%s=%s" % (key, w))
                self.assertIn("agentos-modem.service: %s=%s reaches the keeper's state (D-154)" % (key, w), self.v())
                self.unit("agentos-modem.service").write_text(good)
        # Each assignment adds to the list: a later one does not hide an earlier one (#2981).
        write(self.root, SYSTEM + "agentos-modem.service.d/99-x.conf",
              "[Service]\nBindPaths=/var/lib/agentos-store:/x\nBindPaths=/srv/y\n")
        self.assertEqual(self.v(), ["agentos-modem.service: BindPaths=/var/lib/agentos-store:/x reaches the keeper's "
                                    "state (D-154)"])

    def test_the_mask_holds_from_the_first_boot(self):
        # #2981 (Security 1): a "-" entry gives no mask to a unit started before the path exists, so
        # the image makes each keeper path at boot, before any main-side unit, and the mask has no "-".
        drop = UNITS / "agentos-.service.d/50-main-side.conf"
        self.assertEqual(ini(drop)["Service"]["InaccessiblePaths"].split(), list(check.KEEPER_PATHS))
        self.assertIn("systemd-tmpfiles-setup.service", ini(drop)["Unit"]["After"].split())
        made = {w[1]: w for w in (l.split() for l in TMPFILES.read_text().splitlines()) if w and w[0] == "d"}
        for p in check.KEEPER_PATHS:
            self.assertEqual(made[p][2], "0700", p)
        self.assertEqual(made["/var/lib/agentos-kernel"][3:5], ["agentos-kernel", "agentos-kernel"])
        names = sorted(n for n in (p.name for p in (self.root / SYSTEM).iterdir())
                       if check.NOEXEC_UNITS.match(n) and n not in check.KEEPER_UNITS + check.NOEXEC_EXEMPT)
        self.edit("agentos-.service.d/50-main-side.conf", " /var/lib/agentos-kernel", " -/var/lib/agentos-kernel")
        self.assertEqual(self.v(), ["%s: InaccessiblePaths=-/var/lib/agentos-kernel gives no mask while the path is "
                                    "missing; the image makes it at boot (D-154)" % n for n in names])

    def test_the_setup_factors_are_masked_and_removed(self):
        # #2981 (Security 2): the Owner Card's factors are hidden from the main side, and enrollment
        # removes them once it has made the store.
        e = exec_args(ENROLL)
        factors = [arg(e, "passphrase-file"), arg(e, "recovery-file")]
        self.assertEqual({f.rsplit("/", 1)[0] for f in factors}, {"/run/agentos-setup"})
        self.assertIn("/run/agentos-setup", check.KEEPER_PATHS)
        self.assertEqual(ini(ENROLL)["Service"]["ExecStartPost"].split(), ["/usr/bin/rm", "-f"] + factors)

    def test_permissions_start_only_is_refused(self):
        # #2981 (Security 3): it runs every command but ExecStart= with full privileges, as "+" does.
        self.add("agentos-boot-report.service", "Service", "PermissionsStartOnly=yes")
        self.assertEqual(self.v(), ["agentos-boot-report.service: PermissionsStartOnly=yes runs commands with full "
                                    "privileges, outside its device policy and namespace (STO-2c)"])

    def test_what_the_manager_opens_from_the_keeper_s_state_is_refused(self):
        # #2981 (L3 1): a file the service manager opens as root and hands to the unit, a directory it
        # makes and chowns for it, or a bind from above the keeper's state made before the mask.
        reach = ("OpenFile=/var/lib/agentos-kernel/log:log:append", "LoadCredential=x:/var/lib/agentos-store/store",
                 "LoadCredentialEncrypted=x:/var/lib/agentos-store", "EnvironmentFile=-/var/lib/agentos-kernel/env",
                 "StandardInput=file:/var/lib/agentos-store/store", "StandardOutput=file:/var/lib/agentos-kernel/log",
                 "StandardOutput=append:/run/agentos-setup/passphrase", "StandardError=truncate:/var/lib/agentos-kernel/x",
                 "TTYPath=/var/lib/agentos-store/store", "StateDirectory=agentos-store",
                 "StateDirectory=agentos x:agentos-kernel", "RuntimeDirectory=agentos-setup",
                 "BindReadOnlyPaths=/var/lib:/srv/vl", "BindReadOnlyPaths=/:/srv/r", "BindPaths=-/run:/srv/run",
                 "OpenFile=/var/lib", "StateDirectory=.")
        for line in reach:
            with self.subTest(line):
                d = write(self.root, SYSTEM + "agentos-boot-report.service.d/99-probe.conf", "[Service]\n%s\n" % line)
                key, val = line.split("=", 1)
                want = "agentos-boot-report.service: %s=%s reaches the keeper's state (D-154)" % (key, val)
                if key.endswith("Directory"):
                    want = "agentos-boot-report.service: %s=%s reaches the keeper's state (D-154)" % (
                        key, [w for w in val.split() if w != "agentos"][0])
                self.assertEqual(self.v(), [want])
                self.assertIn(want, check.violations(self.root))
                d.unlink()
        for line in ("LoadCredential=x:%S/agentos-store/store", "EnvironmentFile=/var/lib/%i"):
            with self.subTest(line):
                d = write(self.root, SYSTEM + "agentos-boot-report.service.d/99-probe.conf", "[Service]\n%s\n" % line)
                self.assertEqual(self.v(), ["agentos-boot-report.service: %s: the tree check does not model it (D-154)" % line])
                d.unlink()
        for line in ("LoadCredential=x", "LoadCredential=x:x.cred", "OpenFile=/etc/hostname", "StandardOutput=journal",
                     "BindReadOnlyPaths=/var/lib/agentos:/srv/a", "StateDirectory=agentos", "RuntimeDirectory=agentos-x",
                     "StandardInput=file:/var/lib/agentos/in"):
            with self.subTest(line):
                d = write(self.root, SYSTEM + "agentos-boot-report.service.d/99-probe.conf", "[Service]\n%s\n" % line)
                self.assertEqual(self.v(), [])
                d.unlink()

    def test_only_the_keeper_s_units_are_in_its_slice(self):
        self.add("agentos-localui.service", "Service", "Slice=agentos-keeper.slice")
        self.assertEqual(self.v(), ["agentos-localui.service: in agentos-keeper.slice but not one of the keeper's units (D-154)"])

    def test_an_unlisted_keeper_unit_is_refused(self):
        write(self.root, SYSTEM + "agentos-keeper-extra.service", self.unit("agentos-boot-report.service").read_text())
        v = self.v()
        self.assertEqual(v[0], "agentos-keeper-extra.service: an agentos-keeper unit not in KEEPER_UNITS; "
                               "the keeper group is listed in one place (D-154)")
        # The keeper's drop-in reaches it by name, so it is in the slice and unmasked: refused too.
        self.assertIn("agentos-keeper-extra.service: in agentos-keeper.slice but not one of the keeper's units (D-154)", v)

    def test_a_keeper_unit_outside_the_slice_is_refused(self):
        (self.root / SYSTEM / "agentos-keeper-.service.d/90-keeper.conf").unlink()
        v = self.v()
        for n in check.KEEPER_UNITS:
            self.assertIn("%s: Slice is None; the keeper's units run in agentos-keeper.slice (D-154)" % n, v)

    # The TPM device allowlist (#2889 Security later 2).

    def test_a_tpm_device_on_another_unit_is_refused(self):
        for spec in ("/dev/tpmrm0", "/dev/tpm0", "char-tpm", "char-tpmrm", "char-misc", "char-tpm*", "char-*",
                     "/dev/char/10:224"):
            with self.subTest(spec):
                good = self.unit("agentos-modem.service").read_text()
                self.add("agentos-modem.service", "Service", "DeviceAllow=%s rw" % spec)
                want = "agentos-modem.service: DeviceAllow=%s reaches the TPM; only %s may (#2889)" % (spec, ", ".join(check.TPM_UNITS))
                self.assertEqual(self.v(), [want])
                self.assertIn(want, check.violations(self.root))  # mkosi.finalize runs the check
                self.unit("agentos-modem.service").write_text(good)
        for spec in ("char-ttyUSB", "block-*", "/dev/mapper/control"):
            self.assertFalse(check.tpm_spec(spec), spec)

    def test_a_tpm_unit_opens_only_the_resource_manager(self):
        self.add("agentos-keeper-kernel.service", "Service", "DeviceAllow=/dev/tpm0 rw")
        self.assertEqual(self.v(), ["agentos-keeper-kernel.service: DeviceAllow=/dev/tpm0; a TPM unit opens only "
                                    "/dev/tpmrm0 (#2889)"])

    def test_a_tpm_unit_keeps_a_closed_device_policy(self):
        self.add("agentos-keeper-enroll.service", "Service", "DevicePolicy=auto")
        self.edit("agentos-keeper-enroll.service", "DevicePolicy=closed\n", "")
        self.assertEqual(self.v(), ["agentos-keeper-enroll.service: DevicePolicy is auto; a TPM unit sets closed or strict (#2889)"])

    def test_every_other_unit_has_a_closed_device_policy(self):
        for name in ("agentos-boot-report.service", "agentos-health.service", "agentos-drive-id.service"):
            with self.subTest(name):
                good = self.unit(name).read_text()
                self.edit(name, "DevicePolicy=closed\n", "")
                self.assertEqual(self.v(), ["%s: neither PrivateDevices=yes nor DevicePolicy=closed; only %s may reach "
                                            "the TPM (#2889)" % (name, ", ".join(check.TPM_UNITS))])
                self.add(name, "Service", "PrivateDevices=yes")
                self.assertEqual(self.v(), [])
                self.unit(name).write_text(good)
        # The old core's broker is frozen (D-139, #917), as for UPD-10.
        self.assertNotIn("DevicePolicy", self.unit("agentosd.service").read_text())

    def test_no_unit_or_user_is_in_a_tpm_group(self):
        for key in ("SupplementaryGroups=tss", "Group=agentos-egress", "User=agentos-egress"):
            with self.subTest(key):
                d = write(self.root, SYSTEM + "agentos-modem.service.d/99-x.conf", "[Service]\n%s\n" % key)
                self.assertEqual(self.v(), ["agentos-modem.service: %s can open the TPM (#2889)" % key])
                d.unlink()
        sysusers = self.root / "usr/lib/sysusers.d/agentos-setup.conf"
        good = sysusers.read_text()
        for line, want in (("m agentos-kernel tss", "puts agentos-kernel in tss"),
                           ("m agentos-localui agentos-egress", "puts agentos-localui in agentos-egress"),
                           ("u agentos-x -:tss", "gives agentos-x the group tss")):
            with self.subTest(line):
                sysusers.write_text(good + line + "\n")
                n = len(good.splitlines()) + 1
                self.assertEqual(self.v(), ["usr/lib/sysusers.d/agentos-setup.conf:%d: %s, which can open the TPM (#2889)"
                                            % (n, want)])
        sysusers.write_text(good)
        # The resource manager's group is the vault process's (udev), and is listed.
        rules = (MK / "mkosi.extra/usr/lib/udev/rules.d/60-agentos-tpm.rules").read_text()
        self.assertIn('GROUP="agentos-egress"', rules)

    def test_a_full_privilege_command_is_refused(self):
        self.add("agentos-boot-report.service", "Service", "ExecStartPre=+/usr/bin/true")
        self.assertEqual(self.v(), ["agentos-boot-report.service: ExecStartPre=+/usr/bin/true runs with full privileges, "
                                    "outside its device policy and namespace (STO-2c)"])
        self.assertEqual(check.FULL_PRIVILEGE_EXEMPT, ("agentos-egress.service",))

    # #2899: the unlock unit.

    def test_the_unlock_unit_gets_no_descriptor_past_2(self):
        for line in ("OpenFile=/etc/hostname", "Sockets=agentos-x.socket", "FileDescriptorStoreMax=1",
                     "AmbientCapabilities=CAP_SYS_ADMIN", "SecureBits=keep-caps"):
            with self.subTest(line):
                good = self.unit("agentos-keeper-kernel.service").read_text()
                self.add("agentos-keeper-kernel.service", "Service", line)
                key, val = line.split("=", 1)
                self.assertEqual(self.v(), ["agentos-keeper-kernel.service: sets %s=%s; nothing reaches the unlock step "
                                            "past descriptor 2 and no privilege survives its drop (#2899)" % (key, val)])
                self.unit("agentos-keeper-kernel.service").write_text(good)

    def test_a_socket_unit_for_the_unlock_step_is_refused(self):
        write(self.root, SYSTEM + "agentos-keeper-kernel.socket", "[Socket]\nListenStream=/run/x.sock\n")
        write(self.root, SYSTEM + "other.socket", "[Socket]\nListenStream=/run/y.sock\nService=agentos-keeper-kernel.service\n")
        self.assertEqual(self.v(), [
            "agentos-keeper-kernel.socket: starts agentos-keeper-kernel.service with its sockets; nothing reaches the "
            "unlock step past descriptor 2 (#2899)",
            "other.socket: starts agentos-keeper-kernel.service with its sockets; nothing reaches the unlock step past "
            "descriptor 2 (#2899)"])

    def test_the_unlock_unit_sets_no_new_privileges(self):
        self.edit("agentos-keeper-kernel.service", "NoNewPrivileges=yes\n", "")
        self.assertEqual(self.v(), ["agentos-keeper-kernel.service: NoNewPrivileges is not yes (#2899)"])

    # #2897: the unit that opens the counter anchor.

    def test_the_unlock_unit_bounds_its_restarts(self):
        u = ini(KERNEL)
        self.assertEqual(u["Unit"]["StartLimitBurst"], "3")
        self.assertEqual(u["Unit"]["StartLimitIntervalSec"], "infinity")
        self.assertEqual(u["Service"]["Restart"], "on-failure")
        cases = (("StartLimitBurst=3\n", "", "StartLimitBurst is None; must be 1 to 5, so a crash loop cannot wear the TPM counter (#2897)"),
                 ("StartLimitBurst=3\n", "StartLimitBurst=100\n", "StartLimitBurst is 100; must be 1 to 5, so a crash loop cannot wear the TPM counter (#2897)"),
                 ("StartLimitIntervalSec=infinity\n", "", "StartLimitIntervalSec is None; a zero or unset interval does not bound restarts (#2897)"),
                 ("StartLimitIntervalSec=infinity\n", "StartLimitIntervalSec=0\n", "StartLimitIntervalSec is 0; a zero or unset interval does not bound restarts (#2897)"),
                 ("StartLimitIntervalSec=infinity\n", "StartLimitIntervalSec=0s\n", "StartLimitIntervalSec is 0s; a zero or unset interval does not bound restarts (#2897)"),
                 ("StartLimitBurst=3\n", "StartLimitBurst=3\nStartLimitAction=reboot\n", "StartLimitAction=reboot; a reboot starts the unlock step again (#2897)"),
                 ("StartLimitBurst=3\n", "StartLimitBurst=3\nFailureAction=reboot-force\n", "FailureAction=reboot-force; a reboot starts the unlock step again (#2897)"),
                 ("StartLimitBurst=3\n", "StartLimitBurst=3\nSuccessAction=reboot\n", "SuccessAction=reboot; a reboot starts the unlock step again (#2897)"),
                 ("StartLimitBurst=3\n", "StartLimitBurst=3\nJobTimeoutAction=reboot-force\n", "JobTimeoutAction=reboot-force; a reboot starts the unlock step again (#2897)"),
                 ("[Service]\n", "[Service]\nStartLimitBurst=100\n", "a start limit outside [Unit]'s StartLimitBurst= and StartLimitIntervalSec=; the tree check does not model it (#2897)"))
        for old, new, want in cases:
            with self.subTest(new or old):
                good = self.unit("agentos-keeper-kernel.service").read_text()
                self.edit("agentos-keeper-kernel.service", old, new)
                self.assertEqual(self.v(), ["agentos-keeper-kernel.service: " + want])
                self.unit("agentos-keeper-kernel.service").write_text(good)

    # #2998: after the unlock cap (#2977) no restart in the same boot unlocks, so a kernel that came up
    # and then failed reboots the box, at most twice an hour; one refused at its start does not.

    def test_a_kernel_that_came_up_and_failed_reboots_the_box(self):
        k = exec_args(KERNEL)
        kern = k[k.index("--") + 1:]
        u = ini(KERNEL)
        self.assertEqual(arg(kern, "up"), "/run/agentos-kernel/up")
        self.assertIn(arg(kern, "up"), check.KERNEL_REBOOT)
        self.assertEqual(u["Service"]["ExecStopPost"], check.KERNEL_REBOOT)
        self.assertEqual(u["Service"]["Restart"], "on-failure")
        # /run/agentos-kernel outlives a stop (#3073), so each start removes the last start's "up" first.
        self.assertEqual(check.KERNEL_UP_CLEAR, "/usr/bin/rm -f " + arg(kern, "up"))
        self.assertIn(check.KERNEL_UP_CLEAR, exec_lines(KERNEL, "ExecStartPre"))

    def test_the_reboot_follows_only_a_kernel_that_came_up(self):
        # The command as systemd runs it ($$ is one $), with the "up" file and systemd-run moved into a
        # temporary directory: it asks for the boot-timed reboot only after a failure of a kernel that
        # made "up".
        argv = shlex.split(check.KERNEL_REBOOT.replace("$$", "$"))
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            run, calls = d / "systemd-run", d / "calls"
            write(d, "systemd-run", '#!/bin/sh\necho "$*" >> %s\n' % calls, 0o755)
            script = argv[2].replace("/run/agentos-kernel/up", str(d / "up")).replace("/usr/bin/systemd-run", str(run))
            for result, up, want in (("success", True, False), ("exit-code", True, True), ("signal", True, True),
                                     ("core-dump", True, True), ("exit-code", False, False), ("signal", False, False)):
                with self.subTest(result=result, up=up):
                    (d / "up").unlink(missing_ok=True)
                    calls.unlink(missing_ok=True)
                    if up:
                        (d / "up").touch()
                    subprocess.run([argv[0], argv[1], script], env={"SERVICE_RESULT": result}, check=True)
                    got = calls.read_text() if calls.exists() else ""
                    self.assertEqual(got, "--on-boot=30min --unit=agentos-kernel-reboot /usr/bin/systemctl reboot\n" if want else "")

    def test_any_other_reboot_of_the_unlock_unit_is_refused(self):
        name = "agentos-keeper-kernel.service"
        stop = "ExecStopPost=" + check.KERNEL_REBOOT + "\n"
        guard = "if [ \"$$SERVICE_RESULT\" != success ] && [ -e /run/agentos-kernel/up ]; then "
        why = "can reboot the box; its one reboot is ExecStopPost=KERNEL_REBOOT, after a kernel that came up and no " \
              "sooner than 30 minutes into the boot (#2897, #2998)"
        cases = ((stop, stop.replace(guard, "if true; then "), "ExecStopPost=/usr/bin/sh " + why),
                 (stop, stop.replace("--on-boot=30min", "--on-boot=1s"), "ExecStopPost=/usr/bin/sh " + why),
                 (stop, stop.replace("ExecStopPost=", "ExecStopPost=-"), "ExecStopPost=-/usr/bin/sh " + why),
                 (stop, stop + "ExecStopPost=/usr/bin/systemctl reboot\n", "ExecStopPost=/usr/bin/systemctl " + why),
                 ("[Service]\n", "[Service]\nExecStartPre=/usr/bin/systemd-run --on-active=1 /usr/bin/true\n",
                  "ExecStartPre=/usr/bin/systemd-run " + why),
                 ("[Unit]\n", "[Unit]\nOnFailure=reboot.target\n",
                  "OnFailure=reboot.target starts a unit when the kernel stops, which the tree check does not model; "
                  "its one reboot is ExecStopPost=KERNEL_REBOOT (#2897, #2998)"))
        for old, new, want in cases:
            with self.subTest(new):
                good = self.unit(name).read_text()
                self.edit(name, old, new)
                self.assertEqual(self.v(), [name + ": " + want])
                self.unit(name).write_text(good)
        # Without the line the kernel stays down after the cap, as before #2998, which the check allows.
        self.edit(name, stop, "")
        self.assertEqual(self.v(), [])

    def test_the_reboot_needs_each_start_to_clear_the_last_up(self):
        # #3073 keeps /run/agentos-kernel across a stop: without the removal, a start refused after a good
        # one finds that start's "up", and its ExecStopPost= asks for the reboot.
        name = "agentos-keeper-kernel.service"
        clear = "ExecStartPre=" + check.KERNEL_UP_CLEAR + "\n"
        why = ("no ExecStartPre=%s; a start refused after a good one would find the last start's \"up\" and "
               "reboot the box (#2897, #2998)" % check.KERNEL_UP_CLEAR)
        for new in ("", clear.replace("=", "=-", 1), clear.replace("/up", "/up.old")):
            with self.subTest(new):
                good = self.unit(name).read_text()
                self.edit(name, clear, new)
                self.assertEqual(self.v(), [name + ": " + why])
                self.unit(name).write_text(good)
        # Without the reboot line the file reboots nothing, so its removal is not required.
        good = self.unit(name).read_text()
        self.edit(name, clear, "")
        self.edit(name, "ExecStopPost=" + check.KERNEL_REBOOT + "\n", "")
        self.assertEqual(self.v(), [])
        self.unit(name).write_text(good)

    # UPD-10 (#2875) on the new units: noexec_violations covers every agentos unit.

    def test_the_keeper_s_units_run_nothing_from_writable_storage(self):
        for name in check.KEEPER_UNITS:
            with self.subTest(name):
                good = self.unit(name).read_text()
                self.edit(name, "NoExecPaths=/\n", "")
                self.assertEqual(check.noexec_violations(self.root),
                                 ["%s: NoExecPaths does not hold /; must be NoExecPaths=/ (UPD-10)" % name])
                self.unit(name).write_text(good)


class KeeperUnitsTest(unittest.TestCase):
    """The keeper's unit files against the mains they run."""

    def test_the_units_agree_with_each_other_and_the_mains(self):
        e, k = exec_args(ENROLL), exec_args(KERNEL)
        self.assertEqual(e[0], "/usr/lib/agentos/agentos-enroll")
        self.assertEqual(k[0], "/usr/lib/agentos/agentos-unlock")
        i = k.index("--")
        unlock, kern = k[1:i], k[i + 1:]
        self.assertEqual(arg(unlock, "exec"), "/usr/lib/agentos/agentos-kernel")
        self.assertEqual(arg(unlock, "store"), arg(e, "state") + "/store")
        self.assertEqual(arg(kern, "anchor-dir"), arg(e, "anchor-dir"))
        self.assertEqual(arg(kern, "log"), arg(e, "log"))
        self.assertEqual((arg(unlock, "uid"), arg(unlock, "gid")), ("@uid:agentos-kernel", "@gid:agentos-kernel"))
        self.assertEqual((arg(e, "kernel-uid"), arg(e, "kernel-gid")), ("@uid:agentos-kernel", "@gid:agentos-kernel"))
        # Every flag the units pass is one the main defines.
        for cmd, words in (("agentos-enroll", e[1:]), ("agentos-unlock", unlock), ("agentos-kernel", kern)):
            flags = go_flags(cmd)
            for w in words:
                if w.startswith("-"):
                    self.assertIn(w[1:], flags, "%s %s" % (cmd, w))
        # The store's path is the conditions'.
        store = arg(unlock, "store")
        conds = re.findall(r"^ConditionPathExists=(.*)$", ENROLL.read_text(), re.M)
        self.assertEqual(conds, ["!" + store, arg(e, "passphrase-file"), arg(e, "recovery-file")])
        self.assertEqual(re.findall(r"^ConditionPathExists=(.*)$", KERNEL.read_text(), re.M), [store])
        # Enrollment comes first, and makes the kernel's state directory for the kernel's user.
        self.assertIn("agentos-keeper-enroll.service", ini(KERNEL)["Unit"]["After"].split())
        self.assertIn("-o agentos-kernel -g agentos-kernel /var/lib/agentos-kernel", ini(ENROLL)["Service"]["ExecStartPre"])
        self.assertEqual(sorted(check.KEEPER_PATHS), sorted({arg(e, "state"), arg(e, "log").rsplit("/", 1)[0],
                                                             arg(e, "passphrase-file").rsplit("/", 1)[0]}))

    def test_the_kernel_owns_its_socket_directory_when_it_binds(self):
        # #3073: systemd chowns a RuntimeDirectory= to the unit's user, root here, at every command's
        # spawn, so a chown in ExecStartPre= is undone before ExecStart and the kernel cannot bind.
        k = exec_args(KERNEL)
        kern = k[k.index("--") + 1:]
        run = {arg(kern, "owner-sock").rsplit("/", 1)[0], arg(kern, "meter-sock").rsplit("/", 1)[0]}
        self.assertEqual(run, {"/run/agentos-kernel"})
        s = ini(KERNEL)["Service"]
        self.assertNotIn("RuntimeDirectory", s)
        self.assertNotIn("User", s)
        self.assertEqual(exec_lines(KERNEL, "ExecStartPre"),
                         ["/usr/bin/install -d -m 0711 -o agentos-kernel -g agentos-kernel /run/agentos-kernel",
                          check.KERNEL_UP_CLEAR])

    def test_the_users_exist_and_none_is_in_a_tpm_group(self):
        lines = [l.split() for l in SYSUSERS.read_text().splitlines() if l.strip() and not l.startswith("#")]
        users = {w[1] for w in lines if w[0] == "u"}
        for unit in (ENROLL, KERNEL):
            for w in exec_args(unit):
                if w.startswith(("@uid:", "@gid:")):
                    self.assertIn(w[5:], users)
        self.assertFalse([w for w in lines if w[0] == "m"])

    def test_with_uids_swaps_group_names_for_gids(self):
        out = subprocess.run([str(WITH_UIDS), "echo", "@gid:root", "@uid:root", "x@gid:root"],
                             capture_output=True, text=True, check=True)
        self.assertEqual(out.stdout, "0 0 x@gid:root\n")
        bad = subprocess.run([str(WITH_UIDS), "echo", "@gid:agentos-no-such-user"], capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(bad.stdout, "")

    def test_the_build_ships_the_keeper_s_mains(self):
        build = (ROOT / "image/build.sh").read_text()
        for cmd in ("agentos-enroll", "agentos-unlock", "agentos-kernel"):
            self.assertRegex(build, r"for cmd in [^;]*\b%s\b" % cmd)

    def test_the_boot_test_enrolls_on_the_first_boot(self):
        report, ci = BOOT_REPORT.read_text(), CI_BOOT.read_text()
        self.assertIn("agentos-keeper:", report)
        self.assertIn("tmpfiles.extra", ci)
        self.assertIn('"agentos-keeper: enroll=ran kernel=active"', ci)
        self.assertIn('"agentos-keeper: enroll=skipped"', ci)
        # The kernel starts setup-only after both boots (#2996), on its own sockets (#3073).
        self.assertIn("/agentos-keeper: enroll=skipped kernel=active/", ci)
        self.assertIn('hasnt "$W/console-reboot.log" "listen unix /run/agentos-kernel/"', ci)
        self.assertNotIn("my store holds none of your hardware keys", ci)
        self.assertIn("agentos-keeper-enroll.service", ini(UNITS / "agentos-boot-report.service")["Unit"]["After"].split())
        # The CI unit whose mounts outlive one command lifts the main-side mask in a drop-in that
        # sorts after it.
        for unit in ("agentos-e2e-seal.service",):
            self.assertIn("'systemd.unit-dropin.%s~99-ci-unmask' '[Service]\\nInaccessiblePaths=\\n'" % unit, ci)
        self.assertLess("50-main-side.conf", "99-ci-unmask.conf")
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text().splitlines()
        for n in check.KEEPER_UNITS:
            self.assertIn("enable " + n, preset)


if __name__ == "__main__":
    unittest.main()
