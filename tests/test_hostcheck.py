# HOST-1e host-untouched check (spec A1, HW-8): snapshot, diff against
# HW-8's disclosed list, and the QEMU/OVMF/swtpm run with a Windows-like
# second disk. REQ: HW-8
#
# The unit tests run everywhere. The QEMU tests boot the stand-in guest and
# need qemu, OVMF, swtpm, tpm2-tools and virt-fw-vars; they run when
# HOSTCHECK_QEMU=1 (the `hostcheck` CI job) and fail rather than skip there if
# a tool is missing. HOSTCHECK_KERNEL names the guest kernel; HOSTCHECK_TOOLS_ROOT, if set,
# a root holding qemu, swtpm and OVMF (CI: the image's Debian snapshot, #4906).
import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import hostcheck  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
from test_workflows import job_steps  # noqa: E402

GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
SYSTEMD = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
SHIM = "605dab50-e046-4300-abb6-3dd810dd8b23"
COUNTER_ATTRS = 0x02040014  # authwrite|counter|authread|no_da, as tpmseal makes it


def snap(**over):
    s = {
        "disk": {"win": "aa" * 32},
        "uefi": {f"{GLOBAL}:BootOrder": {"attr": 7, "sha256": "11"},
                 f"{GLOBAL}:Boot0000": {"attr": 7, "sha256": "22"}},
        "tpm-nv": {"0x1500020": {"name": "n1", "attributes": 0x20060006, "size": 8, "data": "d1"}},
        "tpm-persistent": {},
        "tpm-setting": {"lockoutAuthSet": 0, "TPM2_PT_MAX_AUTH_FAIL": 3},
    }
    for k, v in over.items():
        s[k.replace("_", "-")] = v
    return s


def flagged(report):
    return {(f["kind"], f["key"], f["change"]) for f in report["flagged"]}


class DiffTest(unittest.TestCase):
    def setUp(self):
        self.allow = hostcheck.load_allow()

    def check(self, before, after, **kw):
        return hostcheck.evaluate(before, after, self.allow, **kw)

    def test_identical_passes(self):
        r = self.check(snap(), snap())
        self.assertTrue(r["pass"])
        self.assertEqual(r["flagged"], [])

    def test_disk_write_flagged(self):
        r = self.check(snap(), snap(disk={"win": "bb" * 32}))
        self.assertFalse(r["pass"])
        self.assertEqual(flagged(r), {("disk", "win", "changed")})

    def test_new_uefi_variable_flagged(self):
        after = snap()
        after["uefi"]["0000-x:Canary"] = {"attr": 7, "sha256": "33"}
        self.assertEqual(flagged(self.check(snap(), after)), {("uefi", "0000-x:Canary", "added")})

    def test_removed_and_changed_uefi_variable_flagged(self):
        after = snap()
        del after["uefi"][f"{GLOBAL}:Boot0000"]
        after["uefi"][f"{GLOBAL}:BootOrder"] = {"attr": 7, "sha256": "99"}
        self.assertEqual(flagged(self.check(snap(), after)),
                         {("uefi", f"{GLOBAL}:Boot0000", "removed"),
                          ("uefi", f"{GLOBAL}:BootOrder", "changed")})

    def test_boot_order_disclosed_only_when_owner_changed_it(self):
        after = snap()
        after["uefi"][f"{GLOBAL}:BootOrder"] = {"attr": 7, "sha256": "99"}
        after["uefi"][f"{GLOBAL}:Boot0003"] = {"attr": 7, "sha256": "44"}
        self.assertFalse(self.check(snap(), after)["pass"])
        r = self.check(snap(), after, flags={"owner-boot-order"})
        self.assertTrue(r["pass"], r)
        self.assertEqual({d["change_id"] for d in r["disclosed"]}, {"boot-order"})

    def test_mok_and_other_shim_variables_are_not_disclosed(self):
        after = snap()
        after["uefi"]["605dab50-e046-4300-abb6-3dd810dd8b23:MokList"] = {"attr": 7, "sha256": "1"}
        self.assertFalse(self.check(snap(), after, flags={"owner-boot-order"})["pass"])

    def test_loader_token_and_sbat_level_disclosed(self):
        after = snap()
        after["uefi"][f"{SYSTEMD}:LoaderSystemToken"] = {"attr": 7, "sha256": "1"}
        after["uefi"][f"{SHIM}:SbatLevel"] = {"attr": 7, "sha256": "2"}
        r = self.check(snap(), after)
        self.assertTrue(r["pass"], r)
        self.assertEqual({d["change_id"] for d in r["disclosed"]},
                         {"loader-system-token", "sbat-level"})

    def test_new_nv_index_flagged(self):
        after = snap()
        after["tpm-nv"]["0x1500016"] = {"name": "n2", "attributes": 0x20060006, "size": 8, "data": "x"}
        self.assertEqual(flagged(self.check(snap(), after)), {("tpm-nv", "0x1500016", "added")})

    def test_written_existing_nv_index_flagged(self):
        after = snap()
        after["tpm-nv"]["0x1500020"] = dict(after["tpm-nv"]["0x1500020"], data="d2")
        self.assertEqual(flagged(self.check(snap(), after)), {("tpm-nv", "0x1500020", "changed")})

    def test_vault_counter_disclosed_only_in_its_shape(self):
        ok = snap()
        ok["tpm-nv"]["0x18a0b0c"] = {"name": "c", "attributes": COUNTER_ATTRS | hostcheck.NV_WRITTEN,
                                     "size": 8, "data": None}
        r = self.check(snap(), ok)
        self.assertTrue(r["pass"], r)
        self.assertEqual([d["change_id"] for d in r["disclosed"]], ["tpm-vault-counter"])
        for bad in ({"attributes": COUNTER_ATTRS | 1 << 17},  # owner-readable: not tpmseal's
                    {"size": 16}):
            after = snap()
            after["tpm-nv"]["0x18a0b0c"] = dict(ok["tpm-nv"]["0x18a0b0c"], **bad)
            self.assertFalse(self.check(snap(), after)["pass"], bad)
        outside = snap()
        outside["tpm-nv"]["0x1c00000"] = ok["tpm-nv"]["0x18a0b0c"]
        self.assertFalse(self.check(snap(), outside)["pass"])
        # A counter the PC already had is never redefined.
        before = snap()
        before["tpm-nv"]["0x18a0b0c"] = dict(ok["tpm-nv"]["0x18a0b0c"], name="old")
        self.assertFalse(self.check(before, ok)["pass"])

    def test_srk_disclosed_only_when_added(self):
        after = snap(tpm_persistent={"0x81000001": "srk"})
        r = self.check(snap(), after)
        self.assertTrue(r["pass"], r)
        replaced = self.check(snap(tpm_persistent={"0x81000001": "windows"}), after)
        self.assertEqual(flagged(replaced), {("tpm-persistent", "0x81000001", "changed")})
        other = self.check(snap(), snap(tpm_persistent={"0x81000002": "x"}))
        self.assertFalse(other["pass"])

    def test_lockout_settings_disclosed(self):
        after = snap(tpm_setting={"lockoutAuthSet": 1, "TPM2_PT_MAX_AUTH_FAIL": 32})
        self.assertTrue(self.check(snap(), after)["pass"])
        owner = snap(tpm_setting={"lockoutAuthSet": 0, "TPM2_PT_MAX_AUTH_FAIL": 3, "ownerAuthSet": 1})
        self.assertFalse(self.check(snap(tpm_setting=dict(owner["tpm-setting"], ownerAuthSet=0)), owner)["pass"])

    def test_rtc_write_flagged(self):
        r = self.check(snap(), snap(), rtc_writes=[{"phase": "task", "offset": 0}])
        self.assertFalse(r["pass"])
        self.assertEqual(flagged(r), {("rtc", "task", "written")})

    def test_rtc_writes_after_the_os_starts_in_each_post_are_the_guests(self):
        # OVMF sets the clock's registers on every power-on self-test, and
        # QEMU throttles RTC_CHANGE to one event a second, so how many events
        # the firmware's writes make varies (CI saw 1 and 2). A write is the
        # guest's when it comes after the OS started on the console and
        # before the next reset.
        ev = lambda t, name, **d: {"event": name, "timestamp": {"seconds": t, "microseconds": 0}, "data": d}
        events = [ev(1, "RTC_CHANGE", offset=0), ev(2, "RTC_CHANGE", offset=-1), ev(6, "RESET"),
                  ev(7, "RTC_CHANGE", offset=0), ev(12, "RTC_CHANGE", offset=0), ev(20, "SHUTDOWN")]
        self.assertEqual(hostcheck.guest_rtc_writes(events, [3.0, 8.0]), [events[4]])
        self.assertEqual(hostcheck.guest_rtc_writes(events, [3.0, 13.0]), [])
        self.assertEqual(hostcheck.guest_rtc_writes(events, []), [])
        self.assertEqual(hostcheck.guest_rtc_writes(events, [0.5]), [events[0], events[1]])

    def test_firmware_noise_excluded_for_uefi_only(self):
        noisy = f"eb704011-1402-11d3-8e77-00a0c969723b:MTC"
        before, after = snap(), snap(disk={"win": "cc" * 32})
        before["uefi"][noisy] = {"attr": 7, "sha256": "1"}
        after["uefi"][noisy] = {"attr": 7, "sha256": "2"}
        r = self.check(before, after, noise={("uefi", noisy), ("disk", "win")})
        self.assertEqual(flagged(r), {("disk", "win", "changed")})
        self.assertEqual([n["key"] for n in r["noise"]], [noisy])

    def test_missing_part_is_an_error_not_a_pass(self):
        after = snap()
        del after["tpm-nv"]
        with self.assertRaises(hostcheck.HostcheckError):
            self.check(snap(), after)


class AllowListTest(unittest.TestCase):
    def test_entries_name_owner_guide_changes(self):
        # Every disclosed change the check allows is one the owner's guide
        # lists (broker/hostchange), and every UEFI or TPM item there has a
        # rule, so the check and the guide cannot drift apart.
        src = (ROOT / "broker" / "hostchange" / "hostchange.go").read_text()
        guide = {m.group(1): m.group(2) for m in re.finditer(r'\{"([a-z-]+)",\s*(UEFI|TPM|Windows)\}', src)}
        self.assertIn("boot-order", guide)
        allow = hostcheck.load_allow()
        ids = {r["change"] for r in allow}
        self.assertLessEqual(ids, set(guide))
        self.assertEqual(ids, {i for i, k in guide.items() if k in ("UEFI", "TPM")})


class SourcesTest(unittest.TestCase):
    def test_disk_hash_sees_last_byte(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d, "disk.img")
            p.write_bytes(b"\0" * (hostcheck.CHUNK + 5))
            h1 = hostcheck.hash_disk(p)
            with open(p, "r+b") as f:
                f.seek(-1, os.SEEK_END)
                f.write(b"\1")
            self.assertNotEqual(h1, hostcheck.hash_disk(p))

    def test_efivarfs_keeps_only_non_volatile(self):
        with tempfile.TemporaryDirectory() as d:
            pathlib.Path(d, f"BootOrder-{GLOBAL}").write_bytes((7).to_bytes(4, "little") + b"\0\0")
            pathlib.Path(d, f"BootCurrent-{GLOBAL}").write_bytes((6).to_bytes(4, "little") + b"\0\0")
            v = hostcheck.uefi_from_efivarfs(d)
            self.assertEqual(set(v), {f"{GLOBAL}:BootOrder"})
            self.assertEqual(v[f"{GLOBAL}:BootOrder"]["attr"], 7)


# CI-hostcheck-image-tools (#4906): the VM stack hostcheck boots (qemu, swtpm, OVMF) comes from a
# root installed from the image's pinned Debian snapshot, never the runner's archive, so a runner
# package update cannot change a hostcheck result.
PINNED = ("qemu-system-x86", "ovmf", "swtpm", "swtpm-tools")


def fake_root(d, versions=None, skip=()):
    """A tools root with the loader, the three binaries and OVMF as regular files."""
    for rel in (hostcheck.TOOLS_LOADER, *hostcheck.TOOLS.values(), *hostcheck.TOOLS_OVMF):
        if rel in skip:
            continue
        f = pathlib.Path(d, rel)
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"x")
    status = pathlib.Path(d, "var/lib/dpkg/status")
    status.parent.mkdir(parents=True, exist_ok=True)
    versions = {p: "1:1.0-1" for p in PINNED} if versions is None else versions
    status.write_text("\n\n".join(f"Package: {p}\nStatus: install ok installed\nVersion: {v}"
                                  for p, v in versions.items()) + "\n")
    return d


class ToolsRootTest(unittest.TestCase):
    def test_no_root_runs_the_path_tools(self):
        self.assertEqual(hostcheck.tool_argv(None, "swtpm"), ["swtpm"])
        self.assertEqual(hostcheck.qemu_data_args(None), ([], None))

    def test_root_tools_run_on_the_roots_loader_and_libraries(self):
        with tempfile.TemporaryDirectory() as d:
            fake_root(d)
            for name, rel in hostcheck.TOOLS.items():
                argv = hostcheck.tool_argv(d, name)
                self.assertEqual(argv[:2], [os.path.join(d, hostcheck.TOOLS_LOADER), "--inhibit-cache"])
                self.assertEqual(argv[-3:], ["--argv0", name, os.path.join(d, rel)])
                libs = argv[argv.index("--library-path") + 1].split(":")
                self.assertTrue(libs and all(lib.startswith(d + os.sep) for lib in libs), libs)
            args, env = hostcheck.qemu_data_args(d)
            self.assertEqual(args, ["-L", os.path.join(d, "usr/share/qemu")])
            self.assertEqual(env["QEMU_MODULE_DIR"], os.path.join(d, "usr/lib/x86_64-linux-gnu/qemu"))

    def test_missing_or_linked_tool_is_an_error_not_the_runners(self):
        for rel in (hostcheck.TOOLS_LOADER, hostcheck.TOOLS["swtpm"]):
            with self.subTest(rel=rel), tempfile.TemporaryDirectory() as d:
                fake_root(d, skip=(rel,))
                with self.assertRaises(hostcheck.HostcheckError):
                    hostcheck.tool_argv(d, "swtpm")
                os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
                os.symlink("/usr/bin/true", os.path.join(d, rel))  # an absolute link reads the runner's
                with self.assertRaises(hostcheck.HostcheckError):
                    hostcheck.tool_argv(d, "swtpm")

    def test_ovmf_defaults_follow_the_root(self):
        with tempfile.TemporaryDirectory() as d:
            fake_root(d)
            a = argparse.Namespace(tools_root=d, ovmf_code=None, ovmf_vars=None)
            hostcheck.resolve_tools(a)
            self.assertEqual((a.ovmf_code, a.ovmf_vars), tuple(os.path.join(d, r) for r in hostcheck.TOOLS_OVMF))
            a = argparse.Namespace(tools_root=d, ovmf_code="/x/code.fd", ovmf_vars=None)
            hostcheck.resolve_tools(a)
            self.assertEqual(a.ovmf_code, "/x/code.fd")
        a = argparse.Namespace(tools_root=None, ovmf_code=None, ovmf_vars=None)
        hostcheck.resolve_tools(a)
        self.assertEqual((a.ovmf_code, a.ovmf_vars), ("/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
                                                      "/usr/share/OVMF/OVMF_VARS_4M.fd"))

    def test_report_names_the_stack_it_booted(self):
        with tempfile.TemporaryDirectory() as d:
            fake_root(d, versions={"qemu-system-x86": "1:10.0.2+ds-2", "ovmf": "2025.02-8",
                                   "swtpm": "0.7.3-1", "swtpm-tools": "0.7.3-1"})
            self.assertEqual(hostcheck.stack_versions(d)["ovmf"], "2025.02-8")
        with tempfile.TemporaryDirectory() as d:
            fake_root(d, versions={"qemu-system-x86": "1", "ovmf": "1", "swtpm": "1"})
            with self.assertRaises(hostcheck.HostcheckError):  # swtpm-tools not installed
                hostcheck.stack_versions(d)
        self.assertEqual(hostcheck.stack_versions(None), "runner")


class HostcheckJobTest(unittest.TestCase):
    """ci.yml's hostcheck job installs the VM stack from the image's snapshot, not the runner's archive."""

    def setUp(self):
        self.ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()

    def problems(self, text):
        out = []
        steps = job_steps(text, "hostcheck")
        # Every runner apt-get install or download command, its continuation lines joined.
        runner_apt = "\n".join(line for _, b in steps for line in b.replace("\\\n", " ").splitlines()
                               if re.search(r"apt-get\s.*\b(install|download)\b", line))
        for pkg in PINNED:
            if re.search(rf"(?<![\w.+-]){re.escape(pkg)}(?![\w.+-])", runner_apt):
                out.append(f"{pkg} installed from the runner's archive")
        root = [b for _, b in steps if "sudo mmdebstrap" in b]
        if len(root) != 1:
            out.append("no single mmdebstrap step builds the tools root")
        else:
            inc = re.search(r"--include=(\S+)", root[0])
            if not inc or set(inc.group(1).split(",")) != set(PINNED):
                out.append("the tools root does not include exactly the pinned stack")
            if "mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources" not in root[0] or "security" in root[0]:
                out.append("the tools root is not read from the image's snapshot alone")
        run = [b for _, b in steps if "tests.test_hostcheck" in b]
        if len(run) != 1 or not re.search(r"HOSTCHECK_TOOLS_ROOT: \$\{\{ runner\.temp \}\}/hostcheck-tools", run[0]):
            out.append("the hostcheck run does not name the tools root")
        return out

    def test_vm_stack_comes_from_the_snapshot(self):
        self.assertEqual(self.problems(self.ci), [])

    def test_check_catches_mutants(self):
        for name, (old, new) in {
            "runner qemu": ("qemu-utils ", "qemu-utils qemu-system-x86 "),
            "runner ovmf": ("qemu-utils ", "qemu-utils ovmf "),
            "runner swtpm": ("qemu-utils ", "qemu-utils swtpm "),
            "root without ovmf": ("--include=qemu-system-x86,ovmf,", "--include=qemu-system-x86,"),
            "no root env": ("HOSTCHECK_TOOLS_ROOT: ${{ runner.temp }}/hostcheck-tools", "HOSTCHECK_X: x"),
        }.items():
            with self.subTest(name):
                self.assertIn(old, self.ci)
                self.assertNotEqual(self.problems(self.ci.replace(old, new, 1)), [])


QEMU = os.environ.get("HOSTCHECK_QEMU") == "1"


@unittest.skipUnless(QEMU, "set HOSTCHECK_QEMU=1 to boot the stand-in guest")
class QemuTest(unittest.TestCase):
    """The harness flags writes a guest really makes, seen from outside it."""

    @classmethod
    def setUpClass(cls):
        cls.tools_root = os.environ.get("HOSTCHECK_TOOLS_ROOT") or None
        for tool in ("qemu-system-x86_64", "swtpm", "swtpm_ioctl"):
            if cls.tools_root:
                hostcheck.tool_argv(cls.tools_root, tool)  # raises if the root lacks it
            elif not shutil.which(tool):
                raise AssertionError(f"{tool} missing")
        for tool in ("tpm2_getcap", "virt-fw-vars", "busybox", "mkntfs", "sfdisk"):
            if not shutil.which(tool):
                raise AssertionError(f"{tool} missing")
        kernel = os.environ.get("HOSTCHECK_KERNEL")
        if not kernel or not os.path.exists(kernel):
            raise AssertionError("HOSTCHECK_KERNEL must name a guest kernel")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = pathlib.Path(cls.tmp.name)
        subprocess.run(["sh", str(ROOT / "tools" / "hostcheck_standin.sh"), str(cls.dir / "standin")],
                       check=True)
        cls.kernel = kernel

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_check(self, name, phases, plant=""):
        work = self.dir / name
        cmd = [sys.executable, str(ROOT / "tools" / "hostcheck.py"), "qemu", "--work", str(work),
               "--kernel", self.kernel, "--initrd", str(self.dir / "standin" / "initrd.cpio"),
               "--host-disk", f"windows={self.dir / 'standin' / 'windows.img'},bus=virtio",
               "--phases", phases]
        if plant:
            cmd += ["--plant", plant]
        if self.tools_root:
            cmd += ["--tools-root", self.tools_root]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        report = work / "report.json"
        if not report.exists():
            self.fail(f"no report (exit {p.returncode}):\n{p.stdout[-3000:]}\n{p.stderr[-3000:]}")
        return p.returncode, json.loads(report.read_text())

    def test_clean_session_passes(self):
        # A task that reads the partition table, a restart and a shutdown
        # leave the host as it was; the input disk image is not modified.
        disk = self.dir / "standin" / "windows.img"
        before = hostcheck.hash_disk(disk)
        rc, report = self.run_check("clean", "task,restart")
        self.assertEqual(rc, 0, json.dumps(report, indent=1))
        self.assertEqual([p["phase"] for p in report["phases"]], ["task", "restart"])
        for p in report["phases"]:
            self.assertTrue(p["pass"], p)
            self.assertEqual(p["rtc_writes"], [])
        self.assertTrue(report["baseline"]["tpm-nv"], "the stand-in host has an NV index to keep")
        self.assertEqual(report["stack"], hostcheck.stack_versions(self.tools_root))
        self.assertEqual(before, hostcheck.hash_disk(disk))

    def test_planted_writes_flagged(self):
        rc, report = self.run_check("planted", "task", plant="disk,uefi,nv,rtc")
        self.assertEqual(rc, 1, json.dumps(report, indent=1))
        (phase,) = report["phases"]
        kinds = {(f["kind"], f["change"]) for f in phase["flagged"]}
        self.assertIn(("disk", "changed"), kinds)
        self.assertIn(("tpm-nv", "added"), kinds)
        self.assertIn(("rtc", "written"), kinds)
        uefi = [f["key"] for f in phase["flagged"] if f["kind"] == "uefi"]
        self.assertTrue(any(k.endswith(":HostcheckCanary") for k in uefi), uefi)
        self.assertEqual([f for f in phase["flagged"] if f["kind"] not in ("disk", "uefi", "tpm-nv", "rtc")], [])


if __name__ == "__main__":
    unittest.main()
