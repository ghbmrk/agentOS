"""CAM-node part (c) (#3513, briefs/CAM-node.md, design point 5): the camera node image's tree, read
without building it. The end-to-end test (image/camnode/e2e/driver, run by camnode-image.yml)
boots the image; these guard the files it is built from, so a change that would open a port, add
a shell or loosen the service fails in every CI run, not only in the image workflow.
"""
# REQ: NET-2, DEV-2, DEV-3, A16
import configparser
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent
TREE = REPO / "image" / "camnode" / "external"
COMMON = TREE / "board" / "common" / "overlay"
UNITS = COMMON / "etc" / "systemd" / "system"
WORKFLOW = REPO / ".github" / "workflows" / "camnode-image.yml"


def unit(path):
    p = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
    p.optionxform = str
    p.read_string(path.read_text())
    return p


def multi(path, section, key):
    """Every value of a key that may repeat (DeviceAllow=)."""
    out, cur = [], None
    for line in path.read_text().splitlines():
        if line.startswith("["):
            cur = line.strip("[]")
        elif cur == section and line.startswith(key + "="):
            out.append(line.split("=", 1)[1])
    return out


class Firewall(unittest.TestCase):
    RULES = (COMMON / "etc" / "camnode" / "firewall.nft").read_text()

    def chain(self, name):
        m = re.search(r"chain %s \{(.*?)\n\t\}" % name, self.RULES, re.S)
        self.assertIsNotNone(m, name)
        return [l.strip() for l in m.group(1).splitlines() if l.strip() and not l.strip().startswith("#")]

    def test_every_chain_drops_by_default(self):
        for c in ("input", "forward", "output"):
            self.assertIn("policy drop;", self.chain(c)[0], c)
        self.assertEqual(self.chain("forward"), ["type filter hook forward priority filter; policy drop;"])

    def test_in_only_the_stream_port_and_dhcp_replies(self):
        self.assertEqual(self.chain("input")[1:], [
            'iif "lo" accept',
            "ct state invalid drop",
            "ct state established,related accept",
            "tcp dport 8443 ct state new accept",
            "udp sport 67 udp dport 68 accept",
        ])

    def test_out_only_replies_and_dhcp_requests(self):
        self.assertEqual(self.chain("output")[1:], [
            'oif "lo" accept',
            "ct state invalid drop",
            "ct state established accept",
            "udp sport 68 udp dport 67 accept",
        ])

    def test_the_socket_is_the_firewall_port(self):
        s = unit(UNITS / "agentos-camnode.socket")
        self.assertEqual(s["Socket"]["ListenStream"], "0.0.0.0:8443")
        self.assertIn("camnode-firewall.service", s["Unit"]["Requires"])


class Service(unittest.TestCase):
    PATH = UNITS / "agentos-camnode.service"

    def test_own_uid_one_capability_no_network_namespace_of_its_own(self):
        s = unit(self.PATH)["Service"]
        self.assertEqual((s["User"], s["Group"]), ("camnode", "camnode"))
        self.assertEqual(s["CapabilityBoundingSet"], "CAP_SYS_BOOT")
        self.assertEqual(s["AmbientCapabilities"], "CAP_SYS_BOOT")
        for k, v in {"PrivateNetwork": "yes", "NoNewPrivileges": "yes", "DevicePolicy": "closed",
                     "ProtectSystem": "strict", "RestrictAddressFamilies": "AF_UNIX AF_NETLINK",
                     "MemoryDenyWriteExecute": "yes"}.items():
            self.assertEqual(s[k], v, k)

    def test_devices_are_the_node_s_only(self):
        self.assertEqual(sorted(multi(self.PATH, "Service", "DeviceAllow")), [
            "/dev/camnode/button r", "/dev/camnode/element rw", "/dev/camnode/slot-a rw", "/dev/camnode/slot-b rw"])
        cm4 = TREE / "board" / "cm4" / "overlay" / UNITS.relative_to(COMMON) / "agentos-camnode.service.d" / "board.conf"
        self.assertEqual(sorted(multi(cm4, "Service", "DeviceAllow")),
                         ["char-dma_heap rw", "char-media rw", "char-video4linux rw"])

    def test_a_failed_start_returns_to_the_old_slot(self):
        u = unit(self.PATH)["Unit"]
        self.assertEqual(u["FailureAction"], "reboot")
        self.assertEqual(unit(self.PATH)["Service"]["Restart"], "on-failure")

    def test_flags_name_the_data_and_boot_mounts(self):
        start = unit(self.PATH)["Service"]["ExecStart"]
        for f in ("-store /var/lib/camnode/bundles", "-slots /var/lib/camnode/slots",
                  "-autoboot /run/camboot/autoboot.txt", "-release /usr/share/agentos/camnode-release.pub"):
            self.assertIn(f, start)
        self.assertEqual(unit(UNITS / "var-lib-camnode.mount")["Mount"]["Options"], "nosuid,nodev,noexec,noatime")
        self.assertIn("noexec", unit(UNITS / "run-camboot.mount")["Mount"]["Options"])


class Config(unittest.TestCase):
    COMMON_CFG = (TREE / "configs" / "common.config").read_text().splitlines()

    def test_no_shell_busybox_getty_or_login(self):
        for line in ("BR2_SYSTEM_BIN_SH_NONE=y", "# BR2_PACKAGE_BUSYBOX is not set",
                     "# BR2_TARGET_GENERIC_GETTY is not set", "# BR2_TARGET_ENABLE_ROOT_LOGIN is not set",
                     "# BR2_TARGET_GENERIC_REMOUNT_ROOTFS_RW is not set", "BR2_TARGET_ROOTFS_EROFS=y"):
            self.assertIn(line, self.COMMON_CFG)
        every = "\n".join(p.read_text() for p in (TREE / "configs").glob("*.config"))
        for pkg in ("OPENSSH", "DROPBEAR", "BASH", "DASH", "MKSH", "ZSH", "TELNETD", "UTIL_LINUX_LOGIN",
                    "UTIL_LINUX_AGETTY", "SUDO", "AVAHI", "CHRONY", "NTP", "WPA_SUPPLICANT", "BLUEZ5_UTILS"):
            self.assertNotRegex(every, r"(?m)^BR2_PACKAGE_%s(_[A-Z0-9_]+)?=y" % pkg, pkg)

    def test_post_build_refuses_a_shell(self):
        text = (TREE / "board" / "common" / "post-build.sh").read_text()
        for name in ("sh", "bash", "busybox", "sshd", "dropbear", "login", "agetty", "getty", "sulogin"):
            self.assertIn("-name %s " % name, text + " ")

    def test_kernel_has_verity_and_no_radio_ipv6_or_devmem(self):
        frag = (TREE / "board" / "common" / "linux.fragment").read_text().splitlines()
        for line in ("CONFIG_DM_VERITY=y", "CONFIG_EROFS_FS=y", "CONFIG_NF_TABLES=y",
                     "# CONFIG_WIRELESS is not set", "# CONFIG_BT is not set", "# CONFIG_IPV6 is not set",
                     "# CONFIG_DEVMEM is not set", "# CONFIG_KEXEC is not set", "# CONFIG_KGDB is not set"):
            self.assertIn(line, frag)
        # systemd's kernel fixup turns IPv6 back on after the fragments; this tree's runs after it.
        mk = (TREE / "package" / "camnode-init" / "camnode-init.mk").read_text()
        self.assertIn("$(call KCONFIG_DISABLE_OPT,CONFIG_IPV6)", mk)


class Init(unittest.TestCase):
    SRC = TREE / "package" / "camnode-init" / "camnode-init.c"

    @unittest.skipUnless(shutil.which("gcc"), "gcc is not installed")
    def test_init_compiles_warning_free(self):
        with tempfile.TemporaryDirectory() as d:
            p = subprocess.run(["gcc", "-Wall", "-Wextra", "-Werror", "-O2", "-o", d + "/init", str(self.SRC)],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)

    def test_corruption_restarts_into_the_default_slot(self):
        src = self.SRC.read_text()
        self.assertIn("restart_on_corruption", src)
        self.assertIn("reboot(RB_AUTOBOOT)", src)
        self.assertIn('"erofs", MS_RDONLY', src)


class Workflow(unittest.TestCase):
    """The build step's filter must not hide the build's exit (Security on #3772): a build that fails
    before printing a line the filter keeps went green."""

    def run_step(self, stub):
        m = re.search(r"\n( +)- name: Build the .*\n +run: \|\n((?:\1    .*\n)+)", WORKFLOW.read_text())
        self.assertIsNotNone(m, "the build step")
        run = "\n".join(l.strip() for l in m.group(2).splitlines())
        with tempfile.TemporaryDirectory() as d:
            fake = pathlib.Path(d) / "build.sh"
            fake.write_text("#!/bin/bash\n" + stub + "\n")
            fake.chmod(0o755)
            script = run.replace("${{ matrix.board }}", "qemu").replace("image/camnode/build.sh", str(fake))
            # GitHub runs a step's script with `bash -e {0}`.
            return subprocess.run(["bash", "-e", "-c", script], env={"RUNNER_TEMP": d, "HOME": d, "PATH": "/usr/bin:/bin"},
                                  capture_output=True, text=True).returncode

    def test_a_failed_build_fails_the_step(self):
        self.assertNotEqual(self.run_step("echo 'sha256sum: WARNING: 1 computed checksum did NOT match'; exit 1"), 0)
        self.assertNotEqual(self.run_step("echo '>>> linux'; exit 2"), 0)

    def test_a_good_build_passes_the_step(self):
        self.assertEqual(self.run_step("exit 0"), 0)
        self.assertEqual(self.run_step("echo '>>> linux'; echo post-image: ok"), 0)


if __name__ == "__main__":
    unittest.main()
