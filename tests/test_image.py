# Tests for the device image build (P2-1): the build-time tree check, the release manifest,
# the counted boot entry, the boot health check, and the image's static configuration.
# The image itself is built and booted under Secure Boot by .github/workflows/image.yml.
# REQ: HW-1, HW-5, UPD-1, UPD-1a
import ast
import base64
import contextlib
import errno
import fnmatch
import hashlib
import json
import configparser
import io
import importlib.machinery
import importlib.util
import os
import re
import pathlib
import socket
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import unittest.mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMG = ROOT / "image"
MK = IMG / "mkosi"


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


check = load("image_check", MK / "mkosi.finalize")
# The tree check takes configuration only through steps owned by root (TREE_OWNER, #1543 Security R1);
# a test cannot make root-owned trees, so it takes its own uid in root's place.
check.TREE_OWNER = os.geteuid()
check.TREE_GROUP = os.getegid()
finish = load("image_finish", IMG / "finish_image.py")


def ini(path):
    # systemd and mkosi files repeat keys and use bare multi-line values.
    p = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
    p.optionxform = str
    p.read(path)
    return p


def write(root, rel, text="", mode=0o644):
    f = root / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text)
    f.chmod(mode)
    return f


# The image's no-dump files (IMG-nodump): copied into a test tree from mkosi.extra, except the
# page's unit, which image/build.sh installs from its command's directory.
NODUMP = ("usr/lib/systemd/coredump.conf.d/50-agentos-nodump.conf",
          "usr/lib/systemd/system.conf.d/50-agentos-nodump.conf",
          "usr/lib/sysctl.d/99-agentos-nodump.conf",
          "usr/lib/systemd/system/agentosd.service",
          "usr/lib/systemd/system/agentos-egress.service",
          "usr/lib/systemd/system/agentos-localui.service")
NODUMP_SRC = {"usr/lib/systemd/system/agentos-localui.service":
              ROOT / "broker/cmd/agentos-localui/agentos-localui.service"}


def nodump(root):
    for rel in NODUMP:
        write(root, rel, NODUMP_SRC.get(rel, MK / "mkosi.extra" / rel).read_text())
    noexec(root)


# The image's noexec mounts (UPD-10): its fstab and /tmp drop-in, copied from mkosi.extra into every
# tree nodump() makes, since the tree check refuses a tree without them.
NOEXEC_FILES = ("etc/fstab", "usr/lib/systemd/system/tmp.mount.d/50-agentos-noexec.conf")


def noexec(root):
    for rel in NOEXEC_FILES + MAIN_SIDE_FILES:
        write(root, rel, (MK / "mkosi.extra" / rel).read_text())


# The main side's mask over the keeper's state and the keeper's lift of it (STO-2c, D-154), which
# every agentos unit carries; the tree check refuses the units nodump() writes without them.
MAIN_SIDE_FILES = ("usr/lib/systemd/system/agentos-.service.d/50-main-side.conf",
                   "usr/lib/systemd/system/agentos-keeper-.service.d/90-keeper.conf")


BT_BLOCK = "usr/lib/modprobe.d/agentos-no-bluetooth.conf"


def without_exec_allow(test):
    """Patches out the boot-code allowlist for TEST, a test of another check that writes sysctl.d or
    modprobe.d files the allowlist refuses as unlisted (#2176); ExecAllowTest is the allowlist's."""
    patch = unittest.mock.patch.object(check, "exec_allow_violations", return_value=[])
    patch.start()
    test.addCleanup(patch.stop)


def bt_block(root):
    # The image's Bluetooth block (#1415); the tree check refuses a tree without it.
    write(root, BT_BLOCK, (MK / "mkosi.extra" / BT_BLOCK).read_text())


UPLINK_REL = "usr/lib/systemd/network/20-agentos-uplink.network"
RESOLVED_REL = "usr/lib/systemd/resolved.conf.d/50-agentos-uplink.conf"


def uplink(root):
    # The image's networkd and resolved files (#1478, #1479), copied from mkosi.extra.
    for rel in (UPLINK_REL, RESOLVED_REL):
        write(root, rel, (MK / "mkosi.extra" / rel).read_text())


# Debian trixie systemd's own .network files that turn on forwarding or multicast DNS when a link
# matches (#1478); the bodies are the keys that matter.
DISTRO_NETWORKS = {
    "80-container-ve.network": "[Match]\nKind=veth\nName=ve-*\n\n[Network]\nDHCPServer=yes\nIPMasquerade=both\n",
    "80-container-vz.network": "[Match]\nKind=bridge\nName=vz-*\n\n[Network]\nDHCPServer=yes\nIPMasquerade=both\n",
    "80-vm-vt.network": "[Match]\nKind=tun\nName=vt-*\n\n[Network]\nDHCPServer=yes\nIPMasquerade=both\n",
    "80-wifi-adhoc.network": "[Match]\nType=wlan\nWLANInterfaceType=ad-hoc\n\n[Network]\nMulticastDNS=yes\n",
}


class TreeCheckTest(unittest.TestCase):
    """HW-1: the image holds no per-install secret; V15: no socket files."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        write(self.root, "etc/machine-id", "uninitialized\n")
        write(self.root, "etc/hostname", "agentos\n")
        write(self.root, "usr/lib/agentos/agentosd", "\x7fELF", 0o755)
        (self.root / "var/lib/agentos").mkdir(parents=True)
        nodump(self.root)
        bt_block(self.root)
        uplink(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    # REQ: HW-8, ONB-2
    def test_disk_assembly_and_automount_tools_are_refused(self):
        # HOST-1a part 2 (hostdisk H11): an LVM activation, an array's resync, a bcache registration or
        # a ZFS import writes the disk, and zpool's import scan ignores udev; nothing automounts.
        self.assertEqual(check.assembly_violations(self.root), [])
        for rel in ("usr/sbin/lvm", "usr/sbin/mdadm", "usr/sbin/make-bcache", "usr/sbin/zpool", "usr/sbin/multipathd",
                    "usr/libexec/udisks2/udisksd", "usr/sbin/automount", "usr/lib/udev/bcache-register"):
            with self.subTest(rel=rel):
                f = write(self.root, rel, "", 0o755)
                self.assertIn(rel + ": ", " | ".join(check.violations(self.root)))
                f.unlink()
        self.assertEqual(check.assembly_violations(self.root), [])

    # REQ: DEV-2, CH-9
    def test_distro_network_files_are_refused(self):
        # #1478: nothing may turn on forwarding (agentos_inbound's forward drop, #2824, is the other layer). Debian's
        # container and VM files set IPMasquerade=both (which turns it on) and the ad-hoc one turns
        # on multicast DNS on a radio; the built tree must carry none of them live.
        for name, body in DISTRO_NETWORKS.items():
            for d in ("usr/lib/systemd/network", "lib/systemd/network", "etc/systemd/network", "run/systemd/network"):
                with self.subTest(name=name, dir=d):
                    f = write(self.root, "%s/%s" % (d, name), body)
                    self.assertIn(name, " ".join(check.violations(self.root)))
                    f.unlink()
        self.assertEqual(check.violations(self.root), [])

    # REQ: DEV-2, CH-9
    def test_any_other_network_file_is_refused(self):
        # The image configures the wired uplink and nothing else: a file the distro adds later (a
        # namespace or tunnel link, DHCP on host0) fails the build until it is masked or removed.
        write(self.root, "usr/lib/systemd/network/80-container-host0.network",
              "[Match]\nKind=veth\nName=host0\n\n[Network]\nDHCP=yes\n")
        self.assertIn("80-container-host0.network", " ".join(check.violations(self.root)))

    # REQ: DEV-2, CH-9
    def test_masked_network_files_pass(self):
        # networkd skips a file shadowed by a link to /dev/null or an empty file of the same name in
        # a higher-precedence directory.
        for i, name in enumerate(DISTRO_NETWORKS):
            write(self.root, "usr/lib/systemd/network/" + name, DISTRO_NETWORKS[name])
            mask = self.root / "etc/systemd/network" / name
            mask.parent.mkdir(parents=True, exist_ok=True)
            if i % 2:
                mask.symlink_to("/dev/null")
            else:
                mask.write_text("")
        self.assertEqual(check.violations(self.root), [])
        # A mask in a lower-precedence directory does not hide the live file.
        name = next(iter(DISTRO_NETWORKS))
        (self.root / "etc/systemd/network" / name).unlink()
        write(self.root, "etc/systemd/network/" + name, DISTRO_NETWORKS[name])
        (self.root / "usr/lib/systemd/network" / name).unlink()
        (self.root / "usr/lib/systemd/network" / name).symlink_to("/dev/null")
        self.assertIn(name, " ".join(check.violations(self.root)))

    # REQ: DEV-2, CH-9
    def test_uplink_must_not_forward_or_be_overridden(self):
        # The image's own file may not turn on forwarding or multicast DNS, a drop-in may not change
        # it, and an /etc file of the same name replaces it.
        base = (MK / "mkosi.extra" / UPLINK_REL).read_text()
        for key in ("IPMasquerade=ipv4", "IPForward=yes", "IPv4Forwarding=yes", "IPv6Forwarding=yes",
                    "MulticastDNS=resolve", "LLMNR=yes"):
            with self.subTest(key):
                write(self.root, UPLINK_REL, base + "\n[Network]\n%s\n" % key)
                self.assertIn(key.split("=")[0], " ".join(check.violations(self.root)))
        write(self.root, UPLINK_REL, base)
        d = write(self.root, "etc/systemd/network/20-agentos-uplink.network.d/50-x.conf", "[DHCPv4]\nSendHostname=yes\n")
        self.assertIn("50-x.conf", " ".join(check.violations(self.root)))
        d.unlink()
        e = write(self.root, "etc/systemd/network/20-agentos-uplink.network", "[Match]\nType=ether\n[Network]\nDHCP=yes\n")
        self.assertIn("SendHostname", " ".join(check.violations(self.root)))
        e.unlink()
        (self.root / UPLINK_REL).unlink()
        self.assertIn("20-agentos-uplink.network", " ".join(check.violations(self.root)))

    # REQ: DEV-2, CH-9
    def test_networkd_forwarding_globals_stay_off(self):
        # systemd 256+ also takes forwarding from networkd.conf.
        write(self.root, "etc/systemd/networkd.conf.d/50-x.conf", "[Network]\nIPv4Forwarding=yes\n")
        self.assertIn("IPv4Forwarding", " ".join(check.violations(self.root)))

    # REQ: DEV-2, CH-9
    def test_indented_key_is_still_read(self):
        # systemd strips leading whitespace, so an indented line is an assignment of its own, not a
        # continuation of the line above it.
        base = (MK / "mkosi.extra" / UPLINK_REL).read_text()
        write(self.root, UPLINK_REL, base.replace("DHCP=yes\n", "DHCP=yes\n    IPMasquerade=both\n"))
        self.assertIn("IPMasquerade is both", " ".join(check.violations(self.root)))
        # A trailing backslash continues a line in systemd; the check refuses any (#1496).
        write(self.root, UPLINK_REL, base + "\n[Network]\nIPForward=\\\nyes")
        self.assertIn("ends in a backslash", " ".join(check.violations(self.root)))
        # A comment is never an assignment.
        write(self.root, UPLINK_REL, base + "\n[Network]\n# IPForward=yes\n; IPMasquerade=both\n")
        self.assertEqual(check.violations(self.root), [])

    # REQ: DEV-2, CH-9
    def test_uplink_answers_and_advertises_nothing(self):
        # Proxy ARP or NDP, router advertisements, a DHCP server or LLDP would make the box answer
        # or advertise on the LAN; class and MUD identifiers tell the LAN what it is.
        base = (MK / "mkosi.extra" / UPLINK_REL).read_text()
        for section, line in (("Network", "EmitLLDP=nearest-bridge"), ("Network", "IPv4ProxyARP=yes"),
                              ("Network", "IPv6ProxyNDP=yes"), ("Network", "IPv6ProxyNDPAddress=2001:db8::1"),
                              ("Network", "IPv6SendRA=yes"), ("Network", "DHCPServer=yes"),
                              ("DHCPv4", "VendorClassIdentifier=agentos"), ("DHCPv4", "UserClass=agentos"),
                              ("DHCPv4", "MUDURL=https://example.invalid/mud"),
                              ("DHCPv6", "VendorClass=agentos"), ("DHCPv6", "UserClass=agentos"),
                              ("DHCPv6", "MUDURL=https://example.invalid/mud"),
                              ("LLDP", "MUDURL=https://example.invalid/mud")):
            with self.subTest(line):
                write(self.root, UPLINK_REL, base + "\n[%s]\n%s\n" % (section, line))
                self.assertIn(line.split("=")[0], " ".join(check.violations(self.root)))
        # #1496: the uplink holds the shipped keys only, so even a key set to no is refused.
        write(self.root, UPLINK_REL, base + "\n[Network]\nEmitLLDP=no\nIPv6SendRA=no\n")
        self.assertIn("EmitLLDP is no; not a key the image ships", " ".join(check.violations(self.root)))

    # REQ: DEV-2, CH-9
    def test_each_privacy_setting_is_required(self):
        # #1479: removing or flipping any one privacy line fails the build.
        base = (MK / "mkosi.extra" / UPLINK_REL).read_text()
        for section, line, flipped in (("[IPv6AcceptRA]", "Token=prefixstable", "Token=eui64"),
                                       ("[Network]", "IPv6PrivacyExtensions=yes", "IPv6PrivacyExtensions=no"),
                                       ("[DHCPv4]", "SendHostname=no", "SendHostname=yes"),
                                       ("[DHCPv6]", "SendHostname=no", "SendHostname=yes")):
            old = "%s\n%s\n" % (section, line) if section.startswith("[DHCP") else line + "\n"
            self.assertIn(old, base)
            key = line.split("=")[0]
            for new in (old.replace(line, flipped), old.replace(line + "\n", "")):
                with self.subTest(section=section, new=new):
                    write(self.root, UPLINK_REL, base.replace(old, new))
                    self.assertIn("%s %s is" % (section, key), " ".join(check.violations(self.root)))

    # REQ: DEV-2, CH-9
    def test_uplink_holds_exactly_the_shipped_keys(self):
        # #1496: a denylist misses old spellings, generic options and list keys, each of which
        # networkd honours. The uplink must hold the shipped (section, key) set, each key once with
        # its shipped value.
        base = (MK / "mkosi.extra" / UPLINK_REL).read_text()
        token = "[IPv6AcceptRA]\nToken=prefixstable\n"
        self.assertIn(token, base)
        for name, text, want in (
                ("ProxyARP alias", base + "\n[Network]\nProxyARP=yes\n", "[Network] ProxyARP is yes"),
                ("IPv6PrefixDelegation alias", base + "\n[Network]\nIPv6PrefixDelegation=yes\n",
                 "[Network] IPv6PrefixDelegation is yes"),
                ("[DHCP] VendorClassIdentifier", base + "\n[DHCP]\nVendorClassIdentifier=agentos\n",
                 "[DHCP] VendorClassIdentifier is agentos"),
                ("[DHCP] UserClass", base + "\n[DHCP]\nUserClass=agentos\n", "[DHCP] UserClass is agentos"),
                ("DHCPv4 SendOption", base + "\n[DHCPv4]\nSendOption=12:string:agentos\n", "[DHCPv4] SendOption is"),
                ("DHCPv4 SendVendorOption", base + "\n[DHCPv4]\nSendVendorOption=60:string:agentos\n",
                 "[DHCPv4] SendVendorOption is"),
                ("DHCPv6 SendOption", base + "\n[DHCPv6]\nSendOption=16:string:agentos\n", "[DHCPv6] SendOption is"),
                ("DHCPv6 SendVendorOption", base + "\n[DHCPv6]\nSendVendorOption=1:2:string:agentos\n",
                 "[DHCPv6] SendVendorOption is"),
                ("eui64 Token before prefixstable",
                 base.replace(token, "[IPv6AcceptRA]\nToken=eui64\nToken=prefixstable\n"),
                 "[IPv6AcceptRA] Token is set 2 times"),
                ("IPv6Token", base + "\n[Network]\nIPv6Token=eui64\n", "[Network] IPv6Token is eui64"),
                ("same key, same value, twice", base + "\n[DHCPv4]\nSendHostname=no\n",
                 "[DHCPv4] SendHostname is set 2 times"),
                ("unknown section", base + "\n[X-Agentos]\nNote=1\n", "[X-Agentos] Note is 1"),
                ("changed match", base.replace("Kind=!*\n", "Kind=!veth\n"), "[Match] Kind is !veth; must be !*"),
                ("line with no =", base + "\n[Network]\nIPMasquerade\n", "neither a section nor an assignment"),
                ("assignment before any section", "IPMasquerade=both\n" + base, "neither a section nor an assignment"),
                ("bad section header", base + "\n[Network\nIPMasquerade=both\n", "neither a section nor an assignment")):
            with self.subTest(name):
                write(self.root, UPLINK_REL, text)
                self.assertIn(want, " ".join(check.violations(self.root)))
        # The shipped file with its comments and blank lines changed still passes.
        write(self.root, UPLINK_REL, "\n".join(ln for ln in base.splitlines() if not ln.startswith("#")) + "\n")
        self.assertEqual(check.violations(self.root), [])

    # REQ: DEV-2, CH-9
    def test_bytes_systemd_reads_differently_are_refused(self):
        # #1496: where this check's parser and networkd's or resolved's can split or join lines
        # differently, a following line could hide from the check. Each case hides IPMasquerade=both.
        hide = "IPMasquerade=both\n"
        base = (MK / "mkosi.extra" / UPLINK_REL).read_text()
        cases = (("backslash then space", "[Network]\nDHCP=yes\\ \n" + hide, "ends in a backslash"),
                 ("double backslash", "[Network]\nDHCP=yes\\\\\n" + hide, "ends in a backslash"),
                 ("backslash on a comment", "[Network]\n# note \\\n" + hide, "ends in a backslash"),
                 ("NUL", "[Network]\nDHCP=yes\x00" + hide, "control"),
                 ("file separator", "[Network]\nDHCP=yes\x1c" + hide, "control"),
                 ("vertical tab", "[Network]\nDHCP=yes\x0b" + hide, "control"),
                 ("form feed", "[Network]\nDHCP=yes\x0c" + hide, "control"),
                 ("carriage return", "[Network]\nDHCP=yes\r" + hide, "control"),
                 ("tab", "[Network]\n\tDHCP=yes\n", "control"),
                 ("DEL", "[Network]\n# \x7f\n", "control"),
                 ("non-ASCII", "[Network]\n# caf\u00e9\n", "non-ASCII"),
                 ("next line", "[Network]\nDHCP=yes\u0085" + hide, "non-ASCII"))
        for name, tail, want in cases:
            with self.subTest(name, file="uplink"):
                write(self.root, UPLINK_REL, base + "\n" + tail)
                self.assertIn("%s: line" % check.UPLINK, " ".join(check.violations(self.root)))
                self.assertIn(want, " ".join(check.violations(self.root)))
        with self.subTest("BOM", file="uplink"):
            write(self.root, UPLINK_REL, "\ufeff" + base)
            self.assertIn("line 1: control, NUL, BOM or non-ASCII byte", " ".join(check.violations(self.root)))
        write(self.root, UPLINK_REL, base)
        # resolved.conf and networkd.conf files too: their LLMNR, multicast DNS and forwarding keys
        # are checked through the same parser.
        rbase = (MK / "mkosi.extra" / RESOLVED_REL).read_text()
        # Debian ships a main networkd.conf, so each drop-in is checked beside a clean one.
        clean = {"etc/systemd/networkd.conf": "[Network]\n#SpeedMeter=no\n"}
        for rel, text in clean.items():
            write(self.root, rel, text)
        for rel, text in ((RESOLVED_REL, "\ufeff" + rbase), (RESOLVED_REL, rbase + "# x\\\nLLMNR=yes\n"),
                          ("etc/systemd/resolved.conf", "[Resolve]\nDNS=192.0.2.1\x0b\n"),
                          ("etc/systemd/networkd.conf", "[Network]\nSpeedMeter=no\x00\n"),
                          ("etc/systemd/networkd.conf.d/50-x.conf", "[Network]\nSpeedMeter=no \\ \n")):
            with self.subTest(rel=rel, text=text):
                f = write(self.root, rel, text)
                self.assertIn("%s: line" % f.name, " ".join(check.violations(self.root)))
                if rel == RESOLVED_REL:
                    write(self.root, rel, rbase)
                elif rel in clean:
                    write(self.root, rel, clean[rel])
                else:
                    f.unlink()
        self.assertEqual(check.violations(self.root), [])

    # REQ: DEV-2, CH-9
    def test_network_links_other_than_a_mask_are_refused(self):
        # #1543 Security B1: networkd follows a link on the box, so a dangling one runs whatever later
        # appears at its target (/var/tmp is world-writable). Only a mask, a link to exactly
        # /dev/null, is read (as nothing); every other link is refused, whatever it points at.
        real = write(self.root, "usr/lib/agentos/80-x.network", DISTRO_NETWORKS["80-container-ve.network"])
        write(self.root, "usr/lib/agentos/empty", "")
        link = self.root / "etc/systemd/network/80-x.network"
        link.parent.mkdir(parents=True, exist_ok=True)
        for target in ("/usr/lib/agentos/80-x.network", "../../../usr/lib/agentos/80-x.network", str(real),
                       "/dev/zero", "/dev/null/../null", "/usr/lib/agentos/empty", "../../../dev/null",
                       "/usr/lib/agentos/missing", "/var/tmp/80-x.network", "../../../var/tmp/80-x.network"):
            with self.subTest(target):
                link.symlink_to(target)
                self.assertIn("etc/systemd/network/80-x.network: unreadable (etc/systemd/network/80-x.network "
                              "is a link to %s;" % target, " ".join(check.violations(self.root)))
                link.unlink()
        link.symlink_to("/dev/null")
        self.assertEqual(check.violations(self.root), [])
        link.unlink()

    # REQ: DEV-2, CH-9
    def test_sysctl_forwarding_stays_off(self):
        # #1478: a sysctl.d file may not turn routing on, for one device, a glob, or all of them.
        without_exec_allow(self)
        for line in ("net.ipv4.ip_forward = 1", "net.ipv4.conf.eth0.forwarding=1", "net/ipv4/conf/all/forwarding=1",
                     "net.ipv4.conf.*.forwarding = 1", "-net.ipv6.conf.all.forwarding = 1",
                     "net.ipv6.conf.default.forwarding=1", "net.ipv6.conf.eth0.force_forwarding=1",
                     "net.ipv4.conf.e*.forwarding=1",
                     # #1497: systemd-sysctl expands every glob against /proc/sys, so any glob key
                     # whose last component could be a forwarding key counts.
                     "net.ipv*.conf.enp*.forwarding=1", "net.ipv4.conf.enp1s0.forw*=1",
                     "net.ipv6.conf.enp1s0.force_forw?rding=1", "net.ipv4.ip_forwar[d]=1", "net.ipv4.*=1",
                     "n?t.ipv4.ip_forward=1", "*.ipv6.conf.all.forwarding=1", "net/ipv4/conf/enp1s0.100/forw*=1",
                     # glibc's glob negates [^x]; Python's fnmatch does not.
                     "n[^x]t.ipv4.ip_forward=1", "net.ipv4.conf.all.forwardin[^x]=1",
                     "net.ipv4.conf.all.forwarding = 2",
                     # #1508: systemd-sysctl normalises a key before it writes it (sysctl_normalize:
                     # empty and "." components go, as does ".." after a leading "/"), so the
                     # components are taken after that, not from the raw key.
                     "/net/ipv4/ip_forward=1", ".net.ipv4.ip_forward=1", "net/ipv4/ip_forward/=1",
                     "net.ipv4.ip_forward.=1", "//net/ipv4/conf/all/forwarding=1",
                     "-/net/ipv4/conf/all/forwarding=1", "- /net/ipv4/conf/all/forwarding=1",
                     "/net/ipv*/conf/*/forwarding=1", "net..ipv4..ip_forward=1", "net/./ipv4/ip_forward=1",
                     "/../net/ipv4/ip_forward=1",
                     # A trailing "." component goes too (path_simplify), so this writes ip_forward.
                     "net/ipv4/ip_forward/.=1",
                     # A glob key's glob() also takes \\ escapes and {a,b} alternatives.
                     "{net,zz}/ipv4/ip_forwar[d]=1", "net/ipv4/conf/al?/{forwarding,zz}=1",
                     "n\\et/ipv4/ip_forwar?=1", "ne?/ipv4/ip_forwar\\d=1"):
            with self.subTest(line):
                f = write(self.root, "etc/sysctl.d/90-x.conf", line + "\n")
                self.assertIn("forwarding must stay 0", " ".join(check.violations(self.root)))
                f.unlink()
        write(self.root, "usr/lib/sysctl.d/50-x.conf", "net.ipv4.ip_forward = 1\n")
        write(self.root, "etc/sysctl.d/90-x.conf", "net.ipv4.ip_forward = 0\nnet.ipv4.conf.all.forwarding=0\n")
        self.assertEqual(check.violations(self.root), [])
        # Globs that cannot reach a forwarding key pass, as does a forwarding glob set to 0.
        write(self.root, "etc/sysctl.d/90-x.conf", "net.ipv4.ip_forward = 0\nnet.ipv4.conf.*.rp_filter = 2\n-net.ipv4.conf.*.promote_secondaries = 1\n"
              "fs.protected_*=1\nkernel.*.forwarding=1\nnet.ipv*.conf.*.forw*=0\n")
        self.assertEqual(check.violations(self.root), [])
        # A later spelling of the same key, or a "-key" line (which unsets it), wins.
        write(self.root, "etc/sysctl.d/90-x.conf", "net.ipv4.ip_forward=1\n/net/ipv4/ip_forward/ = 0\n"
              "net.ipv4.conf.all.forwarding=1\n-net/ipv4/conf/all/forwarding\n")
        self.assertEqual(check.violations(self.root), [])

    # REQ: DEV-2, CH-9, C13
    def test_sysctl_lines_split_as_systemd_splits_them(self):
        # #1508: systemd-sysctl ends a line at LF, CR or NUL; Python's splitlines does not split at
        # NUL or CR the same way and also splits at \x0b, \x1c and U+2028. The check refuses those
        # bytes in every sysctl file, for the forwarding keys and for kernel.core_pattern alike.
        without_exec_allow(self)
        for key, val in (("net.ipv4.ip_forward", "0"), ("kernel.core_pattern", "|/usr/bin/false")):
            for name, text in (("NUL", "a.b=1\x00%s=9\n"), ("CR", "a.b=1\r%s=9\n"),
                               ("x1c", "%%s=9\na.b=1\x1c%%s=%s\n" % val), ("x0b", "%%s=9\na.b=1\x0b%%s=%s\n" % val),
                               ("U+2028", "%%s=9\na.b=1\u2028%%s=%s\n" % val), ("BOM", "\ufeff%s=9\n"),
                               ("x0c", "%%s=9\na.b=1\x0c%%s=%s\n" % val), ("U+0085", "%%s=9\na.b=1\x85%%s=%s\n" % val)):
                with self.subTest(key=key, byte=name):
                    f = write(self.root, "etc/sysctl.d/99-x.conf", text.replace("%s", key))
                    self.assertIn("etc/sysctl.d/99-x.conf: line", " ".join(check.violations(self.root)))
                    f.unlink()
        # A tab is space to both; a backslash continues no sysctl line.
        write(self.root, "etc/sysctl.d/99-x.conf", "\tnet.ipv4.ip_forward\t=\t0\n# x \\\nnet.ipv4.conf.all.forwarding = 0\n")
        self.assertEqual(check.violations(self.root), [])

    # REQ: DEV-2
    def test_resolved_answers_nothing_on_the_lan(self):
        # #1479: resolved's LLMNR and multicast DNS send single-label lookups onto the LAN, where any
        # host can answer. The image turns both off, and a later file may not turn them back on.
        (self.root / RESOLVED_REL).unlink()
        v = " ".join(check.violations(self.root))
        self.assertIn("LLMNR", v)
        self.assertIn("MulticastDNS", v)
        write(self.root, RESOLVED_REL, (MK / "mkosi.extra" / RESOLVED_REL).read_text())
        write(self.root, "etc/systemd/resolved.conf.d/90-x.conf", "[Resolve]\nLLMNR=resolve\n")
        self.assertIn("LLMNR", " ".join(check.violations(self.root)))

    def test_clean_tree_passes(self):
        self.assertEqual(check.violations(self.root), [])

    def test_empty_machine_id_passes(self):
        write(self.root, "etc/machine-id", "")
        self.assertEqual(check.violations(self.root), [])

    def test_baked_machine_id(self):
        write(self.root, "etc/machine-id", "0123456789abcdef0123456789abcdef\n")
        self.assertIn("etc/machine-id", " ".join(check.violations(self.root)))

    def test_generated_secret_files(self):
        for rel in ("var/lib/systemd/random-seed", "var/lib/systemd/credential.secret",
                    "etc/ssh/ssh_host_ed25519_key", "etc/ssl/private/ssl-cert-snakeoil.key",
                    "var/lib/dbus/machine-id"):
            with self.subTest(rel=rel):
                f = write(self.root, rel, "x")
                self.assertTrue(any(rel in v for v in check.violations(self.root)))
                f.unlink()

    def test_owner_state_must_not_ship(self):
        write(self.root, "etc/agentos/agentosd.env", "AGENTOS_OWNER=+15550100\n")
        self.assertIn("etc/agentos", " ".join(check.violations(self.root)))
        (self.root / "etc/agentos/agentosd.env").unlink()
        (self.root / "etc/agentos").rmdir()
        write(self.root, "var/lib/agentos/journal.log", "{}")
        self.assertIn("var/lib/agentos", " ".join(check.violations(self.root)))
        (self.root / "var/lib/agentos/journal.log").unlink()
        # It ships empty (WIFI-del-b2, #3235: the former loader's ap directory went with the loader);
        # even an empty directory in it is state.
        self.assertNotIn("var/lib/agentos", " ".join(check.violations(self.root)))
        (self.root / "var/lib/agentos/ap").mkdir()
        self.assertIn("var/lib/agentos", " ".join(check.violations(self.root)))
        (self.root / "var/lib/agentos/ap").rmdir()
        (self.root / "var/lib/agentos/drive-id").write_text("x")
        self.assertIn("var/lib/agentos", " ".join(check.violations(self.root)))

    def test_credstore_and_other_key_formats(self):
        write(self.root, "etc/credstore.encrypted/agentos.token", "x")
        write(self.root, "etc/backup/key.asc", "-----BEGIN PGP PRIVATE KEY BLOCK-----\n")
        write(self.root, "var/lib/age/key.txt", "AGE-SECRET-KEY-1SYNTHETICCANARY\n")
        v = " ".join(check.violations(self.root))
        for rel in ("etc/credstore.encrypted/agentos.token", "etc/backup/key.asc", "var/lib/age/key.txt"):
            self.assertIn(rel, v)

    def test_private_key_content(self):
        # A synthetic header only: no real key material in the repository.
        write(self.root, "etc/something/key.pem", "-----BEGIN PRIVATE KEY-----\nAAAA\n")
        write(self.root, "root/.ssh/id", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n")
        v = " ".join(check.violations(self.root))
        self.assertIn("etc/something/key.pem", v)
        self.assertIn("root/.ssh/id", v)

    def test_public_material_under_usr_share_is_not_scanned(self):
        write(self.root, "usr/share/doc/pkg/example.pem", "-----BEGIN PRIVATE KEY-----\n")
        self.assertEqual(check.violations(self.root), [])

    def test_socket_file_anywhere(self):
        p = self.root / "usr/lib/agentos/images/openclaw/run/agentos/broker.sock"
        p.parent.mkdir(parents=True)
        with socket.socket(socket.AF_UNIX) as s:
            s.bind(str(p))
        self.assertTrue(stat.S_ISSOCK(os.lstat(p).st_mode))
        self.assertIn("broker.sock", " ".join(check.violations(self.root)))

    # REQ: CH-7, HW-10
    def test_bluetooth_must_stay_blocked(self):
        # The MT7922's Bluetooth half (btusb, btmtk) would come up from the same package; nothing in
        # the spec uses it, so the image blocks both modules (#1415 security R1).
        (self.root / BT_BLOCK).unlink()
        v = " ".join(check.violations(self.root))
        self.assertIn("btusb", v)
        self.assertIn("btmtk", v)
        # An earlier install line for the module wins in kmod, so a drop-in sorted first undoes it.
        write(self.root, BT_BLOCK, (MK / "mkosi.extra" / BT_BLOCK).read_text())
        write(self.root, "etc/modprobe.d/00-bt.conf", "install btusb /sbin/modprobe --ignore-install btusb\n")
        self.assertIn("btusb", " ".join(check.violations(self.root)))
        # The same file name in /etc replaces the image's file.
        (self.root / "etc/modprobe.d/00-bt.conf").unlink()
        write(self.root, "etc/modprobe.d/" + BT_BLOCK.rsplit("/", 1)[1], "# emptied\n")
        self.assertIn("btmtk", " ".join(check.violations(self.root)))
        (self.root / "etc/modprobe.d" / BT_BLOCK.rsplit("/", 1)[1]).unlink()
        self.assertEqual(check.violations(self.root), [])

    # REQ: CH-7, HW-10
    def test_bluetooth_block_read_as_kmod_reads_lines(self):
        # #1528: each tree passes main's Python reader while kmod's first install for btusb is not a
        # refusal (the reviewer ran real kmod 31 on each; KmodDiffTest checks the reader against it).
        without_exec_allow(self)
        block = (MK / "mkosi.extra" / BT_BLOCK).read_bytes()
        over = "etc/modprobe.d/" + BT_BLOCK.rsplit("/", 1)[1]
        k1 = lambda pre: (over, block.replace(b"install btusb", pre + b"install btusb"), "btusb is not blocked")
        early = lambda line, why: ("etc/modprobe.d/00-bt.conf", line + b"\n", why)
        cases = {
            "K1": k1(b"# refuse both \\\n"),
            "K1b": k1(b"blacklist btmtk \\\n"),
            "K2": (over, block.replace(b"install btusb", b"#\x0cinstall btusb"), "btusb is not blocked"),
            "K3": (over, block.replace(b"install btusb", b"install\xc2\xa0btusb"), "btusb is not blocked"),
            "K4": early(b"install bt[^x]sb /sbin/modprobe --ignore-install btusb", "not modelled"),
            "K5": early(b"install bt[t-v]sb /sbin/modprobe --ignore-install btusb", "not modelled"),
            # kmod drops a backslash before any other byte, and splits words on space and tab only.
            "escape": early(b"install bt\\usb /sbin/modprobe --ignore-install btusb", "btusb is not blocked"),
            "vtab": early(b"install btusb /bin/false\x0b", "btusb is not blocked"),
        }
        for name, (rel, data, why) in cases.items():
            with self.subTest(name):
                write_b(self.root, rel.encode(), data)
                self.assertIn(why, " ".join(check.violations(self.root)))
                (self.root / rel).unlink()
        # What kmod reads as the block still passes: a joined line, tabs, and extra spaces.
        write_b(self.root, b"etc/modprobe.d/00-bt.conf", b"install\tbt-usb \\\n  /bin/false \t\ninstall btmtk  /usr/bin/false\n")
        self.assertEqual(check.violations(self.root), [])

    # REQ: CH-7, HW-10
    def test_no_install_line_loads_bluetooth_another_way(self):
        # Security R2 on #1543: another module's install or remove command can load btusb past its
        # own install line (modprobe -i skips install lines; insmod never reads them).
        without_exec_allow(self)
        for line in (b"install snd_x /sbin/modprobe --ignore-install btusb",
                     b"install snd_x /sbin/modprobe --ignore-install snd_x; /sbin/modprobe -i x",
                     b"install snd_x modprobe -qi snd_y", b"install snd_x modprobe --ignore-i snd_y",
                     b"install snd_x modprobe --ignore-install=1 snd_y",
                     b"install snd_x /sbin/insmod /lib/modules/x/bt.ko", b"install snd_x insmod y.ko",
                     b"remove snd_x /sbin/modprobe BTMTK", b"install btusb /bin/false; modprobe btusb",
                     b"install snd_x sh -c 'modprobe btusb'"):
            with self.subTest(line):
                write_b(self.root, b"usr/lib/modprobe.d/zz-x.conf", line + b"\n")
                self.assertIn("could load Bluetooth", " ".join(check.violations(self.root)))
        for line in (b"install snd_x /sbin/modprobe --ignore-remove snd_x", b"install snd_x /bin/true",
                     b"install snd_x modprobe -q snd_y --first-time", b"blacklist btusb",
                     b"install snd_x modprobe --ignore- snd_y"):
            with self.subTest(ok=line):
                write_b(self.root, b"usr/lib/modprobe.d/zz-x.conf", line + b"\n")
                self.assertEqual(check.violations(self.root), [])

    def test_kmod_reader(self):
        # REQ: CH-7, HW-10
        self.assertEqual(check.kmod_lines(b"a \\\nb\\c\\\\\nd\0e\nf\\"), [b"a bc\\", b"d", b"f\xff"])
        self.assertEqual(check.kmod_installs(b"install x-y[a-b] cmd\n  install z c\ninstall q\ninstall q \n"
                                             b"install ]x c\ninstall [x c\n#install c c\ninstall  w\t \tc d \n"),
                         [(b"x_y[a-b]", b"cmd"), (b"z", b"c"), (b"w", b" \tc d ")])

    def test_main_exits_nonzero_on_violation(self):
        write(self.root, "var/lib/systemd/random-seed", "x")
        r = subprocess.run([str(MK / "mkosi.finalize")], env=dict(os.environ, BUILDROOT=str(self.root)),
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("random-seed", r.stdout + r.stderr)


ENTRY = """title Debian GNU/Linux 13 (trixie)
version 6.12.48+deb13-amd64
sort-key debian
options console=tty0 console=ttyS0 rw quiet usrhash=%s
linux /debian/6.12.48+deb13-amd64/linux
initrd /debian/6.12.48+deb13-amd64/initrd
"""
H = "ab" * 32


class ReleaseTest(unittest.TestCase):
    """UPD-1a: a release is the /usr verity root hash plus its boot entry; UPD-1: entries are counted."""

    def test_entry_is_counted_and_titled(self):
        name, text = finish.counted_entry(ENTRY % H, "7", tries=3)
        self.assertEqual(name, "agentos_7+3.conf")
        self.assertIn("title AgentOS\n", text)
        self.assertIn("version 7\n", text)
        self.assertIn("usrhash=%s" % H, text)
        self.assertEqual(text.count("title "), 1)

    def test_entry_without_usrhash_is_refused(self):
        with self.assertRaises(ValueError):
            finish.counted_entry(ENTRY.replace(" usrhash=%s", "") % (), "7", tries=3)

    def test_manifest_binds_hash_and_entry(self):
        name, text = finish.counted_entry(ENTRY % H, "7", tries=3)
        m = finish.manifest("7", H, name, text, {"agentos_7.usr.raw": "11" * 32})
        self.assertEqual(m["version"], "7")
        self.assertEqual(m["usrhash"], H)
        self.assertEqual(m["boot_entry"]["name"], "agentos_7.conf")
        self.assertEqual(len(m["boot_entry"]["sha256"]), 64)
        self.assertEqual(m["files"], {"agentos_7.usr.raw": "11" * 32})

    def test_manifest_records_the_boot_payload(self):
        name, text = finish.counted_entry(ENTRY % H, "7", tries=3)
        boot = {"debian/6.12.48+deb13-amd64/linux": "22" * 32, "debian/6.12.48+deb13-amd64/initrd": "33" * 32}
        self.assertEqual(finish.boot_files(text), list(reversed(sorted(boot))))
        self.assertEqual(finish.manifest("7", H, name, text, {}, boot)["boot"], boot)

    def test_loader_conf_has_no_editor_or_enrollment(self):
        # F1: with the editor on, anyone at the keyboard could drop usrhash= or add init=/bin/sh.
        lines = finish.LOADER_CONF.splitlines()
        self.assertIn("timeout 0", lines)
        self.assertIn("editor no", lines)
        self.assertIn("secure-boot-enroll off", lines)

    def test_esp_allowlist(self):
        name, text = finish.counted_entry(ENTRY % H, "7", tries=3)
        clean = ["EFI/BOOT/BOOTX64.EFI", "EFI/BOOT/grubx64.efi", "EFI/BOOT/mmx64.efi",
                 "EFI/systemd/systemd-bootx64.efi", "loader/loader.conf", "loader/entries.srel",
                 "loader/entries/" + name, "debian/6.12.48+deb13-amd64/linux", "debian/6.12.48+deb13-amd64/initrd"]
        self.assertEqual(finish.esp_violations(clean, text), [])
        planted = clean + ["loader/random-seed", "loader/credentials/agentos.cred", "debian/other/initrd",
                           "loader/entries/debian-6.12.conf"]
        self.assertEqual(finish.esp_violations(planted, text),
                         ["debian/other/initrd", "loader/credentials/agentos.cred",
                          "loader/entries/debian-6.12.conf", "loader/random-seed"])

    def test_build_drops_debian_boot_files_and_seed_from_esp(self):
        # HW-1: the ESP is built from /efi and /boot (00-esp.conf). Debian's kernel package leaves
        # vmlinuz-, config- and System.map- in /boot, and bootctl install writes loader/random-seed,
        # which would ship identical on every drive. mkosi.conf's RemoveFiles drops them; mkosi
        # v24.3 runs it after copying the kernel to /usr/lib/modules and before the entry is installed.
        k = "6.12.111+deb13-amd64"
        pats = ini(MK / "mkosi.conf")["Content"]["RemoveFiles"].split()
        name, text = finish.counted_entry(ENTRY % H, "7", tries=3)
        with tempfile.TemporaryDirectory() as t:
            r = pathlib.Path(t)
            for f in ("efi/EFI/BOOT/BOOTX64.EFI", "efi/EFI/systemd/systemd-bootx64.efi", "efi/loader/loader.conf",
                      "efi/loader/entries.srel", "efi/loader/random-seed", "boot/vmlinuz-" + k,
                      "boot/config-" + k, "boot/System.map-" + k, "usr/lib/modules/%s/vmlinuz" % k):
                write(r, f, "x")
            for pat in pats:
                for f in r.glob(pat.lstrip("/")):
                    f.unlink()
            self.assertTrue((r / "usr/lib/modules" / k / "vmlinuz").exists())
            esp = sorted(str(f.relative_to(r / d)) for d in ("efi", "boot") for f in (r / d).rglob("*") if f.is_file())
            self.assertEqual(finish.esp_violations(esp, text), [], esp)

    def test_verify_usr_fails_when_veritysetup_refuses(self):
        with tempfile.TemporaryDirectory() as t:
            b = pathlib.Path(t)
            stub(b, "veritysetup", "exit 1")
            old = os.environ["PATH"]
            os.environ["PATH"] = "%s:%s" % (b, old)
            try:
                with self.assertRaises(ValueError):
                    finish.verify_usr("d", "t", H)
                stub(b, "veritysetup", '[ "$1" = verify ] && [ "$4" = "%s" ]' % H)
                finish.verify_usr("d", "t", H)
            finally:
                os.environ["PATH"] = old

    def test_manifest_refuses_a_mismatched_entry(self):
        name, text = finish.counted_entry(ENTRY % H, "7", tries=3)
        with self.assertRaises(ValueError):
            finish.manifest("7", "cd" * 32, name, text, {})


SWAPS_HEADER = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"


def stub(d, name, body):
    write(d, name, "#!/bin/sh\n" + body + "\n", 0o755)


def newc(names, trailer=True):
    """A newc cpio archive holding NAMES, each a one-byte file, as cpio --format=newc writes it."""
    out = b""
    for i, n in enumerate(list(names) + (["TRAILER!!!"] if trailer else [])):
        body = b"" if n == "TRAILER!!!" else b"x"
        name = n.encode() + b"\0"
        hdr = b"070701" + b"".join(b"%08X" % v for v in (i, 0o100644, 0, 0, 1, 0, len(body), 0, 0, 0, 0, len(name), 0))
        out += hdr + name
        out += b"\0" * (-len(out) % 4) + body
        out += b"\0" * (-len(out) % 4)
    return out


# The image's two initrds as mkosi builds them, Bluetooth aside: modules with their firmware, and
# the default initrd's systemd (#1475).
KMODS = ["usr", "usr/lib/modules/6.12.111+deb13-amd64/kernel/drivers/net/wireless/mediatek/mt76/mt7921/mt7921e.ko.xz",
         "usr/lib/modules/6.12.111+deb13-amd64/kernel/fs/btrfs/btrfs.ko.xz",
         "usr/lib/modules/6.12.111+deb13-amd64/kernel/drivers/media/pci/bt8xx/bt878.ko.xz",
         "usr/lib/firmware/mediatek/WIFI_RAM_CODE_MT7922_1.bin", "usr/lib/modules/6.12.111+deb13-amd64/modules.alias",
         "usr/lib/systemd/system/bluetooth.target", "usr/lib/systemd/systemd-udevd"]


class InitrdBluetoothTest(unittest.TestCase):
    """#1475: the initrd lacks the image's Bluetooth modprobe block, so it must not hold Bluetooth."""
    # REQ: CH-7, HW-10

    def test_clean_initrd_passes(self):
        self.assertEqual(finish.bluetooth_violations(finish.cpio_names(newc(KMODS))), [])
        self.assertEqual(finish.cpio_names(newc(KMODS)), KMODS)

    def test_any_bluetooth_module_firmware_or_service_fails(self):
        k = "usr/lib/modules/6.12.111+deb13-amd64/kernel/"
        for bad in (k + "drivers/bluetooth/btusb.ko.xz", k + "drivers/bluetooth/btmtk.ko.xz",
                    k + "drivers/bluetooth/btintel.ko.zst", k + "net/bluetooth/bluetooth.ko.xz",
                    k + "net/bluetooth/rfcomm/rfcomm.ko", k + "updates/btusb.ko", k + "extra/btmtk.ko.xz",
                    "usr/lib/firmware/mediatek/BT_RAM_CODE_MT7922_1_1_hdr.bin",
                    "usr/lib/firmware/mediatek/BT_RAM_CODE_MT7961_1_2_hdr.bin.zst",
                    "usr/lib/firmware/rtl_bt/rtl8852bu_fw.bin", "usr/lib/firmware/intel/ibt-0040-0041.sfi",
                    "usr/lib/firmware/brcm/BCM4350C5.hcd", "usr/lib/systemd/system/bluetooth.service",
                    "usr/libexec/bluetooth/bluetoothd", "usr/lib/udev/rules.d/90-Bluetooth.rules"):
            with self.subTest(bad):
                self.assertEqual(finish.bluetooth_violations(finish.cpio_names(newc(KMODS + [bad]))), [bad])

    def test_kernel_modules_initrd_excludes_every_bluetooth_module(self):
        # mkosi v24.3 (kmod.filter_kernel_modules) joins the regexes with | and re.search()es each
        # module path below usr/. Paths from the kernel-modules initrd of CI's build of #1509.
        rx = re.compile("|".join(ini(MK / "mkosi.conf")["Content"]["KernelModulesInitrdExclude"].split()))
        k = "lib/modules/6.12.111+deb13-amd64/kernel/"
        for m in ("drivers/bluetooth/btusb.ko.xz", "drivers/bluetooth/btmtk.ko.xz", "drivers/bluetooth/hci_uart.ko.xz",
                  "drivers/platform/x86/toshiba_bluetooth.ko.xz", "net/bluetooth/bluetooth.ko.xz",
                  "net/bluetooth/rfcomm/rfcomm.ko.xz", "updates/btusb.ko", "extra/btmtk.ko.zst",
                  # rsi_91x depends on btrsi, and mkosi adds a kept module's dependencies back.
                  "drivers/net/wireless/rsi/rsi_91x.ko.xz", "drivers/net/wireless/rsi/rsi_usb.ko.xz"):
            with self.subTest(m):
                self.assertTrue(rx.search(k + m))
                if "/rsi/" not in m:
                    self.assertTrue(finish.bluetooth_violations(["usr/" + k + m]))
        for m in ("fs/btrfs/btrfs.ko.xz", "drivers/media/pci/bt8xx/bt878.ko.xz", "drivers/nvme/host/nvme.ko.xz",
                  "drivers/net/wireless/mediatek/mt76/mt7921/mt7921e.ko.xz", "drivers/usb/host/xhci-pci.ko.xz",
                  "drivers/md/dm-verity.ko.xz"):
            with self.subTest(m):
                self.assertFalse(rx.search(k + m))

    def test_only_the_inert_target_is_allowed(self):
        self.assertEqual(finish.BT_ALLOWED, ("usr/lib/systemd/system/bluetooth.target",
                                             "usr/lib/systemd/user/bluetooth.target"))
        self.assertEqual(finish.bluetooth_violations(list(finish.BT_ALLOWED)), [])
        self.assertEqual(finish.bluetooth_violations(["etc/systemd/system/bluetooth.target"]),
                         ["etc/systemd/system/bluetooth.target"])

    def test_reads_concatenated_and_compressed_archives(self):
        import gzip
        import lzma
        early, main = newc(["kernel/x86/microcode/AuthenticAMD.bin"]), newc(KMODS + ["usr/lib/modules/k/kernel/drivers/bluetooth/btusb.ko"])
        for comp in (gzip.compress, lzma.compress):
            with self.subTest(comp.__module__):
                names = finish.cpio_names(early + b"\0" * 512 + comp(main))
                self.assertEqual(names[0], "kernel/x86/microcode/AuthenticAMD.bin")
                self.assertEqual(finish.bluetooth_violations(names), ["usr/lib/modules/k/kernel/drivers/bluetooth/btusb.ko"])
        # zstd goes through the zstd tool, which the build installs; the dispatch is the same.
        seen = []
        fake = {finish.ZSTD: lambda d: seen.append(d) or (main, b"")}
        self.assertIn("usr/lib/modules/k/kernel/drivers/bluetooth/btusb.ko",
                      finish.cpio_names(early + finish.ZSTD + b"frame", fake))
        self.assertEqual(seen, [finish.ZSTD + b"frame"])

    def test_reads_past_a_compressed_segment(self):
        # #1513: the kernel's unpack_to_rootfs keeps reading after a compressed segment, so an
        # archive appended to an xz or gzip stream is unpacked at boot and must be checked too.
        # REQ: CH-7, HW-10
        import gzip
        import lzma
        bt = "usr/lib/modules/k/kernel/drivers/bluetooth/btusb.ko"
        for comp in (gzip.compress, lzma.compress):
            with self.subTest(comp.__module__):
                names = finish.cpio_names(comp(newc(KMODS)) + newc([bt]))
                self.assertEqual(names, KMODS + [bt])
                self.assertEqual(finish.bluetooth_violations(names), [bt])
                # Two compressed streams back to back, the second holding Bluetooth.
                names = finish.cpio_names(comp(newc(KMODS)) + b"\0" * 4 + comp(newc([bt])))
                self.assertEqual(finish.bluetooth_violations(names), [bt])
                # Unreadable data after the stream fails closed.
                with self.assertRaises(ValueError):
                    finish.cpio_names(comp(newc(KMODS)) + b"junk")
                # A truncated stream fails closed.
                with self.assertRaises(ValueError):
                    finish.cpio_names(comp(newc(KMODS))[:-8])

    def test_unreadable_initrd_fails_closed(self):
        good = newc(KMODS)
        for bad in (b"BZh91AY&SY" + good, good + b"junk", good[:-200], newc(KMODS, trailer=False),
                    good[:60], good.replace(b"070701", b"0707zz", 1)):
            with self.subTest(bad[:12]):
                with self.assertRaises(ValueError):
                    finish.cpio_names(bad)

    def test_finish_checks_every_initrd_line(self):
        name, text = finish.counted_entry(ENTRY % H, "7", tries=3)
        self.assertEqual(finish.initrd_files(text), ["debian/6.12.48+deb13-amd64/initrd"])
        two = text + "initrd /agentos/6.12.48+deb13-amd64/kernel-modules.initrd\n"
        self.assertEqual(finish.initrd_files(two), ["debian/6.12.48+deb13-amd64/initrd",
                                                    "agentos/6.12.48+deb13-amd64/kernel-modules.initrd"])
        src = (IMG / "finish_image.py").read_text()
        self.assertIn("if p in initrd_files(text):\n            check_initrd(p, data_)", src)

    def test_check_initrd_exits_on_bluetooth_or_no_files(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            finish.check_initrd("agentos/initrd", newc(KMODS))
        self.assertIn("initrd agentos/initrd: 8 files, 3 kernel modules", out.getvalue())
        for data in (newc(KMODS + ["usr/lib/firmware/mediatek/BT_RAM_CODE_MT7922_1_1_hdr.bin"]), newc([])):
            with self.subTest(len(data)), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as e:
                    finish.check_initrd("agentos/initrd", data)
                self.assertIn("could bring up Bluetooth (#1475)", str(e.exception.code))


def manifest_dir(root, side, text):
    d = root / side
    d.mkdir()
    if text is not None:
        (d / "agentos_7.manifest").write_text(text)
    return d


class ManifestCompareTest(unittest.TestCase):
    """#1474: the reproduce job's package comparison must not pass on a missing or empty manifest."""
    # REQ: UPD-1a

    GOOD = json.dumps({"manifest_version": 1, "config": {}, "packages": [
        {"type": "deb", "name": "systemd", "version": "257.13-1~deb13u1", "architecture": "amd64"},
        {"type": "deb", "name": "kmod", "version": "34.2-2", "architecture": "amd64"}]})

    def run_compare(self, a, b):
        cm = load("compare_manifests", IMG / "compare_manifests.py")
        with tempfile.TemporaryDirectory() as t:
            t = pathlib.Path(t)
            da, db = manifest_dir(t, "release-a", a), manifest_dir(t, "release-b", b)
            with unittest.mock.patch("sys.stdout", new_callable=__import__("io").StringIO) as out:
                rc = cm.main(str(da), str(db))
            return rc, out.getvalue()

    def test_same_manifests_print_counts(self):
        rc, out = self.run_compare(self.GOOD, self.GOOD)
        self.assertEqual(rc, 0)
        self.assertIn("packages a=2 b=2", out)
        self.assertIn("same packages", out)

    def test_missing_empty_or_truncated_manifest_fails(self):
        bad = {"missing": None, "empty file": "", "truncated": self.GOOD[:40], "not an object": "[]",
               "no packages key": json.dumps({"manifest_version": 1}),
               "zero packages": json.dumps({"manifest_version": 1, "packages": []}),
               "nameless package": json.dumps({"packages": [{"version": "1"}]}),
               "versionless package": json.dumps({"packages": [{"name": "systemd"}]})}
        for what, text in bad.items():
            for a, b in ((text, self.GOOD), (self.GOOD, text), (text, text)):
                with self.subTest(what, a_bad=a is text):
                    rc, out = self.run_compare(a, b)
                    self.assertEqual(rc, 1)
                    self.assertIn("MISMATCH package manifest", out)
                    self.assertNotIn("same packages", out)

    def test_two_manifests_on_one_side_fail(self):
        cm = load("compare_manifests", IMG / "compare_manifests.py")
        with tempfile.TemporaryDirectory() as t:
            d = manifest_dir(pathlib.Path(t), "a", self.GOOD)
            (d / "other.manifest").write_text(self.GOOD)
            with self.assertRaises(ValueError):
                cm.packages(str(d))

    def test_differing_packages_are_reported(self):
        other = self.GOOD.replace("34.2-2", "34.2-3")
        rc, out = self.run_compare(self.GOOD, other)
        self.assertEqual(rc, 0)
        self.assertIn("package manifests differ", out)
        self.assertNotIn("same packages", out)

    def test_reproduce_job_fails_on_the_check(self):
        wf = (ROOT / ".github/workflows/image.yml").read_text()
        job = wf[wf.index("  reproduce:"):]
        self.assertIn("python3 image/compare_manifests.py rec/release-a rec/release-b || ok=0", job)
        self.assertIn("actions/checkout@", job)
        self.assertNotIn("*.manifest", job)
        # The check runs after ok=1 and before the job's verdict.
        self.assertLess(job.index("ok=1"), job.index("compare_manifests.py"))
        self.assertLess(job.index("compare_manifests.py"), job.index("[ $ok = 1 ]"))

    def test_an_e2e_fail_does_not_skip_compress_or_reproduce(self):
        # #1984: a red e2e step must leave the image upload and the reproducibility check running.
        wf = (ROOT / ".github/workflows/image.yml").read_text()
        job = wf[wf.index("  reproduce:"):]
        self.assertIn("if: ${{ !cancelled() }}", job[:job.index("steps:")])
        build = wf[:wf.index("  reproduce:")]
        step = build[build.index("- name: Compress the image"):]
        self.assertIn("if: ${{ !cancelled() && matrix.run == 'a' }}", step.splitlines()[1])


class HealthTest(unittest.TestCase):
    """UPD-1: boot-complete (and so blessing the entry) waits on this check."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(self.tmp.name)
        self.bin, self.lib, self.root = t / "bin", t / "lib", t / "root"
        stub(self.bin, "veritysetup", 'echo "/dev/mapper/usr is active and is in use."; echo "  type:        VERITY";'
                                      ' echo "  status:      verified"; echo "  root hash:   %s"' % H)
        self.findmnt("/dev/mapper/usr", "ro,relatime")
        stub(self.lib, "agentosd", "exit 0")
        stub(self.lib, "drive-id", "exit 0")
        stub(self.lib, "agentos-hostdisk", '[ "$*" = health ] && echo hostdisk=ok')
        stub(self.lib, "runsc", 'echo "runsc version release-20260928.0"')
        stub(self.lib, "gvisor-bin/gvisor_sentry", "exit 0")
        self.nft("drop")
        (self.lib / "images/openclaw/opt/openclaw").mkdir(parents=True)
        write(self.lib, "guest/launch.json", "{}")
        write(self.root, "proc/cmdline", "console=ttyS0 rw quiet usrhash=%s\n" % H)
        write(self.root, "proc/swaps", SWAPS_HEADER)
        write(self.root, "proc/sys/kernel/core_pattern", "|/usr/bin/false\n")
        write(self.root, "proc/sys/net/ipv4/ip_forward", "0\n")
        for v in ("ipv4", "ipv6"):
            for dev in ("all", "default", "lo", "eth0"):
                write(self.root, "proc/sys/net/%s/conf/%s/forwarding" % (v, dev), "0\n")
        write(self.root, "proc/sys/net/ipv6/conf/eth0/force_forwarding", "0\n")
        ev = self.root / "sys/firmware/efi/efivars"
        ev.mkdir(parents=True)
        (ev / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c").write_bytes(b"\x06\x00\x00\x00\x01")

    def nft(self, last):
        # The loaded input chain, as "nft list chain" prints it, ending in LAST.
        stub(self.bin, "nft", '[ "$*" = "list chain inet agentos_inbound input" ] || exit 1; '
                              'printf "table inet agentos_inbound {\\n\\tchain input {\\n\\t\\tiifname @exempt accept\\n'
                              '\\t\\t%s\\n\\t}\\n}\\n"' % last)

    def findmnt(self, source, options):
        stub(self.bin, "findmnt", 'case "$2" in SOURCE) echo "%s" ;; *) echo "%s" ;; esac' % (source, options))

    def tearDown(self):
        self.tmp.cleanup()

    def run_health(self, cwd=None):
        env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]),
                   AGENTOS_LIB=str(self.lib), AGENTOS_HEALTH_ROOT=str(self.root))
        return subprocess.run(["sh", str(MK / "mkosi.extra/usr/lib/agentos/health")], env=env,
                              capture_output=True, text=True, cwd=cwd)

    def test_pass(self):
        r = self.run_health()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("agentos-health: PASS", r.stdout)
        self.assertIn("secure_boot=on", r.stdout)
        self.assertIn("inbound=drop", r.stdout)
        self.assertIn("swap=off dumps=off", r.stdout)
        self.assertIn("forward=off", r.stdout)

    # REQ: HW-8
    def test_the_drive_must_be_found_among_the_disks(self):
        # HOST-1a part 2 (hostdisk H11): the health item is HostDisks().Health. With no drive the
        # host-disk rules leave the disk under the root "unknown", so the boot is never blessed.
        self.assertIn("hostdisk=ok", self.run_health().stdout)
        for body in ("echo hostdisk=drive-mismatch; exit 1", "echo hostdisk=root-disk-unknown; exit 1",
                     "echo hostdisk=ok; exit 1", "echo hostdisk=bad; exit 0", "exit 0"):
            with self.subTest(helper=body):
                stub(self.lib, "agentos-hostdisk", body)
                r = self.run_health()
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("agentos-health: FAIL the agentOS drive is not found among the disks", r.stdout)
        (self.lib / "agentos-hostdisk").unlink()
        r = self.run_health()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("(no answer)", r.stdout)

    def test_kernel_without_forced_forwarding_passes(self):
        # Kernels before 6.17 have no force_forwarding switch; its absence is not a failure.
        (self.root / "proc/sys/net/ipv6/conf/eth0/force_forwarding").unlink()
        r = self.run_health()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def cat_vanishes(self, path, gone=True):
        # A cat whose read of PATH (a sysctl under /proc/sys/net, glob allowed) fails as if the
        # device left between the health check's glob and its read; with GONE the file is removed
        # first (#2803).
        rm = 'rm -f "$1"; ' if gone else ''
        stub(self.bin, "cat", 'case "$1" in */proc/sys/net/%s) %sexit 1 ;; esac; exec /bin/cat "$@"'
             % (path, rm))

    def test_device_that_vanishes_mid_check_passes(self):
        # REQ: UPD-1. #2803: hwsim moved wlan1 into its own namespace between the glob and the read.
        for v in ("ipv4", "ipv6"):
            write(self.root, "proc/sys/net/%s/conf/wlan1/forwarding" % v, "0\n")
        write(self.root, "proc/sys/net/ipv6/conf/wlan1/force_forwarding", "0\n")
        self.cat_vanishes("*/conf/wlan1/*forwarding")
        r = self.run_health()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("forward=off", r.stdout)

    def test_device_present_but_unreadable_fails(self):
        # Only a switch that is gone is skipped: one still present that cannot be read fails.
        self.cat_vanishes("*/conf/eth0/*forwarding", gone=False)
        r = self.run_health()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("forwarding is on (/proc/sys/net/ipv4/conf/eth0/forwarding)", r.stdout)

    def test_renamed_device_is_reglobbed(self):
        # REQ: UPD-1. A rename looks like a vanish, and the new name was never globbed: eth0 with
        # forwarding on becomes eth1 during its read (the read fails) or just after it (the read
        # gave 1 and the switch is gone by the existence check). The fresh glob finds eth1.
        for name, act in (("during the read", "exit 1"), ("after the read", "echo 1; exit 0")):
            with self.subTest(name):
                self.tearDown()
                self.setUp()
                conf = self.root / "proc/sys/net/ipv4/conf"
                write(conf, "eth0/forwarding", "1\n")
                stub(self.bin, "cat", 'case "$1" in */ipv4/conf/eth0/forwarding) mv "%s/eth0" "%s/eth1"; %s ;; esac;'
                                      ' exec /bin/cat "$@"' % (conf, conf, act))
                r = self.run_health()
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("forwarding is on (/proc/sys/net/ipv4/conf/eth1/forwarding)", r.stdout)

    def test_missing_device_tree_fails_on_all(self):
        # With no ipv4/conf at all the device glob matches nothing, which is no device; the check
        # still fails, because "all" and "default" must exist.
        shutil.rmtree(self.root / "proc/sys/net/ipv4/conf")
        r = self.run_health()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("forwarding state unreadable (/proc/sys/net/ipv4/conf/all/forwarding)", r.stdout)

    def test_device_named_like_the_glob_is_reglobbed(self):
        # A device may be named "*", so a path equal to the glob is no device only when "all"
        # lacks the switch too. Here "all" has it, so "*" renamed mid-read gets the fresh glob.
        conf = self.root / "proc/sys/net/ipv6/conf"
        write(conf, "all/force_forwarding", "0\n")
        write(conf, "*/force_forwarding", "1\n")
        stub(self.bin, "cat", 'case "$1" in */ipv6/conf/[*]/force_forwarding) mv "%s/*" "%s/x"; exit 1 ;; esac;'
                              ' exec /bin/cat "$@"' % (conf, conf))
        r = self.run_health()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("forwarding is on (/proc/sys/net/ipv6/conf/x/force_forwarding)", r.stdout)

    def test_device_globs_ignore_the_working_directory(self):
        # REQ: UPD-1. A working directory holding a path that matches a device pattern must not
        # stand in for the real devices: eth0 with forwarding on still fails.
        for rel, sw in (("ipv4/conf/zz/forwarding", "ipv4/conf/eth0/forwarding"),
                        ("ipv6/conf/zz/forwarding", "ipv6/conf/eth0/forwarding"),
                        ("ipv6/conf/zz/force_forwarding", "ipv6/conf/eth0/force_forwarding")):
            with self.subTest(rel):
                self.tearDown()
                self.setUp()
                cwd = pathlib.Path(self.tmp.name) / "cwd"
                write(cwd, rel, "0\n")
                write(self.root, "proc/sys/net/" + sw, "1\n")
                r = self.run_health(cwd=cwd)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("forwarding is on (/proc/sys/net/%s)" % sw, r.stdout)

    def test_device_that_keeps_vanishing_fails(self):
        # One re-glob is the limit: a switch that is gone again on the second pass fails.
        conf = self.root / "proc/sys/net/ipv4/conf"
        write(conf, "wlan1/forwarding", "0\n")
        stub(self.bin, "cat", 'case "$1" in */ipv4/conf/wlan1/*) mv "%s/wlan1" "%s/wlan2"; exit 1 ;;'
                              ' */ipv4/conf/wlan2/*) mv "%s/wlan2" "%s/wlan1"; exit 1 ;; esac; exec /bin/cat "$@"'
             % ((conf,) * 4))
        r = self.run_health()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("forwarding switches keep vanishing", r.stdout)

    def test_global_switches_never_skipped(self):
        # ip_forward, "all" and "default" never vanish: a failed read of one fails, whether the
        # switch is still present or gone. ip_forward is read only by the global check; "all" and
        # "default" are first read by the device loop, so one gone there fails as missing.
        for path, gone, why in (("ipv4/ip_forward", True, "is on"), ("ipv4/ip_forward", False, "is on"),
                                ("ipv4/conf/all/forwarding", True, "state unreadable"),
                                ("ipv4/conf/all/forwarding", False, "is on"),
                                ("ipv6/conf/default/forwarding", True, "state unreadable"),
                                ("ipv6/conf/default/forwarding", False, "is on")):
            with self.subTest(path=path, gone=gone):
                self.tearDown()
                self.setUp()
                self.cat_vanishes(path, gone)
                r = self.run_health()
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("forwarding %s (/proc/sys/net/%s)" % (why, path), r.stdout)

    def test_secure_boot_off_is_reported_not_failed(self):
        (self.root / "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c").write_bytes(
            b"\x06\x00\x00\x00\x00")
        r = self.run_health()
        self.assertEqual(r.returncode, 0)
        self.assertIn("secure_boot=off", r.stdout)

    def test_fail_cases(self):
        cases = {
            "usr not verity": lambda: stub(self.bin, "veritysetup", "exit 4"),
            "usr writable": lambda: self.findmnt("/dev/mapper/usr", "rw,relatime"),
            "usr not from verity device": lambda: self.findmnt("/dev/sda3", "ro,relatime"),
            "usr is another release": lambda: write(self.root, "proc/cmdline", "usrhash=%s\n" % ("cd" * 32)),
            "entry names no release": lambda: write(self.root, "proc/cmdline", "rw quiet\n"),
            "launch.json missing": lambda: (self.lib / "guest/launch.json").unlink(),
            "boot drive ambiguous": lambda: stub(self.lib, "drive-id", "echo 'agentos-drive-id: FAIL'; exit 1"),
            "broker missing": lambda: (self.lib / "agentosd").unlink(),
            "broker broken": lambda: stub(self.lib, "agentosd", "exit 2"),
            "runsc broken": lambda: stub(self.lib, "runsc", "exit 1"),
            # #1701: runsc's STRICT sidecar policy refuses every machine start without it.
            "gVisor sentry missing": lambda: (self.lib / "gvisor-bin/gvisor_sentry").unlink(),
            "guest image missing": lambda: (self.lib / "images/openclaw/opt/openclaw").rmdir(),
            "inbound rules not loaded": lambda: stub(self.bin, "nft", "echo 'No such file or directory' >&2; exit 1"),
            "inbound chain ends in accept": lambda: self.nft("accept"),
            # IMG-nodump (HW-1): a swap device or a core dump that lands on disk is never blessed.
            "swap active": lambda: write(self.root, "proc/swaps", SWAPS_HEADER +
                                         "/dev/sda4  partition\t1048572\t0\t-2\n"),
            "swaps unreadable": lambda: (self.root / "proc/swaps").unlink(),
            "core dumps to a file": lambda: write(self.root, "proc/sys/kernel/core_pattern", "core\n"),
            "core dumps to systemd-coredump": lambda: write(
                self.root, "proc/sys/kernel/core_pattern", "|/usr/lib/systemd/systemd-coredump %P %u\n"),
            # #1478 (DEV-2, CH-9): the box never routes between the uplink and anything else.
            "ipv4 forwarding on": lambda: write(self.root, "proc/sys/net/ipv4/ip_forward", "1\n"),
            "ipv6 forwarding on": lambda: write(self.root, "proc/sys/net/ipv6/conf/all/forwarding", "1\n"),
            "forwarding unreadable": lambda: (self.root / "proc/sys/net/ipv4/ip_forward").unlink(),
            # IPv4 forwards by input device: ip_forward=0 with one device's switch on still routes.
            "ipv4 eth0 forwarding on": lambda: write(self.root, "proc/sys/net/ipv4/conf/eth0/forwarding", "1\n"),
            "ipv4 default forwarding on": lambda: write(self.root, "proc/sys/net/ipv4/conf/default/forwarding", "1\n"),
            "ipv4 all forwarding on": lambda: write(self.root, "proc/sys/net/ipv4/conf/all/forwarding", "1\n"),
            "ipv6 default forwarding on": lambda: write(self.root, "proc/sys/net/ipv6/conf/default/forwarding", "1\n"),
            "ipv6 eth0 forwarding on": lambda: write(self.root, "proc/sys/net/ipv6/conf/eth0/forwarding", "1\n"),
            "ipv6 eth0 forced forwarding": lambda: write(self.root, "proc/sys/net/ipv6/conf/eth0/force_forwarding", "1\n"),
            "ipv6 default unreadable": lambda: (self.root / "proc/sys/net/ipv6/conf/default/forwarding").unlink(),
            "ipv4 all unreadable": lambda: (self.root / "proc/sys/net/ipv4/conf/all/forwarding").unlink(),
        }
        for name, breakit in cases.items():
            with self.subTest(name):
                self.tearDown()
                self.setUp()
                breakit()
                r = self.run_health()
                self.assertEqual(r.returncode, 1, name)
                self.assertIn("agentos-health: FAIL", r.stdout)


class FallbackTest(unittest.TestCase):
    """UPD-1 (L3 blockers on #41): a failed health check reboots into the next counted try, with no
    owner action; at no tries left it reboots into the previous release if the drive has one, and
    stays up otherwise."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(self.tmp.name)
        self.bin, self.root, self.log = t / "bin", t / "root", t / "systemctl.log"
        (self.root / "sys/firmware/efi/efivars").mkdir(parents=True)
        stub(self.bin, "systemctl", 'echo "$*" >>"%s"' % self.log)

    def tearDown(self):
        self.tmp.cleanup()

    def run_fallback(self, entry=None, entries=None):
        efivars = self.root / "sys/firmware/efi/efivars"
        if entry is not None:
            (efivars / "LoaderBootCountPath-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
             ).write_bytes(b"\x06\x00\x00\x00" + ("\\loader\\entries\\%s\0" % entry).encode("utf-16le"))
        if entries is not None:
            # systemd-boot lists entry IDs (file names without the counter) NUL-separated, in UTF-16.
            (efivars / "LoaderEntries-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
             ).write_bytes(b"\x06\x00\x00\x00" + "".join(e + "\0" for e in entries).encode("utf-16le"))
        env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]), AGENTOS_HEALTH_ROOT=str(self.root))
        r = subprocess.run(["sh", str(MK / "mkosi.extra/usr/lib/agentos/fallback")], env=env,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r.stdout, self.log.read_text() if self.log.exists() else ""

    def test_reboots_while_tries_are_left(self):
        for entry in ("agentos_7+2-1.conf", "agentos_7+1-2.conf", "agentos_7+3.conf"):
            with self.subTest(entry):
                self.log.unlink(missing_ok=True)
                out, calls = self.run_fallback(entry)
                self.assertEqual(calls, "reboot\n")
                self.assertIn("rebooting", out)

    def test_reboots_into_the_previous_release_with_no_tries_left(self):
        # systemd-boot sorts a +0 entry last, so the reboot boots the other release (no default is set).
        out, calls = self.run_fallback("agentos_7+0-3.conf",
                                       ["agentos_8.conf", "agentos_7.conf", "auto-reboot-to-firmware-setup"])
        self.assertEqual(calls, "reboot\n")
        self.assertIn("rebooting into the previous release", out)

    def test_stays_up_with_no_tries_left_and_no_other_release(self):
        for entries in (["agentos_7.conf", "auto-reboot-to-firmware-setup"], None):
            with self.subTest(entries):
                out, calls = self.run_fallback("agentos_7+0-3.conf", entries)
                self.assertEqual(calls, "")
                self.assertIn("staying up", out)

    def test_stays_up_on_an_entry_with_no_counter(self):
        for entry in ("agentos_7.conf", None):
            with self.subTest(entry):
                out, calls = self.run_fallback(entry, ["agentos_8.conf", "agentos_7.conf"])
                self.assertEqual(calls, "")
                self.assertIn("staying up", out)


ESP_GUID = "9bb3f5ba-ad2b-4857-929b-cc8ff3ed410c"


class DriveIdTest(unittest.TestCase):
    """HW-1, HW-5 (L3 MUST on #41): every drive starts with the image's partition GUIDs, so boot is
    bound to the drive only while one partition carries the booted ESP's GUID; each drive then gets
    its own GUIDs."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(self.tmp.name)
        self.bin, self.root, self.log = t / "bin", t / "root", t / "sfdisk.log"
        ev = self.root / "sys/firmware/efi/efivars"
        ev.mkdir(parents=True)
        (self.root / "run").mkdir()
        (ev / "LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f").write_bytes(
            b"\x06\x00\x00\x00" + (ESP_GUID.upper() + "\0").encode("utf-16le"))
        for name, n in (("vda1", 1), ("vda6", 6), ("vdb1", 1), ("vdb6", 6)):
            write(self.root, "sys/class/block/%s/partition" % name, "%d\n" % n)
        write(self.root, "proc/sys/kernel/random/uuid", "0f0e0d0c-0b0a-4908-8706-050403020100\n")
        self.disks(("vda1 vda " + ESP_GUID, "vda2 vda aaaaaaaa-0000-4000-8000-000000000002",
                    "vda6 vda bbbbbbbb-0000-4000-8000-000000000006"))
        self.root_on("/dev/vda6")
        stub(self.bin, "sfdisk", 'echo "$*" >>"%s"' % self.log)
        stub(self.bin, "sync", 'echo "sync $*" >>"%s"' % self.log)

    def disks(self, partitions):
        lines = ["vda  ", "vdb  "] + list(partitions) + ["usr vda2 ", "usr vda3 "]
        stub(self.bin, "lsblk", "cat <<'E'\n%s\nE" % "\n".join(lines))

    def root_on(self, dev):
        stub(self.bin, "findmnt", 'echo "%s"' % dev)

    def tearDown(self):
        self.tmp.cleanup()

    def run_id(self, mode):
        env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]), AGENTOS_HEALTH_ROOT=str(self.root))
        return subprocess.run(["sh", str(MK / "mkosi.extra/usr/lib/agentos/drive-id"), mode], env=env,
                              capture_output=True, text=True)

    def sfdisk_calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_check_passes_on_one_drive(self):
        r = self.run_id("check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.sfdisk_calls(), [])

    def test_check_fails_when_another_disk_carries_the_esp_guid(self):
        self.disks(("vda1 vda " + ESP_GUID, "vda6 vda bbbbbbbb-0000-4000-8000-000000000006",
                    "vdb1 vdb " + ESP_GUID, "vdb6 vdb bbbbbbbb-0000-4000-8000-000000000006"))
        r = self.run_id("check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("agentos-drive-id: FAIL 2 partitions", r.stdout)

    # REQ: HW-8
    def test_a_hidden_host_disk_still_counts(self):
        # HOST-1a part 2: the 59 host-disk rule keeps blkid off a host disk, so udev (and lsblk) has no
        # PARTUUID for its partitions; drive-id reads that disk's table itself, read-only, and a
        # second agentOS drive attached as a host disk still fails the check.
        self.disks(("vda1 vda " + ESP_GUID, "vda6 vda bbbbbbbb-0000-4000-8000-000000000006", "vdb1 vdb ", "vdb6 vdb "))
        stub(self.bin, "sfdisk", 'echo "$*" >>"%s"; [ "$*" = "-d /dev/vdb" ] || exit 1; cat <<E\n'
             'label: gpt\n/dev/vdb1 : start=2048, size=1024, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=%s\n'
             '/dev/vdb6 : start=4096, size=1024, type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709, uuid=BBBBBBBB-0000-4000-8000-000000000006\nE'
             % (self.log, ESP_GUID.upper()))
        r = self.run_id("check")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("agentos-drive-id: FAIL 2 partitions", r.stdout)
        self.assertEqual(self.sfdisk_calls(), ["-d /dev/vdb"])
        # A host disk that is not a copy passes; one whose table cannot be read adds nothing.
        stub(self.bin, "sfdisk", 'echo "$*" >>"%s"; echo "/dev/vdb1 : start=2048, size=1024, uuid=1234ABCD-0000-4000-8000-000000000001"'
             % self.log)
        self.assertEqual(self.run_id("check").returncode, 0)
        stub(self.bin, "sfdisk", "exit 1")
        self.assertEqual(self.run_id("check").returncode, 0)
        # A dm device (its PKNAME a partition) is never read as a disk.
        self.disks(("vda1 vda " + ESP_GUID, "vda6 vda bbbbbbbb-0000-4000-8000-000000000006"))
        self.log.unlink()
        stub(self.bin, "sfdisk", 'echo "$*" >>"%s"' % self.log)
        self.assertEqual(self.run_id("check").returncode, 0)
        self.assertEqual(self.sfdisk_calls(), [])

    def test_check_fails_when_root_is_on_another_disk(self):
        self.root_on("/dev/vdb6")
        self.disks(("vda1 vda " + ESP_GUID, "vdb6 vdb bbbbbbbb-0000-4000-8000-000000000006"))
        r = self.run_id("check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not on the boot drive", r.stdout)

    def test_check_fails_without_the_loader_variable(self):
        next((self.root / "sys/firmware/efi/efivars").iterdir()).unlink()
        self.assertEqual(self.run_id("check").returncode, 1)

    def test_check_fails_on_an_unreadable_loader_variable(self):
        # An empty GUID must not match the rows lsblk prints with no PARTUUID (disks, dm devices).
        next((self.root / "sys/firmware/efi/efivars").iterdir()).write_bytes(b"\x06\x00\x00\x00")
        r = self.run_id("check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("unreadable", r.stdout)

    def test_assign_gives_the_drive_its_own_guids(self):
        r = self.run_id("assign")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        u = "0f0e0d0c-0b0a-4908-8706-050403020100"
        nr = "--no-reread --no-tell-kernel"
        self.assertEqual(self.sfdisk_calls(), ["%s --disk-id /dev/vda %s" % (nr, u),
                                               "%s --part-uuid /dev/vda 1 %s" % (nr, u),
                                               "%s --part-uuid /dev/vda 6 %s" % (nr, u),
                                               "sync -f %s/var/lib/agentos/drive-id" % self.root])
        self.assertTrue((self.root / "var/lib/agentos/drive-id").exists())

    def test_check_passes_later_in_the_boot_that_assigned(self):
        # #1716: udev shows the new GUIDs at once while the boot loader still names the old ESP
        # GUID; a broker or vault start later in that boot (the claim restarts the vault) passes.
        self.assertEqual(self.run_id("assign").returncode, 0)
        self.disks(("vda1 vda 11111111-0000-4000-8000-000000000001", "vda2 vda aaaaaaaa-0000-4000-8000-000000000002",
                    "vda6 vda 66666666-0000-4000-8000-000000000006"))
        r = self.run_id("check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_the_assign_record_admits_no_other_drive(self):
        self.assertEqual(self.run_id("assign").returncode, 0)
        new = ("vda1 vda 11111111-0000-4000-8000-000000000001", "vda6 vda 66666666-0000-4000-8000-000000000006")
        # A fresh copy attached afterwards carries the old GUID: two drives again, root on the first.
        self.disks(new + ("vdb1 vdb " + ESP_GUID, "vdb6 vdb bbbbbbbb-0000-4000-8000-000000000006"))
        r = self.run_id("check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not on the boot drive", r.stdout)
        # Root moved off the recorded disk.
        self.disks(new + ("vdb6 vdb bbbbbbbb-0000-4000-8000-000000000006",))
        self.root_on("/dev/vdb6")
        self.assertEqual(self.run_id("check").returncode, 1)

    def test_the_assign_record_counts_only_for_its_own_boot_guid(self):
        write(self.root, "run/agentos-drive-id", "cccccccc-0000-4000-8000-00000000000c vda1 vda\n")
        self.disks(("vda1 vda 11111111-0000-4000-8000-000000000001", "vda6 vda bbbbbbbb-0000-4000-8000-000000000006"))
        r = self.run_id("check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAIL 0 partitions", r.stdout)
        # Nor for a partition that is no longer on the recorded disk.
        write(self.root, "run/agentos-drive-id", "%s vda1 vdb\n" % ESP_GUID)
        self.assertEqual(self.run_id("check").returncode, 1)

    def test_assign_writes_nothing_when_the_check_fails(self):
        self.disks(("vda1 vda " + ESP_GUID, "vda6 vda bbbbbbbb-0000-4000-8000-000000000006",
                    "vdb1 vdb " + ESP_GUID))
        r = self.run_id("assign")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.sfdisk_calls(), [])
        self.assertFalse((self.root / "var/lib/agentos/drive-id").exists())
        self.assertFalse((self.root / "run/agentos-drive-id").exists())


class ConfigTest(unittest.TestCase):
    def test_drive_gets_its_own_guids_once_after_a_blessed_boot(self):
        u = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentos-drive-id.service")
        self.assertIn("boot-complete.target", u["Unit"]["Requires"])
        self.assertIn("systemd-bless-boot.service", u["Unit"]["After"])
        self.assertEqual(u["Unit"]["ConditionPathExists"], "!/var/lib/agentos/drive-id")
        self.assertEqual(u["Service"]["ExecStart"], "/usr/lib/agentos/drive-id assign")
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text()
        self.assertIn("enable agentos-drive-id.service", preset)
        self.assertIn("fdisk", ini(MK / "mkosi.conf")["Content"]["Packages"].split())
        report = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentos-boot-report.service")
        self.assertIn("agentos-drive-id.service", report["Unit"]["After"])

    def test_a_try_that_never_reaches_health_reboots(self):
        # L3 blocker 2 on #41 (UPD-1): a kernel panic reboots, and emergency or rescue mode, in the
        # initrd or the host, runs the fallback first. The default initrd has no mkosi.extra, so the
        # drop-ins come as systemd.unit-dropin credentials on the command line, which both read.
        args = ini(MK / "mkosi.conf")["Content"]["KernelCommandLine"].split()
        self.assertIn("panic=10", args)
        creds = dict(a.split("=", 1)[1].split(":", 1) for a in args
                     if a.startswith("systemd.set_credential_binary="))
        for unit in ("emergency.service", "rescue.service"):
            with self.subTest(unit):
                d = configparser.ConfigParser(interpolation=None)
                d.read_string(base64.b64decode(creds["systemd.unit-dropin." + unit]).decode())
                cmd = d["Service"]["ExecStartPre"]
                self.assertTrue(cmd.startswith("-bash -c '") and cmd.endswith("'"), cmd)
                with tempfile.TemporaryDirectory() as t:
                    t = pathlib.Path(t)
                    log, fallback = t / "log", t / "fallback"
                    stub(t, "systemctl", 'echo "systemctl $*" >>"%s"' % log)
                    script = cmd[len("-bash -c '"):-1].replace("/usr/lib/agentos/fallback", str(fallback))
                    env = dict(os.environ, PATH="%s:%s" % (t, os.environ["PATH"]))
                    subprocess.run(["bash", "-c", script], env=env, check=True)  # initrd: no fallback
                    self.assertEqual(log.read_text(), "systemctl reboot\n")
                    log.unlink()
                    stub(t, "fallback", 'echo "fallback" >>"%s"' % log)
                    subprocess.run(["bash", "-c", script], env=env, check=True)  # host: tries-aware
                    self.assertEqual(log.read_text(), "fallback\n")

    def test_broker_runs_only_on_the_boot_drive(self):
        u = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentosd.service")
        self.assertEqual(u["Service"]["ExecStartPre"], "/usr/lib/agentos/drive-id check")

    def test_the_modem_roles_directory_exists_before_the_bridge_starts(self):
        # G1-e2e: agentosd records the SIM setup binds in agentos-modem's roles file, and the bridge
        # sees it only through its bind of the roles directory, which it skips when the directory is
        # missing. agentosd's unit makes the directory before the bridge's starts (After=).
        u = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentosd.service")["Service"]
        self.assertEqual(u["StateDirectory"], "agentos/modem")
        roles = re.search(r'"modem-roles", "([^"]+)"', (ROOT / "broker/cmd/agentosd/main.go").read_text()).group(1)
        self.assertEqual(os.path.dirname(roles), "/var/lib/agentos/modem")
        m = ini(ROOT / "broker/cmd/agentos-modem/agentos-modem.service")
        self.assertIn("agentosd.service", m["Unit"]["After"].split())
        self.assertEqual(m["Service"]["BindReadOnlyPaths"], "-/var/lib/agentos/modem")
        self.assertIn("-roles " + roles, m["Service"]["ExecStart"])

    def test_nothing_writes_the_hardware_clock(self):
        # L3 SHOULD on #41 (HW-8, HOST-1b): timesyncd's sync turns on the kernel's 11-minute RTC
        # update. chrony with rtcsync off comes with HOST-1b; until then the image has no time sync.
        self.assertNotIn("systemd-timesyncd", ini(MK / "mkosi.conf")["Content"]["Packages"].split())
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text()
        self.assertNotIn("timesyncd", preset)

    def test_secure_boot_chain_is_distribution_signed(self):
        # HW-5: Microsoft-signed shim -> Debian-signed systemd-boot -> Debian-signed kernel.
        c = ini(MK / "mkosi.conf")
        self.assertEqual(c["Content"]["Bootloader"], "systemd-boot")
        self.assertEqual(c["Content"]["ShimBootloader"], "signed")
        self.assertEqual(c["Content"]["UnifiedKernelImages"], "no")
        pk = c["Content"]["Packages"].split()
        for p in ("shim-signed", "systemd-boot-efi-amd64-signed", "linux-image-amd64"):
            self.assertIn(p, pk)
        self.assertNotIn("SecureBootKey", c["Content"])

    def test_reproducibility_inputs_are_pinned(self):
        c = ini(MK / "mkosi.conf")
        self.assertRegex(c["Distribution"]["Mirror"], r"^https://snapshot\.debian\.org/archive/debian/\d{8}T\d{6}Z/?$")
        self.assertRegex(c["Output"]["Seed"], r"^[0-9a-f-]{36}$")
        b = (IMG / "build.sh").read_text()
        self.assertIn("SOURCE_DATE_EPOCH", b)
        self.assertIn("-trimpath", b)

    def test_build_ships_gvisors_sidecars_beside_runsc(self):
        # REQ: RES-4
        # #1701: runsc of this release starts no sandbox without its sidecars in gvisor-bin/ beside
        # it (STRICT), so the build installs that directory as CI's machine tests do.
        b = (IMG / "build.sh").read_text()
        self.assertIn('install -m 0755 "$OUT/gvisor/runsc" "$STAGE/usr/lib/agentos/runsc"', b)
        self.assertIn('install -m 0755 "$OUT"/gvisor/gvisor-bin/* "$STAGE/usr/lib/agentos/gvisor-bin/"', b)
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("install -m 0755 /tmp/gv/gvisor-bin/* /usr/local/bin/gvisor-bin/", ci)

    def test_snapshot_sources_outlive_their_valid_until(self):
        # The pinned snapshot's Release files expire a week after the timestamp; apt must still read
        # them (signatures checked), while live security.debian.org keeps the expiry check.
        mirror = ini(MK / "mkosi.conf")["Distribution"]["Mirror"].rstrip("/")
        text = (MK / "mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources").read_text()
        stanzas = [dict(l.split(": ", 1) for l in s.splitlines() if l and not l.startswith("#"))
                   for s in text.split("\n\n")]
        stanzas = [s for s in stanzas if s]
        snap = [s for s in stanzas if s["URIs"].rstrip("/") == mirror]
        live = [s for s in stanzas if s["URIs"].rstrip("/") != mirror]
        self.assertEqual(len(snap), 1)
        self.assertEqual(snap[0]["Suites"].split(), ["trixie", "trixie-updates"])
        self.assertEqual(snap[0]["Check-Valid-Until"], "no")
        self.assertEqual([s["Suites"] for s in live], ["trixie-security"])
        self.assertNotIn("Check-Valid-Until", live[0])
        for s in stanzas:
            self.assertEqual(s["Signed-By"], "/usr/share/keyrings/debian-archive-keyring.gpg")
            self.assertNotIn("Trusted", s)

    # REQ: HW-10
    def test_packages_come_from_the_pinned_snapshot(self):
        # Only Debian's main component, in mkosi.conf and in the build's apt sources, from the same
        # snapshot; non-free-firmware went with the radio's firmware (D-178, #1415).
        c = ini(MK / "mkosi.conf")
        self.assertEqual(c["Distribution"]["Repositories"].split(","), ["main"])
        mirror = c["Distribution"]["Mirror"].rstrip("/")
        text = (MK / "mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources").read_text()
        stanzas = [dict(l.split(": ", 1) for l in s.splitlines() if l and not l.startswith("#"))
                   for s in text.split("\n\n")]
        stanzas = [s for s in stanzas if s]
        for s in stanzas:
            self.assertEqual(s["Components"].split(), ["main"], s["URIs"])
        self.assertEqual([s["URIs"].rstrip("/") for s in stanzas if "trixie" in s["Suites"].split()], [mirror])
        # Every packaged line in Packages= is a package name: an indented comment would become one.
        self.assertFalse([p for p in c["Content"]["Packages"].split() if not re.fullmatch(r"[a-z0-9][a-z0-9.+-]+", p)])

    def test_ab_usr_slots(self):
        # UPD-1: two equal /usr slots plus verity, so an update writes the idle one.
        parts = [ini(f)["Partition"] for f in sorted((MK / "mkosi.repart").glob("*.conf"))]
        usr = [p for p in parts if p["Type"] == "usr"]
        ver = [p for p in parts if p["Type"] == "usr-verity"]
        self.assertEqual(len(usr), 2)
        self.assertEqual(len(ver), 2)
        for group in (usr, ver):
            self.assertEqual(group[0]["SizeMinBytes"], group[0]["SizeMaxBytes"])
            self.assertEqual({g["SizeMaxBytes"] for g in group}, {group[0]["SizeMaxBytes"]})
            self.assertEqual(group[1]["Label"], "_empty")
            self.assertNotIn("Minimize", group[0])
        self.assertEqual(parts[-1]["Type"], "root")

    def test_root_grows_to_fill_the_drive(self):
        p = ini(MK / "mkosi.extra/usr/lib/repart.d/50-root.conf")["Partition"]
        self.assertEqual(p["Type"], "root")
        self.assertEqual(p["GrowFileSystem"], "yes")

    def test_health_gates_boot_complete(self):
        u = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentos-health.service")
        self.assertIn("boot-complete.target", u["Unit"]["Before"])
        self.assertEqual(u["Install"]["RequiredBy"], "boot-complete.target")
        # UPD-1 (L3 blocker on #41): a failed or hung check reboots into the next try.
        self.assertEqual(u["Unit"]["OnFailure"], "agentos-fallback.service")
        self.assertIn("TimeoutStartSec", u["Service"])
        f = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentos-fallback.service")
        self.assertEqual(f["Service"]["ExecStart"], "/usr/lib/agentos/fallback")
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text()
        self.assertIn("enable agentos-health.service", preset)

    def test_inbound_rules_load_before_any_listener_and_fail_closed(self):
        # DEV-net-e 2a (DEV-2 In): the drop loads before the network comes up, and nothing that
        # listens or brings a link up starts without it.
        u = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentos-inbound.service")
        self.assertEqual(u["Unit"]["DefaultDependencies"], "no")
        self.assertIn("network-pre.target", u["Unit"]["Before"].split())
        self.assertIn("network-pre.target", u["Unit"]["Wants"].split())
        self.assertEqual(u["Service"]["Type"], "oneshot")
        self.assertEqual(u["Service"]["RemainAfterExit"], "yes")
        self.assertEqual(u["Service"]["ExecStart"], "/usr/sbin/nft -f /usr/lib/agentos/inbound.nft")
        self.assertEqual(u["Install"]["WantedBy"], "sysinit.target")
        self.assertTrue((MK / "mkosi.extra/usr/lib/agentos/inbound.nft").is_file())
        for unit in ("agentosd.service", "systemd-networkd.service", "systemd-resolved.service"):
            with self.subTest(unit):
                f = MK / "mkosi.extra/usr/lib/systemd/system" / unit
                if unit != "agentosd.service":
                    f = f.parent / (unit + ".d") / "agentos-inbound.conf"
                d = ini(f)["Unit"]
                self.assertIn("agentos-inbound.service", d["Requires"].split())
                self.assertIn("agentos-inbound.service", d["After"].split())
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text().split("\n")
        self.assertIn("enable agentos-inbound.service", preset)
        # Debian's nftables.service flushes the whole ruleset from /etc/nftables.conf.
        self.assertIn("disable nftables.service", preset)
        self.assertIn("nftables", ini(MK / "mkosi.conf")["Content"]["Packages"].split())

    def test_root_is_locked(self):
        self.assertEqual(ini(MK / "mkosi.conf")["Content"]["RootPassword"], "hashed:!")

    def test_broker_flags_exist(self):
        # MUST 1 on #41: a flag agentosd lacks makes it exit at start and loop on restart.
        src = (ROOT / "broker/cmd/agentosd").glob("*.go")
        defined = set()
        for f in src:
            defined |= set(re.findall(r'flag\.\w+\([^,]+,\s*"([\w-]+)"', f.read_text()))
        exe = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentosd.service")["Service"]["ExecStart"]
        used = re.findall(r"(?:^|\s)-([a-z][\w-]*)", exe)
        self.assertTrue(used)
        self.assertEqual(sorted(set(used) - defined), [])

    # REQ: CLK-1
    def test_broker_calls_the_kernel_as_the_owner_side(self):
        # #2682: the broker calls the kernel's owner socket as the one peer the kernel's unit admits
        # there, and calls only the kernel's uid; ordered after the kernel's unit, never requiring it.
        units = MK / "mkosi.extra/usr/lib/systemd/system"
        broker = exec_args(units / "agentosd.service")
        unlock = exec_args(units / "agentos-keeper-kernel.service")
        kernel = unlock[unlock.index("--") + 1:]
        self.assertEqual(arg(broker, "kernel-owner"), arg(kernel, "owner-sock"))
        self.assertEqual(arg(broker, "kernel-owner-uid"), arg(kernel, "owner-uid"))
        self.assertEqual(arg(broker, "kernel-uid"), arg(unlock, "uid"))
        u = ini(units / "agentosd.service")["Unit"]
        self.assertIn("agentos-keeper-kernel.service", u["After"].split())
        for key in ("Requires", "Wants", "BindsTo", "Requisite"):
            self.assertNotIn("agentos-keeper-kernel.service", u.get(key, "").split())

    def test_broker_starts_when_onboarding_writes_its_settings(self):
        p = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentosd.path")
        self.assertEqual(p["Path"]["PathExists"], "/etc/agentos/agentosd.env")
        self.assertEqual(p["Path"]["Unit"], "agentosd.service")
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text()
        self.assertIn("enable agentosd.path", preset)

    def test_broker_and_its_children_cannot_gain_privileges(self):
        # P3-4b-3r-confine-r3 (LOOP-7, #588 Security R1): no child agentosd starts gains privileges
        # through a setuid or file-capability binary; the audit is agentosd ASSUMPTIONS L7-6.
        u = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentosd.service")
        self.assertEqual(u["Service"]["NoNewPrivileges"], "yes")

    # REQ: CAP-11, CAP-8
    def test_broker_registers_the_codex_image_and_offers_worker_tools(self):
        # #1721: provider_run is offered only when worker tools are on (-worker-image names a
        # registered image), and a Codex run starts from the image the declaration names, which
        # -image must register at the path build.sh writes it to.
        exe = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentosd.service")["Service"]["ExecStart"]
        images = dict(v.split("=", 1) for v in re.findall(r"(?:^|\s)-image\s+(\S+)", exe))
        decl = re.search(r'"codex": \{\s*ID: "codex",.*?Image: "(\w+)"', (ROOT / "broker/provagent/declare.go").read_text(), re.S)
        self.assertEqual(images.get(decl.group(1)), "/usr/lib/agentos/images/codex")
        worker = re.search(r"(?:^|\s)-worker-image\s+(\S+)", exe)
        self.assertIsNotNone(worker)
        self.assertIn(worker.group(1), images)
        b = (IMG / "build.sh").read_text()
        self.assertIn('sh "$REPO/guest/codex/build-rootfs.sh" "$STAGE' + images["codex"] + '"', b)

    # REQ: CAP-8
    def test_worker_images_ship_the_worker_argv(self):
        # A worker machine runs -worker-argv (default "sleep infinity") while the guest drives it.
        argv = re.search(r'"worker-argv", "([^"]+)"', (ROOT / "broker/cmd/agentosd/main.go").read_text()).group(1)
        exe = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentosd.service")["Service"]["ExecStart"]
        self.assertNotIn("-worker-argv", exe)
        worker = re.search(r"(?:^|\s)-worker-image\s+(\S+)", exe).group(1)
        loop = next(l for l in (ROOT / "guest" / worker / "build-rootfs.sh").read_text().splitlines()
                    if l.startswith("for b in /bin/sh "))
        self.assertIn("/bin/" + argv.split()[0], loop.removesuffix("; do").split()[3:])

    def test_broker_reads_onboarding_s_settings(self):
        # It no longer waits for them (SetupServicesTest): a preloaded box starts it in setup mode.
        u = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentosd.service")
        self.assertEqual(u["Service"]["EnvironmentFile"], "-/etc/agentos/agentosd.env")
        self.assertIn("/usr/lib/agentos/agentosd", u["Service"]["ExecStart"])


class NoDumpTest(unittest.TestCase):
    """IMG-nodump (security S1 on #1060): the Owner Card passphrase is a Go string that cannot be
    zeroed (card C13), so no crash may write the broker's memory to disk and no heap page may be
    swapped out. Core dumps are discarded and the image has no swap; the build fails otherwise."""
    # REQ: HW-1

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        write(self.root, "etc/machine-id", "uninitialized\n")
        nodump(self.root)
        bt_block(self.root)
        uplink(self.root)
        without_exec_allow(self)

    def tearDown(self):
        self.tmp.cleanup()

    def v(self):
        return " | ".join(check.violations(self.root))

    def test_shipped_files_say_what_the_check_needs(self):
        extra = MK / "mkosi.extra"
        self.assertEqual(ini(extra / NODUMP[0])["Coredump"]["Storage"], "none")
        self.assertEqual(ini(extra / NODUMP[1])["Manager"]["DefaultLimitCORE"], "0")
        for rel in NODUMP[3:]:
            self.assertEqual(ini(NODUMP_SRC.get(rel, extra / rel))["Service"]["LimitCORE"], "0")
        self.assertEqual(check.sysctl(self.root, "kernel.core_pattern"), "|/usr/bin/false")
        self.assertEqual(check.sysctl(self.root, "fs.suid_dumpable"), "0")
        self.assertEqual(check.violations(self.root), [])

    def test_removing_any_dump_setting_fails_the_build(self):
        for rel, needle in zip(NODUMP, ("Storage=none", "DefaultLimitCORE=0", "kernel.core_pattern",
                                        "LimitCORE=0", "LimitCORE=0", "LimitCORE=0")):
            with self.subTest(rel=rel):
                f = self.root / rel
                text = f.read_text()
                f.write_text("".join(ln for ln in text.splitlines(True) if needle not in ln))
                self.assertIn(rel.rsplit("/", 1)[-1], self.v())
                f.unlink()
                self.assertIn(rel.rsplit("/", 1)[-1], self.v())
                f.write_text(text)
                self.assertEqual(check.violations(self.root), [])

    def test_a_later_file_cannot_turn_dumps_back_on(self):
        # systemd reads drop-ins in file-name order, /etc over /usr/lib; the last value wins.
        cases = (
            ("etc/systemd/coredump.conf.d/zz.conf", "[Coredump]\nStorage=external\n", "Storage"),
            ("usr/lib/systemd/system.conf.d/zz.conf", "[Manager]\nDefaultLimitCORE=infinity\n", "DefaultLimitCORE"),
            ("etc/systemd/system/agentosd.service.d/zz.conf", "[Service]\nLimitCORE=infinity\n", "LimitCORE"),
            ("usr/lib/sysctl.d/99-zz.conf", "kernel.core_pattern = core\n", "core_pattern"),
            # #1508: systemd-sysctl normalises keys, so these are kernel.core_pattern too; a "-key"
            # line unsets it, leaving the kernel's default (dump to a file).
            ("usr/lib/sysctl.d/99-zz.conf", "/kernel/core_pattern = core\n", "core_pattern"),
            ("usr/lib/sysctl.d/99-zz.conf", "kernel.core_pattern. = core\n", "core_pattern"),
            ("usr/lib/sysctl.d/99-zz.conf", "-kernel.core_pattern\n", "core_pattern"),
            # systemd-coredump's own file, if a package ever adds it, sorts before ours.
            ("etc/sysctl.d/99-agentos-nodump.conf", "fs.suid_dumpable=2\n", "core_pattern"),
        )
        for rel, text, needle in cases:
            with self.subTest(rel=rel):
                f = write(self.root, rel, text)
                self.assertIn(needle, self.v())
                f.unlink()
        write(self.root, "usr/lib/sysctl.d/50-coredump.conf",
              "kernel.core_pattern=|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h\n")
        self.assertEqual(check.violations(self.root), [])

    def test_no_swap_in_the_tree(self):
        cases = (
            ("etc/fstab", "/dev/sda4 none swap sw 0 0\n"),
            ("etc/fstab", "# comment\nUUID=x / ext4 defaults 0 1\n/swapfile none swap defaults 0 0\n"),
            ("etc/systemd/system/swapfile.swap", "[Swap]\nWhat=/swapfile\n"),
            ("usr/lib/systemd/system/dev-sda4.swap", "[Swap]\nWhat=/dev/sda4\n"),
            ("usr/lib/systemd/system-generators/zram-generator", "#!/bin/sh\n"),
            ("swapfile", "x"),
        )
        for rel, text in cases:
            with self.subTest(rel=rel):
                f = write(self.root, rel, text)
                self.assertIn("swap", self.v())
                f.unlink()
        write(self.root, "etc/fstab", "# no swap here\nUUID=x / ext4 defaults,noexec 0 1\n"
              + (MK / "mkosi.extra/etc/fstab").read_text())
        self.assertEqual(check.violations(self.root), [])

    def test_no_swap_partition_and_generators_off(self):
        # Built disk: no partition carries the swap type, and gpt-auto and fstab make no swap
        # units (systemd.swap=0), so a swap partition added to the drive later is never used.
        for d in (MK / "mkosi.repart", MK / "mkosi.extra/usr/lib/repart.d"):
            for f in sorted(d.glob("*.conf")):
                with self.subTest(f=f.name):
                    self.assertNotEqual(ini(f)["Partition"]["Type"], "swap")
        args = ini(MK / "mkosi.conf")["Content"]["KernelCommandLine"].split()
        self.assertIn("systemd.swap=0", args)
        entry = ENTRY % H
        self.assertIn("systemd.swap=0", finish.swap_violations([], entry)[0])
        entry = entry.replace("rw quiet", "rw quiet systemd.swap=0")
        table = [{"type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"}, {"type": "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709"}]
        self.assertEqual(finish.swap_violations(table, entry), [])
        swap = table + [{"type": "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F", "node": "agentos.raw4"}]
        self.assertIn("swap partition", " ".join(finish.swap_violations(swap, entry)))
        self.assertIn("systemd.swap=0", " ".join(finish.swap_violations(
            table, entry.replace("systemd.swap=0", "systemd.swap=0 systemd.swap=1"))))

    def test_no_sysctl_on_the_command_line(self):
        # REQ: DEV-2, CH-9 (#1530)
        # The kernel writes sysctl.<key>= arguments at boot, and systemd-sysctl and systemd-tmpfiles
        # read the sysctl.extra and tmpfiles.extra credentials PID 1 takes from the command line, so
        # either could turn forwarding on while sysctl.d is clean. The line is an allowlist: what
        # mkosi v24.3 writes (usrhash= then mkosi.conf's words) passes, and nothing else does.
        args = ini(MK / "mkosi.conf")["Content"]["KernelCommandLine"]
        self.assertEqual(finish.config_cmdline(), args.split())
        entry = (ENTRY % H).replace("console=tty0 console=ttyS0 rw quiet", "usrhash=%s %s" % (H, " ".join(args.split())))
        self.assertEqual(finish.cmdline_violations(entry), [])
        self.assertEqual(finish.cmdline_violations(entry.replace("options", "  options")), [])
        self.assertEqual(len(re.findall("set_credential", entry)), 2)
        cred = "systemd.set_credential%s=%s:bmV0LmlwdjQuaXBfZm9yd2FyZD0xCg=="
        for bad in ("sysctl.net.ipv4.ip_forward=1", "sysctl/net/ipv4/ip_forward=1", "rd.sysctl.kernel.x=1",
                    "SYSCTL.net.ipv4.ip_forward=1", '"sysctl.net.ipv4.ip_forward=1"', 'sysctl."net.ipv4 x"=1',
                    cred % ("", "sysctl.extra"), cred % ("_binary", "sysctl.extra"),
                    cred % ("_binary", "tmpfiles.extra"), cred % ("-binary", "sysctl.extra"),
                    "rd." + cred % ("", "sysctl.extra"), cred % ("", "systemd.unit-dropin.emergency.service2"),
                    cred % ("", '"sysctl.extra'), "systemd.set_credential=sysctl.extra",
                    # Security R3: anything else PID 1 or the kernel acts on.
                    "systemd.run=/bin/sh", "rd.systemd.run=/bin/sh", "systemd.run_success_action=none",
                    "init=/bin/sh", "rdinit=/bin/sh", "sysctlx=1", "kernel.sysctl=1",
                    "systemd.setenv=sysctl.x=1", "emergency", "--", "usrhash=" + H[:63],
                    "usrhash=%s" % H.upper(), '"quiet systemd.run=/bin/sh"',
                    "systemd.set_credential_binary=systemd.unit-dropin.rescue.service:W1NlcnZpY2VdCg==",
                    cred % ("", "systemd.unit-dropin.emergency.service")):
            with self.subTest(bad=bad):
                self.assertNotEqual(finish.cmdline_violations(entry.replace("quiet", "quiet " + bad)), [])
        # A refused word is refused even when mkosi.conf lists it; a listed word passes.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        conf = pathlib.Path(tmp.name) / "mkosi.conf"
        conf.write_text("[Content]\nKernelCommandLine=quiet systemd.run=/bin/sh\n  init=/bin/sh x=1 rdinit=/s rd.systemd.run=/s\nHostname=y\n")
        self.assertEqual(finish.config_cmdline(conf), ["quiet", "systemd.run=/bin/sh", "init=/bin/sh", "x=1",
                                                       "rdinit=/s", "rd.systemd.run=/s"])
        one = "options quiet x=1 %s\n"
        self.assertEqual(finish.cmdline_violations(one % "", conf), [])
        for bad in ("systemd.run=/bin/sh", "init=/bin/sh", "rdinit=/s", "rd.systemd.run=/s", "Hostname=y", "rw"):
            with self.subTest(listed=bad):
                self.assertNotEqual(finish.cmdline_violations(one % bad, conf), [])
        # #1543 P/UX B1: one listed word per rule that refuses it anyway (the sysctl branch, the
        # credential branch, _binary, lower(), - read as _, rd., quote stripping), so a refactor that
        # drops any of them fails here. Each word is in the scratch mkosi.conf, and refused by its rule.
        for bad in ("sysctl.net.ipv4.ip_forward=1", "SYSCTL.net.ipv4.ip_forward=1", '"sysctl.net.ipv4.ip_forward=1"',
                    "rd.sysctl.net.ipv4.ip_forward=1", cred % ("", "sysctl.extra"), cred % ("_binary", "tmpfiles.extra"),
                    "SYSTEMD.SET_CREDENTIAL=sysctl.extra:eA==", cred % ("-binary", "sysctl.extra"),
                    "systemd.set-credential=sysctl.extra:eA==", "rd." + cred % ("", "sysctl.extra")):
            with self.subTest(listed=bad):
                conf.write_text("[Content]\nKernelCommandLine=quiet x=1 %s\n" % bad)
                self.assertIn(bad, finish.config_cmdline(conf))
                self.assertEqual(finish.cmdline_violations(one % "", conf), [])
                v = finish.cmdline_violations(one % bad, conf)
                self.assertEqual(len(v), 1, v)
                self.assertNotIn("not in mkosi.conf", v[0])
        # systemd-boot joins every options line, indented or not; a bare one adds nothing.
        for extra in ("options \noptions\tsysctl.kernel.x=1\n", "\toptions systemd.run=/bin/sh\n"):
            with self.subTest(extra=extra):
                self.assertNotEqual(finish.cmdline_violations(entry + extra), [])
        self.assertEqual(finish.entry_args(entry + " options systemd.swap=1\n", "systemd.swap"), ["0", "1"])
        # main() runs it on the entry it writes, and fails the build.

        class Proc:
            @staticmethod
            def check_output(*a, **k):
                return "::/loader/entries/a.conf\n"

            @staticmethod
            def run(*a, **k):
                return None

        bad = entry.replace("quiet", "quiet sysctl.net.ipv4.ip_forward=1")
        with tempfile.TemporaryDirectory() as d, \
                unittest.mock.patch.multiple(finish, subprocess=Proc, esp_offset=lambda img: 0,
                                             counted_entry=lambda src, v: ("a+3.conf", bad),
                                             esp_violations=lambda paths, text: []):
            with self.assertRaises(SystemExit) as e:
                finish.main(d, "1.0")
        self.assertIn("#1530", str(e.exception.code))

    def test_root_has_project_quotas(self):
        # REQ: RES-4
        # agentosd caps each machine's disk with project quotas (broker/quota); without them
        # quota.Open fails and agent machines stay off. The root ext4 gets the features at build
        # time (mkosi passes Environment= to systemd-repart's mkfs) and is mounted with prjquota
        # (gpt-auto honours rootflags=). finish_image.py checks both on the built disk.
        c = ini(MK / "mkosi.conf")["Content"]
        self.assertIn('SYSTEMD_REPART_MKFS_OPTIONS_EXT4=-Oquota,project', c["Environment"].split("\n"))
        flags = [w for w in c["KernelCommandLine"].split() if w.startswith("rootflags=")]
        self.assertEqual(len(flags), 1)
        self.assertIn("prjquota", flags[0][len("rootflags="):].split(","))
        self.assertEqual(ini(MK / "mkosi.repart/30-root.conf")["Partition"]["Format"], "ext4")
        entry = (ENTRY % H).replace("rw quiet", "rw quiet rootflags=prjquota")
        sb = bytearray(1024)
        struct.pack_into("<H", sb, 0x38, 0xEF53)
        struct.pack_into("<I", sb, 0x64, 0x0100 | 0x2000)
        struct.pack_into("<I", sb, 0x26C, 12)
        with tempfile.TemporaryDirectory() as d:
            def disk(super_block):
                img = pathlib.Path(d) / "disk.raw"
                img.write_bytes(bytes(8 * 512 + 1024) + bytes(super_block) + bytes(2048))
                return str(img)
            table = {"sectorsize": 512, "partitions": [
                {"type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "start": 2},
                {"type": "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", "start": 8}]}
            self.assertEqual(finish.quota_violations(disk(sb), table, entry), [])
            self.assertIn("rootflags=prjquota", " ".join(finish.quota_violations(disk(sb), table, ENTRY % H)))
            self.assertIn("rootflags=prjquota", " ".join(finish.quota_violations(
                disk(sb), table, entry.replace("rootflags=prjquota", "rootflags=prjquota rootflags=noquota"))))
            for off, val, why in ((0x64, 0x2000, "quota"), (0x64, 0x0100, "project"), (0x26C, 0, "project quota inode"),
                                  (0x38, 0, "ext4")):
                bad = bytearray(sb)
                struct.pack_into("<H" if off == 0x38 else "<I", bad, off, val)
                with self.subTest(why):
                    self.assertIn(why, " ".join(finish.quota_violations(disk(bad), table, entry)))
            self.assertIn("root partition", " ".join(finish.quota_violations(
                disk(sb), {"partitions": table["partitions"][:1]}, entry)))
            if shutil.which("mkfs.ext4"):
                # The real thing: mkfs.ext4 with the options the build passes.
                fs = pathlib.Path(d) / "root.ext4"
                with open(fs, "wb") as f:
                    f.truncate(32 << 20)
                subprocess.run(["mkfs.ext4", "-q", "-F", "-Oquota,project", str(fs)], check=True)
                img = pathlib.Path(d) / "real.raw"
                img.write_bytes(bytes(8 * 512) + fs.read_bytes()[:8192])
                self.assertEqual(finish.quota_violations(str(img), table, entry), [])

    def test_main_refuses_a_disk_without_quotas(self):
        # REQ: RES-4
        # finish_image.main() itself runs the quota check on the built disk and stops the release:
        # the checks above pass alone even if main never calls it (P/UX on #1302).
        calls = []

        def quota(img, table, entry):
            calls.append((img, table, entry))
            return ["root ext4 lacks the project feature"]

        class Proc:
            @staticmethod
            def check_output(*a, **k):
                return "::/loader/entries/a.conf\n"

            @staticmethod
            def run(*a, **k):
                return None

        entry = ENTRY % H
        with tempfile.TemporaryDirectory() as d, \
                unittest.mock.patch.multiple(finish, subprocess=Proc, esp_offset=lambda img: 0,
                                             counted_entry=lambda src, v: ("a+3.conf", entry),
                                             esp_violations=lambda paths, text: [],
                                             swap_violations=lambda parts, text: [],
                                             partition_table=lambda img: {"partitions": []},
                                             quota_violations=quota):
            with self.assertRaises(SystemExit) as e:
                finish.main(d, "1.0")
        self.assertIn("RES-4", str(e.exception.code))
        self.assertIn("project feature", str(e.exception.code))
        self.assertEqual(calls, [(str(pathlib.Path(d) / "agentos_1.0.raw"), {"partitions": []}, entry)])

    def test_boot_test_expects_the_runtime_check(self):
        # The booted image reports swap and core dumps off in the health line, so CI shows them on
        # a real boot, not only in this tree check.
        self.assertIn("swap=off dumps=off", (IMG / "ci_boot.sh").read_text())
        # REQ: DEV-2, CH-9 (#1478): and forwarding off.
        self.assertIn("swap=off dumps=off forward=off", (IMG / "ci_boot.sh").read_text())


UNITS = MK / "mkosi.extra/usr/lib/systemd/system"
AGENTOS_LIB = MK / "mkosi.extra/usr/lib/agentos"
PAGE_UNIT = ROOT / "broker/cmd/agentos-localui/agentos-localui.service"
# The unit image/build.sh installs from its command's directory.
MODEM_UNIT = ROOT / "broker/cmd/agentos-modem/agentos-modem.service"


def flags(cmd):
    """The flag names a Go command under broker/cmd defines (flag.X or a FlagSet's fs.X)."""
    out = set()
    for f in (ROOT / "broker/cmd" / cmd).glob("*.go"):
        if not f.name.endswith("_test.go"):
            out |= set(re.findall(r'\b(?:flag|fs)\.\w+\(\s*(?:&?[\w.]+,\s*)?"([\w-]+)"', f.read_text()))
    return out


def flag_default(cmd, name):
    """NAME's default string in broker/cmd/CMD, or None."""
    for f in (ROOT / "broker/cmd" / cmd).glob("*.go"):
        if not f.name.endswith("_test.go"):
            m = re.search(r'\b(?:flag|fs)\.String(?:Var)?\(\s*(?:&[\w.]+,\s*)?"%s",\s*"([^"]*)"' % re.escape(name), f.read_text())
            if m:
                return m.group(1)
    return None


def exec_args(unit):
    """A unit's ExecStart as its words, with with-uids taken off the front."""
    words = ini(unit)["Service"]["ExecStart"].replace("\\\n", " ").split()
    if words[0] == "/usr/lib/agentos/with-uids":
        words = words[1:]
    return words


def settings(unit):
    """A unit's KEY=VALUE lines as KEY -> every value in order (systemd repeats keys)."""
    out = {}
    for l in unit.read_text().replace("\\\n", " ").splitlines():
        l = l.strip()
        if l and not l.startswith(("#", "[")):
            k, _, v = l.partition("=")
            out.setdefault(k, []).append(v)
    return out


def arg(words, name):
    i = words.index("-" + name)
    return words[i + 1]


def write_b(root, rel, data):
    # A file whose name may hold any bytes (os.fsencode and back).
    p = os.path.join(os.fsencode(str(root)), rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)
    return p


def link(root, rel, target):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.symlink_to(target)
    return p


class ConfFilesTest(unittest.TestCase):
    """#1508 (B2, R2, R3, R5): the tree check reads the files systemd 257.13 reads, in its order,
    through the image: conf_files is conf_files_list_strv, main_conf is
    config_parse_standard_file_with_dropins, and config_lines is config_parse. Each case here passed
    the check before and is a tree whose box forwards, dumps or answers on the LAN."""
    # REQ: DEV-2, CH-9, C13

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        write(self.root, "etc/machine-id", "uninitialized\n")
        nodump(self.root)
        bt_block(self.root)
        uplink(self.root)
        without_exec_allow(self)

    def tearDown(self):
        self.tmp.cleanup()

    def v(self):
        return " | ".join(check.violations(self.root))

    def test_clean_tree_passes(self):
        self.assertEqual(check.violations(self.root), [])

    def test_etc_sysctl_conf_is_read_only_through_sysctl_d(self):
        # systemd-sysctl never lists /etc/sysctl.conf. Older Debian's 99-sysctl.conf link read it in
        # sysctl.d order; trixie ships no such link, and the check refuses one (#1543 Security B1)
        # though it still takes the link's name in the listing.
        write(self.root, "etc/sysctl.d/90-x.conf", "net.ipv4.ip_forward=1\n")
        write(self.root, "etc/sysctl.conf", "net.ipv4.ip_forward=0\n")
        self.assertIn("forwarding must stay 0", self.v())
        link(self.root, "etc/sysctl.d/99-sysctl.conf", "../sysctl.conf")
        self.assertEqual([f.rel for f in check.sysctl_files(self.root)][-2:],
                         ["usr/lib/sysctl.d/99-agentos-nodump.conf", "etc/sysctl.d/99-sysctl.conf"])
        self.assertIn("etc/sysctl.d/99-sysctl.conf: unreadable (etc/sysctl.d/99-sysctl.conf is a link to ../sysctl.conf;",
                      self.v())

    def test_hidden_and_backup_names_are_skipped(self):
        # FOREACH_DIRENT skips hidden names, so ".b.conf" never resets "+a.conf".
        write(self.root, "etc/sysctl.d/+a.conf", "net.ipv4.ip_forward=1\n")
        write(self.root, "etc/sysctl.d/.b.conf", "net.ipv4.ip_forward=0\n")
        self.assertIn("forwarding must stay 0", self.v())
        # The same holds for every reader that lists files this way (with the image's own file
        # out of the way, so the two files decide).
        for rel, text, needle, base in (
                ("etc/systemd/resolved.conf.d/.zz.conf", "[Resolve]\nLLMNR=no\nMulticastDNS=no\n", "LLMNR", RESOLVED_REL),
                ("etc/systemd/coredump.conf.d/.zz.conf", "[Coredump]\nStorage=none\n", "Storage", NODUMP[0]),
                ("etc/systemd/system/agentosd.service.d/.zz.conf", "[Service]\nLimitCORE=0\n", "LimitCORE", None)):
            with self.subTest(rel):
                bad = {"LLMNR": "[Resolve]\nLLMNR=yes\n", "Storage": "[Coredump]\nStorage=external\n",
                       "LimitCORE": "[Service]\nLimitCORE=infinity\n"}[needle]
                saved = base and (self.root / base).read_text()
                if base:
                    (self.root / base).unlink()
                a = write(self.root, rel.rsplit("/", 1)[0] + "/+a.conf", bad)
                b = write(self.root, rel, text)
                self.assertIn(needle, self.v())
                a.unlink()
                b.unlink()
                if base:
                    write(self.root, base, saved)
        # kmod skips hidden names too: a hidden file's install line is not the first one.
        (self.root / BT_BLOCK).unlink()
        write(self.root, "usr/lib/modprobe.d/.0.conf", "install btusb /bin/false\ninstall btmtk /bin/false\n")
        write(self.root, "usr/lib/modprobe.d/z.conf", "install btusb /bin/true\ninstall btmtk /bin/true\n")
        self.assertIn("btusb is not blocked", self.v())

    def test_names_sort_as_bytes(self):
        # path_compare_filename is strcmp: \xee\x80\x80 sorts before \xff, while Python sorts the
        # surrogate-escaped \xff (U+DCFF) before U+E000.
        write_b(self.root, b"etc/sysctl.d/\xff.conf", b"net.ipv4.ip_forward=1\n")
        write_b(self.root, b"etc/sysctl.d/\xee\x80\x80.conf", b"net.ipv4.ip_forward=0\n")
        self.assertIn("forwarding must stay 0", self.v())
        self.assertEqual([os.fsencode(f.name) for f in check.sysctl_files(self.root)][-2:],
                         [b"\xee\x80\x80.conf", b"\xff.conf"])
        os.unlink(os.path.join(os.fsencode(str(self.root)), b"etc/sysctl.d/\xff.conf"))
        os.unlink(os.path.join(os.fsencode(str(self.root)), b"etc/sysctl.d/\xee\x80\x80.conf"))
        write_b(self.root, b"etc/systemd/resolved.conf.d/\xff.conf", b"[Resolve]\nLLMNR=yes\n")
        write_b(self.root, b"etc/systemd/resolved.conf.d/\xee\x80\x80.conf", b"[Resolve]\nLLMNR=no\n")
        self.assertIn("LLMNR", self.v())

    def test_dangling_sysctl_link_is_refused(self):
        # #1543 Security B1b: a dangling link read as nothing at build, and on the box systemd-sysctl
        # reads whatever any local user writes at its target in /var/tmp. Relative and absolute,
        # in /etc and /usr/lib, before and after the target exists.
        for rel in ("etc/sysctl.d/99-z.conf", "usr/lib/sysctl.d/99-z.conf"):
            for target in ("/var/tmp/99.conf", "../" * rel.count("/") + "var/tmp/99.conf"):
                with self.subTest(rel=rel, target=target):
                    f = link(self.root, rel, target)
                    want = "%s: unreadable (%s is a link to %s;" % (rel, rel, target)
                    self.assertIn(want, self.v())
                    write(self.root, "var/tmp/99.conf", "kernel.core_pattern=|/usr/bin/false\n")
                    self.assertIn(want, self.v())
                    (self.root / "var/tmp/99.conf").unlink()
                    with self.assertRaises(check.LinkRefused):
                        check.Conf(str(self.root), rel).content()
                    f.unlink()

    def test_links_other_than_a_mask_are_refused(self):
        # #1543 Security B1: a link in a configuration directory, wherever it points (a file in the
        # image, a host path, a directory), is refused rather than followed. Each of these once
        # passed or was followed (R3 of #1508).
        write(self.root, "etc/passwd", "kernel.core_pattern=|/usr/bin/false\n")
        write(self.root, "usr/lib/agentos/sd/90-x.conf", "kernel.core_pattern=|/usr/bin/false\n")
        write(self.root, "usr/lib/agentos/nd/50-x.conf", "[DHCPv4]\nSendHostname=no\n")
        (self.root / "usr/lib/agentos/empty").mkdir()
        # A linked parent first: the later cases create usr/local/lib/systemd as a directory. Only
        # trixie's /lib -> usr/lib is followed: /lib linked anywhere else is refused, and a linked
        # directory is refused even when it holds nothing yet.
        for rel, target in (("usr/local/lib/systemd", "/var/tmp/sd"), ("lib", "/var/tmp/lib"), ("lib", "usr/share"),
                            ("usr/local/lib/sysctl.d", "/usr/lib/agentos/empty"), ("usr/local/lib/sysctl.d", "/etc/passwd"),
                            ("etc/sysctl.d/99-x.conf", "/etc/passwd"),
                            ("etc/sysctl.d/99-x.conf", "/" + NODUMP[2]),
                            ("etc/sysctl.d/99-x.conf", "../../usr/lib/agentos/sd/90-x.conf"),
                            ("usr/local/lib/sysctl.d", "/usr/lib/agentos/sd"),
                            ("usr/local/lib/sysctl.d", "/var/tmp/sd"),
                            ("etc/systemd/resolved.conf.d/90-x.conf", "/etc/passwd"),
                            ("usr/local/lib/systemd/resolved.conf.d", "/var/tmp/rd"),
                            ("etc/systemd/network/20-agentos-uplink.network.d", "/usr/lib/agentos/nd"),
                            ("etc/systemd/system/agentosd.service.d/90-x.conf", "/var/tmp/x.conf"),
                            ("usr/local/lib/systemd/system/agentosd.service.d", "/var/tmp/ud"),
                            ("etc/systemd/coredump.conf", "/var/tmp/c.conf"),
                            ("etc/modprobe.d/90-x.conf", "/var/tmp/m.conf"),
                            ("usr/local/lib/modprobe.d", "/var/tmp/md")):
            with self.subTest(rel=rel, target=target):
                f = link(self.root, rel, target)
                self.assertIn("%s is a link to %s;" % (rel, target), self.v())
                f.unlink()
        # A linked unit directory is refused where the secret-holding units are looked up, too.
        shutil.rmtree(self.root / "usr/local/lib/systemd/system")
        f = link(self.root, "usr/local/lib/systemd/system", "/var/tmp/us")
        self.assertIn("usr/local/lib/systemd/system: unreadable (usr/local/lib/systemd/system is a link to /var/tmp/us;"
                      " the tree check reads only a regular file or a mask", self.v())
        self.assertIn("the tree check never passes a unit directory it cannot read", self.v())
        f.unlink()
        self.assertEqual(check.violations(self.root), [])

    def test_fstab_and_machine_id_links_are_refused(self):
        # #1543 Security delta 4 B1: etc/fstab was read through pathlib, which follows a link on the
        # build host, so a dangling etc/fstab -> ../var/tmp/fstab read as no fstab; on the box
        # systemd-fstab-generator mounted whatever a local user wrote there (a bind mount over
        # /etc/sysctl.d, or swap). It and etc/machine-id are now read through the chase: a link other
        # than a mask is refused, relative or absolute, before and after its target exists.
        (self.root / "etc/machine-id").unlink()
        (self.root / "etc/fstab").unlink()
        for rel, body in (("etc/fstab", "/var/tmp/sd /etc/sysctl.d none bind 0 0\n"),
                          ("etc/machine-id", "0123456789abcdef0123456789abcdef\n")):
            for target in ("../var/tmp/" + rel[4:], "/var/tmp/" + rel[4:]):
                with self.subTest(rel=rel, target=target):
                    f = link(self.root, rel, target)
                    want = "%s: unreadable (%s is a link to %s;" % (rel, rel, target)
                    try:
                        self.assertIn(want, self.v())
                        t = write(self.root, "var/tmp/" + rel[4:], body)
                        self.assertIn(want, self.v())
                        t.unlink()
                    finally:
                        f.unlink()
            # A mask still reads as nothing: for etc/fstab, that is no noexec lines (UPD-10).
            with self.subTest(rel=rel, target="/dev/null"):
                f = link(self.root, rel, "/dev/null")
                self.assertEqual(check.violations(self.root), [] if rel != "etc/fstab" else [
                    "etc/fstab: no %s line; the box remounts it noexec from etc/fstab (UPD-10)" % t
                    for t in check.NOEXEC_FSTAB])
                f.unlink()
            if rel == "etc/fstab":
                noexec(self.root)
        write(self.root, "etc/machine-id", "uninitialized\n")
        self.assertEqual(check.violations(self.root), [])

    def test_steps_others_can_write_are_refused(self):
        # #1543 Security R1: no link, but a file whose content a local user can change after the
        # build. Every step on the way to a configuration file (the tree's root, each directory and
        # the file) must be TREE_OWNER's (root's in the build) and writable by no one else.
        uid = os.geteuid()

        def want(rel, step, owner, mode):
            return "%s: unreadable (%s is owned by uid %d with mode %s;" % (rel, step, owner, mode)

        f = write(self.root, "etc/sysctl.d/90-x.conf", "", mode=0o666)
        self.assertIn(want("etc/sysctl.d/90-x.conf", "etc/sysctl.d/90-x.conf", uid, "0666"), self.v())
        f.unlink()
        # A 1777 sysctl.d is refused while it is still empty: anyone could add a file at boot.
        d = self.root / "etc/sysctl.d"
        d.chmod(0o1777)
        self.assertIn(want("etc/sysctl.d", "etc/sysctl.d", uid, "1777"), self.v())
        d.chmod(0o755)
        self.assertEqual(check.violations(self.root), [])
        # A hard link to a 0666 file in /var/tmp has its mode.
        t = write(self.root, "var/tmp/x.conf", "kernel.core_pattern=|/usr/bin/false\n", mode=0o666)
        os.link(t, self.root / "etc/sysctl.d/90-x.conf")
        self.assertIn(want("etc/sysctl.d/90-x.conf", "etc/sysctl.d/90-x.conf", uid, "0666"), self.v())
        (self.root / "etc/sysctl.d/90-x.conf").unlink()
        t.unlink()
        # A file another user owns, even 0644 (chown where the test is root, else lstat says so).
        other = 1000 if uid != 1000 else 1001
        f = write(self.root, "etc/sysctl.d/90-x.conf", "")
        real = check.tree_lstat

        def lstat_as_other(root, rel):
            st = real(root, rel)
            if rel == "etc/sysctl.d/90-x.conf" and st is not None:
                st = os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, other, st.st_gid, st.st_size,
                                     st.st_atime, st.st_mtime, st.st_ctime))
            return st

        if uid == 0:
            os.chown(f, other, other)
            self.assertIn(want("etc/sysctl.d/90-x.conf", "etc/sysctl.d/90-x.conf", other, "0644"), self.v())
        with unittest.mock.patch.object(check, "tree_lstat", lstat_as_other):
            self.assertIn(want("etc/sysctl.d/90-x.conf", "etc/sysctl.d/90-x.conf", other, "0644"), self.v())
        f.unlink()
        # A group-writable directory, and a writable parent of a directory that is not there yet.
        d = self.root / "usr/lib/sysctl.d"
        d.chmod(0o775)
        self.assertIn(want("usr/lib/sysctl.d/99-agentos-nodump.conf", "usr/lib/sysctl.d", uid, "0775"), self.v())
        d.chmod(0o755)
        (self.root / "usr/local").mkdir(parents=True, exist_ok=True)
        (self.root / "usr/local").chmod(0o1777)
        self.assertIn(want("usr/local/lib/sysctl.d", "usr/local", uid, "1777"), self.v())
        (self.root / "usr/local").chmod(0o755)
        # The tree's root itself.
        self.root.chmod(0o777)
        self.assertIn("is owned by uid %d with mode 0777; the tree check reads configuration only through steps"
                      % uid, self.v())
        self.assertIn("(the tree's root is owned by", self.v())
        self.root.chmod(0o700)
        # A mask and trixie's /lib -> usr/lib are links, not steps anyone writes: both still pass.
        link(self.root, "etc/sysctl.d/50-x.conf", "/dev/null")
        link(self.root, "lib", "usr/lib")
        self.assertEqual(check.violations(self.root), [])

    def test_links_into_world_writable_directories_are_refused(self):
        # #1543 Security R2: a link outside the files the check reads, dangling at build, that a
        # local user fills at its target on the box: a unit, enabled, is then root code at the next
        # boot. Refused wherever the link is and whatever reads it, when its target is inside a
        # directory anyone on the box can write, whether the tree holds that directory or not.
        for rel in ("var/tmp", "var/lib/shared"):
            (self.root / rel).mkdir(parents=True)
            (self.root / rel).chmod(0o1777)
        link(self.root, "var/lock", "../run/lock")
        cases = (("etc/systemd/system/x.service", "/var/tmp/x.service", "var/tmp"),
                 ("etc/systemd/system/x.service", "../../../var/tmp/x.service", "var/tmp"),
                 ("usr/lib/x/y", "/tmp/y", "tmp"), ("usr/lib/x/y", "/dev/shm/y", "dev/shm"),
                 ("usr/lib/x/y", "/run/lock/y", "run/lock"), ("usr/lib/x/y", "/var/lock/y", "run/lock"),
                 ("usr/lib/x/y", "/var/lib/shared/y", "var/lib/shared"),
                 ("usr/lib/x/y", "/var/tmp/no/such/dir/y", "var/tmp"), ("usr/lib/x/y", "/usr/../var/tmp/y", "var/tmp"))
        for rel, target, under in cases:
            with self.subTest(rel=rel, target=target):
                f = link(self.root, rel, target)
                want = "%s: a link to %s, inside /%s, which anyone on the box can write" % (rel, target, under)
                try:
                    self.assertIn(want, self.v())
                finally:
                    f.unlink()
        # The delta 4 repro: the unit, and the wants link that enables it, which reaches it too.
        link(self.root, "etc/systemd/system/x.service", "/var/tmp/x.service")
        w = link(self.root, "etc/systemd/system/multi-user.target.wants/x.service", "../x.service")
        self.assertIn("etc/systemd/system/x.service: a link to /var/tmp/x.service, inside /var/tmp", self.v())
        self.assertIn("etc/systemd/system/multi-user.target.wants/x.service: a link to ../x.service, inside /var/tmp",
                      self.v())
        w.unlink()
        (self.root / "etc/systemd/system/x.service").unlink()
        # Trixie's own var/lock -> ../run/lock passes, and so does a link elsewhere.
        link(self.root, "usr/lib/x/f", "../../share/f")
        self.assertEqual(check.violations(self.root), ["var/lib/shared: mode 1777 is writable by anyone on the box (#1702)"])
        (self.root / "var/lib/shared").chmod(0o755)
        self.assertEqual(check.violations(self.root), [])

    def test_a_link_to_a_world_writable_directory_itself_is_refused(self):
        # #1702 item 1: every name inside such a directory is the user's, so a link to the directory
        # (a drop-in directory, a wants directory, udev's rules.d, a generator directory) is refused
        # as one into it is. Only var/lock -> ../run/lock or -> /run/lock (CI's stock build has the
        # absolute form), matched by path and target, passes.
        for ok in ("../run/lock", "/run/lock"):
            f = link(self.root, "var/lock", ok)
            self.assertEqual(check.violations(self.root), [], ok)
            f.unlink()
        link(self.root, "var/lock", "../run/lock")
        cases = (("etc/systemd/system/getty@.service.d", "/var/tmp", "var/tmp"),
                 ("etc/systemd/system/getty@.service.d", "../../../var/tmp", "var/tmp"),
                 ("etc/systemd/system/multi-user.target.wants", "/var/tmp", "var/tmp"),
                 ("etc/udev/rules.d", "/var/tmp", "var/tmp"),
                 ("etc/systemd/system-generators", "/tmp", "tmp"),
                 ("etc/modules-load.d", "/dev/shm", "dev/shm"),
                 ("usr/lib/x/q", "/dev/mqueue", "dev/mqueue"),
                 ("usr/lib/x/q", "/run/lock", "run/lock"),
                 ("var/lock", "../run/lock/", "run/lock"), ("var/lock", "/run/lock/", "run/lock"),
                 ("var/lock", "/var/tmp", "var/tmp"),
                 ("usr/lib/x/lock", "../../../run/lock", "run/lock"))
        for rel, target, under in cases:
            with self.subTest(rel=rel, target=target):
                if rel == "var/lock":
                    (self.root / rel).unlink()
                f = link(self.root, rel, target)
                try:
                    self.assertIn("%s: a link to %s, inside /%s," % (rel, target, under), self.v())
                finally:
                    f.unlink()
                    if rel == "var/lock":
                        link(self.root, "var/lock", "../run/lock")
        # With the user's 0666 file already in it, the reviewer's repro.
        write(self.root, "var/tmp/zz-user.conf", "[Service]\nExecStartPre=/var/tmp/payload\n").chmod(0o666)
        link(self.root, "etc/systemd/system/getty@.service.d", "/var/tmp")
        self.assertIn("etc/systemd/system/getty@.service.d: a link to /var/tmp, inside /var/tmp,", self.v())

    def test_a_link_into_a_service_users_directory_is_refused(self):
        # #1702 item 3: a compromise of a service user, the page's user or a login user then becomes
        # root, since systemd and udev read the link's target as root.
        for d in check.SERVICE_DIRS:
            for rel, target in (("etc/systemd/system/ssh.service.d/x.conf", "/%s/x.conf" % d),
                                ("etc/udev/rules.d/99-x.rules", "/%s/x.rules" % d),
                                ("etc/modules-load.d", "/" + d), ("etc/systemd/system/x.d", "../../../" + d)):
                with self.subTest(rel=rel, target=target):
                    f = link(self.root, rel, target)
                    try:
                        self.assertIn("%s: a link to %s, inside /%s," % (rel, target, d), self.v())
                    finally:
                        f.unlink()
        self.assertEqual(sorted(check.SERVICE_DIRS), sorted((
            "var/lib/agentos-localui", "var/lib/agentos-egress", "home", "run/user",
            "var/lib/private", "run/agentos-egress", "run/agentos-localui")))

    def test_a_dotdot_after_a_box_mount_or_a_missing_step_cannot_reach_run_lock(self):
        # #1702 (Security 1): /run/.. is / on the box, so /run/../var/lock is /var/lock, which is
        # /run/lock (1777). The tail after a mount the tree does not hold, or after a step it lacks,
        # is not cancelled lexically; a link that goes up past one is refused.
        link(self.root, "var/lock", "../run/lock")
        link(self.root, "var/run", "/run")
        cases = [("/%s/../var/lock" % m) for m in check.BOX_MOUNTS] + [
            "/run/../var/lock/x.conf", "../../run/../var/lock", "../../../../run/../var/lock",
            "/run/../var/run/lock", "/run/../var/run/user/1000", "/opt/nope/../../var/lock"]
        for rel in ("etc/udev/rules.d", "etc/systemd/system/ssh.service.d/x.conf"):
            for target in cases:
                with self.subTest(rel=rel, target=target):
                    f = link(self.root, rel, target)
                    try:
                        self.assertIn("%s: a link to %s, which goes up with '..' past a directory" % (rel, target),
                                      self.v())
                    finally:
                        f.unlink()
        # The same links without the detour were refused already, and a '..' inside the tree is resolved.
        for target in ("/var/lock", "/var/run/lock", "/var/run/user/1000"):
            f = link(self.root, "etc/udev/rules.d", target)
            self.assertNotEqual(self.v(), [], target)
            f.unlink()
        f = link(self.root, "etc/udev/rules.d", "../../usr/lib/../share/f")
        # The boot-code allowlist refuses any linked rules.d (ExecAllowTest); the link check is under test.
        with unittest.mock.patch.object(check, "exec_allow_violations", return_value=[]):
            self.assertEqual(check.violations(self.root), [])
        f.unlink()

    # #1702 (delta 2, Security 1, P/UX 1): links through what the box makes at boot, none with a '..'.
    BOX_BYPASSES = ("/proc/self/root/var/lock", "/proc/self/root/var/tmp", "/proc/1/root/var/tmp",
                    "/proc/1/root/tmp/x", "/proc/thread-self/root/home/u", "/proc/thread-self/root/home",
                    "/proc/self/cwd/var/tmp", "/proc/self/root/run/lock/x.rules", "/proc/self/fd/3",
                    "/proc/self/map_files/x", "/dev/fd/3", "/dev/fd", "/dev/stdin", "/dev/stdout", "/dev/stderr",
                    "/dev/stdin/x", "/sys/x", "/run/x", "/var/run/systemd/x", "../../../../../proc/self/root/var/tmp")

    def box_tree(self):
        link(self.root, "var/lock", "/run/lock")
        link(self.root, "var/run", "/run")

    def test_a_link_through_what_the_box_mounts_is_refused(self):
        # Default deny: a link that reaches a box mount ends where the box says at boot (/proc/self/root
        # is the reader's /, /dev/fd/3 its fd 3), so only BOX_LINKS' exact stock links may end there.
        self.box_tree()
        for rel in ("etc/udev/rules.d", "etc/systemd/system/ssh.service.d/x.conf"):
            for target in self.BOX_BYPASSES:
                with self.subTest(rel=rel, target=target):
                    f = link(self.root, rel, target)
                    try:
                        self.assertTrue(self.box_refused(rel, target), self.v())
                    finally:
                        f.unlink()
        # A link the tree holds under a box mount is hidden by the mount on the box.
        f = link(self.root, "run/x", "/proc/self/root/var/tmp")
        self.assertEqual(check.violations(self.root), [])
        f.unlink()

    def box_refused(self, rel, target):
        # The default deny's refusal of REL, naming the link, its target once (or where it reaches, if
        # that differs) and the remedy.
        path = check.tree_chase(str(self.root), rel, missing_ok=True)[0]
        head = "%s: a link to %s%s, which ends in /%s," % (
            rel, target, "" if path == target else ", which reaches " + path, path.split("/")[1])
        return any(x.startswith(head) and x.count(target) == 1 and "add it to BOX_LINKS per I23" in x
                   for x in check.violations(self.root))

    def mutant(self, old, new):
        # mkosi.finalize with OLD (which must be there exactly once) replaced by NEW, loaded as a module.
        src = (MK / "mkosi.finalize").read_text()
        self.assertEqual(src.count(old), 1, "the mutant's source line is gone from mkosi.finalize; "
                         "update this test to the line as it now reads: %r" % old)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        mut = pathlib.Path(tmp.name) / "mutant.py"
        mut.write_text(src.replace(old, new))
        # Beside the mutant, where it looks for its allowlist, so its whole check can run.
        for name in (check.TMPFILES_ALLOW, check.EXEC_ALLOW):
            (pathlib.Path(tmp.name) / name).write_text((MK / name).read_text())
        m = load("image_check_mutant", mut)
        m.TREE_OWNER = os.geteuid()
        m.TREE_GROUP = os.getegid()
        return m

    def test_without_the_default_deny_the_box_links_pass(self):
        # The mutant: drop the default deny, and every bypass passes the link rule (the '..', world-
        # writable and SERVICE_DIRS rules do not see them).
        m = self.mutant('    if path.startswith("/") and (made or rel.split("/", 1)[0] not in BOX_MOUNTS):\n',
                        "    if False:\n")
        self.box_tree()
        for target in self.BOX_BYPASSES:
            with self.subTest(target=target):
                f = link(self.root, "etc/udev/rules.d", target)
                try:
                    self.assertEqual(m.world_writable_link(str(self.root), "etc/udev/rules.d"), [])
                    self.assertNotEqual(check.world_writable_link(str(self.root), "etc/udev/rules.d"), [])
                finally:
                    f.unlink()

    # Security delta 3: a link at a box mount point; the box would move its mount onto the target.
    MOUNT_POINT_LINKS = (("dev", "var/tmp"), ("proc", "var/tmp"), ("sys", "var/tmp"), ("dev", "/dev/null"),
                         ("run", "var/tmp"), ("tmp", "var/tmp"), ("run", "/var/x"), ("sys", "../usr/lib"),
                         ("proc", "/proc"))

    def test_a_link_at_a_box_mount_point_is_refused(self):
        self.box_tree()
        for rel, target in self.MOUNT_POINT_LINKS:
            with self.subTest(rel=rel, target=target):
                f = link(self.root, rel, target)
                try:
                    self.assertIn("%s: a link to %s; /%s is where the box mounts its " % (rel, target, rel),
                                  self.v())
                    self.assertIn("a link there would move the mount (#1702)", self.v())
                finally:
                    f.unlink()

    def test_without_the_mount_point_rule_a_link_there_passes(self):
        # The mutant: drop the mount-point line, and dev, proc and sys links pass the link rule (the
        # carve-out exempts them, and a /dev/null target is a mask); run and tmp were refused only by
        # accident (stray_violations' ELOOP, WORLD_WRITABLE's /tmp).
        m = self.mutant("    if rel in BOX_MOUNTS:\n", "    if False:\n")
        self.box_tree()
        for rel, target in self.MOUNT_POINT_LINKS:
            with self.subTest(rel=rel, target=target):
                f = link(self.root, rel, target)
                try:
                    self.assertNotEqual(check.world_writable_link(str(self.root), rel), [])
                    mv = m.world_writable_link(str(self.root), rel)
                    self.assertFalse(any("would move the mount" in x for x in mv), mv)
                    if rel in ("dev", "proc", "sys"):
                        self.assertEqual(m.violations(self.root), [])
                finally:
                    f.unlink()

    def test_box_links_is_exactly_the_stock_set(self):
        # #1702 (P/UX 2): pinned, as SERVICE_DIRS is, so widening the table takes a second, reviewed edit.
        self.assertEqual(check.BOX_LINKS, {"var/lock": ("../run/lock", "/run/lock"),
                                           "var/run": ("../run", "/run"),
                                           "etc/mtab": ("../proc/self/mounts",),
                                           "etc/resolv.conf": ("../run/systemd/resolve/stub-resolv.conf",)})

    def test_box_links_mutants_are_killed(self):
        # M6, an extra entry to a reader-relative target, and M13, BOX_LINKS matched by path suffix:
        # each lets a link through that the real check refuses.
        old = '             "etc/resolv.conf": ("../run/systemd/resolve/stub-resolv.conf",)}\n'
        m6 = self.mutant(old, old[:-2] + ',\n             "etc/foo": ("/dev/fd/3",)}\n')
        with self.assertRaises(AssertionError):
            self.assertEqual(m6.BOX_LINKS, check.BOX_LINKS)
        f = link(self.root, "etc/foo", "/dev/fd/3")
        self.assertEqual(m6.world_writable_link(str(self.root), "etc/foo"), [])
        self.assertNotEqual(check.world_writable_link(str(self.root), "etc/foo"), [])
        f.unlink()
        m13 = self.mutant("    if target == MASK or target in BOX_LINKS.get(rel, ()):\n",
                          "    if target == MASK or any(rel.endswith(k) and target in v "
                          "for k, v in BOX_LINKS.items()):\n")
        for rel, target in (("etc/x/var/run", "/run"), ("x/var/lock", "/run/lock")):
            with self.subTest(rel=rel, target=target):
                f = link(self.root, rel, target)
                try:
                    self.assertEqual(m13.world_writable_link(str(self.root), rel), [])
                    self.assertNotEqual(check.world_writable_link(str(self.root), rel), [])
                finally:
                    f.unlink()

    def test_each_stock_box_link_passes_and_only_exactly(self):
        # Every BOX_LINKS entry passes as the stock tree holds it, and a mask anywhere; a link that
        # differs from an entry by one component, in its path or its target, is refused.
        for rel, targets in sorted(check.BOX_LINKS.items()):
            for target in targets:
                with self.subTest(rel=rel, target=target):
                    f = link(self.root, rel, target)
                    try:
                        self.assertEqual(check.violations(self.root), [])
                    finally:
                        f.unlink()
        f = link(self.root, "usr/lib/systemd/system/x.service", "/dev/null")
        self.assertEqual(check.violations(self.root), [])
        f.unlink()
        near = [("etc/x/mtab", "../../proc/self/mounts"), ("etc/mtab", "../proc/self/mountinfo"),
                ("etc/mtab", "../proc/1/mounts"), ("etc/mtab", "../proc/self/root/mounts"),
                ("etc/mtab", "/proc/self/mounts"),
                ("var/run", "/run/user"), ("var/run", "/sys"), ("etc/run", "/run"),
                ("etc/x/var/run", "/run"), ("x/var/lock", "/run/lock"),
                ("etc/resolv.conf", "../run/systemd/resolve/resolv.conf"),
                ("etc/resolv.conf", "../run/systemd/resolve/stub-resolv.conf/x"),
                ("etc/resolv.conf", "../run/systemd/x/stub-resolv.conf"), ("etc/resolv.conf", "/run/systemd/resolve/stub-resolv.conf"), ("etc/resolv2.conf", "/run/systemd/resolve/stub-resolv.conf"),
                ("etc/udev/rules.d/x.rules", "/dev/null/x"), ("etc/udev/rules.d/x.rules", "/dev/zero"),
                ("etc/udev/rules.d/x.rules", "../../../dev/null")]
        for rel, target in near:
            with self.subTest(rel=rel, target=target):
                f = link(self.root, rel, target)
                try:
                    self.assertNotEqual(check.violations(self.root), [])
                finally:
                    f.unlink()

    def test_a_link_into_a_runtime_dir_through_var_run_is_refused(self):
        # SERVICE_DIRS' run/agentos-* entries, reached the way stock links go: through var/run.
        self.box_tree()
        for d in ("agentos-egress",):
            f = link(self.root, "etc/udev/rules.d", "/var/run/%s/x" % d)
            self.assertIn("etc/udev/rules.d: a link to /var/run/%s/x, inside /run/%s," % (d, d), self.v())
            f.unlink()

    def test_a_link_loop_fails_open(self):
        # A loop, or a non-directory step, fails the same lookup on the box, so the link reads nothing:
        # world_writable_link passes it on purpose (its OSError path), and nothing else here refuses it.
        link(self.root, "usr/lib/x/a", "b")
        link(self.root, "usr/lib/x/b", "a")
        write(self.root, "usr/lib/x/f", "x\n")
        link(self.root, "usr/lib/x/c", "f/y")
        for rel in ("usr/lib/x/a", "usr/lib/x/b", "usr/lib/x/c"):
            self.assertEqual(check.world_writable_link(str(self.root), rel), [], rel)
        self.assertEqual(check.violations(self.root), [])

    def test_the_lock_and_world_writable_exemptions_are_exact(self):
        # #1702 (Security, L3): the lock link is matched by path, not by suffix; a link through
        # var/lock reaches run/lock; the o+w exemption is by directory name, not by prefix.
        link(self.root, "var/lock", "../run/lock")
        f = link(self.root, "etc/x/lock", "/run/lock")
        self.assertIn("etc/x/lock: a link to /run/lock, inside /run/lock,", self.v())
        f.unlink()
        for target in ("/var/lock/x", "/var/lock"):
            f = link(self.root, "etc/udev/rules.d", target)
            self.assertIn("etc/udev/rules.d: a link to %s, inside /run/lock," % target, self.v(), target)
            f.unlink()
        for rel in ("var/tmpx", "run/lockx"):
            (self.root / rel).mkdir(parents=True, exist_ok=True)
            (self.root / rel).chmod(0o777)
            self.assertIn("%s: mode 0777 is writable by anyone on the box" % rel, self.v())
            (self.root / rel).rmdir()
        (self.root / "var/tmp").mkdir(parents=True, exist_ok=True)
        write(self.root, "var/tmp/f", "x\n").chmod(0o666)
        self.assertEqual(check.violations(self.root), [])

    def test_an_entry_anyone_can_write_is_refused_wherever_it_is(self):
        # #1702 item 2: a 1777 drop-in directory, a 0777 rules.d, a 0666 enabled unit, a 0777 generator.
        # Group write is not a rule (stock trixie has 2775 var/mail and var/local).
        write(self.root, "etc/systemd/system/x.service", "[Service]\n")
        link(self.root, "etc/systemd/system/multi-user.target.wants/x.service", "../x.service")
        cases = (("etc/systemd/system/getty@.service.d", 0o1777, True), ("etc/udev/rules.d", 0o777, True),
                 ("etc/systemd/system/x.service", 0o666, False), ("usr/lib/systemd/system-generators/x", 0o777, False),
                 ("etc/foo", 0o2, False), ("etc/foo", 0o1777, True))
        for rel, mode, is_dir in cases:
            with self.subTest(rel=rel, mode=oct(mode)):
                if is_dir:
                    (self.root / rel).mkdir(parents=True, exist_ok=True)
                else:
                    write(self.root, rel, "x\n")
                (self.root / rel).chmod(mode)
                try:
                    self.assertIn("%s: mode %04o is writable by anyone on the box" % (rel, mode), self.v())
                finally:
                    if is_dir:
                        (self.root / rel).rmdir()
                    elif rel != "etc/systemd/system/x.service":
                        (self.root / rel).unlink()
        (self.root / "etc/systemd/system/x.service").chmod(0o644)
        self.assertEqual(check.violations(self.root), [])
        for rel, mode in (("var/mail", 0o2775), ("var/local", 0o2775), ("usr/lib/x", 0o775)):
            (self.root / rel).mkdir(parents=True, exist_ok=True)
            (self.root / rel).chmod(mode)
        self.assertEqual(check.violations(self.root), [])
        # The directories the box makes 1777 are the ones exempt, and only by their own names.
        for rel in check.WORLD_WRITABLE:
            (self.root / rel).mkdir(parents=True, exist_ok=True)
            (self.root / rel).chmod(0o1777)
        self.assertEqual(check.violations(self.root), [])

    def test_a_mask_is_still_read_as_nothing(self):
        # A mask (a link to exactly /dev/null) still hides a lower file of its name, in sysctl.d and
        # for a main file.
        write(self.root, "usr/lib/sysctl.d/50-pid-max.conf", "net.ipv4.ip_forward=1\n")
        self.assertIn("forwarding must stay 0", self.v())
        link(self.root, "etc/sysctl.d/50-pid-max.conf", "/dev/null")
        self.assertEqual(check.violations(self.root), [])
        self.assertEqual(check.Conf(str(self.root), "etc/sysctl.d/50-pid-max.conf").content(), b"")

    def test_split_usr_lib_and_run_are_not_read(self):
        # systemd 257 does not search a split-/usr /lib, and /run is a tmpfs on the box: a reset
        # there is never read, and the tree must not hold one.
        write(self.root, "usr/lib/sysctl.d/90-x.conf", "net.ipv4.ip_forward=1\n")
        for rel in ("lib/sysctl.d/99-reset.conf", "run/sysctl.d/99-reset.conf"):
            with self.subTest(rel):
                f = write(self.root, rel, "net.ipv4.ip_forward=0\n")
                v = self.v()
                self.assertIn("forwarding must stay 0", v)
                self.assertIn(rel + ":", v)
                f.unlink()
        # A merged-/usr /lib (a link to usr/lib) is the same directory, not a stray one.
        (self.root / "usr/lib/sysctl.d/90-x.conf").unlink()
        shutil.rmtree(self.root / "lib")
        link(self.root, "lib", "usr/lib")
        self.assertEqual(check.violations(self.root), [])

    def test_only_the_first_main_file_is_read(self):
        # config_parse_many_files reads the first resolved.conf it finds (/etc before /usr/lib),
        # not both.
        (self.root / RESOLVED_REL).unlink()
        write(self.root, "usr/lib/systemd/resolved.conf", "[Resolve]\nLLMNR=no\nMulticastDNS=no\n")
        self.assertEqual(check.violations(self.root), [])
        write(self.root, "etc/systemd/resolved.conf", "[Resolve]\n#LLMNR=yes\n")
        self.assertIn("LLMNR is None", self.v())
        # A link to /dev/null is a main file that reads as nothing; a dangling link is refused, not
        # skipped (#1543 Security B1): systemd would read whatever later appears at its target.
        (self.root / "etc/systemd/resolved.conf").unlink()
        link(self.root, "etc/systemd/resolved.conf", "/dev/null")
        self.assertIn("LLMNR is None", self.v())
        (self.root / "etc/systemd/resolved.conf").unlink()
        link(self.root, "etc/systemd/resolved.conf", "/usr/lib/agentos/missing")
        self.assertIn("unreadable resolved.conf (etc/systemd/resolved.conf is a link to /usr/lib/agentos/missing;",
                      self.v())

    def test_unit_dropins_are_the_ones_systemd_applies(self):
        # dropin.c: NAME.d, each "-" prefix's .d, and service.d, in every unit directory, including
        # system.control and system.attached; a name in an earlier directory list entry wins.
        for rel in ("etc/systemd/system/agentos-.service.d/zz.conf",
                    "etc/systemd/system.control/agentosd.service.d/zz.conf",
                    "etc/systemd/system.attached/agentosd.service.d/zz.conf",
                    "usr/local/lib/systemd/system/service.d/zz.conf"):
            with self.subTest(rel):
                f = write(self.root, rel, "[Service]\nLimitCORE=infinity\n")
                self.assertIn("LimitCORE is infinity", self.v())
                f.unlink()
        # Same name: /usr/lib's agentosd.service.d comes before /etc's service.d in the list.
        write(self.root, "usr/lib/systemd/system/agentosd.service.d/10-x.conf", "[Service]\nLimitCORE=infinity\n")
        write(self.root, "etc/systemd/system/service.d/10-x.conf", "[Service]\nLimitCORE=0\n")
        self.assertIn("agentosd.service: LimitCORE is infinity", self.v())
        (self.root / "usr/lib/systemd/system/agentosd.service.d/10-x.conf").unlink()
        (self.root / "etc/systemd/system/service.d/10-x.conf").unlink()
        # The first unit directory with the name holds the unit; an alias is refused.
        write(self.root, "etc/systemd/system.control/agentosd.service", "[Service]\nExecStart=/x\n")
        self.assertIn("agentosd.service: LimitCORE is None", self.v())
        (self.root / "etc/systemd/system.control/agentosd.service").unlink()
        link(self.root, "etc/systemd/system/x.service", "/usr/lib/systemd/system/agentosd.service")
        self.assertIn("an alias of agentosd.service", self.v())
        self.assertEqual(check.unit_dropin_names("agentos-egress.service"),
                         ["agentos-egress.service", "agentos-.service"])
        self.assertEqual(check.unit_dropin_names("a-b-c.service"), ["a-b-c.service", "a-b-.service", "a-.service"])
        self.assertEqual(check.unit_dropin_names("agentosd.service"), ["agentosd.service"])

    def test_config_parse_stops_where_systemd_stops(self):
        # Where config_parse fails, systemd reads no further (for resolved, networkd, coredump and
        # system.conf, no further file either), so a later "good" value must not count.
        cases = (
            ("etc/systemd/coredump.conf.d/90-a.conf", "[Coredump]\nStorage=external\n",
             "etc/systemd/coredump.conf.d/91-b.conf", "[Coredump\n", "Storage"),
            ("etc/systemd/coredump.conf.d/90-a.conf", "[Coredump]\nStorage=external\n",
             "etc/systemd/coredump.conf.d/91-b.conf", "[Coredump]\n#" + "x" * ((1 << 20) - 1) + "\nStorage=none\n", "Storage"),
            ("etc/systemd/coredump.conf.d/90-a.conf", "[Coredump]\nStorage=external\n",
             "etc/systemd/coredump.conf.d/91-b.conf", "[Coredump]\nX=\xff\nStorage=none\n", "Storage"),
            ("etc/systemd/resolved.conf.d/90-a.conf", "[Resolve]\nLLMNR=yes\n",
             "etc/systemd/resolved.conf.d/91-b.conf", "[Res\"olve]\nLLMNR=no\n", "LLMNR"),
        )
        for rel_a, text_a, rel_b, text_b, needle in cases:
            with self.subTest(rel_b, text=text_b[:20]):
                a = write(self.root, rel_a, text_a)
                b = self.root / rel_b
                b.write_bytes(text_b.encode("latin-1") if "\xff" in text_b else text_b.encode())
                self.assertIn(needle, self.v())
                a.unlink()
                b.unlink()
        self.assertEqual(check.violations(self.root), [])

    def test_config_lines_split_as_systemd_splits_them(self):
        # One BOM is dropped; a backslash continues a line only when it is the line's last byte
        # and unescaped; a comment inside a continuation is skipped.
        for rel, text in (("etc/systemd/system/agentosd.service.d/x.conf", "\ufeff[Service]\nLimitCORE=infinity\n"),
                          ("etc/systemd/system/agentosd.service.d/x.conf", "[Service]\nX=a\\ \nLimitCORE=infinity\n")):
            with self.subTest(text):
                f = write(self.root, rel, text)
                self.assertIn("LimitCORE is infinity", self.v())
                f.unlink()
        lines = check.config_lines
        self.assertEqual(lines(b"\xef\xbb\xbf[Service]\nLimitCORE=infinity\n"), [("Service", "LimitCORE", "infinity")])
        self.assertEqual(lines(b"[Service]\nX=a\\ \nLimitCORE=infinity\n"),
                         [("Service", "X", "a\\"), ("Service", "LimitCORE", "infinity")])
        self.assertEqual(lines(b"[Service]\nX=a\\\\\nLimitCORE=infinity"),
                         [("Service", "X", "a\\\\"), ("Service", "LimitCORE", "infinity")])
        self.assertEqual(lines(b"[Service]\nX=a\\\n# c\nb\nLimitCORE=0\n"),
                         [("Service", "X", "a b"), ("Service", "LimitCORE", "0")])
        self.assertEqual(lines(b"[Service]\n\x0bLimitCORE=0\n"), [("Service", "\x0bLimitCORE", "0")])

    def test_long_sysctl_line_stops_the_file(self):
        # R2: read_line fails on a line of LONG_LINE_MAX bytes or more, and systemd-sysctl applies
        # nothing after it in that file (LONG_LINE_MAX is 1 MiB).
        n = 1 << 20
        f = write(self.root, "etc/sysctl.d/99-x.conf", "net.ipv4.ip_forward=1\n#" + "x" * (n - 1) + "\nnet.ipv4.ip_forward=0\n")
        v = self.v()
        self.assertIn("forwarding must stay 0", v)
        self.assertIn("99-x.conf: line 2 is 1 MiB or longer", v)
        f.write_text("net.ipv4.ip_forward=1\n#" + "x" * (n - 2) + "\nnet.ipv4.ip_forward=0\n")
        self.assertEqual(check.violations(self.root), [])
        # The uplink and networkd/resolved files are refused the same way.
        f.unlink()
        f = write(self.root, "etc/systemd/resolved.conf.d/90-x.conf", "#" + "x" * n + "\n")
        self.assertIn("90-x.conf: line 1 is 1 MiB or longer", self.v())

    def test_unreadable_sysctl_file_is_refused(self):
        # R5: a sysctl.d entry systemd-sysctl cannot read (a directory, a link into what the box
        # mounts at boot, or, for a non-root build, a file without read permission) never passes.
        d = self.root / "etc/sysctl.d/99-x.conf"
        d.mkdir(parents=True)
        self.assertIn("etc/sysctl.d/99-x.conf: unreadable (a directory)", self.v())
        d.rmdir()
        link(self.root, "etc/sysctl.d/99-x.conf", "/run/agentos/x.conf")
        self.assertIn("etc/sysctl.d/99-x.conf: unreadable (etc/sysctl.d/99-x.conf is a link to /run/agentos/x.conf", self.v())
        d.unlink()
        # Only a build without root's DAC override (CI's checks job) can see a mode-000 file fail.
        f = write(self.root, "etc/sysctl.d/99-x.conf", "net.ipv4.ip_forward=1\n", mode=0o000)
        try:
            f.read_bytes()
        except PermissionError:
            self.assertIn("etc/sysctl.d/99-x.conf: unreadable (Permission denied)", self.v())
        f.chmod(0o644)
        f.unlink()
        # Unreadable through the same code path, whoever runs it.
        with unittest.mock.patch.object(check.Conf, "content", side_effect=PermissionError(13, "Permission denied")):
            self.assertIn("99-agentos-nodump.conf: unreadable (Permission denied)",
                          " ".join(check.sysctl_byte_violations(self.root)))

    # #1529: one case per rule of the port that no test held (P1-P10 of #1508's delta 3), each a
    # tree that dumps, answers on the LAN or loads Bluetooth unless the rule holds.
    def coredump(self, data):
        write_b(self.root, b"etc/systemd/coredump.conf.d/90-x.conf", data)
        return self.v()

    def test_bom_is_dropped_once(self):
        # P1: a second BOM line is not a section header, so Storage= stays in [Coredump].
        bom = b"\xef\xbb\xbf"
        self.assertIn("coredump Storage is external", self.coredump(bom + b"[Coredump]\n" + bom + b"[X]\nStorage=external\n"))

    def test_noncharacters_stop_the_parse(self):
        # P2: utf8_is_valid refuses noncharacters, so config_parse stops before Storage=none.
        for c in ("﷐", "﷯", "￾", "\U0001ffff"):
            with self.subTest(c=repr(c)):
                self.assertIn("invalid UTF-8", self.coredump(("[Coredump]\nX=%s\nStorage=none\n" % c).encode()))

    def test_bad_section_characters_stop_the_parse(self):
        # P3: string_has_cc and the quote and backslash checks in parse_line.
        for c in ('"', "'", "\\", "\x01", "\x1f", "\x7f"):
            with self.subTest(c=repr(c)):
                self.assertIn("bad characters in section header", self.coredump(("[Core%sdump]\n" % c).encode()))
        self.assertNotIn("section header", self.coredump(b"[Core dump x]\n"))

    def test_empty_assignment_resets(self):
        # P4: LLMNR= after LLMNR=no gives resolved's default, which answers on the LAN.
        write(self.root, "etc/systemd/resolved.conf.d/90-x.conf", "[Resolve]\nLLMNR=no\nLLMNR=\n")
        self.assertIn("LLMNR", self.v())

    def test_kmod_reads_a_file_in_place_of_modprobe_d(self):
        # P5: kmod's conf_files_list reads a non-directory in its list as a file of its own (named
        # modprobe.d, so it sorts after the block; a pattern the check cannot model is still refused).
        write(self.root, "etc/modprobe.d", "install b[t]usb /sbin/modprobe --ignore-install btusb\n")
        self.assertIn("etc/modprobe.d: install b[t]usb: a pattern with [", self.v())

    def test_config_directory_linked_into_run_is_refused(self):
        # P6: the box mounts a tmpfs over /run, so the directory the tree check reads is not the box's.
        link(self.root, "etc/sysctl.d", "/run/sysctl.d")
        self.assertIn("etc/sysctl.d: unreadable (etc/sysctl.d is a link to /run/sysctl.d", self.v())

    def test_unit_dropin_directories_go_by_lookup_path_first(self):
        # P7: unit_file_find_dropin_paths walks lookup paths, then names, so /etc's prefix drop-in
        # takes the name 10.conf before /usr/lib's own one.
        write(self.root, "etc/systemd/system/agentos-.service.d/10.conf", "[Service]\nLimitCORE=infinity\n")
        write(self.root, "usr/lib/systemd/system/agentos-egress.service.d/10.conf", "[Service]\nLimitCORE=0\n")
        self.assertIn("agentos-egress.service: LimitCORE is infinity", self.v())

    def test_link_as_card_unit_is_refused(self):
        # P8: a link as the unit could name a file systemd reads under another name's drop-ins.
        link(self.root, "etc/systemd/system/agentosd.service", "/usr/lib/systemd/system/agentosd.service")
        self.assertIn("etc/systemd/system/agentosd.service: a link", self.v())

    def test_continued_line_over_1_mib_stops_the_parse(self):
        # P9: each line is under LONG_LINE_MAX, the joined one is not.
        half = b"a" * (check.LONG_LINE_MAX // 2 + 1)
        self.assertIn("continued line too long", self.coredump(b"[Coredump]\nX=" + half + b"\\\n" + half + b"\nStorage=none\n"))

    def test_continuation_at_end_of_file_is_parsed(self):
        # P10: config_parse parses what a trailing backslash left pending.
        self.assertIn("coredump Storage is external", self.coredump(b"[Coredump]\nStorage=external\\"))
        self.assertIn("coredump Storage is external", self.coredump(b"[Coredump]\nStorage=\\\nexternal\n"))

    def test_unreadable_network_file_is_refused(self):
        # #1529 (L1 of #1508): byte_violations never passes a networkd or resolved file it cannot read.
        d = self.root / "etc/systemd/resolved.conf.d/90-x.conf"
        d.mkdir(parents=True)
        self.assertIn("etc/systemd/resolved.conf.d/90-x.conf: unreadable (a directory); the tree check", self.v())
        d.rmdir()
        with unittest.mock.patch.object(check.Conf, "content", side_effect=PermissionError(13, "Permission denied")):
            self.assertEqual(check.byte_violations(check.Conf(str(self.root), RESOLVED_REL)),
                             ["%s: unreadable (Permission denied); the tree check never passes a file it cannot read"
                              % RESOLVED_REL])


# Lines like Debian trixie's own tmpfiles.d (debian.conf, var.conf, etc.conf, systemd.conf,
# provision.conf), each of which must pass the tmpfiles check (#1530).
TMPFILES_PASS = ("d /run/user 0755 root root -", "L /var/run - - - - ../run", "L+ /var/run - - - - /run",
                 "L+ /var/run - - - - ../run", "L /var/run - - - - /run", "L /etc/mtab - - - - ../proc/self/mounts",
                 "L+ /etc/mtab   -    -    -    -  ../proc/self/mounts", "x /tmp/systemd-private-%b-*",
                 "d %t/agentos 0750", "d /run/systemd/netif 0755 - - -", "f^ /etc/hosts - - - - network.hosts",
                 "r /run/sysctlx.d", "C! /etc/pam.d - - - -",
                 "L /etc/os-release - - - - /usr/lib/os-release",
                 # trixie's credstore.conf, debian.conf, legacy.conf and systemd-resolve.conf (CI build of #1543).
                 "d /etc/credstore 0700 root root", "d /etc/credstore.encrypted 0700 root root",
                 "z /run/credstore 0700 root root", "z /run/credstore.encrypted 0700 root root",
                 "L+ /etc/default/locale - - -  -  ../locale.conf", "L /var/lock - - - - ../run/lock",
                 "L$ /var/log/README - - - - ../../usr/share/doc/systemd/README.logs",
                 "L! /etc/resolv.conf - - - - ../run/systemd/resolve/stub-resolv.conf")
AGENTOS_TMPFILES = MK / "mkosi.extra/usr/lib/tmpfiles.d/agentos.conf"


def allow_groups():
    """image/mkosi/tmpfiles.allow's entries grouped by file, each file's lines in their order
    (#1543 P/UX P1): {path in the tree: [line, ...]}."""
    out = {}
    for ln in (MK / check.TMPFILES_ALLOW).read_text().split("\n"):
        if ln.strip() and not ln.startswith("#"):
            rel, _, line = ln.partition("\t")
            out.setdefault(rel, []).append(line.strip(" \t"))
    return out


# What the box reads that a tmpfiles.d line could change, by name under each configuration
# directory, listed here apart from the check's own TMPFILES_TARGETS so that a name dropped there
# shows here (#1543 P/UX B2).
GUARDED_NAMES = ("sysctl.d", "modprobe.d", "tmpfiles.d", "systemd/network", "systemd/system",
                 "systemd/system.control", "systemd/system.attached", "systemd/system.conf",
                 "systemd/system.conf.d", "systemd/coredump.conf", "systemd/coredump.conf.d",
                 "systemd/networkd.conf", "systemd/networkd.conf.d", "systemd/resolved.conf",
                 "systemd/resolved.conf.d", "systemd/system-generators", "credstore", "credstore.encrypted",
                 # #2176: every boot-code channel exec.allow holds.
                 "udev/rules.d", "modules-load.d", "systemd/system-environment-generators", "binfmt.d",
                 "systemd/system-shutdown", "systemd/system-sleep")
# #1543 reviews at bf7e5d3: B1 (C+ on an ancestor of /run/sysctl.d), B2 (a stock link with more
# after its target, which systemd takes raw), B3 (/etc/sysctl.d and /etc/sysctl.conf) and R1 (every
# other directory the tree check reads), plus /sys and ".." paths. Each must be refused.
TMPFILES_PROBES = (
    "w /proc/sys/net/ipv4/ip_forward - - - - 1",
    "C+ /run - - - - /usr/share/x", "C+ %t - - - - /usr/share/x", "C+ /var/run - - - - /usr/share/x",
    "C+ / - - - - /usr/share/x", "C /run/systemd - - - - /usr/share/x",
    "L+ /var/run - - - - ../run /../../proc/sys", "L+ /etc/mtab - - - - ../proc/self/mounts junk",
    'L+ /var/run - - - - "../run"', "L+ /var/run - - - - ../run\\x20",
    "f /etc/sysctl.d/zz.conf - - - - net.ipv4.ip_forward=1", "w /etc/sysctl.d/99-x.conf - - - - x",
    "L /etc/sysctl.d/zz.conf - - - - /usr/share/x/f.conf", "C /etc/sysctl.d/zz.conf - - - - /usr/share/x/f",
    "C /etc/sysctl.d - - - - /usr/share/x/sysctl.d", "f /etc/sysctl.conf", "d /etc/sysctl.d",
    "r /etc/sysctl.d/99-sysctl.conf", "L /etc/z - - - - /etc/sysctl.d",
    "C /etc/z - - - - /etc/sysctl.d", "C /usr/share/z - - - - /etc/modprobe.d", "L /etc/z - - - - /x /../proc/sys",
    'L /etc/z - - - - "/proc/sys"',
    "f /etc/modprobe.d/00-bt.conf - - - - install btusb /sbin/modprobe --ignore-install btusb",
    "f /run/modprobe.d/x.conf", "f /etc/systemd/network/10-x.network",
    "f /etc/systemd/resolved.conf.d/x.conf", "f /etc/systemd/resolved.conf",
    "f /etc/systemd/system/agentosd.service.d/x.conf", "L /etc/systemd/system/x.service - - - - /dev/null",
    "f /etc/tmpfiles.d/y.conf", "f /usr/lib/firmware/mediatek/x.bin", "f /etc/fstab",
    "w /sys/kernel/x - - - - 1", "w /sys/kernel/mm/ksm/run - - - - 0",
    "w /var/run/../proc/sys/x - - - - 1", "f /var/lock/../sysctl.d/x.conf", "f /usr/lib/../../x",
    "f /etc/systemd/*/x.conf", "f /etc/sysctl.?/x.conf",
    # #1543 Security delta at 4b636bf. B1: ".." in a link target, then a write through the link (a
    # chain the one-line differential test could not see). B2: an options line appended to the ESP's
    # boot entry. B3: the credential stores. R1: the generators and owner configuration.
    "L /opt/q - - - - /var/run/../etc/sysctl.d\nf /opt/q/99-x.conf - - - - net.ipv4.ip_forward=1",
    "L /opt/q - - - - /var/run/../etc/sysctl.d", "L /opt/q - - - - ../var/run/../etc",
    "C /opt/q - - - - /usr/share/x/../../../etc/sysctl.d",
    "w+ /efi/loader/entries/*.conf - - - - \\noptions sysctl.net.ipv4.ip_forward=1",
    "f /efi/loader/entries/agentos_z.conf - - - - options x", "w+ /boot/loader/entries/x.conf - - - - x",
    "f /etc/credstore/sysctl.extra - - - - net.ipv4.ip_forward=1",
    "f /run/credstore.encrypted/tmpfiles.extra", "f /usr/lib/credstore/sysctl.extra",
    "f /etc/systemd/system-generators/x 0755 - - - #!/bin/sh",
    "L /etc/systemd/system-generators/zram-generator - - - - /usr/lib/x/zram",
    "f /etc/agentos/modem.env - - - - COUNTRY_CODE=1", "f /lib/firmware/x.bin",
    # #2176 item 3: a file planted at boot in a boot-code channel exec.allow holds, by link or copy,
    # and kmod's /etc/modules, which Debian's modules-load.d/modules.conf links to.
    "L /etc/udev/rules.d/99-x.rules - - - - /usr/share/x/x.rules",
    "C /run/udev/rules.d/99-x.rules - - - - /usr/share/x/x.rules",
    "L /etc/modules-load.d/x.conf - - - - /usr/share/x/x.conf", "C /run/modules-load.d - - - - /usr/share/x",
    "L /etc/systemd/system-environment-generators/x - - - - /usr/share/x/x",
    "C /run/systemd/system-environment-generators/x - - - - /usr/share/x/x",
    "L /etc/binfmt.d/x.conf - - - - /usr/share/x/x.conf", "C /run/binfmt.d/x.conf - - - - /usr/share/x/x.conf",
    "L /usr/lib/systemd/system-shutdown/x - - - - /usr/share/x/x",
    "C /usr/lib/systemd/system-sleep/x - - - - /usr/share/x/x", "f /etc/modules - - - - tun")
# One probe per guarded name, under each configuration directory (#1543 P/UX B2). /usr is read-only
# on the box and trixie's /lib is /usr/lib, but the check guards them anyway.
TMPFILES_PROBES += tuple("f /%s/%s/x" % (top, n) for top in ("etc", "run", "usr/local/lib", "lib") for n in GUARDED_NAMES)


class TmpfilesTest(unittest.TestCase):
    """#1530: systemd-tmpfiles runs before systemd-sysctl and kmod, and can write /proc/sys or
    create, copy, link or remove the configuration the tree check reads (/etc/sysctl.d, /run/sysctl.d,
    modprobe.d, networkd, unit drop-ins, ...). Each refused line here could change what the box runs
    without the build seeing it."""
    # REQ: DEV-2, CH-9

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        write(self.root, "etc/machine-id", "uninitialized\n")
        nodump(self.root)
        bt_block(self.root)
        uplink(self.root)
        (self.root / "run").mkdir()
        (self.root / "proc").mkdir()
        link(self.root, "var/run", "/run")
        # These tests are of the guarded-path check; TmpfilesAllowTest is the allowlist's.
        patch = unittest.mock.patch.object(check, "tmpfiles_allow_violations", return_value=[])
        patch.start()
        self.addCleanup(patch.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def refused(self, line, name="usr/lib/tmpfiles.d/x.conf"):
        f = write(self.root, name, line)
        try:
            return "x.conf: line" in " | ".join(check.violations(self.root))
        finally:
            f.unlink()

    def test_debian_lines_pass(self):
        write(self.root, "usr/lib/tmpfiles.d/debian.conf", "# comment\n\n" + "\n".join(TMPFILES_PASS) + "\n")
        write(self.root, "usr/lib/tmpfiles.d/agentos.conf", AGENTOS_TMPFILES.read_text())
        self.assertEqual(check.violations(self.root), [])
        # The image already holds /etc/mtab, so the line's own path resolves into /proc.
        os.symlink("../proc/self/mounts", os.path.join(self.root, "etc/mtab"))
        self.assertEqual(check.violations(self.root), [])
        # Any other line through the existing /etc/mtab link still reaches /proc.
        for ln in ("f /etc/mtab", "w /etc/mtab - - - - x", "L+ /etc/mtab - - - - /proc/self/root"):
            self.assertTrue(self.refused(ln + "\n"), ln)

    def test_review_probes_are_refused(self):
        for ln in TMPFILES_PROBES:
            self.assertTrue(self.refused(ln + "\n"), ln)
        # A link already in a target dir makes its target one too (Debian's 99-sysctl.conf).
        write(self.root, "etc/sysctl.conf", "")
        link(self.root, "etc/sysctl.d/98-x.conf", "/usr/share/x/f.conf")
        self.assertTrue(self.refused("f /usr/share/x/f.conf - - - - net.ipv4.ip_forward=1\n"))
        self.assertFalse(self.refused("f /usr/share/x/g.conf\n"))
        # A link with no target names /usr/share/factory/<path>, which may itself be a link to a target.
        link(self.root, "usr/share/factory/etc/q", "/proc/sys")
        self.assertTrue(self.refused("L /etc/q\n"))
        self.assertTrue(self.refused("L /etc/q - - - - -\n"))
        self.assertFalse(self.refused("L /etc/r\n"))

    def test_proc_sys_writes_are_refused(self):
        for ln in ("w /proc/sys/net/ipv4/ip_forward - - - - 1", "w+ /proc/sys/net/ipv4/ip_forward - - - - 1",
                   'w "/proc/sys/net/ipv4/ip_forward" - - - - 1', "w /pro\\x63/sys/net/ipv4/ip_forward - - - - 1",
                   "w /proc/sys/net/ipv4/conf/*/forwarding - - - - 1", "w /pro?/sys/x - - - - 1",
                   "w /{proc,x}/sys/x - - - - 1", "w //proc/./sys/../sys/x - - - - 1", "w /run/../proc/sys/x - - - - 1",
                   "  w\t/proc/sys/x", "w /proc/sys/x\r", "d /proc"):
            self.assertTrue(self.refused(ln + "\n"), ln)
        # NUL and CR end a line for systemd-tmpfiles, so a comment cannot hide the next one.
        self.assertTrue(self.refused("# x\rw /proc/sys/x - - - - 1\n"))
        self.assertTrue(self.refused("# x\0w /proc/sys/x - - - - 1\n"))
        # Every tmpfiles.d directory systemd-tmpfiles reads.
        for d in ("etc", "usr/local/lib", "usr/lib"):
            self.assertTrue(self.refused("w /proc/sys/x - - - - 1\n", d + "/tmpfiles.d/x.conf"), d)

    def test_run_sysctl_d_is_refused(self):
        for ln in ("f /run/sysctl.d/x.conf - - - - net.ipv4.ip_forward=1", "f %t/sysctl.d/x.conf",
                   "F /var/run/sysctl.d/x.conf", "C /run/sysctl.d/x.conf - - - - /etc/x", "d /run/sysctl.d",
                   "f /run/sysctl?d/x.conf"):
            self.assertTrue(self.refused(ln + "\n"), ln)
        # Without /var/run in the tree, an allowed "L /var/run - - - - ../run" can make it at boot.
        (self.root / "var/run").unlink()
        self.assertTrue(self.refused("F /var/run/sysctl.d/x.conf\n"))

    def test_links_in_the_tree_are_followed(self):
        link(self.root, "etc/x", "/proc/sys/net")
        self.assertTrue(self.refused("w /etc/x/ipv4/ip_forward - - - - 1\n"))
        link(self.root, "etc/y", "../run")
        self.assertTrue(self.refused("f /etc/y/sysctl.d/x.conf\n"))
        self.assertTrue(self.refused("f /e*/y/sysctl.d/x.conf\n"))

    def test_links_to_a_target_or_above_are_refused(self):
        for ln in ("L /etc/y - - - - /run", "L /etc/y - - - - /proc/sys", "L /etc/y - - - - ../proc",
                   "L+ /etc/y - - - - %t", "L /run/x - - - - sysctl.d", "L /etc/y - - - - /",
                   "L /etc/y - - - - /proc/self/mounts", "L /etc/mtab - - - - /proc/self/root",
                   "L /etc/mtab - - - - /proc/self"):
            self.assertTrue(self.refused(ln + "\n"), ln)
        self.assertFalse(self.refused("L /etc/y - - - - /usr/lib/agentos\n"))
        # #1803: a link tmpfiles.d makes is held to the tree's link rules, so one into /run, which the
        # box fills at boot, is refused too (TreeLinkTmpfilesTest).
        self.assertTrue(self.refused("L /etc/y - - - - /run/agentos\n"))
        # Any ".." in a link target or copy source is refused, even a harmless one (#1543 Security B1):
        # the check walks it without links, the box with them. Only TMPFILES_STOCK's lines are exempt.
        for ln in ("L /etc/os-release - - - - ../usr/lib/os-release", "C /opt/x - - - - /usr/share/../share/y",
                   'L /opt/q - - - - "/var/run/../etc"', "L /opt/q - - - - /var/run/..",
                   "L /opt/q - - - - %t/../etc"):
            self.assertTrue(self.refused(ln + "\n"), ln)
        self.assertFalse(self.refused("L /opt/q - - - - /usr/share/..x\n"))

    def test_unreadable_and_run_tmpfiles_are_refused(self):
        d = self.root / "usr/lib/tmpfiles.d/x.conf"
        d.mkdir(parents=True)
        self.assertIn("usr/lib/tmpfiles.d/x.conf: unreadable (a directory)", " | ".join(check.violations(self.root)))
        d.rmdir()
        write(self.root, "usr/lib/tmpfiles.d/x.conf", "d /run/user\n")
        with unittest.mock.patch.object(check.Conf, "content", side_effect=PermissionError(13, "Permission denied")):
            self.assertIn("x.conf: unreadable (Permission denied)", " ".join(check.tmpfiles_violations(self.root)))
        write(self.root, "run/tmpfiles.d/x.conf", "d /run/user\n")
        self.assertIn("run/tmpfiles.d", " | ".join(check.violations(self.root)))

    def test_words(self):
        self.assertEqual(check.tmpfiles_words('w "/a b"\\x41 - - - - 1 2'), (["w", "/a bA", "-", "-", "-", "-"], "1 2"))
        self.assertEqual(check.tmpfiles_words("f /a\\101\\u0042\\U00000043\\n'c d'"), (["f", "/aABC\nc d"], ""))
        self.assertEqual(check.path_parts("//a/./b/../c/"), ["a", "c"])
        self.assertTrue(check.glob_reaches(["run"], ("run", "sysctl.d"), ancestor=True))
        self.assertFalse(check.glob_reaches(["run"], ("run", "sysctl.d")))


# systemd-analyze cat-config lists files with the same conf_files_list_strv (its --root chases
# directories inside the tree, though it reads a listed file's absolute link on the host). It stops
# at the first entry it cannot cat, so each tree has at most one such entry, sorted last.
DIFF_TREES = (
    {  # names: hidden, backups, suffixes, case and byte order, override by name across directories
        b"usr/lib/sysctl.d/10-a.conf": b"a.b=1\n", b"usr/local/lib/sysctl.d/10-a.conf": b"a.b=2\n",
        b"etc/sysctl.d/10-a.conf": "/dev/null", b"usr/lib/sysctl.d/20-b.conf": b"a.b=3\n",
        b"etc/sysctl.d/20-b.conf": b"", b"etc/sysctl.d/.hidden.conf": b"a.b=4\n",
        b"etc/sysctl.d/30.conf~": b"a.b=5\n", b"etc/sysctl.d/31.conf.dpkg-old": b"x\n",
        b"etc/sysctl.d/32.CONF": b"x\n", b"etc/sysctl.d/33.conf.bak": b"x\n", b"etc/sysctl.d/A.conf": b"x\n",
        b"etc/sysctl.d/a.conf": b"x\n", b"etc/sysctl.d/+a.conf": b"x\n", b"etc/sysctl.d/-a.conf": b"x\n",
        b"etc/sysctl.d/\xff.conf": b"x\n", b"etc/sysctl.d/\xee\x80\x80.conf": b"x\n",
        b"etc/sysctl.d/\xc3\xa9.conf": b"x\n", b"etc/sysctl.d/a b.conf": b"x\n", b"etc/sysctl.d/a.conf.conf": b"x\n",
        b"etc/sysctl.d/1-a.conf": b"x\n", b"etc/sysctl.d/10.conf": b"x\n", b"usr/lib/sysctl.d/~x.conf": b"x\n",
        b"lib/sysctl.d/05-lib.conf": b"x\n", b"etc/sysctl.conf": b"x\n",
        b"etc/sysctl.d/99-sysctl.conf": "../sysctl.conf",
        b"etc/systemd/resolved.conf": b"[Resolve]\n", b"usr/lib/systemd/resolved.conf": b"[Resolve]\n",
        b"usr/lib/systemd/resolved.conf.d/50-a.conf": b"x\n", b"etc/systemd/resolved.conf.d/50-a.conf": b"x\n",
        b"etc/systemd/resolved.conf.d/.h.conf": b"x\n", b"usr/local/lib/systemd/resolved.conf.d/\xff.conf": b"x\n",
        b"usr/local/lib/systemd/resolved.conf.d/A.conf": b"x\n",
        b"usr/lib/systemd/networkd.conf": b"[Network]\n", b"usr/lib/systemd/networkd.conf.d/z.conf": b"x\n",
        b"usr/local/lib/systemd/coredump.conf": b"[Coredump]\n", b"usr/lib/systemd/coredump.conf": b"[Coredump]\n",
        b"etc/systemd/system.conf.d/a.conf": b"x\n", b"etc/systemd/system.conf.d/a.conf~": b"x\n",
    },
    {  # linked directories, relative and absolute, resolved inside the tree; a dangling entry last
        b"usr/share/sd/10-a.conf": b"x\n", b"usr/share/sd/.b.conf": b"x\n",
        b"etc/sysctl.d": "../usr/share/sd", b"opt/x/10-a.conf": b"x\n", b"opt/x/20-c.conf": b"x\n",
        b"usr/local/lib/sysctl.d": "/opt/x", b"usr/lib/sysctl.d/30-d.conf": "../../../opt/x/20-c.conf",
        b"usr/lib/sysctl.d/zz-dangling.conf": "/nonexistent",
        b"opt/r/50-r.conf": b"x\n", b"etc/systemd/resolved.conf.d": "/opt/r",
        b"usr/lib/systemd/resolved.conf": b"x\n", b"usr/lib/systemd/resolved.conf.d/50-r.conf": b"y\n",
        b"etc/systemd/coredump.conf": "/dev/null", b"usr/lib/systemd/coredump.conf": b"x\n",
    },
    {  # a directory entry sorts last and takes its name
        b"usr/lib/sysctl.d/90-a.conf": b"x\n", b"usr/lib/sysctl.d/zz.conf": b"x\n",
        b"etc/sysctl.d/zz.conf/": None, b"usr/lib/systemd/system.conf": b"x\n",
    },
)


def reference_tool(case, name):
    """The path of a reference tool a differential test runs against. Where it is missing the test
    skips, unless AGENTOS_REQUIRE_REFERENCE_TOOLS=1 (CI's checks step sets it, #1531): then a runner
    without it fails rather than skipping quietly."""
    path = shutil.which(name, path=os.environ.get("PATH", "") + ":/usr/sbin:/sbin")
    if not path:
        if os.environ.get("AGENTOS_REQUIRE_REFERENCE_TOOLS") == "1":
            case.fail("AGENTOS_REQUIRE_REFERENCE_TOOLS=1 but %s is not installed" % name)
        case.skipTest("%s is not installed; this test is skipped without it" % name)
    return path


class TreeLinkTmpfilesTest(unittest.TestCase):
    """#1803: the link rules hold for links tmpfiles.d makes on the box, for tree links through steps
    tmpfiles.d makes, for '..' past a box mount in tmpfiles' own resolution, and for steps of the tree
    whose owner or ACL, not mode, lets someone else write them. Each refused case passed before."""
    # REQ: HW-1, DEV-2

    RULES = "etc/udev/rules.d"
    mutant = ConfFilesTest.mutant

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        write(self.root, "etc/machine-id", "uninitialized\n")
        nodump(self.root)
        bt_block(self.root)
        uplink(self.root)
        (self.root / "run").mkdir()
        (self.root / "proc").mkdir()
        (self.root / "usr/lib/x").mkdir(parents=True)
        link(self.root, "var/run", "/run")
        link(self.root, "var/lock", "/run/lock")
        # The guarded-path and link checks are under test here; TmpfilesAllowTest and ExecAllowTest
        # are the allowlists' (the latter refuses any linked rules.d).
        for name in ("tmpfiles_allow_violations", "exec_allow_violations"):
            patch = unittest.mock.patch.object(check, name, return_value=[])
            patch.start()
            self.addCleanup(patch.stop)

    def tmpfiles(self, text):
        return write(self.root, "usr/lib/tmpfiles.d/x.conf", text)

    def v(self, mod=check):
        return " | ".join(mod.violations(self.root))

    # (a) A tmpfiles.d L line makes a link on the box, so the tree's link rules apply to it.

    # The tmpfiles lines link /etc/udev/hwdb.d: a link into rules.d is refused before the link rule
    # runs, by the guarded-path check (#2176).

    def test_a_tmpfiles_link_into_a_world_writable_or_service_directory_is_refused(self):
        for ln in ("L /etc/udev/hwdb.d - - - - /var/tmp", "L+ /etc/udev/hwdb.d - - - - /var/tmp/r",
                   "L /etc/udev/hwdb.d - - - - /tmp", "L /etc/udev/hwdb.d - - - - /var/lib/agentos-egress",
                   "L /etc/udev/hwdb.d - - - - /run/agentos-egress/r", "L /etc/x - - - - /home/u",
                   "L /etc/x - - - - %V", "L /etc/x - - - - /dev/shm"):
            with self.subTest(ln=ln):
                f = self.tmpfiles(ln + "\n")
                try:
                    self.assertIn("x.conf: line 1: %s; a link to " % ln, self.v())
                finally:
                    f.unlink()

    def test_a_tmpfiles_link_into_what_the_box_fills_is_refused(self):
        # Default deny: /dev/fd/3 is the reader's fd 3. A tmpfiles link under a box mount is made on
        # the box, after the mount, so unlike a tree link there it is not hidden.
        for ln in ("L /etc/udev/hwdb.d - - - - /dev/fd/3", "L /run/x - - - - /dev/fd/4",
                   "L /etc/y - - - - /run/agentos", "L /var/run/x - - - - /dev/stdin"):
            with self.subTest(ln=ln):
                f = self.tmpfiles(ln + "\n")
                try:
                    self.assertIn("x.conf: line 1: %s; a link to " % ln, self.v())
                    self.assertIn("which the box fills at boot", self.v())
                finally:
                    f.unlink()

    def test_a_tree_link_through_a_tmpfiles_link_is_refused_twice(self):
        # The tree link reads a path the tree lacks; tmpfiles.d makes that path a link to fd 3.
        link(self.root, self.RULES, "/var/lib/x")
        self.tmpfiles("L /var/lib/x - - - - /dev/fd/3\n")
        out = self.v()
        self.assertIn("x.conf: line 1: L /var/lib/x - - - - /dev/fd/3; a link to /dev/fd/3", out)
        self.assertIn("etc/udev/rules.d: a link to /var/lib/x, through /var/lib/x, which the tree lacks "
                      "and usr/lib/tmpfiles.d/x.conf line 1 makes a link", out)

    def test_stock_and_allowlisted_tmpfiles_links_pass(self):
        # Every L line on the allowlist, and Debian's /run/shm alias of /dev/shm (TMPFILES_STOCK).
        lines = [ln.partition("\t")[2] for ln in (MK / check.TMPFILES_ALLOW).read_text().split("\n")
                 if re.match(r"[^#\t][^\t]*\tL", ln)]
        self.assertIn("L /run/shm     -    -    -    -   /dev/shm", lines)
        for ln in lines + ["L /etc/y - - - - /usr/lib/x", "L /etc/y - - - - /usr/lib/x/y"]:
            with self.subTest(ln=ln):
                f = self.tmpfiles(ln + "\n")
                try:
                    self.assertNotIn("x.conf: line", self.v())
                finally:
                    f.unlink()

    def test_without_the_tmpfiles_link_rule_its_links_pass(self):
        m = self.mutant('            elif typ[:1] == "L" and any(tmpfiles_link_refusal(root, path, p) for p in names[1:]):\n',
                        "            elif False:\n")
        self.tmpfiles("L /etc/udev/hwdb.d - - - - /var/tmp\n")
        self.assertNotIn("x.conf: line", self.v(m))
        self.assertIn("x.conf: line", self.v())

    # (b) A tree link through a step the tree lacks: tmpfiles.d may make that step.

    def test_a_tree_link_through_a_step_tmpfiles_makes_for_someone_else_is_refused(self):
        link(self.root, self.RULES, "/opt/nope/x")
        for ln, how in (("L /opt/nope - - - - /usr/lib", "makes a link"),
                        ("L+ /opt/* - - - - /usr/lib", "makes a link"),
                        ("d /opt/nope 1777 root root", "makes mode 1777 for root:root"),
                        ("D /opt/nope 0755 agentos-egress -", "makes mode 0755 for agentos-egress:-"),
                        ("d /opt/nope - agentos-egress -", "makes mode - for agentos-egress:-"),
                        ("d /opt/nope 0775 root agentos", "makes mode 0775 for root:agentos"),
                        ("d /opt/nope 07x9 root root", "makes with a mode it cannot parse (07x9)"),
                        ("a+ /opt/nope - - - - u:agentos-egress:rwx", "makes with a POSIX ACL"),
                        ("d /opt/nope/x 0700 agentos-egress -", "makes mode 0700 for agentos-egress:-")):
            with self.subTest(ln=ln):
                f = self.tmpfiles(ln + "\n")
                try:
                    self.assertIn("etc/udev/rules.d: a link to /opt/nope/x, through /opt/", self.v())
                    self.assertIn("usr/lib/tmpfiles.d/x.conf line 1 %s" % how, self.v())
                finally:
                    f.unlink()

    def test_a_tree_link_through_a_root_only_step_tmpfiles_makes_passes(self):
        link(self.root, self.RULES, "/opt/nope/x")
        for ln in ("d /opt/nope 0755 root root", "d /opt/nope - - -", "d /opt/nope 0775 root root",
                   "d /opt/nope", "L /opt/other - - - - /var/tmp"):
            with self.subTest(ln=ln):
                f = self.tmpfiles(ln + "\n")
                try:
                    self.assertNotIn("etc/udev/rules.d:", self.v())
                finally:
                    f.unlink()

    def test_a_link_into_a_service_users_cache_is_refused(self):
        # Debian's man-db makes /var/cache/man for the man user at boot, and the tree may lack it.
        (self.root / "var/cache").mkdir(parents=True)
        link(self.root, self.RULES, "/var/cache/man/r")
        self.tmpfiles("d /var/cache/man 0755 man man\n")
        self.assertIn("etc/udev/rules.d: a link to /var/cache/man/r, through /var/cache/man, which the tree "
                      "lacks and usr/lib/tmpfiles.d/x.conf line 1 makes mode 0755 for man:man", self.v())

    def test_lines_that_make_a_missing_step_group_writable_are_refused(self):
        # REQ: HW-1, DEV-2 (#1829, security and combined delta 2): a step the tree lacks takes its
        # parent's group (the tree or a line may set the setgid bit), and a line naming a non-root
        # group is refused outright; a d line with only g+w passes under a root-group parent.
        (self.root / "usr/lib/x").mkdir(parents=True, exist_ok=True)
        link(self.root, self.RULES, "/usr/lib/x/c/r")
        other = check.TREE_GROUP + 1000
        for text, gid, mode, n, how in (
                ("d /usr/lib/x/c 0775\n", other, 0o2755, 1, "mode 0775 for -:- under a parent of gid %d" % other),
                ("d /usr/lib/x/c 0775\n", other, 0o755, 1, "mode 0775 for -:- under a parent of gid %d" % other),
                # G1b: the parent's mode is the tree's or a line's; the gid is what the child takes.
                ("z /usr/lib/x 2755\nd /usr/lib/x/c 0775\n", other, 0o755, 2,
                 "mode 0775 for -:- under a parent of gid %d" % other),
                ("d /usr/lib/x/c 0775\nz /usr/lib/x/c - - 1000\n", None, 0o755, 2, "mode - for -:1000")):
            with self.subTest(text=text, gid=gid, mode=mode), self.attrs("usr/lib/x", gid=gid, mode=mode):
                f = self.tmpfiles(text)
                try:
                    self.assertIn("etc/udev/rules.d: a link to /usr/lib/x/c/r, through /usr/lib/x/c, which the tree "
                                  "lacks and usr/lib/tmpfiles.d/x.conf line %d makes %s; ship the step" % (n, how),
                                  self.v())
                finally:
                    f.unlink()
        # G1: a line that gives the parent a non-root group and the setgid bit is refused at the parent.
        f = self.tmpfiles("z /usr/lib/x 2755 - 1000\nd /usr/lib/x/c 0775\n")
        try:
            self.assertIn("etc/udev/rules.d: a link to /usr/lib/x/c/r, through /usr/lib/x, which "
                          "usr/lib/tmpfiles.d/x.conf line 1 remakes mode 2755 for -:1000 on the box", self.v())
        finally:
            f.unlink()
        for gid, mode in ((check.TREE_GROUP, 0o755), (check.TREE_GROUP, 0o2755)):
            with self.subTest(gid=gid, mode=mode), self.attrs("usr/lib/x", gid=gid, mode=mode):
                f = self.tmpfiles("d /usr/lib/x/c 0775\n")
                try:
                    self.assertNotIn("etc/udev/rules.d:", self.v())
                finally:
                    f.unlink()

    def test_security_delta_2_cases_are_refused(self):
        # REQ: HW-1, DEV-2 (#1829, security delta 2): a setgid line on a missing parent (P3, and a
        # gid carried down two missing steps), and lines systemd drops (a relative path, P4; a
        # duplicate d line, P8) trusted to reset the tree's mode.
        other = check.TREE_GROUP + 1000
        (self.root / "usr/lib/x").mkdir(parents=True, exist_ok=True)
        link(self.root, self.RULES, "/usr/lib/x/b/c/r")
        for text, gid, mode, step, n, how in (
                ("d /usr/lib/x/b 2755 - 1000\nd /usr/lib/x/b/c 0775\n", None, None, "b", 1, "mode 2755 for -:1000"),
                ("d /usr/lib/x/b 2755\nd /usr/lib/x/b/c 0775\n", other, 0o755, "b/c", 2,
                 "mode 0775 for -:- under a parent of gid %d" % other)):
            with self.subTest(text=text), self.attrs("usr/lib/x", gid=gid, mode=mode):
                f = self.tmpfiles(text)
                try:
                    self.assertIn("etc/udev/rules.d: a link to /usr/lib/x/b/c/r, through /usr/lib/x/%s, which the tree "
                                  "lacks and usr/lib/tmpfiles.d/x.conf line %d makes %s; ship the step" % (step, n, how),
                                  self.v())
                finally:
                    f.unlink()
        (self.root / self.RULES).unlink()
        link(self.root, self.RULES, "/usr/lib/x/r")
        for text, n in (("z usr/lib/x 0755 - -\nz /usr/lib/x - - 1000\n", 2),
                        ("d /usr/lib/x - - -\nd /usr/lib/x 0755 - -\nz /usr/lib/x - - 1000\n", 3)):
            with self.subTest(text=text), self.attrs("usr/lib/x", mode=0o775):
                f = self.tmpfiles(text)
                try:
                    self.assertIn("etc/udev/rules.d: a link to /usr/lib/x/r, through /usr/lib/x, which "
                                  "usr/lib/tmpfiles.d/x.conf line %d remakes mode - for -:1000 on the box" % n, self.v())
                finally:
                    f.unlink()

    def test_security_delta_3_steps_a_line_can_remove_are_weighed_as_lacking(self):
        # REQ: HW-1, DEV-2 (#1829, security delta 3): a line that removes a held step (r, R on it or a
        # parent, D or an age on a parent) leaves it to the line that makes it again, which the box
        # runs with the step taking its parent's group, so that line is weighed with the parent's gid.
        other = check.TREE_GROUP + 1000
        (self.root / "usr/lib/x/c/e").mkdir(parents=True, exist_ok=True)
        link(self.root, self.RULES, "/usr/lib/x/c/r")
        made = "usr/lib/tmpfiles.d/x.conf line 2 makes mode 0775 for -:- under a parent of gid %d" % other
        cases = ("R /usr/lib/x/c\n", "R /usr/lib/x/*\n", "r /usr/lib/x/c\n", "D /usr/lib/x\n",
                 "d /usr/lib/x - - - 10d\n", "e /usr/lib/x - - - 1h\n")
        for rm in cases:
            with self.subTest(rm=rm), self.attrs("usr/lib/x", gid=other, mode=0o2755):
                f = self.tmpfiles(rm + "d /usr/lib/x/c 0775\n")
                try:
                    self.assertIn("etc/udev/rules.d: a link to /usr/lib/x/c/r, through /usr/lib/x/c, which "
                                  "usr/lib/tmpfiles.d/x.conf line 1 can remove and %s on the box" % made, self.v())
                finally:
                    f.unlink()
        # The parent's gid is carried down a removed step to the next one, which goes with it.
        (self.root / self.RULES).unlink()
        link(self.root, self.RULES, "/usr/lib/x/c/e/r")
        with self.attrs("usr/lib/x", gid=other, mode=0o2755):
            f = self.tmpfiles("R /usr/lib/x/c\nd /usr/lib/x/c/e 0775\n")
            try:
                self.assertIn("etc/udev/rules.d: a link to /usr/lib/x/c/e/r, through /usr/lib/x/c/e, which "
                              "usr/lib/tmpfiles.d/x.conf line 1 can remove and %s on the box" % made, self.v())
            finally:
                f.unlink()
        # A tmpfiles.d link in a removed step is held to it as well.
        (self.root / self.RULES).unlink()
        with self.attrs("usr/lib/x", gid=other, mode=0o2755):
            f = self.tmpfiles("D /usr/lib/x\nd /usr/lib/x/c 0775\nL /usr/lib/x/c/l - - - - /etc/machine-id\n")
            try:
                self.assertIn("x.conf: line 3: L /usr/lib/x/c/l - - - - /etc/machine-id; a link to /etc/machine-id, "
                              "in /usr/lib/x/c, which usr/lib/tmpfiles.d/x.conf line 1 can remove and %s on the box"
                              % made, self.v())
            finally:
                f.unlink()
        # Passes: a root-group parent, a line that only removes, an age on the step itself (it cleans
        # what is below), and x/X lines, whose age only excludes.
        link(self.root, self.RULES, "/usr/lib/x/c/r")
        for text, gid in (("R /usr/lib/x/c\nd /usr/lib/x/c 0775\n", check.TREE_GROUP),
                          ("D /usr/lib/x\nd /usr/lib/x/c 0775\n", check.TREE_GROUP),
                          ("R /usr/lib/x/c\n", other), ("D /usr/lib/x/c\nd /usr/lib/x/c 0775\n", other),
                          ("d /usr/lib/x/c - - - 10d\nd /usr/lib/x/c 0775\n", other),
                          ("x /usr/lib/x - - - 10d\nd /usr/lib/x/c 0775\n", other),
                          ("X /usr/lib/x - - - 10d\nd /usr/lib/x/c 0775\n", other)):
            with self.subTest(text=text, gid=gid), self.attrs("usr/lib/x", gid=gid, mode=0o2755):
                f = self.tmpfiles(text)
                try:
                    self.assertNotIn("etc/udev/rules.d:", self.v())
                finally:
                    f.unlink()

    def test_without_the_removal_rules_those_links_pass(self):
        # Without the remover check, the gid it carries down, or the age rule, a delta 3 case passes.
        other = check.TREE_GROUP + 1000
        (self.root / "usr/lib/x/c/e").mkdir(parents=True, exist_ok=True)
        for old, new, text, to in (
                ("        removed = tmpfiles_remover(root, path_parts(d))\n", "        removed = None\n",
                 "R /usr/lib/x/c\nd /usr/lib/x/c 0775\n", "/usr/lib/x/c/r"),
                ("    if st.st_gid == TREE_GROUP and tmpfiles_remover(root, path_parts(d)):\n", "    if False:\n",
                 "R /usr/lib/x/c\nd /usr/lib/x/c/e 0775\n", "/usr/lib/x/c/e/r"),
                ('        if reach is None and typ not in ("x", "X") and age not in ("-", ""):\n',
                 "        if False:\n", "d /usr/lib/x - - - 10d\nd /usr/lib/x/c 0775\n", "/usr/lib/x/c/r")):
            with self.subTest(text=text):
                m = self.mutant(old, new)
                link(self.root, self.RULES, to)
                f = self.tmpfiles(text)
                try:
                    with self.attrs("usr/lib/x", gid=other, mode=0o2755):
                        with unittest.mock.patch.object(m, "tree_lstat", check.tree_lstat):
                            self.assertEqual(m.world_writable_link(str(self.root), self.RULES), [])
                        self.assertNotEqual(check.world_writable_link(str(self.root), self.RULES), [])
                finally:
                    f.unlink()
                    (self.root / self.RULES).unlink()

    def test_without_the_parent_gid_or_group_rules_those_links_pass(self):
        # A missing step that took root's group, a non-root group line weighed by its mode, or a g+w
        # line that ignored the step's gid would each let a case above through.
        (self.root / "usr/lib/x").mkdir(parents=True, exist_ok=True)
        link(self.root, self.RULES, "/usr/lib/x/c/r")
        other = check.TREE_GROUP + 1000
        for old, new, text, at in (
                ("        if st is not None:\n            gid = step_gid(root, d, st, gid)\n",
                 "        if st is not None:\n            gid = TREE_GROUP\n", "d /usr/lib/x/c 0775\n", "usr/lib/x"),
                ('        elif user.lstrip(":") not in ("-", "", "root", "0") or group.lstrip(":") not in '
                 '("-", "", "root", "0") \\\n', '        elif user.lstrip(":") not in ("-", "", "root", "0") \\\n',
                 "z /usr/lib/x 0755 - 1000\n", None),
                ("        elif st is not None and st.st_gid != TREE_GROUP and any(\n",
                 "        elif st is not None and False and any(\n", "z /usr/lib/x 0775 - -\n", "usr/lib/x")):
            with self.subTest(text=text):
                m = self.mutant(old, new)
                f = self.tmpfiles(text)
                try:
                    with self.attrs("usr/lib/x", gid=other, mode=0o755) if at else contextlib.nullcontext():
                        with unittest.mock.patch.object(m, "tree_lstat", check.tree_lstat):
                            self.assertEqual(m.world_writable_link(str(self.root), self.RULES), [])
                        self.assertNotEqual(check.world_writable_link(str(self.root), self.RULES), [])
                finally:
                    f.unlink()

    def test_without_the_tmpfiles_step_rule_the_link_passes(self):
        m = self.mutant("            made = tmpfiles_maker(root, parts[:k], os.stat_result((stat.S_IFDIR, 0, 0, 0, 0, gid, "
                        "0, 0, 0, 0)),\n                                  lacks=True)\n", "            made = None\n")
        link(self.root, self.RULES, "/opt/nope/x")
        self.tmpfiles("d /opt/nope 1777 root root\n")
        self.assertEqual(m.world_writable_link(str(self.root), self.RULES), [])
        self.assertNotEqual(check.world_writable_link(str(self.root), self.RULES), [])

    # (c) tmpfiles' own resolution: a '..' after a box mount is the box's to resolve.

    def test_tree_resolve_refuses_a_dotdot_past_a_box_mount(self):
        link(self.root, "a", "/run/q/../etc")
        with self.assertRaises(OSError) as e:
            check.tree_resolve(str(self.root), ["a", "sysctl.d", "x.conf"])
        self.assertEqual(e.exception.errno, errno.EXDEV)
        self.assertEqual(check.tree_resolve(str(self.root), ["var", "run", "q"]), ["run", "q"])
        # tmpfiles_hits takes such a path as one that may reach a guarded one.
        self.tmpfiles("f /a/sysctl.d/x.conf\n")
        self.assertIn("x.conf: line 1: f /a/sysctl.d/x.conf; it reaches /proc, /sys", self.v())

    def test_without_the_dotdot_refusal_tree_resolve_pops_it(self):
        m = self.mutant('        if ".." in p.split("/") + parts[k:]:\n', "        if False:\n")
        link(self.root, "a", "/run/q/../etc")
        self.assertEqual(m.tree_resolve(str(self.root), ["a", "x"]), ["run", "etc", "x"])

    # (d) Who can write a step is its owner and ACL as well as its mode.

    def test_a_link_through_a_step_with_a_posix_acl_is_refused(self):
        link(self.root, self.RULES, "/usr/lib/x/r")
        real = check.tree_xattrs
        for acl in check.ACL_XATTRS:
            with self.subTest(acl=acl), unittest.mock.patch.object(
                    check, "tree_xattrs", lambda root, rel, acl=acl: [acl] if rel == "usr/lib/x" else real(root, rel)):
                self.assertIn("etc/udev/rules.d: a link to /usr/lib/x/r, through /usr/lib/x, which carries a "
                              "POSIX ACL (%s)" % acl, self.v())
        with unittest.mock.patch.object(check, "tree_xattrs", lambda root, rel: ["user.x", "security.selinux"]):
            self.assertNotIn("etc/udev/rules.d:", self.v())

    def test_a_step_whose_attributes_cannot_be_read_is_refused(self):
        link(self.root, self.RULES, "/usr/lib/x/r")
        def boom(root, rel):
            raise OSError(errno.EIO, "Input/output error")
        with unittest.mock.patch.object(check, "tree_xattrs", boom):
            # #1829: the directory holding the link is asked first.
            self.assertIn("etc/udev/rules.d: a link to /usr/lib/x/r, in /etc, which carries a POSIX ACL "
                          "(unreadable (Input/output error))", self.v())

    def test_tree_xattrs_reads_the_names_and_none_where_unsupported(self):
        names = check.tree_xattrs(str(self.root), "usr/lib/x")
        self.assertFalse(set(names) & set(check.ACL_XATTRS))
        with unittest.mock.patch.object(check.os, "listxattr", side_effect=OSError(errno.ENOTSUP, "no")):
            self.assertEqual(check.tree_xattrs(str(self.root), "usr/lib/x"), [])
        with unittest.mock.patch.object(check.os, "listxattr", side_effect=OSError(errno.EIO, "io")):
            with self.assertRaises(OSError):
                check.tree_xattrs(str(self.root), "usr/lib/x")
        with self.assertRaises(FileNotFoundError):
            check.tree_xattrs(str(self.root), "usr/lib/nope")
        link(self.root, "usr/lib/l", "/var/tmp")
        with self.assertRaises(OSError):
            check.tree_xattrs(str(self.root), "usr/lib/l/x")

    def test_a_link_through_a_step_another_uid_owns_is_refused(self):
        link(self.root, self.RULES, "/usr/lib/x/r")
        owner = check.TREE_OWNER
        real = check.tree_lstat

        def lstat(root, rel):
            st = real(root, rel)
            if rel != "usr/lib/x" or st is None:
                return st
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, owner + 1000) + tuple(st)[5:])
        with unittest.mock.patch.object(check, "tree_lstat", lstat):
            self.assertIn("etc/udev/rules.d: a link to /usr/lib/x/r, through /usr/lib/x, which uid %d owns"
                          % (owner + 1000), self.v())
        self.assertNotIn("etc/udev/rules.d:", self.v())

    def test_without_the_owner_and_acl_rule_those_links_pass(self):
        m = self.mutant("        if st.st_uid != TREE_OWNER or acl:\n", "        if False:\n")
        link(self.root, self.RULES, "/usr/lib/x/r")
        with unittest.mock.patch.object(m, "tree_xattrs", lambda root, rel: [check.ACL_XATTRS[0]]):
            self.assertEqual(m.world_writable_link(str(self.root), self.RULES), [])
        with unittest.mock.patch.object(check, "tree_xattrs", lambda root, rel: [check.ACL_XATTRS[0]]):
            self.assertNotEqual(check.world_writable_link(str(self.root), self.RULES), [])

    # (e) The rules hold for each directory the chase walks through, not only the steps of where it
    # ends: whoever can write a directory holding a link the chase follows decides where it leads.

    def owned(self, rel):
        # tree_lstat with REL owned by a uid other than the tree's.
        real, owner = check.tree_lstat, check.TREE_OWNER

        def lstat(root, r):
            st = real(root, r)
            if r != rel or st is None:
                return st
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, owner + 1000) + tuple(st)[5:])
        return unittest.mock.patch.object(check, "tree_lstat", lstat)

    def test_a_link_through_a_directory_another_uid_owns_is_refused(self):
        (self.root / "opt/d").mkdir(parents=True)
        link(self.root, "opt/d/x", "/usr/lib/x")
        link(self.root, self.RULES, "/opt/d/x")
        with self.owned("opt/d"):
            self.assertIn("etc/udev/rules.d: a link to /opt/d/x, through /opt/d, which uid %d owns"
                          % (check.TREE_OWNER + 1000), self.v())
        self.assertNotIn("etc/udev/rules.d:", self.v())

    def test_a_tmpfiles_link_through_a_directory_another_uid_owns_is_refused(self):
        (self.root / "opt/d").mkdir(parents=True)
        link(self.root, "opt/d/x", "/usr/lib/x")
        ln = "L /etc/udev/hwdb.d - - - - /opt/d/x"
        self.tmpfiles(ln + "\n")
        with self.owned("opt/d"):
            self.assertIn("x.conf: line 1: %s; a link to /opt/d/x, through /opt/d, which uid %d owns"
                          % (ln, check.TREE_OWNER + 1000), self.v())
        self.assertNotIn("x.conf:", self.v())

    def test_a_link_through_a_world_writable_directory_is_refused(self):
        (self.root / "var/tmp").mkdir(parents=True)
        (self.root / "var/tmp").chmod(0o1777)
        (self.root / "opt/w").mkdir(parents=True)
        (self.root / "opt/w").chmod(0o1777)
        for d in ("var/tmp", "opt/w"):
            with self.subTest(d=d):
                link(self.root, d + "/x", "/usr/lib/x")
                link(self.root, self.RULES, "/%s/x" % d)
                try:
                    self.assertIn("etc/udev/rules.d: a link to /%s/x, inside /%s, which anyone" % (d, d), self.v())
                finally:
                    (self.root / self.RULES).unlink()

    def test_a_link_through_a_root_owned_directory_passes(self):
        (self.root / "opt/d").mkdir(parents=True)
        link(self.root, "opt/d/x", "/usr/lib/x")
        link(self.root, self.RULES, "/opt/d/x")
        self.tmpfiles("L /etc/udev/hwdb.d - - - - /opt/d/x\n")
        self.assertNotIn("etc/udev/rules.d:", self.v())
        self.assertNotIn("x.conf:", self.v())

    def test_without_the_walked_rule_those_links_pass(self):
        m = self.mutant("        why = step_refusal(root, d, target, True)\n", "        why = None\n")
        (self.root / "opt/w").mkdir(parents=True)
        (self.root / "opt/w").chmod(0o1777)
        link(self.root, "opt/w/x", "/usr/lib/x")
        link(self.root, self.RULES, "/opt/w/x")
        self.assertEqual(m.world_writable_link(str(self.root), self.RULES), [])
        self.assertIsNone(m.tmpfiles_link_refusal(str(self.root), self.RULES, "/opt/w/x"))
        self.assertNotEqual(check.world_writable_link(str(self.root), self.RULES), [])
        self.assertIsNotNone(check.tmpfiles_link_refusal(str(self.root), self.RULES, "/opt/w/x"))

    # (f) Potency R1: the rules no other test pins.

    def test_a_tmpfiles_link_the_check_cannot_follow_is_refused(self):
        link(self.root, "etc/loop", "/etc/loop")
        ln = "L /etc/x - - - - /etc/loop/y"
        self.tmpfiles(ln + "\n")
        self.assertIn("x.conf: line 1: %s; a link to /etc/loop/y, which the tree check cannot follow" % ln, self.v())
        m = self.mutant('        return "a link to %s, which the tree check cannot follow (%s) (#1803)" % (to, e.strerror)\n',
                        "        return None\n")
        self.assertIsNone(m.tmpfiles_link_refusal(str(self.root), "etc/x", "/etc/loop/y"))

    def test_a_step_tmpfiles_makes_through_a_tree_link_is_refused(self):
        (self.root / "opt").mkdir()
        link(self.root, "usr/local", "/opt")
        link(self.root, self.RULES, "/opt/nope/r")
        self.tmpfiles("d /usr/local/nope 1777 root root\n")
        self.assertIn("etc/udev/rules.d: a link to /opt/nope/r, through /opt/nope, which the tree lacks", self.v())
        m = self.mutant("        paths.append(tree_resolve(root, parts[:-1]) + parts[-1:] if link else tree_resolve(root, parts))\n",
                        "        pass\n")
        self.assertEqual(m.world_writable_link(str(self.root), self.RULES), [])

    def test_a_link_to_a_file_another_uid_owns_or_with_an_acl_is_refused(self):
        write(self.root, "usr/lib/x/r", "r\n")
        link(self.root, self.RULES, "/usr/lib/x/r")
        with self.owned("usr/lib/x/r"):
            self.assertIn("etc/udev/rules.d: a link to /usr/lib/x/r, through /usr/lib/x/r, which uid %d owns"
                          % (check.TREE_OWNER + 1000), self.v())
        real = check.tree_xattrs
        with unittest.mock.patch.object(check, "tree_xattrs", lambda root, rel: [check.ACL_XATTRS[0]]
                                        if rel == "usr/lib/x/r" else real(root, rel)):
            self.assertIn("through /usr/lib/x/r, which carries a POSIX ACL", self.v())
        self.assertNotIn("etc/udev/rules.d:", self.v())
        m = self.mutant('        why = step_refusal(root, d, target, not path.startswith("/"), st, gid=gid)\n',
                        '        why = step_refusal(root, d, target, not path.startswith("/") and k < len(parts), st, gid=gid)\n')
        with unittest.mock.patch.object(m, "tree_xattrs", lambda root, rel: [check.ACL_XATTRS[0]]
                                        if rel == "usr/lib/x/r" else []):
            self.assertEqual(m.world_writable_link(str(self.root), self.RULES), [])

    # (g) #1829: what the box does to a step after the build, and the directories a link sits in.
    # REQ: HW-1, DEV-2

    def attrs(self, rel, uid=None, gid=None, mode=None):
        # tree_lstat with REL given another owner, group or permission bits.
        real = check.tree_lstat

        def lstat(root, r):
            st = real(root, r)
            if r != rel or st is None:
                return st
            t = list(st)
            if mode is not None:
                t[0] = stat.S_IFMT(st.st_mode) | mode
            t[4] = st.st_uid if uid is None else uid
            t[5] = st.st_gid if gid is None else gid
            return os.stat_result(tuple(t))
        return unittest.mock.patch.object(check, "tree_lstat", lstat)

    def test_a_tmpfiles_line_that_changes_a_held_step_is_refused(self):
        link(self.root, self.RULES, "/usr/lib/x/r")
        for ln, step, how in (("z /usr/lib/x 0777 - - -", "usr/lib/x", "mode 0777 for -:-"),
                              ("a+ /usr/lib/x - - - - u:1000:rwx", "usr/lib/x", "with a POSIX ACL"),
                              ("Z /usr 0757 - -", "usr", "mode 0757 for -:-"),
                              ("A+ /usr/lib - - - - d:u:1000:rwx", "usr/lib", "with a POSIX ACL"),
                              ("D /usr/lib/x 0755 1000 -", "usr/lib/x", "mode 0755 for 1000:-"),
                              ("e /usr/lib/x 0775 root 1000", "usr/lib/x", "mode 0775 for root:1000"),
                              ("z /usr/lib/* 0777", "usr/lib/x", "mode 0777 for -:-"),
                              ("z /usr/lib/x ~0777", "usr/lib/x", "mode ~0777 for -:-"),
                              ("L+ /usr/lib/x - - - - /var/tmp", "usr/lib/x", "a link"),
                              ("C+ /usr/lib/x - - - - /var/tmp/u", "usr/lib/x", "a copy of /var/tmp/u")):
            with self.subTest(ln=ln):
                f = self.tmpfiles(ln + "\n")
                try:
                    self.assertIn("etc/udev/rules.d: a link to /usr/lib/x/r, through /%s, which "
                                  "usr/lib/tmpfiles.d/x.conf line 1 remakes %s on the box" % (step, how), self.v())
                finally:
                    f.unlink()
        # Combined delta 2: a line naming a non-root group is refused whatever the mode, as the step's
        # mode, another line or a setgid bit may give that group write.
        other = check.TREE_GROUP + 1000
        for ln, step, how in (("z /usr/lib/x - - 1000", "usr/lib/x", "mode - for -:1000"),
                              ("e /usr/lib/x - - 1000", "usr/lib/x", "mode - for -:1000"),
                              ("d /usr/lib/x - - 1000", "usr/lib/x", "mode - for -:1000"),
                              ("z /usr/lib/x 0755 - 1000", "usr/lib/x", "mode 0755 for -:1000"),
                              ("z /usr/lib/x :0755 - 1000", "usr/lib/x", "mode :0755 for -:1000"),
                              ("z /usr/lib/* - - 1000", "usr/lib/x", "mode - for -:1000"),
                              ("Z /usr - - 1000", "usr", "mode - for -:1000"),
                              ("z /usr/lib/x 2755 - 1000\nz /usr/lib/x 0775 - -", "usr/lib/x", "mode 2755 for -:1000")):
            with self.subTest(ln=ln):
                f = self.tmpfiles(ln + "\n")
                try:
                    self.assertIn("etc/udev/rules.d: a link to /usr/lib/x/r, through /%s, which "
                                  "usr/lib/tmpfiles.d/x.conf line 1 remakes %s on the box; the line, not the tree, "
                                  "decides who can write it" % (step, how), self.v())
                finally:
                    f.unlink()
        # A g+w line that names no group but root counts where the step's tree gid is not root: no line
        # is trusted to replace that group, since systemd skips a duplicate line for a path (G2), and
        # Z does not follow a link (G3). A Z line counts on the steps below it too.
        link(self.root, "opt/l", "/usr/lib")
        for lines, step in ((("z /usr/lib/x 0775 - -",), "usr/lib/x"),
                            (("d /usr/lib/x 0775",), "usr/lib/x"),
                            (("z /usr/lib/x 0775 - root",), "usr/lib/x"),
                            (("z /usr/lib/x 0775 - 0",), "usr/lib/x"),
                            (("Z /usr 0775 - -",), "usr/lib/x"),
                            (("d /usr/lib/x 0775 - -", "d /usr/lib/x - - root"), "usr/lib/x"),
                            (("z /usr/lib/x 0775 - -", "Z /opt/l - - root"), "usr/lib/x")):
            with self.subTest(lines=lines), self.attrs("usr/lib/x", gid=other, mode=0o755):
                f = self.tmpfiles("\n".join(lines) + "\n")
                try:
                    self.assertIn("etc/udev/rules.d: a link to /usr/lib/x/r, through /%s, which "
                                  "usr/lib/tmpfiles.d/x.conf line 1 remakes mode %s for -:%s over the tree's gid %d "
                                  "on the box" % (step, lines[0].split()[2], lines[0].split()[4] if len(
                                      lines[0].split()) > 4 else "-", other), self.v())
                finally:
                    f.unlink()
        # G2 across two files: the reset in another file is skipped just the same.
        f = self.tmpfiles("d /usr/lib/x 0775 - -\n")
        g = write(self.root, "etc/tmpfiles.d/a.conf", "d /usr/lib/x - - root\n")
        try:
            with self.attrs("usr/lib/x", gid=other, mode=0o755):
                self.assertIn("usr/lib/tmpfiles.d/x.conf line 1 remakes mode 0775 for -:- over the tree's gid %d"
                              % other, self.v())
        finally:
            f.unlink()
            g.unlink()
        (self.root / "opt/l").unlink()
        # L3 point 2: a directory the chase walks through, off the final path.
        (self.root / self.RULES).unlink()
        (self.root / "opt/d").mkdir(parents=True)
        link(self.root, "opt/d/x", "/usr/lib/x")
        link(self.root, self.RULES, "/opt/d/x")
        self.tmpfiles("d /opt/d 0777\n")
        self.assertIn("etc/udev/rules.d: a link to /opt/d/x, through /opt/d, which usr/lib/tmpfiles.d/x.conf "
                      "line 1 remakes mode 0777 for -:- on the box", self.v())

    def test_a_tmpfiles_line_that_keeps_a_held_step_root_only_passes(self):
        link(self.root, self.RULES, "/usr/lib/x/r")
        for ln in ("z /usr/lib/x 0755 root root", "d /usr/lib/x 0755 - -", "Z /usr 0755 root root",
                   "a+ /usr/lib/y - - - - u:1000:rwx", "z /usr/lib/x/r/q 0777", "e /usr/lib/x 0775 root root",
                   "L /etc/other - - - - /usr/lib/x"):
            with self.subTest(ln=ln):
                f = self.tmpfiles(ln + "\n")
                try:
                    self.assertNotIn("etc/udev/rules.d:", self.v())
                finally:
                    f.unlink()
        # A g+w line over a root-group step, or a line without group write over a non-root one.
        other = check.TREE_GROUP + 1000
        for ln, gid, mode in (("z /usr/lib/x 0775 - -", None, 0o755), ("z /usr/lib/x 0775 - root", None, 0o755),
                              ("d /usr/lib/x 0775", None, 0o755), ("Z /usr 0775 root root", None, 0o755),
                              ("z /usr/lib/x 0755 - -", other, 0o755), ("z /usr/lib/x 2755 - root", other, 0o755),
                              ("z /usr/lib/x 0775 - root\nz /usr/lib/x 0755 - -", None, 0o755)):
            with self.subTest(ln=ln, gid=gid), self.attrs("usr/lib/x", gid=gid, mode=mode):
                f = self.tmpfiles(ln + "\n")
                try:
                    self.assertNotIn("etc/udev/rules.d:", self.v())
                finally:
                    f.unlink()

    def test_without_the_held_step_tmpfiles_rule_those_links_pass(self):
        m = self.mutant("        made = tmpfiles_maker(root, path_parts(d), st)\n", "        made = None\n")
        link(self.root, self.RULES, "/usr/lib/x/r")
        self.tmpfiles("z /usr/lib/x 0777 - - -\n")
        self.assertEqual(m.world_writable_link(str(self.root), self.RULES), [])
        self.assertNotEqual(check.world_writable_link(str(self.root), self.RULES), [])

    def test_a_held_step_a_non_root_group_can_write_is_refused(self):
        link(self.root, self.RULES, "/usr/lib/x/r")
        other = check.TREE_GROUP + 1000
        with self.attrs("usr/lib/x", gid=other, mode=0o775):
            self.assertIn("etc/udev/rules.d: a link to /usr/lib/x/r, through /usr/lib/x, which gid %d can write"
                          % other, self.v())
        # var/mail and var/local are stock 2775 for mail and staff: a link through them is refused too.
        (self.root / "var/mail").mkdir(parents=True)
        link(self.root, "etc/udev/hwdb.d", "/var/mail/h")
        with self.attrs("var/mail", gid=other, mode=0o2775):
            self.assertIn("etc/udev/hwdb.d: a link to /var/mail/h, through /var/mail, which gid %d can write"
                          % other, self.v())
        for gid, mode in ((check.TREE_GROUP, 0o775), (other, 0o755)):
            with self.subTest(gid=gid, mode=mode), self.attrs("usr/lib/x", gid=gid, mode=mode):
                self.assertNotIn("etc/udev/rules.d:", self.v())

    def test_without_the_group_write_rule_the_link_passes(self):
        m = self.mutant("        if st.st_mode & 0o020 and st.st_gid != TREE_GROUP:\n", "        if False:\n")
        link(self.root, self.RULES, "/usr/lib/x/r")
        with self.attrs("usr/lib/x", gid=check.TREE_GROUP + 1000, mode=0o775):
            with unittest.mock.patch.object(m, "tree_lstat", check.tree_lstat):
                self.assertEqual(m.world_writable_link(str(self.root), self.RULES), [])
            self.assertNotEqual(check.world_writable_link(str(self.root), self.RULES), [])

    def test_a_tree_link_through_a_step_a_copy_line_makes_is_refused(self):
        link(self.root, self.RULES, "/opt/nope/x")
        for ln, how in (("C /opt/nope - - - - /var/tmp/u", "a copy of /var/tmp/u"),
                        ("C /opt/nope", "a copy of its factory default"),
                        ("C+ /opt/* 0755 root root - /usr/lib/x", "a copy of /usr/lib/x")):
            with self.subTest(ln=ln):
                f = self.tmpfiles(ln + "\n")
                try:
                    self.assertIn("etc/udev/rules.d: a link to /opt/nope/x, through /opt/nope, which the tree lacks "
                                  "and usr/lib/tmpfiles.d/x.conf line 1 makes %s" % how, self.v())
                finally:
                    f.unlink()

    def test_without_the_copy_rule_the_type_allowlist_still_refuses_the_link(self):
        # #2174: C is off TMPFILES_STEP_TYPES, so the copy rule now only names what the line does.
        m = self.mutant('        elif typ[:1] == "C":\n', "        elif False:\n")
        link(self.root, self.RULES, "/opt/nope/x")
        self.tmpfiles("C /opt/nope - - - - /var/tmp/u\n")
        self.assertIn("makes type C (off the step check's allowlist, #2174)",
                      " | ".join(m.world_writable_link(str(self.root), self.RULES)))
        self.assertIn("makes a copy of /var/tmp/u", " | ".join(check.world_writable_link(str(self.root), self.RULES)))
    # REQ: HW-1, DEV-2
    # #2174 (TREE-STEP-ALLOW): the step check is an allowlist of line types. A type or modifier not
    # known to leave a step root-only counts as making it writable, so a t or T line that sets an ACL
    # through its xattr (system.posix_acl_access) is refused like an a or A line.
    def test_a_tmpfiles_line_of_a_type_off_the_allowlist_is_refused(self):
        link(self.root, self.RULES, "/usr/lib/x/r")
        for ln, step, typ in (("t /usr/lib/x - - - - system.posix_acl_access=0sAgAAAAEABgD", "usr/lib/x", "t"),
                              ("T /usr - - - - system.posix_acl_default=0sAgAAAAEABgD", "usr", "T"),
                              ("t+ /usr/lib/x - - - - user.canary=1", "usr/lib/x", "t+"),
                              ("h /usr/lib/x - - - - -i", "usr/lib/x", "h"),
                              ("H /usr/lib - - - - -i", "usr/lib", "H"),
                              ("p /usr/lib/x 0600", "usr/lib/x", "p"),
                              ("c+ /usr/lib/x 0600 - - - 1:3", "usr/lib/x", "c+"),
                              ("b /usr/lib/x 0600 - - - 8:0", "usr/lib/x", "b"),
                              ("Y /usr/lib/x 0755", "usr/lib/x", "Y"),
                              ("f^ /usr/lib/x 0644 - - - canary.cred", "usr/lib/x", "f^"),
                              ("d= /usr/lib/x 0755", "usr/lib/x", "d="),
                              ("z? /usr/lib/x 0755", "usr/lib/x", "z?")):
            with self.subTest(ln=ln):
                f = self.tmpfiles(ln + "\n")
                try:
                    self.assertIn("etc/udev/rules.d: a link to /usr/lib/x/r, through /%s, which "
                                  "usr/lib/tmpfiles.d/x.conf line 1 remakes type %s (off the step check's "
                                  "allowlist, #2174) on the box" % (step, typ), self.v())
                finally:
                    f.unlink()
        # A step the tree lacks.
        (self.root / self.RULES).unlink()
        link(self.root, self.RULES, "/opt/nope/x")
        f = self.tmpfiles("t /opt/nope - - - - user.canary=1\n")
        try:
            self.assertIn("etc/udev/rules.d: a link to /opt/nope/x, through /opt/nope, which the tree lacks and "
                          "usr/lib/tmpfiles.d/x.conf line 1 makes type t (off the step check's allowlist, #2174)",
                          self.v())
        finally:
            f.unlink()

    def test_a_tmpfiles_line_of_an_allowlisted_type_keeping_a_step_root_only_passes(self):
        link(self.root, self.RULES, "/usr/lib/x/r")
        for ln in ("f /usr/lib/x 0644", "f+! /usr/lib/x 0644 root root - y", "w /usr/lib/x - - - - y",
                   "w+ /usr/lib/x - - - - y", "d /usr/lib/x 0755", "d- /usr/lib/x 0755", "d$ /usr/lib/x 0755",
                   "D! /usr/lib/x 0755 root root", "e /usr/lib/x 0755", "v /usr/lib/x 0755", "q /usr/lib/x 0755",
                   "Q /usr/lib/x 0755", "z /usr/lib/x 0755", "Z /usr 0755 root root", "f~ /usr/lib/x 0644 - - - eQ==",
                   "x /usr/lib/x", "X /usr/lib/x", "t /usr/lib/y - - - - user.canary=1"):
            with self.subTest(ln=ln):
                f = self.tmpfiles(ln + "\n")
                try:
                    self.assertNotIn("etc/udev/rules.d:", self.v())
                finally:
                    f.unlink()

    def test_without_the_type_allowlist_a_t_line_passes(self):
        m = self.mutant("        elif typ[:1] not in TMPFILES_STEP_TYPES or not set(typ[1:]) <= TMPFILES_STEP_MODIFIERS:\n",
                        "        elif False:\n")
        link(self.root, self.RULES, "/usr/lib/x/r")
        self.tmpfiles("t /usr/lib/x - - - - system.posix_acl_access=0sAgAAAAEABgD\n")
        self.assertEqual(m.world_writable_link(str(self.root), self.RULES), [])
        self.assertNotEqual(check.world_writable_link(str(self.root), self.RULES), [])

    def test_a_link_in_a_directory_someone_else_can_write_is_refused(self):
        (self.root / "etc/foo.d").mkdir(parents=True)
        link(self.root, "etc/foo.d/r", "/usr/lib/x/r")
        other = check.TREE_OWNER + 1000
        with self.attrs("etc/foo.d", uid=other):
            self.assertIn("etc/foo.d/r: a link to /usr/lib/x/r, in /etc/foo.d, which uid %d owns" % other, self.v())
        with self.attrs("etc/foo.d", gid=check.TREE_GROUP + 1000, mode=0o775):
            self.assertIn("etc/foo.d/r: a link to /usr/lib/x/r, in /etc/foo.d, which gid %d can write"
                          % (check.TREE_GROUP + 1000), self.v())
        real = check.tree_xattrs
        with unittest.mock.patch.object(check, "tree_xattrs", lambda root, rel: [check.ACL_XATTRS[0]]
                                        if rel == "etc/foo.d" else real(root, rel)):
            self.assertIn("etc/foo.d/r: a link to /usr/lib/x/r, in /etc/foo.d, which carries a POSIX ACL", self.v())
        # A mask is replaced as easily as any other link.
        link(self.root, "etc/foo.d/m", "/dev/null")
        with self.attrs("etc/foo.d", uid=other):
            self.assertIn("etc/foo.d/m: a link to /dev/null, in /etc/foo.d, which uid %d owns" % other, self.v())
        self.tmpfiles("z /etc/foo.d 0777\n")
        self.assertIn("etc/foo.d/r: a link to /usr/lib/x/r, in /etc/foo.d, which usr/lib/tmpfiles.d/x.conf "
                      "line 1 remakes mode 0777 for -:- on the box", self.v())
        # A link a tmpfiles.d L line makes there.
        ln = "L /etc/foo.d/t - - - - /usr/lib/x"
        self.tmpfiles(ln + "\n")
        with self.attrs("etc/foo.d", uid=other):
            self.assertIn("x.conf: line 1: %s; a link to /usr/lib/x, in /etc/foo.d, which uid %d owns" % (ln, other),
                          self.v())
        self.assertNotIn("etc/foo.d", self.v())

    def test_without_the_holder_rule_those_links_pass(self):
        m = self.mutant("            why = step_refusal(root, d, target, held, st, via=\"in\", gid=gid)\n", "            why = None\n")
        (self.root / "etc/foo.d").mkdir(parents=True)
        link(self.root, "etc/foo.d/r", "/usr/lib/x/r")
        self.tmpfiles("z /etc/foo.d 0777\n")
        self.assertEqual(m.world_writable_link(str(self.root), "etc/foo.d/r"), [])
        self.assertIsNone(m.tmpfiles_link_refusal(str(self.root), "etc/foo.d/t", "/usr/lib/x"))
        self.assertNotEqual(check.world_writable_link(str(self.root), "etc/foo.d/r"), [])
        self.assertIsNotNone(check.tmpfiles_link_refusal(str(self.root), "etc/foo.d/t", "/usr/lib/x"))

    def test_violations_reads_the_makers_once(self):
        for i in range(3):
            link(self.root, "etc/udev/rules.d/%d" % i, "/usr/lib/x/%d" % i)
        self.tmpfiles("L /etc/y - - - - /usr/lib/x\n")
        real = check.tmpfiles_makers
        with unittest.mock.patch.object(check, "tmpfiles_makers", side_effect=real) as makers:
            check.violations(self.root)
            self.assertEqual(makers.call_count, 1)
            # Outside violations() nothing is kept: a direct call reads the tree as it is now.
            check.world_writable_link(str(self.root), "etc/udev/rules.d/0")
            check.world_writable_link(str(self.root), "etc/udev/rules.d/0")
            self.assertGreater(makers.call_count, 2)
        self.assertIsNone(check._MAKERS)

    # SERVICE_DIRS lists every directory a unit's service user owns.

    # The image's units and those build.sh installs from their commands' directories.
    UNITS = sorted(list((MK / "mkosi.extra/usr/lib/systemd/system").glob("*.service"))
                   + [u for u in (ROOT / "broker/cmd").glob("*/*.service")
                      if '"$REPO/%s"' % u.relative_to(ROOT) in (IMG / "build.sh").read_text()])
    UNIT_DIRS = {"StateDirectory": "var/lib", "RuntimeDirectory": "run", "CacheDirectory": "var/cache",
                 "LogsDirectory": "var/log"}

    def service_dirs_missing(self, service_dirs):
        out = []
        for u in self.UNITS:
            keys = {}
            for ln in u.read_text().split("\n"):
                k, _, val = ln.strip().partition("=")
                keys.setdefault(k.strip(), []).append(val.strip())
            dyn = (keys.get("DynamicUser") or ["no"])[-1].lower() in ("yes", "true", "1", "on")
            user = (keys.get("User") or ["root"])[-1]
            if not dyn and user in ("", "root", "0"):
                continue
            for key, top in self.UNIT_DIRS.items():
                for val in keys.get(key, []):
                    for d in val.split():
                        d = top + "/" + d.split(":")[0].strip("/")
                        if not any(d == s or d.startswith(s + "/") for s in service_dirs):
                            out.append("%s: %s" % (u.name, d))
        return out

    def test_every_service_users_directory_is_in_service_dirs(self):
        self.assertIn("agentos-egress.service", [u.name for u in self.UNITS])
        self.assertIn("agentos-localui.service", [u.name for u in self.UNITS])
        self.assertEqual(self.service_dirs_missing(check.SERVICE_DIRS), [])
        # The check sees a dropped entry.
        for gone in ("var/lib/agentos-egress", "run/agentos-egress", "var/lib/agentos-localui"):
            with self.subTest(gone=gone):
                self.assertNotEqual(self.service_dirs_missing([s for s in check.SERVICE_DIRS if s != gone]), [])


class ReferenceToolTest(unittest.TestCase):
    """#1531: the differential tests fail, not skip, where CI requires their reference tools."""
    # REQ: DEV-2, CH-9

    def test_required_tool_missing_fails(self):
        with unittest.mock.patch.dict(os.environ, {"AGENTOS_REQUIRE_REFERENCE_TOOLS": "1", "PATH": ""}), \
                unittest.mock.patch.object(shutil, "which", return_value=None):
            with self.assertRaises(AssertionError):
                reference_tool(self, "systemd-analyze")
        with unittest.mock.patch.dict(os.environ, {"AGENTOS_REQUIRE_REFERENCE_TOOLS": ""}), \
                unittest.mock.patch.object(shutil, "which", return_value=None):
            with self.assertRaises(unittest.SkipTest):
                reference_tool(self, "systemd-analyze")

    def test_ci_checks_step_requires_them(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        step = ci[ci.index("- name: Unit tests"):]
        step = step[:step.index("\n      - ")]
        self.assertIn('AGENTOS_REQUIRE_REFERENCE_TOOLS: "1"', step)
        self.assertIn("unittest discover -s tests", step)


class SystemdDiffTest(unittest.TestCase):
    """#1508: conf_files and main_conf against systemd's own listing, `systemd-analyze cat-config
    --root=TREE`, over trees built to split them (hidden and backup names, byte order, override and
    masking across directories, linked directories, a split-/usr /lib). Without systemd-analyze it
    skips, unless AGENTOS_REQUIRE_REFERENCE_TOOLS=1 (CI sets it), where it fails instead and
    ReferenceDiffsRanTest fails on any skip; GitHub's ubuntu-latest runners have it (systemd 255,
    whose conf-files.c listing is the same as 257.13's)."""
    # REQ: DEV-2, CH-9, C13

    FAMILIES = (("sysctl.d", check.sysctl_files),
                ("systemd/resolved.conf", lambda r: check.main_conf(r, "resolved.conf")),
                ("systemd/networkd.conf", lambda r: check.main_conf(r, "networkd.conf")),
                ("systemd/coredump.conf", lambda r: check.main_conf(r, "coredump.conf")),
                ("systemd/system.conf", lambda r: check.main_conf(r, "system.conf")))

    def systemd_list(self, root, name):
        p = subprocess.run(["systemd-analyze", "cat-config", "--no-pager", "--root=" + str(root), name],
                           capture_output=True, timeout=60)
        prefix = os.fsencode(str(root)) + b"/"
        out = [ln[2 + len(prefix):] for ln in p.stdout.split(b"\n") if ln.startswith(b"# " + prefix)]
        m = re.search(rb"Failed to cat " + re.escape(prefix) + rb"(.*?): ", p.stderr)
        if m and out[-1:] != [m.group(1)]:
            out.append(m.group(1))
        return out

    def setUp(self):
        reference_tool(self, "systemd-analyze")

    def test_file_lists_match_systemd(self):
        for i, tree in enumerate(DIFF_TREES):
            with tempfile.TemporaryDirectory() as tmp:
                broot = os.fsencode(tmp)
                for rel, body in sorted(tree.items(), key=lambda kv: isinstance(kv[1], str)):
                    p = os.path.join(broot, rel)
                    os.makedirs(os.path.dirname(p.rstrip(b"/")), exist_ok=True)
                    if body is None:
                        os.mkdir(p)
                    elif isinstance(body, str):
                        os.symlink(body, p)
                    else:
                        with open(p, "wb") as f:
                            f.write(body)
                for name, ours in self.FAMILIES:
                    with self.subTest(tree=i, family=name):
                        mine = [os.fsencode(f.rel) for f in ours(pathlib.Path(tmp))]
                        self.assertEqual(mine, self.systemd_list(tmp, name))


class TmpfilesDiffTest(unittest.TestCase):
    """#1530: the guarded-path check against systemd-tmpfiles itself. Each case (Debian's lines,
    the image's, every review probe; a probe may be several lines, so a chain of lines is one case;
    and every file on tmpfiles.allow with all its listed lines, #1543 P/UX P1) is one tmpfiles.d
    file run through the real `systemd-tmpfiles --root=TREE --create --remove --boot` on a scratch
    tree that passes the tree check, never the host. A file the check passes must leave every path
    the box reads configuration from (GUARDED) as it was, and the tree must still pass the whole
    check after it. The allowlist (TmpfilesAllowTest) is the main guard; this is its backstop."""
    # REQ: DEV-2, CH-9
    # Probes that systemd-tmpfiles really turns into a write to a guarded path, so the oracle can fail.
    WRITES = ("C+ /run - - - - /usr/share/x", "w /proc/sys/net/ipv4/ip_forward - - - - 1",
              "f /etc/sysctl.d/zz.conf - - - - net.ipv4.ip_forward=1",
              "L /etc/sysctl.d/zz.conf - - - - /usr/share/x/f.conf",
              "f /etc/modprobe.d/00-bt.conf - - - - install btusb /sbin/modprobe --ignore-install btusb",
              "f /etc/systemd/network/10-x.network", "w /sys/kernel/x - - - - 1",
              "L /opt/q - - - - /var/run/../etc/sysctl.d\nf /opt/q/99-x.conf - - - - net.ipv4.ip_forward=1",
              "w+ /efi/loader/entries/*.conf - - - - \\noptions sysctl.net.ipv4.ip_forward=1",
              "f /etc/credstore/sysctl.extra - - - - net.ipv4.ip_forward=1")

    def tree(self, tmp):
        root = pathlib.Path(tmp)
        write(root, "etc/machine-id", "uninitialized\n")
        nodump(root)
        bt_block(root)
        uplink(root)
        (root / "run").mkdir()
        link(root, "var/run", "../run")
        write(root, "proc/sys/net/ipv4/ip_forward", "0\n")
        write(root, "sys/kernel/x", "0\n")
        write(root, "sys/kernel/mm/ksm/run", "0\n")
        write(root, "usr/share/x/sysctl.d/99-x.conf", "net.ipv4.ip_forward=1\n")
        write(root, "usr/share/x/f.conf", "net.ipv4.ip_forward=1\n")
        write(root, "etc/sysctl.conf", "")
        (root / "etc/sysctl.d").mkdir()
        # The empty credential stores the build's systemd-tmpfiles run leaves.
        (root / "etc/credstore").mkdir(mode=0o700)
        (root / "etc/credstore.encrypted").mkdir(mode=0o700)
        # The ESP as the box mounts it (#1543 Security B2), with an entry to append to.
        write(root, "efi/loader/entries/agentos_1+3.conf", "title AgentOS\noptions rw\n")
        return root

    # What the box reads that a tmpfiles.d line could change, listed here apart from the check's own
    # TMPFILES_TARGETS so that a target dropped there shows here.
    GUARDED = ("proc", "sys", "etc/sysctl.conf", "etc/fstab", "usr/lib/firmware", "lib/firmware", "etc/agentos",
               "efi", "boot") + tuple("%s/%s" % (top, n) for top in ("etc", "usr/local/lib", "usr/lib", "lib", "run")
                                      for n in GUARDED_NAMES)

    def snapshot(self, root):
        out = {}
        for t in self.GUARDED:
            top = os.path.join(root, t)
            for p in [top] + [os.path.join(d, n) for d, ds, fs in os.walk(top) for n in ds + fs]:
                rel = os.path.relpath(p, root)
                if os.path.islink(p):
                    out[rel] = ("link", os.readlink(p))
                elif os.path.isfile(p):
                    out[rel] = ("file", pathlib.Path(p).read_bytes())
                elif os.path.isdir(p):
                    out[rel] = ("dir",)
        return out

    def test_passed_lines_change_nothing_guarded(self):
        tool = reference_tool(self, "systemd-tmpfiles")
        lines = TMPFILES_PASS + tuple(ln for ln in AGENTOS_TMPFILES.read_text().splitlines()
                                      if ln and not ln.startswith("#")) + TMPFILES_PROBES
        # Every allowlisted file whole, under its own path, so that an entry added to tmpfiles.allow
        # is run too (#1543 P/UX P1): the tree then passes the allowlist as well as the guard.
        cases = [("usr/lib/tmpfiles.d/x.conf", ln) for ln in lines] + [
            (rel, "\n".join(group)) for rel, group in sorted(allow_groups().items())]
        changed = set()
        for rel, ln in cases:
            with self.subTest(file=rel, line=ln), tempfile.TemporaryDirectory() as tmp:
                root = self.tree(tmp)
                self.assertEqual(check.violations(root), [])
                f = write(root, rel, ln + "\n")
                passed = not check.tmpfiles_violations(root)
                before = self.snapshot(tmp)
                # --root keeps every path inside the scratch tree; the exit code is the line's own
                # business (a missing user or credential), what it did to the tree is the test.
                subprocess.run([tool, "--root=" + tmp, "--create", "--remove", "--boot"], capture_output=True, timeout=60)
                if self.snapshot(tmp) != before:
                    changed.add(ln)
                self.assertEqual(passed, ln not in TMPFILES_PROBES)
                if passed:
                    self.assertNotIn(ln, changed)
                    if rel != "usr/lib/tmpfiles.d/x.conf":
                        self.assertEqual(check.violations(root), [])
                    f.unlink()
                    self.assertEqual(check.violations(root), [])
        for ln in self.WRITES:
            self.assertIn(ln, changed, "systemd-tmpfiles did not write through %r; the oracle is vacuous" % ln)


def clean_tree(root):
    """A tree that passes the whole tree check: the image's own files from mkosi.extra."""
    root = pathlib.Path(root)
    write(root, "etc/machine-id", "uninitialized\n")
    nodump(root)
    bt_block(root)
    uplink(root)
    write(root, "usr/lib/tmpfiles.d/agentos.conf", AGENTOS_TMPFILES.read_text())
    tpm = "usr/lib/udev/rules.d/60-agentos-tpm.rules"
    write(root, tpm, (MK / "mkosi.extra" / tpm).read_text())
    return root


class TmpfilesAllowTest(unittest.TestCase):
    """#1543: every tmpfiles.d line in the image must be on image/mkosi/tmpfiles.allow, exactly and
    under the file it is in. The list was generated from the stock build, so a line a package update
    or an edit adds fails the build until it is reviewed and listed. This replaced a list of refused
    paths, which every review round found a way around (a chain of lines, the ESP, the credential
    store); the guarded-path check (TmpfilesTest) still runs behind it."""
    # REQ: DEV-2, CH-9
    AGENTOS = "usr/lib/tmpfiles.d/agentos.conf"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = clean_tree(self.tmp.name)

    def v(self):
        return check.tmpfiles_allow_violations(self.root)

    def test_allowlist_file(self):
        text = (MK / check.TMPFILES_ALLOW).read_text()
        self.assertTrue(text.startswith(check.TMPFILES_ALLOW_HEADER))
        allowed = check.tmpfiles_allowed()
        self.assertIsNotNone(allowed)
        self.assertGreater(len(allowed), 5)
        for ln in text.split("\n"):
            if ln and not ln.startswith("#"):
                rel, tab, line = ln.partition("\t")
                self.assertTrue(tab and line and line == line.strip(" \t") and not line.startswith("#"), ln)
                self.assertRegex(rel, r"^(etc|usr/local/lib|usr/lib)/tmpfiles\.d/[^/]+\.conf$")
        # The image's own file is on it line for line, and nothing else is listed under its name, so
        # an edit to agentos.conf fails here before it fails the build.
        mine = {(self.AGENTOS, ln) for n, ln in check.tmpfiles_lines(AGENTOS_TMPFILES.read_bytes())}
        self.assertEqual({e for e in allowed if e[0] == self.AGENTOS}, mine)

    def test_every_entry_passes_the_guard_under_its_own_file(self):
        # #1543 P/UX P1: every entry on the list, not only agentos.conf's, goes through the
        # guarded-path check, each file with all its lines (TmpfilesDiffTest runs the same files
        # through systemd-tmpfiles). An entry added to the list that writes configuration the tree
        # check reads fails here, and not only in the build.
        groups = allow_groups()
        self.assertEqual({(rel, ln) for rel, g in groups.items() for ln in g}, check.tmpfiles_allowed())
        for rel, group in sorted(groups.items()):
            with self.subTest(file=rel):
                write(self.root, rel, "\n".join(group) + "\n")
                self.assertEqual(check.tmpfiles_violations(self.root), [])
        self.assertEqual(check.tmpfiles_allow_violations(self.root), [])
        self.assertEqual(check.violations(self.root), [])

    def test_links_in_tmpfiles_d_are_refused(self):
        # #1543 Security B1: a dangling link read as nothing, so etc/tmpfiles.d/agentos.conf ->
        # /var/tmp/agentos.conf masked the shipped file and passed both layers; at the next boot
        # root's systemd-tmpfiles ran whatever a local user wrote there. Stock tmpfiles.d has no
        # links, so every one is refused (a mask, and a link to a listed file, too), relative or
        # absolute, before and after its target exists, and so is a linked directory.
        for rel in ("etc/tmpfiles.d/agentos.conf", "usr/lib/tmpfiles.d/x.conf"):
            for target in ("/var/tmp/agentos.conf", "../" * rel.count("/") + "var/tmp/agentos.conf", "/dev/null",
                           "/" + self.AGENTOS):
                if target == "/" + rel:
                    continue
                with self.subTest(rel=rel, target=target):
                    f = link(self.root, rel, target)
                    want = "%s: unreadable (a link to %s; tmpfiles.d ships no links" % (rel, target)
                    for v in (self.v(), check.tmpfiles_violations(self.root), check.violations(self.root)):
                        self.assertIn(want, " | ".join(v))
                    write(self.root, "var/tmp/agentos.conf", "f /etc/sysctl.d/99-x.conf - - - - net.ipv4.ip_forward=1\n")
                    self.assertIn(want, " | ".join(self.v()))
                    (self.root / "var/tmp/agentos.conf").unlink()
                    f.unlink()
        self.assertEqual(check.violations(self.root), [])
        (self.root / "etc/tmpfiles.d").rmdir()
        for target in ("/var/tmp/td", "../var/tmp/td"):
            with self.subTest(dir_target=target):
                f = link(self.root, "etc/tmpfiles.d", target)
                self.assertIn("etc/tmpfiles.d: unreadable (etc/tmpfiles.d is a link to %s;" % target,
                              " | ".join(check.violations(self.root)))
                f.unlink()

    def test_listed_lines_pass_and_others_fail(self):
        self.assertEqual(self.v(), [])
        self.assertEqual(check.violations(self.root), [])
        base = AGENTOS_TMPFILES.read_text()
        first = next(ln for n, ln in check.tmpfiles_lines(base.encode()))
        # Comments, blank lines and blanks around a line change nothing.
        write(self.root, self.AGENTOS, "\n# x\n  \t" + base.replace("\n", " \t\n") + "\n\n")
        self.assertEqual(self.v(), [])
        for body, want in (
                (base + "w /proc/sys/net/ipv4/ip_forward - - - - 1\n", "line %d" % (base.count("\n") + 1)),
                (base.replace(first, first.replace(" ", "  ", 1)), "line 2"),
                (base.replace(first, first.replace(" ", "\t", 1)), "line 2"),
                (base + "d /var/lib/agentos 0700 root root\n", "not on"),
                (base.rstrip("\n") + "\rf /etc/sysctl.d/x.conf\n", "f /etc/sysctl.d/x.conf"),
                (base.rstrip("\n") + "\0f /etc/sysctl.d/x.conf\n", "f /etc/sysctl.d/x.conf"),
                # CR and NUL end a line, so a comment cannot hide the line after them.
                (base + "# x\rw /proc/sys/x - - - - 1\n", "w /proc/sys/x"),
                (base + "# x\0w /proc/sys/x - - - - 1\n", "w /proc/sys/x"),
                (base + "L /opt/q - - - - /var/run/../etc/sysctl.d\nf /opt/q/99-x.conf - - - - net.ipv4.ip_forward=1\n",
                 "f /opt/q/99-x.conf")):
            with self.subTest(body=body):
                write(self.root, self.AGENTOS, body)
                v = self.v()
                self.assertTrue(v and all("not on the tmpfiles.d allowlist" in m for m in v), v)
                self.assertIn(want, " | ".join(v))
                self.assertIn("not on the tmpfiles.d allowlist", " | ".join(check.violations(self.root)))
        write(self.root, self.AGENTOS, base)
        # The entry that would allow a line is in the message, ready to review and copy.
        write(self.root, "usr/lib/tmpfiles.d/x.conf", "d /run/y 0755\n")
        self.assertEqual(self.v(), ["usr/lib/tmpfiles.d/x.conf line 1: not on the tmpfiles.d allowlist "
                                    "(image/mkosi/tmpfiles.allow, #1543); review this line, then add the entry after "
                                    "'entry:' to that file (each line is reviewed on its own: mkosi.finalize "
                                    "--tmpfiles-allowlist ROOT only lists what a tree holds, it reviews nothing); "
                                    "entry: usr/lib/tmpfiles.d/x.conf\td /run/y 0755"])
        # A line the guarded-path check refuses is offered no entry: it must not be listed (#1543 P/UX U4-1).
        write(self.root, "usr/lib/tmpfiles.d/x.conf", "d /run/y 0755\nw /proc/sys/net/ipv4/ip_forward - - - - 1\n")
        v = self.v()
        self.assertEqual(v[1], "usr/lib/tmpfiles.d/x.conf line 2: w /proc/sys/net/ipv4/ip_forward - - - - 1: not on "
                               "the tmpfiles.d allowlist (image/mkosi/tmpfiles.allow, #1543), and the guarded-path "
                               "check refuses it too: remove the line; it must not be added")
        self.assertNotIn("entry:", v[1])
        self.assertIn("usr/lib/tmpfiles.d/x.conf: line 2: w /proc/sys/net/ipv4/ip_forward", " | ".join(check.violations(self.root)))
        write(self.root, "usr/lib/tmpfiles.d/x.conf", "d /run/y 0755\n")
        # The build's last line names the file too, not per-install state (#1543 P/UX U1).
        with unittest.mock.patch.object(sys, "argv", ["mkosi.finalize", str(self.root)]), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as e:
            check.main()
        self.assertEqual(str(e.exception), "image check: 1 problem(s) in the image tree, each named above; a "
                         "tmpfiles.d line missing from image/mkosi/tmpfiles.allow that the guarded-path check passes "
                         "ends in the entry to review and add there")

    def test_lines_are_keyed_by_file(self):
        # A listed line in another file, or the same file in another directory, is not listed.
        for rel in ("usr/lib/tmpfiles.d/x.conf", "etc/tmpfiles.d/agentos.conf", "usr/local/lib/tmpfiles.d/agentos.conf",
                    "etc/tmpfiles.d/x.conf"):
            with self.subTest(rel=rel):
                f = write(self.root, rel, AGENTOS_TMPFILES.read_text())
                self.assertIn(rel + " line", " | ".join(self.v()))
                f.unlink()
        # A split-/usr /lib is read too (and stray_violations refuses it).
        write(self.root, "lib/tmpfiles.d/x.conf", "d /run/y\n")
        self.assertIn("lib/tmpfiles.d/x.conf line 1", " | ".join(self.v()))
        (self.root / "lib/tmpfiles.d/x.conf").unlink()
        # tmpfiles.d takes no link at all (#1543 Security B1): stock has none, and a link in /etc
        # would mask the listed file. A mask is refused too, not only a link to elsewhere.
        link(self.root, "etc/tmpfiles.d/agentos.conf", "/dev/null")
        self.assertIn("etc/tmpfiles.d/agentos.conf: unreadable (a link to /dev/null; tmpfiles.d ships no links",
                      " | ".join(self.v()))
        (self.root / "etc/tmpfiles.d/agentos.conf").unlink()
        # Anything at all under /run/tmpfiles.d, and a file that cannot be read.
        write(self.root, "run/tmpfiles.d/agentos.conf", AGENTOS_TMPFILES.read_text())
        self.assertIn("run/tmpfiles.d: not on the tmpfiles.d allowlist", " | ".join(self.v()))
        shutil.rmtree(self.root / "run/tmpfiles.d")
        (self.root / "usr/lib/tmpfiles.d/y.conf").mkdir()
        self.assertIn("usr/lib/tmpfiles.d/y.conf: unreadable", " | ".join(self.v()))

    def test_found_under_mkosi_and_missing_fails(self):
        # mkosi v24.3 runs the script from /work/finalize with the configuration directory at $SRCDIR.
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(MK / "mkosi.finalize", os.path.join(tmp, "finalize"))
            moved = load("image_check_moved", os.path.join(tmp, "finalize"))
            moved.TREE_OWNER = check.TREE_OWNER
            with unittest.mock.patch.dict(os.environ, {"SRCDIR": str(MK)}):
                self.assertEqual(moved.tmpfiles_allow_path(), str(MK / check.TMPFILES_ALLOW))
                self.assertEqual(moved.tmpfiles_allow_violations(self.root), [])
            with unittest.mock.patch.dict(os.environ, {"SRCDIR": tmp}):
                self.assertIsNone(moved.tmpfiles_allow_path())
                self.assertEqual(moved.tmpfiles_allow_violations(self.root),
                                 ["tmpfiles.allow: missing; every tmpfiles.d line must be on it (#1543)"])
                self.assertIn("tmpfiles.allow: missing", " | ".join(moved.violations(self.root)))

    def test_regenerate(self):
        write(self.root, "etc/tmpfiles.d/x.conf", "  d /run/y 0755\t\n# c\nL+ /var/run - - - - ../run\n")
        out = io.StringIO()
        with unittest.mock.patch.object(sys, "argv", ["mkosi.finalize", "--tmpfiles-allowlist", str(self.root)]), \
                contextlib.redirect_stdout(out):
            check.main()
        self.assertTrue(out.getvalue().startswith(check.TMPFILES_ALLOW_HEADER))
        f = pathlib.Path(self.tmp.name) / "allow"
        f.write_text(out.getvalue())
        allowed = check.tmpfiles_allowed(str(f))
        self.assertIn(("etc/tmpfiles.d/x.conf", "d /run/y 0755"), allowed)
        self.assertIn(("etc/tmpfiles.d/x.conf", "L+ /var/run - - - - ../run"), allowed)
        self.assertEqual(check.tmpfiles_allow_violations(self.root, allowed), [])
        self.assertNotEqual(check.tmpfiles_allow_violations(self.root, allowed - {("etc/tmpfiles.d/x.conf", "d /run/y 0755")}), [])


class ExecAllowTest(unittest.TestCase):
    """#1556: the code root runs at boot outside unit Exec lines (udev rules, system and environment
    generators, modules-load.d) is held to image/mkosi/exec.allow: every file in every directory
    systemd 257 reads them from, by its path and the SHA-256 of what the box reads. A rule that runs
    sysctl, or a changed stock generator, fails the build until it is reviewed and listed."""
    # REQ: DEV-2, CH-9
    TPM = "usr/lib/udev/rules.d/60-agentos-tpm.rules"
    HARM = 'ACTION=="add", SUBSYSTEM=="net", RUN+="/usr/sbin/sysctl -w net.ipv4.ip_forward=1"\n'
    CHANNELS = ("etc/udev/rules.d/99-x.rules", "usr/local/lib/udev/rules.d/99-x.rules",
                "usr/lib/udev/rules.d/99-x.rules", "etc/systemd/system-generators/x",
                "usr/local/lib/systemd/system-generators/x", "usr/lib/systemd/system-generators/x",
                "etc/systemd/system-environment-generators/x", "usr/lib/systemd/system-environment-generators/x",
                "etc/modules-load.d/x.conf", "usr/local/lib/modules-load.d/x.conf", "usr/lib/modules-load.d/x.conf",
                # #2176: modprobe.d install lines, sysctl.d helpers, binfmt.d, shutdown and sleep hooks.
                "etc/modprobe.d/x.conf", "usr/local/lib/modprobe.d/x.conf", "usr/lib/modprobe.d/x.conf",
                "lib/modprobe.d/x.conf", "etc/sysctl.d/x.conf", "usr/local/lib/sysctl.d/x.conf",
                "usr/lib/sysctl.d/x.conf", "etc/binfmt.d/x.conf", "usr/lib/binfmt.d/x.conf",
                "usr/lib/systemd/system-shutdown/x", "usr/lib/systemd/system-sleep/x",
                "etc/systemd/system-shutdown/x", "usr/local/lib/systemd/system-sleep/x")
    # #2176's failure paths: each runs root code at boot from a file the old check never hashed.
    PATHS = {"usr/lib/modprobe.d/x.conf": "install tun /usr/sbin/sysctl -w net.ipv4.ip_forward=1\n",
             "usr/lib/sysctl.d/x.conf": "kernel.modprobe = /usr/local/bin/x\n",
             "etc/sysctl.d/y.conf": "kernel/hotplug=/usr/local/bin/x\n",
             "usr/lib/binfmt.d/x.conf": ":x:E::x::/usr/local/bin/x:\n",
             "usr/lib/systemd/system-shutdown/x": "#!/bin/sh\nsysctl -w net.ipv4.ip_forward=1\n",
             "usr/lib/systemd/system-sleep/x": "#!/bin/sh\nsysctl -w net.ipv4.ip_forward=1\n"}
    GENERATORS = ("usr/lib/systemd/system-generators/systemd-sysv-generator",
                  "usr/lib/systemd/system-generators/systemd-rc-local-generator")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = clean_tree(self.tmp.name)

    def v(self, allowed=None):
        return check.exec_allow_violations(self.root, allowed)

    @staticmethod
    def entry(data):
        return "sha256:" + hashlib.sha256(data.encode()).hexdigest()

    def test_allowlist_file(self):
        text = (MK / check.EXEC_ALLOW).read_text()
        self.assertTrue(text.startswith(check.EXEC_ALLOW_HEADER))
        self.assertIn(check.EXEC_REGENERATE.replace("ROOT", ""), check.EXEC_ALLOW_HEADER)
        allowed = check.exec_allowed()
        self.assertIsNotNone(allowed)
        for ln in text.split("\n"):
            if ln and not ln.startswith("#"):
                rel, tab, value = ln.partition("\t")
                self.assertTrue(tab, ln)
                self.assertRegex(rel, r"^((etc|usr/local/lib|usr/lib|lib)/(udev/rules\.d/[^/]+\.rules|systemd/system-"
                                      r"((environment-)?generators|shutdown|sleep)/[^/]+|"
                                      r"(modules-load|modprobe|sysctl|binfmt)\.d/[^/]+\.conf)|"
                                      # #2622: bus and polkit policy.
                                      r"(etc|usr/share)/polkit-1/rules\.d/[^/]+|usr/share/polkit-1/actions/[^/]+|"
                                      r"etc/dbus-1/.+|usr/share/dbus-1/(system\.d/[^/]+|system-services/[^/]+|"
                                      r"system\.conf))$")
                self.assertRegex(value, r"^(sha256:[0-9a-f]{64}|mask)$")
        # The image's own rules file is on it by its hash, so an edit to it fails here first.
        tpm = (MK / "mkosi.extra" / self.TPM).read_text()
        self.assertIn((self.TPM, self.entry(tpm)), allowed)
        # So are its modprobe.d and sysctl.d files (#2176), and neither sysv generator.
        for rel in (BT_BLOCK, "usr/lib/sysctl.d/99-agentos-nodump.conf"):
            self.assertIn((rel, self.entry((MK / "mkosi.extra" / rel).read_text())), allowed)
        for rel in self.GENERATORS:
            self.assertNotIn(rel, {r for r, _ in allowed})
        self.assertEqual(self.v(), [])
        self.assertEqual(check.violations(self.root), [])

    def test_listed_files_pass_and_others_fail(self):
        self.assertEqual(self.v(), [])
        for rel in self.CHANNELS:
            with self.subTest(rel=rel):
                p = write(self.root, rel, self.HARM, 0o755)
                want = "%s: not on the boot-code allowlist (%s, #1556)" % (rel, check.EXEC_ALLOW_REPO)
                v = self.v()
                self.assertEqual(len(v), 1, v)
                self.assertTrue(v[0].startswith(want), v)
                self.assertTrue(v[0].endswith("entry: %s\t%s" % (rel, self.entry(self.HARM))), v)
                self.assertIn(want, " | ".join(check.violations(self.root)))
                allowed = check.exec_allowed() | {(rel, self.entry(self.HARM))}
                self.assertEqual(self.v(allowed), [])
                # One byte changed, and the listed file fails again.
                write(self.root, rel, self.HARM.replace("=1", "=0"), 0o755)
                self.assertTrue(self.v(allowed) and self.v(allowed)[0].startswith(want))
                p.unlink()
        # The image's own file, changed.
        write(self.root, self.TPM, (MK / "mkosi.extra" / self.TPM).read_text() + self.HARM)
        self.assertIn("%s: not on the boot-code allowlist" % self.TPM, " | ".join(check.violations(self.root)))

    def test_2176_failure_paths(self):
        for rel, data in self.PATHS.items():
            with self.subTest(rel=rel):
                p = write(self.root, rel, data, 0o755)
                want = "%s: not on the boot-code allowlist (%s, #1556)" % (rel, check.EXEC_ALLOW_REPO)
                self.assertIn(want, " | ".join(check.violations(self.root)))
                self.assertEqual(self.v(check.exec_allowed() | {(rel, self.entry(data))}), [])
                p.unlink()
        # The sysv and rc-local generators turn /etc/init.d and /etc/rc.local into units; the image
        # removes them, so one that comes back fails.
        for rel in self.GENERATORS:
            with self.subTest(rel=rel):
                p = write(self.root, rel, "\x7fELF", 0o755)
                self.assertIn("%s: not on the boot-code allowlist" % rel, " | ".join(check.violations(self.root)))
                p.unlink()
        conf = (MK / "mkosi.conf").read_text()
        for rel in self.GENERATORS:
            self.assertRegex(conf, r"(?m)^\s*(RemoveFiles=)?/%s$" % re.escape(rel))

    def test_modprobe_listing_follows_kmod(self):
        # kmod reads only *.conf and skips only dot names, so a backup name is skipped by its suffix;
        # it reads a non-directory modprobe.d as one file, which must then be listed.
        for rel in ("usr/lib/modprobe.d/x.conf~", "usr/lib/modprobe.d/.x.conf", "usr/lib/modprobe.d/x.txt"):
            write(self.root, rel, self.PATHS["usr/lib/modprobe.d/x.conf"])
        self.assertEqual(self.v(), [])
        shutil.rmtree(self.root / "usr/lib/modprobe.d")
        write(self.root, "etc/modprobe.d", "install tun /bin/true\n")
        self.assertIn("etc/modprobe.d: not on the boot-code allowlist", " | ".join(self.v()))

    def test_every_file_is_listed_not_only_the_winner(self):
        # systemd runs a generator only if it is executable, and a non-executable file of the same name
        # in /etc does not take the name, so the /usr/lib one still runs: every file is listed.
        rel = "usr/lib/systemd/system-generators/x"
        write(self.root, rel, "#!/bin/sh\nsysctl -w net.ipv4.ip_forward=1\n", 0o755)
        write(self.root, "etc/systemd/system-generators/x", "", 0o644)
        allowed = check.exec_allowed() | {("etc/systemd/system-generators/x", "mask")}
        self.assertIn("%s: not on the boot-code allowlist" % rel, " | ".join(self.v(allowed)))
        # Hidden and backup names are skipped as systemd skips them; other suffixes in udev and
        # modules-load.d too, since neither reads them.
        (self.root / rel).unlink()
        for rel in ("usr/lib/udev/rules.d/.x.rules", "usr/lib/udev/rules.d/x.rules~", "usr/lib/udev/rules.d/x.txt",
                    "usr/lib/modules-load.d/x.conf.dpkg-old", "usr/lib/systemd/system-generators/x.bak"):
            write(self.root, rel, self.HARM, 0o755)
        self.assertEqual(self.v(allowed), [])

    def test_links_and_masks(self):
        rel = "etc/udev/rules.d/60-agentos-tpm.rules"
        write(self.root, "var/tmp/x.rules", self.HARM)
        for target in ("/var/tmp/x.rules", "../../../var/tmp/x.rules", "/" + self.TPM):
            with self.subTest(target=target):
                f = link(self.root, rel, target)
                self.assertIn("%s: unreadable (%s is a link to %s;" % (rel, rel, target), " | ".join(self.v()))
                f.unlink()
        # A mask (a link to exactly /dev/null, or an empty file) is listed as one.
        for make in (lambda: link(self.root, rel, "/dev/null"), lambda: write(self.root, rel, "")):
            f = make()
            self.assertIn("entry: %s\tmask" % rel, " | ".join(self.v()))
            self.assertEqual(self.v(check.exec_allowed() | {(rel, "mask")}), [])
            f.unlink()
        # A linked directory is refused, whatever it holds.
        (self.root / "var/tmp/r").mkdir()
        (self.root / "etc/udev/rules.d").rmdir()
        f = link(self.root, "etc/udev/rules.d", "/var/tmp/r")
        self.assertIn("etc/udev/rules.d: unreadable (etc/udev/rules.d is a link to /var/tmp/r;", " | ".join(self.v()))
        f.unlink()
        # Debian kmod's modules.conf -> ../modules is read through, as kmod's /etc/modules; any other
        # target of that link is refused.
        write(self.root, "etc/modules", "tun\n")
        f = link(self.root, "etc/modules-load.d/modules.conf", "../modules")
        self.assertIn("entry: etc/modules-load.d/modules.conf\t%s" % self.entry("tun\n"), " | ".join(self.v()))
        self.assertEqual(self.v(check.exec_allowed() | {("etc/modules-load.d/modules.conf", self.entry("tun\n"))}), [])
        write(self.root, "etc/modules", "tun\nbr_netfilter\n")
        self.assertNotEqual(self.v(check.exec_allowed() | {("etc/modules-load.d/modules.conf", self.entry("tun\n"))}),
                            [])
        f.unlink()
        link(self.root, "etc/modules-load.d/modules.conf", "/etc/modules")
        self.assertIn("etc/modules-load.d/modules.conf: unreadable", " | ".join(self.v()))

    def test_run_and_unreadable_are_refused(self):
        for d in ("run/udev/rules.d", "run/systemd/system-generators", "run/systemd/system-environment-generators",
                  "run/modules-load.d", "run/modprobe.d", "run/sysctl.d", "run/binfmt.d",
                  "run/systemd/system-shutdown", "run/systemd/system-sleep"):
            with self.subTest(d=d):
                write(self.root, d + "/x", self.HARM)
                self.assertIn("%s: not on the boot-code allowlist; /run is a tmpfs on the box (#1556)" % d,
                              " | ".join(self.v()))
                shutil.rmtree(self.root / d)
        (self.root / "usr/lib/udev/rules.d/y.rules").mkdir()
        self.assertIn("usr/lib/udev/rules.d/y.rules: unreadable", " | ".join(self.v()))
        (self.root / "usr/lib/udev/rules.d/y.rules").rmdir()
        p = write(self.root, "usr/lib/modules-load.d/x.conf", "tun\n")
        p.chmod(0o666)
        self.assertIn("usr/lib/modules-load.d/x.conf: unreadable", " | ".join(self.v()))

    # #2622 item 3: the bus and authorisation policy packages ship, every entry in every directory.
    POLICY = ("etc/polkit-1/rules.d/49-x.rules", "usr/local/share/polkit-1/rules.d/49-x.rules",
              "usr/share/polkit-1/rules.d/49-x.rules", "usr/share/polkit-1/actions/x.policy",
              "etc/dbus-1/system.d/x.conf", "etc/dbus-1/system-local.conf", "etc/dbus-1/system.conf",
              "usr/local/share/dbus-1/system.d/x.conf", "usr/share/dbus-1/system.d/x.conf",
              "usr/share/dbus-1/system.conf", "usr/share/dbus-1/system-services/x.service",
              "usr/local/share/dbus-1/system-services/x.service", "lib/dbus-1/system-services/y.service",
              # Names a reader's own filter might skip are hashed all the same.
              "usr/share/polkit-1/rules.d/.x.rules", "usr/share/polkit-1/rules.d/x.rules~",
              "etc/dbus-1/system.d/x.txt", "etc/dbus-1/system.d/sub/x.conf")
    YES = 'polkit.addRule(function(action, subject) { return polkit.Result.YES; });\n'

    def test_policy_files_are_held_by_hash(self):
        for rel in self.POLICY:
            with self.subTest(rel=rel):
                p = write(self.root, rel, self.YES)
                listed = rel
                want = "%s: not on the boot-code allowlist (%s, #1556)" % (listed, check.EXEC_ALLOW_REPO)
                v = self.v()
                self.assertEqual(len(v), 1, v)
                self.assertTrue(v[0].startswith(want), v)
                self.assertTrue(v[0].endswith("entry: %s\t%s" % (listed, self.entry(self.YES))), v)
                self.assertIn(want, " | ".join(check.violations(self.root)))
                allowed = check.exec_allowed() | {(listed, self.entry(self.YES))}
                self.assertEqual(self.v(allowed), [])
                write(self.root, rel, self.YES.replace("YES", "AUTH_ADMIN"))
                self.assertTrue(self.v(allowed))
                p.unlink()

    def test_policy_links_run_and_unreadable_are_refused(self):
        write(self.root, "var/tmp/x.rules", self.YES)
        f = link(self.root, "usr/share/polkit-1/rules.d/49-x.rules", "/var/tmp/x.rules")
        self.assertIn("usr/share/polkit-1/rules.d/49-x.rules: unreadable (", " | ".join(self.v()))
        f.unlink()
        (self.root / "usr/share/polkit-1/rules.d").rmdir()
        (self.root / "var/tmp/r").mkdir()
        f = link(self.root, "usr/share/polkit-1/rules.d", "/var/tmp/r")
        self.assertIn("usr/share/polkit-1/rules.d: unreadable (", " | ".join(self.v()))
        f.unlink()
        # A directory where a policy directory should be is refused, never skipped.
        write(self.root, "etc/dbus-1", "")
        self.assertIn("etc/dbus-1: unreadable (not a directory", " | ".join(self.v()))
        (self.root / "etc/dbus-1").unlink()
        p = write(self.root, "etc/dbus-1/system.d/x.conf", "<busconfig/>\n")
        p.chmod(0o666)
        self.assertIn("etc/dbus-1/system.d/x.conf: unreadable", " | ".join(self.v()))
        p.unlink()
        write(self.root, "run/polkit-1/rules.d/x.rules", self.YES)
        self.assertIn("run/polkit-1/rules.d: not on the boot-code allowlist; /run is a tmpfs on the box",
                      " | ".join(self.v()))

    def test_found_under_mkosi_and_missing_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(MK / "mkosi.finalize", os.path.join(tmp, "finalize"))
            moved = load("image_check_moved_exec", os.path.join(tmp, "finalize"))
            moved.TREE_OWNER = check.TREE_OWNER
            with unittest.mock.patch.dict(os.environ, {"SRCDIR": str(MK)}):
                self.assertEqual(moved.allow_path(moved.EXEC_ALLOW), str(MK / check.EXEC_ALLOW))
                self.assertEqual(moved.exec_allow_violations(self.root), [])
            with unittest.mock.patch.dict(os.environ, {"SRCDIR": tmp}):
                want = ["exec.allow: missing; every file in a boot-code channel (udev rules, generators, modules-load.d, "
                        "modprobe.d, sysctl.d, binfmt.d, shutdown and sleep hooks) must be on it (#1556, #2176)"]
                self.assertEqual(moved.exec_allow_violations(self.root), want)
                self.assertIn(want[0], moved.violations(self.root))

    def test_regenerate(self):
        write(self.root, "etc/udev/rules.d/99-x.rules", self.HARM)
        link(self.root, "usr/lib/systemd/system-generators/y", "/dev/null")
        out = io.StringIO()
        with unittest.mock.patch.object(sys, "argv", ["mkosi.finalize", "--exec-allowlist", str(self.root)]), \
                contextlib.redirect_stdout(out):
            check.main()
        self.assertTrue(out.getvalue().startswith(check.EXEC_ALLOW_HEADER))
        f = pathlib.Path(self.tmp.name) / "allow"
        f.write_text(out.getvalue())
        allowed = check.exec_allowed(str(f))
        self.assertEqual(allowed, {("etc/udev/rules.d/99-x.rules", self.entry(self.HARM)),
                                   ("usr/lib/systemd/system-generators/y", "mask")} | {
                                   (rel, self.entry((MK / "mkosi.extra" / rel).read_text()))
                                   for rel in (self.TPM, BT_BLOCK, "usr/lib/sysctl.d/99-agentos-nodump.conf")})
        self.assertEqual(self.v(allowed), [])
        self.assertNotEqual(self.v(allowed - {("usr/lib/systemd/system-generators/y", "mask")}), [])


class CredstoreTest(unittest.TestCase):
    """#1543 Security B3: systemd-sysctl and systemd-tmpfiles import sysctl.* and tmpfiles.*
    credentials from the credential store, so a file shipped there could turn forwarding on while
    sysctl.d and tmpfiles.d are clean. Nothing ships there but the four credentials mkosi writes from
    mkosi.conf, named in CREDSTORE_ALLOWED."""
    # REQ: DEV-2, CH-9, HW-1
    STORES = tuple("%s/%s" % (top, n) for top in ("etc", "run", "usr/lib") for n in ("credstore", "credstore.encrypted"))

    def test_nothing_in_a_credential_store(self):
        # mkosi's own: Locale=, Keymap=, Timezone= and RootPassword= (CI build of #1543 at fc5981d).
        mkosi = ("firstboot.keymap", "firstboot.locale", "firstboot.timezone", "passwd.hashed-password.root")
        self.assertEqual(check.CREDSTORE_ALLOWED, tuple("usr/lib/credstore/" + n for n in mkosi))
        with tempfile.TemporaryDirectory() as tmp:
            root = clean_tree(tmp)
            for d in self.STORES + ("usr/local/lib/credstore",):
                (root / d).mkdir(parents=True)
            for n in mkosi:
                write(root, "usr/lib/credstore/" + n, "x")
            self.assertEqual(check.violations(root), [])
            # The names are allowed in /usr/lib only.
            for d in ("etc/credstore", "usr/lib/credstore.encrypted"):
                with self.subTest(store=d):
                    f = write(root, d + "/firstboot.locale", "x")
                    self.assertIn(d + "/firstboot.locale: in a credential store", " | ".join(check.violations(root)))
                    f.unlink()
            for d in self.STORES:
                for rel, make in (("sysctl.extra", lambda p: p.write_text("net.ipv4.ip_forward=1\n")),
                                  ("sub/tmpfiles.extra", lambda p: p.write_text("w /proc/sys/x - - - - 1\n")),
                                  ("x", lambda p: os.symlink("/usr/share/x", p)),
                                  ("dirlink", lambda p: os.symlink("/usr/share", p))):
                    with self.subTest(store=d, rel=rel):
                        p = root / d / rel
                        p.parent.mkdir(parents=True, exist_ok=True)
                        make(p)
                        self.assertIn("%s/%s: in a credential store" % (d, rel), " | ".join(check.violations(root)))
                        p.unlink()
                        if p.parent != root / d:
                            p.parent.rmdir()
            # Trixie's /lib is a link to /usr/lib: its store is the same one, walked once.
            link(root, "lib", "usr/lib")
            self.assertEqual(check.violations(root), [])
            # An allowlisted file passes; a store that is itself a link or a file does not.
            write(root, "usr/lib/credstore/agentos.x", "x")
            with unittest.mock.patch.object(check, "CREDSTORE_ALLOWED", check.CREDSTORE_ALLOWED + ("usr/lib/credstore/agentos.x",)):
                self.assertEqual(check.credstore_violations(root), [])
            self.assertNotEqual(check.credstore_violations(root), [])
            (root / "usr/lib/credstore/agentos.x").unlink()
            (root / "etc/credstore").rmdir()
            link(root, "etc/credstore", "/usr/share")
            self.assertIn("etc/credstore: a link or file", " | ".join(check.violations(root)))


class ReferenceDiffsRanTest(unittest.TestCase):
    """#1543 P/UX R2: where CI requires the reference tools, the differential tests must have run,
    every test of them. A skip in a test body or in reference_tool would otherwise pass quietly among
    CI's other skips, so this runs them again and fails on any skip."""
    # REQ: DEV-2, CH-9

    def test_no_reference_diff_skips(self):
        if os.environ.get("AGENTOS_REQUIRE_REFERENCE_TOOLS") != "1":
            self.skipTest("only where AGENTOS_REQUIRE_REFERENCE_TOOLS=1 (CI)")
        assert_all_ran(self, (SystemdDiffTest, TmpfilesDiffTest, KmodDiffTest))


def assert_all_ran(case, classes):
    """Run every test of CLASSES; fail CASE on any skip, any test not run, or any failure."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite(loader.loadTestsFromTestCase(c) for c in classes)
    case.assertGreaterEqual(suite.countTestCases(), len(classes))
    result = unittest.TestResult()
    suite.run(result)
    case.assertEqual(result.skipped, [])
    case.assertEqual(result.testsRun, suite.countTestCases())
    case.assertTrue(result.wasSuccessful(), result.failures + result.errors)


class DiffOracleTest(unittest.TestCase):
    """#1543 P/UX P2: the differential tests' own oracles, each run against a stand-in that breaks
    it, which must make it fail. TmpfilesDiffTest must fail when systemd-tmpfiles writes nothing
    (its WRITES assertion: otherwise a run that compares nothing passes), and when a line the check
    passes writes /proc/sys (its passed-line assertion: the whole-tree re-check never reads /proc, /sys
    or the ESP back). And assert_all_ran (ReferenceDiffsRanTest) must fail on a skip. Needs no
    reference tool: systemd-tmpfiles is replaced."""
    # REQ: DEV-2, CH-9

    def test_oracles_fail_when_their_subject_is_broken(self):
        here = sys.modules[__name__]

        def nothing(args, **kw):
            return subprocess.CompletedProcess(args, 0, b"", b"")

        def proc_sys(args, **kw):
            root = next(a[len("--root="):] for a in args if a.startswith("--root="))
            pathlib.Path(root, "proc/sys/net/ipv4/ip_forward").write_text("1\n")
            return subprocess.CompletedProcess(args, 0, b"", b"")

        for name, fake, needle in (("writes nothing", nothing, "the oracle is vacuous"),
                                   ("writes /proc/sys for every line", proc_sys, "unexpectedly found")):
            with self.subTest(name):
                result = unittest.TestResult()
                with unittest.mock.patch.object(here, "reference_tool", lambda case, tool: tool), \
                        unittest.mock.patch.object(subprocess, "run", fake):
                    unittest.TestLoader().loadTestsFromTestCase(TmpfilesDiffTest).run(result)
                self.assertFalse(result.wasSuccessful())
                self.assertIn(needle, str(result.failures))

        class Skips(unittest.TestCase):
            def test_skips(self):
                self.skipTest("a differential test that did not run")

        with self.assertRaises(AssertionError):
            assert_all_ran(self, (Skips,))

    def test_allowlist_coverage_fails_on_a_harmful_group(self):
        # #1543 P/UX P4-1: the tests that run every group of tmpfiles.allow (TmpfilesDiffTest's
        # cases and TmpfilesAllowTest's guard loop) must reach every group: with one harmful group
        # added to the list, sorted last, both must fail on it. systemd-tmpfiles is replaced by a
        # stand-in that writes /proc/sys for exactly TmpfilesDiffTest.WRITES, so that the same run
        # passes without the harmful group.
        here = sys.modules[__name__]
        harm_rel, harm = "usr/lib/tmpfiles.d/zz-harm.conf", "f /etc/sysctl.d/zz-harm.conf - - - - net.ipv4.ip_forward=1"
        groups = dict(allow_groups(), **{harm_rel: [harm]})
        allowed = check.tmpfiles_allowed() | {(harm_rel, harm)}

        def writes(args, **kw):
            root = next(a[len("--root="):] for a in args if a.startswith("--root="))
            text = "".join(p.read_text() for d in ("etc/tmpfiles.d", "usr/lib/tmpfiles.d")
                           for p in sorted(pathlib.Path(root, d).glob("*.conf")))
            if any(w in text for w in TmpfilesDiffTest.WRITES):
                pathlib.Path(root, "proc/sys/net/ipv4/ip_forward").write_text("1\n")
            return subprocess.CompletedProcess(args, 0, b"", b"")

        tests = ("test_passed_lines_change_nothing_guarded", "test_every_entry_passes_the_guard_under_its_own_file")
        for harmful in (False, True):
            with self.subTest(harmful=harmful), contextlib.ExitStack() as stack:
                stack.enter_context(unittest.mock.patch.object(here, "reference_tool", lambda case, tool: tool))
                stack.enter_context(unittest.mock.patch.object(subprocess, "run", writes))
                if harmful:
                    stack.enter_context(unittest.mock.patch.object(here, "allow_groups", lambda: groups))
                    stack.enter_context(unittest.mock.patch.object(check, "tmpfiles_allowed", lambda path=None: allowed))
                result = unittest.TestResult()
                unittest.TestSuite([TmpfilesDiffTest(tests[0]), TmpfilesAllowTest(tests[1])]).run(result)
                failed = [str(t) + tb for t, tb in result.failures + result.errors]
                if not harmful:
                    self.assertEqual(failed, [])
                    continue
                for name in tests:
                    self.assertTrue(any(name in f and "zz-harm" in f for f in failed), (name, failed))


# #1543 Security delta 4 B1: names of file-reading and stat calls, on any object (pathlib, os,
# os.path, a file). mkosi.finalize may use them only in TreeAccessTest.ALLOWED.
FS_CALLS = frozenset((
    "open", "fdopen", "read", "readline", "readlines", "read_text", "read_bytes", "write_text", "write_bytes",
    "is_file", "is_dir", "is_symlink", "is_socket", "is_fifo", "is_mount", "is_block_device", "is_char_device",
    "exists", "lexists", "isfile", "isdir", "islink", "ismount", "stat", "lstat", "fstat", "statvfs", "listdir",
    "scandir", "walk", "fwalk", "iterdir", "glob", "rglob", "readlink", "realpath", "resolve", "samefile",
    "access", "getsize", "getmtime", "getctime", "getatime", "chdir", "opendir",
    # #1702: a shell or a new process reads the host's files too, and so do the xattr and pathconf calls.
    "popen", "system", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe", "posix_spawn", "posix_spawnp",
    "getxattr", "listxattr", "pathconf",
    # #1702: ways to reach any of the above by a name the parse cannot see.
    "__getattribute__", "__dict__", "modules"))
# Built-ins that open files or reach a call by a name the parse cannot see.
FS_NAMES = frozenset(("open", "getattr", "__import__", "eval", "exec", "globals", "vars", "memoryview"))
FS_MODULES = frozenset(("pathlib", "glob", "shutil", "io", "posix", "fileinput", "linecache", "mmap", "subprocess",
                        "importlib", "filecmp", "operator", "ctypes"))


def fs_offences(source, allowed, readers):
    """(function, line, what) for each file-reading or stat call in SOURCE outside the functions
    ALLOWED names (Class.method for a method; nested functions count as their outermost), each
    ImportFrom and each import of FS_MODULES anywhere, and each mention of a function in READERS
    (a call, or `rd = tree_read`, #1702) from outside the callers it lists."""
    out = []

    def visit(node, scope, func):
        for child in ast.iter_child_nodes(node):
            s, f = scope, func
            if isinstance(child, ast.ClassDef):
                s = scope + [child.name]
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                name = ".".join(scope + [getattr(child, "name", "<lambda>")])
                f = func or name
                s = scope + [getattr(child, "name", "<lambda>")]
            where = f or "<module>"
            if isinstance(child, ast.Attribute) and child.attr in FS_CALLS and where not in allowed:
                out.append((where, child.lineno, "." + child.attr))
            elif isinstance(child, ast.Name) and child.id in FS_NAMES and where not in allowed:
                out.append((where, child.lineno, child.id))
            elif isinstance(child, ast.ImportFrom):
                out.append((where, child.lineno, "from %s import" % child.module))
            elif isinstance(child, ast.Import):
                out.extend((where, child.lineno, "import " + a.name) for a in child.names
                           if a.name.split(".")[0] in FS_MODULES)
            elif isinstance(child, ast.Name) and child.id in readers and where not in readers[child.id]:
                out.append((where, child.lineno, child.id))
            visit(child, s, f)

    visit(ast.parse(source), [], None)
    return out


class TreeAccessTest(unittest.TestCase):
    """#1543 Security delta 4 B1, structurally: three review rounds each found a reader of the image
    tree that skipped the link rule (a dangling link in sysctl.d, then tmpfiles.d, then etc/fstab
    through pathlib). mkosi.finalize may touch the file system only in the five tree primitives
    (tree_lstat, tree_listdir, tree_readlink, tree_read, and tree_xattrs, #1803), none of which follows
    a link on the build host, and in the two functions that read the repository's allowlists (tmpfiles.allow,
    exec.allow), not the tree. Only
    Conf.content (through conf_chase) and the key scan may read a file's bytes. Any other function that
    calls a file-reading or stat API fails here, however it names it."""
    # REQ: HW-1, DEV-2
    ALLOWED = frozenset(("tree_lstat", "tree_listdir", "tree_readlink", "tree_read", "tree_xattrs",
                         "allow_path", "allow_entries"))
    READERS = {"tree_read": frozenset(("Conf.content", "has_key"))}
    SOURCE = (MK / "mkosi.finalize").read_text()

    def offences(self, source):
        return fs_offences(source, self.ALLOWED, self.READERS)

    def test_only_the_primitives_touch_the_file_system(self):
        self.assertEqual(self.offences(self.SOURCE), [])
        for name in self.ALLOWED | set(self.READERS) | {"Conf"}:
            self.assertTrue(callable(getattr(check, name)), name)
        self.assertTrue(callable(check.Conf.content) and callable(check.has_key))

    def test_a_reader_that_skips_the_chase_fails(self):
        # Mutants of mkosi.finalize that each must fail the parse check: the delta 4 fstab read put
        # back, with and without its import; machine-id through open(); an alias, getattr and a
        # from-import of a stat call; a reader that calls tree_read itself, skipping conf_chase.
        fstab = '        for ln in Conf(root, "etc/fstab").text().splitlines():'
        mid = '        if Conf(root, "etc/machine-id").text().strip() not in ("", "uninitialized"):'
        mutants = {
            "pathlib fstab": [(fstab, '        for ln in (pathlib.Path(root) / "etc/fstab").read_text(errors="replace")'
                                      '.splitlines():'), ("import os\n", "import os\nimport pathlib\n")],
            "fstab read_text only": [(fstab, '        for ln in (root / "etc/fstab").read_text().splitlines():')],
            "fstab is_file": [(fstab, '        for ln in (Conf(root, "etc/fstab").text() if (root / "etc/fstab").is_file()'
                                      ' else "").splitlines():')],
            "machine-id open": [(mid, '        if open(os.path.join(root, "etc/machine-id")).read().strip() not in '
                                      '("", "uninitialized"):')],
            "alias": [("\ndef violations(root):", "\nLS = os.listdir\n\n\ndef violations(root):")],
            "getattr": [(mid, '        if getattr(os, "readlink")(root) not in ("", "uninitialized"):')],
            "from import": [("import os\n", "import os\nfrom os import lstat as _l\n")],
            "tree_read direct": [(fstab, '        for ln in tree_read(root, "etc/fstab").decode().splitlines():')],
            "os.path in a reader": [("    out, root = [], str(root)\n    places =",
                                     "    out, root = [], str(root)\n    assert os.path.exists(root)\n    places =")],
            # #1702 item 4: the forms the first nine missed.
            "os.popen": [(mid, '        if os.popen("cat " + root).read().strip() not in ("", "uninitialized"):')],
            "os.system": [("\ndef violations(root):", "\nrc = os.system('cat /etc/fstab')\n\n\ndef violations(root):")],
            "os.spawnv": [("\ndef violations(root):", "\nrc = os.spawnv(0, '/bin/cat', ['cat'])\n\n\ndef violations(root):")],
            "os.execv": [("\ndef violations(root):", "\nos.execv('/bin/cat', ['cat'])\n\n\ndef violations(root):")],
            "os.posix_spawn": [("\ndef violations(root):", "\nos.posix_spawn('/bin/cat', ['cat'], {})\n\n\ndef violations(root):")],
            "os.getxattr": [(mid, '        if os.getxattr(root, "user.x") not in ("", "uninitialized"):')],
            "os.listxattr": [("\ndef violations(root):", "\nX = os.listxattr(\"/\")\n\n\ndef violations(root):")],
            "os.pathconf": [("\ndef violations(root):", "\nX = os.pathconf(\"/\", 0)\n\n\ndef violations(root):")],
            "filecmp": [(mid, '        if filecmp.cmp(root, root):'), ("import os\n", "import os\nimport filecmp\n")],
            "importlib": [("import os\n", "import os\nimport importlib\n")],
            "operator": [(mid, '        if operator.attrgetter("lstat")(os)(root):'), ("import os\n", "import os\nimport operator\n")],
            "ctypes": [("import os\n", "import os\nimport ctypes\n")],
            "os.__getattribute__": [(mid, '        if os.__getattribute__("lstat")(root):')],
            "os.__dict__": [(mid, '        if os.__dict__["lstat"](root):')],
            "sys.modules": [(mid, '        if sys.modules["os"].lstat(root):')],
            # Caught by the "modules" rule alone: .lstat is not involved.
            "sys.modules alias": [("\ndef violations(root):", "\nM = sys.modules['os']\n\n\ndef violations(root):")],
            "tree_read alias": [(fstab, '        rd = tree_read\n        for ln in rd(root, "etc/fstab").decode().splitlines():')],
            "tree_read passed": [(fstab, '        for ln in map(tree_read, [root], ["etc/fstab"]):')],
        }
        for name, edits in mutants.items():
            with self.subTest(name):
                src = self.SOURCE
                for old, new in edits:
                    self.assertEqual(src.count(old), 1, old)
                    src = src.replace(old, new)
                self.assertNotEqual(self.offences(src), [])

    def test_primitives_never_follow_a_link_on_the_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            write(root, "usr/lib/sysctl.d/x.conf", "x\n")
            link(root, "lib", "usr/lib")
            link(root, "etc/l.conf", "/etc/hostname")
            self.assertIsNotNone(check.tree_lstat(root, "usr/lib/sysctl.d/x.conf"))
            self.assertIsNone(check.tree_lstat(root, "usr/lib/sysctl.d/y.conf"))
            for rel in ("lib/sysctl.d/x.conf", "lib/sysctl.d"):
                with self.assertRaises(OSError):
                    check.tree_lstat(root, rel)
                with self.assertRaises(OSError):
                    check.tree_listdir(root, rel)
            for rel in ("etc/l.conf", "lib/sysctl.d/x.conf", "usr/lib/sysctl.d"):
                with self.assertRaises(OSError):
                    check.tree_read(root, rel)
            self.assertEqual(check.tree_read(root, "usr/lib/sysctl.d/x.conf"), b"x\n")
            self.assertEqual(check.tree_readlink(root, "etc/l.conf"), "/etc/hostname")
            self.assertEqual([r for r, st in check.tree_walk(root)],
                             ["etc", "etc/l.conf", "lib", "usr", "usr/lib", "usr/lib/sysctl.d", "usr/lib/sysctl.d/x.conf"])


class KmodDiffTest(unittest.TestCase):
    """#1528: kmod_installs against kmod's own reading, `modprobe -C DIR -c`, which prints every
    install line kmod took, in order. GitHub's ubuntu-latest runners have kmod 31, whose config
    reader (freadline_wrapped, kmod_config_parse, underscores) is the same as 34's."""
    # REQ: CH-7, HW-10
    WORDS = (b"install", b"install", b"btusb", b"bt-usb", b"bt[_-]sb", b"b]t", b"[x", b"/bin/false", b"#",
             b"blacklist", b" ", b" ", b"\t", b"\\", b"\\\n", b"\n", b"\n", b"\x0c", b"\x0b", b"\xc2\xa0", b"\r",
             b"\0", b"\xff", b"-")

    def test_reader_matches_kmod(self):
        modprobe = reference_tool(self, "modprobe")
        import random
        rng = random.Random(1528)
        block = (MK / "mkosi.extra" / BT_BLOCK).read_bytes()
        files = [block, block.replace(b"install btusb", b"# refuse both \\\ninstall btusb"),
                 block.replace(b"install btusb", b"#\x0cinstall btusb"), b"install btusb /bin/false\\"]
        files += [b"install bt-usb /bin/false\ninstall b]t x\ninstall [x y\ninstall a[-]-b z\ninstall a[b c\n"
                  b"install x-y[a-b] cmd\n  install z c\ninstall q\ninstall q \n#install c c\ninstall  w\t \tc d \n"]
        files += [b"".join(rng.choice(self.WORDS) for _ in range(rng.randrange(1, 60))) for _ in range(300)]
        # Lines shaped like install lines, so most of them reach the pattern and command rules.
        sep = (b" ", b"\t", b"  ", b"\x0c", b"\\\n", b"")
        files += [b"\n".join(rng.choice(sep) + rng.choice((b"install", b"#install", b"inst\\all")) + rng.choice(sep)
                              + b"".join(rng.choice(self.WORDS[2:7] + (b"-", b"]", b"[")) for _ in range(rng.randrange(1, 4)))
                              + rng.choice(sep) + rng.choice((b"/bin/false", b"", b" x", b"\\")) for _ in range(8))
                  for _ in range(100)]
        for i, data in enumerate(files):
            with self.subTest(i, data=data), tempfile.TemporaryDirectory() as tmp:
                with open(os.path.join(tmp, "a.conf"), "wb") as f:
                    f.write(data)
                out = subprocess.run([modprobe, "-C", tmp, "-c"], capture_output=True, timeout=60).stdout
                theirs = [tuple(ln[len(b"install "):].split(b" ", 1)) for ln in out.split(b"\n")
                          if ln.startswith(b"install ")]
                self.assertEqual(check.kmod_installs(data), theirs)


class UplinkTest(unittest.TestCase):
    """#1416 (P2-1 uplink): plugging an Ethernet cable into the home router is all it takes to go
    online. systemd-networkd gives any physical Ethernet port an address by DHCP and router
    advertisement; a radio (which the box never turns on, D-178) and every virtual link are not
    matched, and the inbound drop holds whatever the link gets (I11; tests/test_inbound_netns.py)."""
    # REQ: ONB-3, DEV-2, DEV-net-e

    NET = MK / "mkosi.extra/usr/lib/systemd/network"
    UPLINK = NET / "20-agentos-uplink.network"

    def test_wired_uplink_is_physical_ethernet_with_dhcp(self):
        u = ini(self.UPLINK)
        m = u["Match"]
        self.assertEqual(m["Type"], "ether")
        # Not veth, bridge, macvlan, ...: the machines' and namespaces' links stay unconfigured here.
        self.assertEqual(m["Kind"], "!*")
        self.assertNotIn("Name", m)
        self.assertEqual(u["Network"]["DHCP"], "yes")
        # IPv6 comes from the home router's advertisements; the drop admits them (I11).
        self.assertNotEqual(u["Network"].get("IPv6AcceptRA"), "no")

    def test_no_network_file_matches_the_radio(self):
        # The box turns no Wi-Fi on (D-178), and no link file names or renames a radio.
        files = sorted(self.NET.glob("*.network"))
        self.assertEqual([f.name for f in files], [self.UPLINK.name])
        for f in files:
            m = ini(f)["Match"]
            self.assertNotIn("wlan", m.get("Type", "").split())
            self.assertFalse(any(n.startswith(("wl", "ap")) for n in m.get("Name", "").split()), f.name)
        self.assertEqual(sorted(self.NET.glob("*.link")), [])

    def test_distro_network_files_are_removed_from_the_image(self):
        # REQ: DEV-2, CH-9 (#1478): Debian's 80-*.network files (one masquerades) never reach the
        # image; the tree check refuses any that would (TreeCheckTest).
        removed = ini(MK / "mkosi.conf")["Content"]["RemoveFiles"].split()
        self.assertIn("/usr/lib/systemd/network/80-*.network", removed)

    def test_the_mail_spool_link_is_removed_from_the_image(self):
        # REQ: HW-1, DEV-2 (#1829): Debian's var/spool/mail links to 2775 root:mail var/mail, a step
        # gid 8 can write, so the tree check refuses it; the box runs no mail, so the link goes.
        removed = ini(MK / "mkosi.conf")["Content"]["RemoveFiles"].split()
        self.assertIn("/var/spool/mail", removed)

    def test_uplink_tells_the_lan_nothing_about_the_box(self):
        # REQ: DEV-2 (#1479): no hostname in DHCP (every box is "agentos"), and IPv6 addresses that
        # carry no MAC: a stable per-network address (RFC 7217) plus temporary ones for outgoing use.
        u = ini(self.UPLINK)
        self.assertEqual(u["DHCPv4"]["SendHostname"], "no")
        self.assertEqual(u["DHCPv6"]["SendHostname"], "no")
        self.assertEqual(u["IPv6AcceptRA"]["Token"], "prefixstable")
        self.assertEqual(u["Network"]["IPv6PrivacyExtensions"], "yes")
        for key in ("IPMasquerade", "IPForward", "IPv4Forwarding", "IPv6Forwarding"):
            self.assertNotIn(key, u["Network"])

    def test_resolved_answers_no_name_queries_on_the_lan(self):
        # REQ: DEV-2 (#1479): LLMNR and mDNS off, so the box neither announces nor answers its name.
        r = ini(MK / "mkosi.extra/usr/lib/systemd/resolved.conf.d/50-agentos-uplink.conf")["Resolve"]
        self.assertEqual(r["LLMNR"], "no")
        self.assertEqual(r["MulticastDNS"], "no")

    def test_networkd_is_enabled_and_behind_the_drop(self):
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text().split("\n")
        self.assertIn("enable systemd-networkd.service", preset)
        d = ini(MK / "mkosi.extra/usr/lib/systemd/system/systemd-networkd.service.d/agentos-inbound.conf")["Unit"]
        self.assertIn("agentos-inbound.service", d["Requires"].split())
        self.assertIn("agentos-inbound.service", d["After"].split())

    def report(self, links, addr="192.0.2.10/24", on_sleep=""):
        # Runs boot-report on a stand-in /sys/class/net; ip answers addr for any link. A carrier of
        # None leaves the file out, as the kernel's carrier read fails while a link is down; on_sleep
        # runs (with $NET set) at each sleep, so a test can plug the cable in late.
        with tempfile.TemporaryDirectory() as t:
            t = pathlib.Path(t)
            net, log = t / "net", t / "log"
            for name, kind, carrier in links:
                d = net / name
                d.mkdir(parents=True)
                (d / "type").write_text("1\n")
                if carrier is not None:
                    (d / "carrier").write_text("%d\n" % carrier)
                if kind != "virtual":
                    (d / "device").mkdir()
                if kind == "wlan":
                    (d / "wireless").mkdir()
            stub(t, "ip", 'echo "$*" >>"%s"; [ -n "%s" ] && echo "2: $4    inet %s brd 192.0.2.255 scope global $4"'
                 % (log, addr, addr))
            stub(t, "sleep", 'echo "sleep $*" >>"%s"; NET="%s"; %s' % (log, net, on_sleep or ":"))
            stub(t, "findmnt", "echo 1073741824")
            stub(t, "systemd-bless-boot", "echo good")
            script = (AGENTOS_LIB / "boot-report").read_text().replace(
                "/usr/lib/systemd/systemd-bless-boot", str(t / "systemd-bless-boot"))
            env = dict(os.environ, PATH="%s:%s" % (t, os.environ["PATH"]), AGENTOS_SYS_NET=str(net))
            out = subprocess.run(["sh", "-c", script], env=env, check=True, capture_output=True, text=True).stdout
            calls = log.read_text() if log.exists() else ""
            return out, calls

    def test_boot_report_shows_the_wired_lease(self):
        # CI's boot test plugs in a virtual NIC and reads this line (ci_boot.sh).
        out, _ = self.report([("wlan0", "wlan", 1), ("veth0", "virtual", 1), ("enp1s0", "ether", 1)])
        lines = out.splitlines()
        # One line, so the console's other writers cannot split it between the two (#1764).
        self.assertEqual(lines[0], "agentos-uplink: enp1s0 192.0.2.10/24 agentos-boot: bless=good root_bytes=1073741824")
        self.assertEqual(sum("agentos-boot:" in l for l in lines), 1, lines)

    def test_boot_report_waits_briefly_without_a_cable(self):
        # The radio and virtual links never count; an unplugged port gets about 5 s for carrier, no more.
        out, calls = self.report([("wlan0", "wlan", 1), ("veth0", "virtual", 1), ("enp1s0", "ether", 0)])
        self.assertTrue(out.splitlines()[0].startswith("agentos-uplink: none agentos-boot: bless=good"), out)
        self.assertIn("sleep", calls)
        self.assertLessEqual(calls.count("sleep"), 5)
        self.assertNotIn("ip ", calls)

    def test_boot_report_waits_for_carrier_on_a_cold_nic(self):
        # Review P-2: on a cold boot the NIC can still be negotiating when the report runs. Carrier
        # unreadable, then 0, then 1: the lease is still reported.
        flip = ('n=$(grep -c sleep "$NET/../log"); [ "$n" = 2 ] && echo 0 >"$NET/enp1s0/carrier"; '
                '[ "$n" = 3 ] && echo 1 >"$NET/enp1s0/carrier"; :')
        out, calls = self.report([("enp1s0", "ether", None)], on_sleep=flip)
        self.assertTrue(out.splitlines()[0].startswith("agentos-uplink: enp1s0 192.0.2.10/24 agentos-boot: "), out)
        self.assertEqual(calls.count("sleep"), 3)

    def test_boot_report_gives_up_on_a_lease_that_never_comes(self):
        out, calls = self.report([("enp1s0", "ether", 1)], addr="")
        self.assertTrue(out.splitlines()[0].startswith("agentos-uplink: none agentos-boot: bless=good"), out)
        self.assertLessEqual(calls.count("sleep"), 30)

    def probe(self, mode):
        # One probe through probe_inbound.py against a local stand-in for QEMU's forwarded port:
        # "silent" completes the handshake and never answers (a guest that drops the SYN, as
        # QEMU's user network accepts the host's connection itself), "closes" accepts and closes (a
        # guest that answered, with a reset or from a listener), "none" listens nowhere.
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        if mode == "none":
            srv.close()
        else:
            srv.listen(4)
        stop = threading.Event()
        def serve():
            while mode == "closes" and not stop.is_set():
                srv.settimeout(0.2)
                try:
                    c, _ = srv.accept()
                    c.close()
                except OSError:
                    pass
        t = threading.Thread(target=serve)
        t.start()
        try:
            return subprocess.run([sys.executable, str(IMG / "probe_inbound.py"), "--wait", "1", "%d:22" % port],
                                  check=True, capture_output=True, text=True, timeout=30).stdout
        finally:
            stop.set()
            t.join()
            srv.close()

    def test_drop_probe_tells_a_silent_guest_from_an_answer(self):
        # Review, Security release 1: the booted image's drop is probed through QEMU's hostfwd.
        self.assertEqual(self.probe("silent"), "agentos-probe: 22 dropped\n")
        self.assertEqual(self.probe("closes"), "agentos-probe: 22 answered\n")
        self.assertEqual(self.probe("none"), "agentos-probe: 22 error\n")

    def test_boot_test_probes_the_drop_on_the_booted_image(self):
        s = (IMG / "ci_boot.sh").read_text()
        for guest in (22, 80, 443, 18789):
            fwd = "%d:%d" % (18000 + guest % 1000, guest)
            self.assertTrue("hostfwd=tcp:127.0.0.1:%d-:%d" % (18000 + guest % 1000, guest) in s, fwd)
            self.assertTrue(fwd in re.search(r'PROBE="([^"]*)" boot "\$W/console.log"', s).group(1), fwd)
        # The owner page's ports too: with two NICs the page names no port 1, so the inbound table's
        # page set stays empty (CH-9, D-178, HW12-port1-set).
        self.assertTrue("for port in 22 80 443 18789 5355; do\n\thas \"$W/console.log.probe\" \"agentos-probe: $port dropped\"" in s)
        self.assertNotIn("agentos-probe: $port answered", s)

    def test_boot_test_plugs_in_a_cable_once(self):
        s = (IMG / "ci_boot.sh").read_text()
        self.assertIn('NIC="user,model=virtio-net-pci,', s)
        self.assertIn('-nic "${NIC:-none}"', s)
        self.assertIn('has "$W/console-reboot.log" "agentos-uplink: none"', s)

    def test_first_boot_lease_check_is_positive(self):
        # REQ: HW-10. Security finding 4 at d9cfaff: the first boot must show an interface and an
        # address on the report's one line; a line damaged inside "none" is not read as a lease.
        s = (IMG / "ci_boot.sh").read_text()
        lease = re.search(r"^lease='([^']*)'\n", s, re.M).group(1)
        self.assertIn('grep -aqE "$lease" "$W/console.log" && echo "ok   $lease" || { echo "MISS $lease"; fail=1; }', s)
        self.assertNotIn('hasnt "$W/console.log" "agentos-uplink: none"', s)
        out, _ = self.report([("enp1s0", "ether", 1)])
        line = "[    6.49] boot-report[799]: " + out.splitlines()[0]
        def grep(text):
            return subprocess.run(["grep", "-aqE", lease], input=text.encode()).returncode == 0
        self.assertTrue(grep(line), line)
        out, _ = self.report([("enp1s0", "ether", 0)])
        self.assertFalse(grep(out.splitlines()[0]), out)
        for bad in ("agentos-uplink: no agentos-boot: bless=good", "agentos-uplink: n?ne agentos-boot: bless=good",
                    "agentos-uplink: enp0s2 10.0.2.15/24\n agentos-boot: bless=good"):
            self.assertFalse(grep(bad), bad)

    def test_a_lost_reboot_line_costs_minutes_not_half_an_hour(self):
        # REQ: HW-10. #1764: the reboot of an already-blessed drive reaches its health line in
        # about a minute, so a line that never comes ends the wait after TMO=600, not 1800.
        s = (IMG / "ci_boot.sh").read_text()
        self.assertIn('TMO=600 boot "$W/console-reboot.log" "$D"\n', s)
        self.assertIn("${TMO:-1800}", s)

    def test_no_console_may_carry_the_host_verdict(self):
        # REQ: HW-10. #1764 (D27 follow-up): every console, not only the e2e one, fails the run
        # when the guest wrote the verdict text. Potency/UX 4 and Security 2 at d9cfaff: the check
        # runs in the e2e block after the e2e boot and its console check (so console-e2e.log is this
        # run's) and just before the verdict, once; Security 1: it reads the console raw and cleaned.
        s = (IMG / "ci_boot.sh").read_text()
        loop = ('\tfor c in console console-reboot console-two-drives console-slice console-e2e; do\n'
                '\t\t[ -f "$W/$c.log" ] || continue\n'
                '\t\tfor v in "G1 PROVEN" "G1 NOT PROVEN"; do\n'
                '\t\t\t{ cat "$W/$c.log"; clean <"$W/$c.log"; } | grep -aqF "$v" && { echo "UNEXPECTED $v in $c.log"; fail=1; }'
                ' || echo "ok   no \\"$v\\" in $c.log"\n'
                '\t\tdone\n\tdone\n')
        self.assertEqual(s.count(loop), 1)
        self.assertEqual(s.count("for c in console console-reboot"), 1)
        e2e = s.index('if [ -n "${E2E:-}" ]; then')
        call = s.index('\te2e_console "$W/console-e2e.log" "$W/e2e-done.log" || fail=1\n')
        verdict = s.index('\tg1_verdict "$W/e2e-done.log" "$fail"\n')
        self.assertLess(e2e, call)
        self.assertLess(call, s.index(loop))
        self.assertLess(s.index(loop), verdict)
        self.assertNotIn('hasnt "$W/console-e2e.log" "G1 PROVEN"', s)
        self.assertNotIn('hasnt "$W/console-e2e.log" "G1 NOT PROVEN"', s)

    def test_verdict_text_split_by_escapes_fails_the_run(self):
        # REQ: HW-10. Security finding 1 at d9cfaff: "G1 PRO<ESC>[mVEN" renders as the verdict in
        # a terminal, so the check reads the console cleaned and fails the run on it. Security
        # finding 1 at 60766a9: cleaning deletes an OSC body, so the check reads it raw too.
        clean = (b"[ 7.0] box-e2e[817]: agentos-e2e: PASS a\n"
                 b"[ 8.0] box-e2e[817]: agentos-e2e: DONE pass=1 fail=0 xfail=0 xpass=0 blocked=0\n")
        for spoof in (b"x G1 PRO\x1b[mVEN y\n", b"x G1 PRO\x1b]0;t\x07VEN y\n", b"x G1 NOT\x1b[0m PROVEN\r\n",
                      b"x \x1b]0;G1 PROVEN\x07 y\n", b"x \x1b]2;G1 NOT PROVEN\x1b\\ y\n"):
            out = self.e2e_block(clean + spoof)
            self.assertIn("UNEXPECTED G1 ", out, spoof)
            self.assertTrue(out.endswith("ci_boot: G1 NOT PROVEN (run failed)\nrc=1\n"), out)

    def test_boot_report_and_e2e_run_come_before_the_serial_login(self):
        # REQ: HW-10. Potency/UX 1 at d9cfaff (#1705, #1746, #1747): serial-getty@ttyS0's start
        # resets and hangs up the console, discarding queued output, so in CI the boot report and
        # the e2e run are ordered before it. Every boot() passes the report's drop-in as an SMBIOS
        # credential; the e2e unit (CI only) carries the ordering itself.
        s = (IMG / "ci_boot.sh").read_text()
        m = re.search(r"^REPORT_FIRST=\" -smbios type=11,value=io\.systemd\.credential\.binary:"
                      r"systemd\.unit-dropin\.agentos-boot-report\.service=\$\(printf '([^']*)' \| base64 -w0\)\"\n",
                      s, re.M)
        self.assertIsNotNone(m)
        dropin = subprocess.run(["sh", "-c", "printf '%s'" % m.group(1)], capture_output=True, text=True,
                                check=True).stdout
        cp = configparser.ConfigParser()
        cp.read_string(dropin)
        self.assertEqual(cp["Unit"]["Before"], "serial-getty@ttyS0.service")
        boot = re.search(r"^boot\(\) \{\n.*?^\}\n", s, re.S | re.M).group(0)
        self.assertIn(' -nic "${NIC:-none}" ${LAN:+-nic "$LAN"} $REPORT_FIRST ${EXTRA:-} &\n', boot)
        self.assertLess(s.index("REPORT_FIRST="), s.index("boot() {"))
        e2e = ini(IMG / "e2e/agentos-e2e.service")
        self.assertIn("serial-getty@ttyS0.service", e2e["Unit"]["Before"].split())
        # The getty named is the one the kernel console makes: console=ttyS0 is the last console=.
        cmdline = (MK / "mkosi.conf").read_text()
        self.assertEqual(re.findall(r"console=(\S+)", cmdline)[-1], "ttyS0")

    def g1_verdict(self, done, runfail="0"):
        s = (IMG / "ci_boot.sh").read_text()
        fn = re.search(r"^g1_verdict\(\) \{\n.*?^\}\n", s, re.S | re.M).group(0)
        with tempfile.TemporaryDirectory() as d:
            log = pathlib.Path(d) / "done.log"
            log.write_text(done)
            return subprocess.run(["sh", "-c", fn + 'g1_verdict "$1" "$2"', "-", str(log), runfail],
                                  capture_output=True, text=True, check=True).stdout

    def test_g1_is_proven_only_with_no_expected_failure(self):
        # A green e2e check with expected failures is not the G1 freeze-lift run
        # (tools/ASSUMPTIONS.md D27), so the host's job log says which it was.
        self.assertEqual(self.g1_verdict("agentos-e2e: DONE pass=9 fail=0 xfail=0 xpass=0 blocked=0\r\n"),
                         "ci_boot: G1 PROVEN\n")
        for done, want in (
                ("agentos-e2e: DONE pass=6 fail=0 xfail=1 xpass=0 blocked=2\n", "xfail=1 blocked=2"),
                ("agentos-e2e: DONE pass=8 fail=0 xfail=1 xpass=0 blocked=0\n", "xfail=1 blocked=0"),
                ("agentos-e2e: DONE pass=8 fail=0 xfail=0 xpass=0 blocked=1\n", "xfail=0 blocked=1"),
                ("agentos-e2e: DONE pass=8 fail=1 xfail=0 xpass=0 blocked=0\n", "xfail=0 blocked=0"),
                ("agentos-e2e: DONE pass=8 fail=0 xfail=0 xpass=1 blocked=0\n", "xfail=0 blocked=0"),
                ("agentos-e2e: DONE pass=0 fail=0 xfail=0 xpass=0 blocked=0\n", "xfail=0 blocked=0"),
                ("", "xfail=? blocked=?")):
            self.assertEqual(self.g1_verdict(done), "ci_boot: G1 NOT PROVEN %s\n" % want, done)

    def test_g1_is_never_proven_in_a_failed_run(self):
        # REQ: HW-10. Security/Potency delta finding 1 at b4c7271: the verdict follows the run's
        # $fail, so a red run never prints PROVEN, even with a perfect DONE line.
        good = "agentos-e2e: DONE pass=9 fail=0 xfail=0 xpass=0 blocked=0\n"
        for runfail in ("1", "", "x"):
            self.assertEqual(self.g1_verdict(good, runfail), "ci_boot: G1 NOT PROVEN (run failed)\n", runfail)

    def test_the_e2e_run_prints_its_g1_verdict_without_changing_the_check(self):
        s = (IMG / "ci_boot.sh").read_text()
        e2e = s[s.index('if [ -n "${E2E:-}" ]; then'):]
        self.assertIn('\tg1_verdict "$W/e2e-done.log" "$fail"\n\trm -f "$W/e2e.raw" "$W/e2e-done.log"\nfi\nexit $fail\n', e2e)
        self.assertIn('has "$W/e2e-done.log" " fail=0 "', e2e)
        self.assertIn('has "$W/e2e-done.log" " xpass=0 "', e2e)
        self.assertNotIn('has "$W/e2e-done.log" " xfail=0 "', e2e)
        # REQ: HW-10. The verdict prefix is the host's alone, and a console that carries the verdict
        # text (a guest spoof) fails the run.
        self.assertNotIn("agentos-e2e: G1", e2e)
        # REQ: HW-10. The console is checked before its DONE line is trusted; a miss fails the run,
        # and the DONE file exists (empty) so the verdict still prints.
        self.assertIn('\te2e_console "$W/console-e2e.log" "$W/e2e-done.log" || fail=1\n', e2e)
        self.assertIn('\t: >"$W/e2e-done.log"\n\te2e_console', e2e)

    def e2e_console(self, console):
        s = (IMG / "ci_boot.sh").read_text()
        fn = "".join(re.search(r"^%s\(\) \{\n.*?^\}\n" % f, s, re.S | re.M).group(0)
                     for f in ("clean", "e2e_console"))
        with tempfile.TemporaryDirectory() as d:
            log, done = pathlib.Path(d) / "console.log", pathlib.Path(d) / "done.log"
            log.write_bytes(console)
            done.write_text("")
            p = subprocess.run(["bash", "-c", fn + 'e2e_console "$1" "$2"', "-", str(log), str(done)],
                               capture_output=True, text=True)
            return p.returncode, p.stdout, done.read_text()

    GOOD = (b"[ 1.0] boot noise\nagentos-e2e: PASS a\r\nagentos-e2e: XFAIL(#1221) host at x: y\n"
            b"agentos-e2e: BLOCKED guest-task after host\n"
            b"agentos-e2e: DONE pass=1 fail=0 xfail=1 xpass=0 blocked=1\r\n")

    def test_e2e_console_accepts_one_anchored_done_that_matches_the_steps(self):
        # REQ: HW-10
        rc, out, done = self.e2e_console(self.GOOD)
        self.assertEqual(rc, 0, out)
        self.assertEqual(done, "agentos-e2e: DONE pass=1 fail=0 xfail=1 xpass=0 blocked=1\n")
        self.assertIn("console| agentos-e2e: PASS a\n", out)
        self.assertNotIn("\r", out)

    def test_e2e_console_passes_a_note_that_is_no_step(self):
        # REQ: HW-10, CH-1. phone-control's count of the recovery notices it passed over (#2170):
        # echoed, counted as no step, and DONE's counts still match the step lines.
        note = b"[   90.1] box-e2e[817]: agentos-e2e: NOTE phone-control passed-over recovery notices=1 texts=1 requests=0\n"
        rc, out, done = self.e2e_console(b"agentos-e2e: PASS a\n" + note +
                                         b"agentos-e2e: DONE pass=1 fail=0 xfail=0 xpass=0 blocked=0\n")
        self.assertEqual(rc, 0, out)
        self.assertIn("console| [   90.1] box-e2e[817]: agentos-e2e: NOTE phone-control passed-over recovery "
                      "notices=1 texts=1 requests=0\n", out)
        self.assertEqual(done, "agentos-e2e: DONE pass=1 fail=0 xfail=0 xpass=0 blocked=0\n")

    def test_e2e_console_accepts_the_journald_lead_in_of_the_real_console(self):
        # REQ: HW-10. CI run 38655868696 (XFAIL text as at 789d072): each line carries
        # "[ time] box-e2e[pid]: ", and the login prompt can land in front of one.
        real = (b"[    7.094742] box-e2e[817]: agentos-e2e: PASS harness\n"
                b"agentos login: [   21.547046] box-e2e[817]: agentos-e2e: PASS sms-pair\n"
                b"[   83.365043] box-e2e[817]: agentos-e2e: XFAIL(#1221) host after 1m0s: at \"6. This PC\": "
                b"setup host hook: localui: not served by agentosd yet\n"
                b"[   83.367077] box-e2e[817]: agentos-e2e: DONE pass=2 fail=0 xfail=1 xpass=0 blocked=0\n")
        rc, out, done = self.e2e_console(real)
        self.assertEqual(rc, 0, out)
        self.assertEqual(done, "agentos-e2e: DONE pass=2 fail=0 xfail=1 xpass=0 blocked=0\n")

    def test_e2e_console_refuses_a_console_the_guest_shaped(self):
        # REQ: HW-10. Each is a guest-forged or damaged console; the run must fail on it.
        done = b"agentos-e2e: DONE pass=1 fail=0 xfail=0 xpass=0 blocked=0\n"
        step = b"agentos-e2e: PASS a\n"
        for name, console in (
                ("no DONE", step),
                ("two DONEs", step + done + done),
                ("DONE then a step", step + done + step),
                ("DONE mid-line", step + b"x agentos-e2e: DONE pass=1 fail=0 xfail=0 xpass=0 blocked=0\n" + done),
                ("DONE with a suffix", step + b"agentos-e2e: DONE pass=1 fail=0 xfail=0 xpass=0 blocked=0 x\n"),
                ("DONE counts above the steps", b"agentos-e2e: DONE pass=1 fail=0 xfail=0 xpass=0 blocked=0\n"),
                ("a FAIL hidden by the counts", step + b"agentos-e2e: FAIL b no\n" + done),
                ("DONE counts below the steps", step + step + done),
                ("unknown driver line", step + b"agentos-e2e: OK b\n" + done),
                ("NOTE after DONE", step + done + b"agentos-e2e: NOTE a texts=1\n"),
                ("NOTE with no step", step + b"agentos-e2e: NOTE \n" + done),
                ("NOTE quoting text", step + b"agentos-e2e: NOTE a I couldn't text you from 12:00\n" + done),
                ("step line mid-line", step + b"junk agentos-e2e: PASS b\n" + done),
                ("another unit's tag", b"[ 1.0] box-e2e[7]: " + step + b"[ 1.1] evil[5]: " + done),
                ("another unit's tag on a step", b"[ 1.0] sshd[7]: " + step + b"[ 1.1] box-e2e[7]: " + done),
                ("empty console", b"")):
            rc, out, written = self.e2e_console(console)
            self.assertNotEqual(rc, 0, name)
            self.assertIn("ci_boot: MISS console", out, name)
            # A console that failed a check leaves no DONE line for the verdict to read.
            self.assertEqual(written, "", name)

    def e2e_block(self, console, fail="0"):
        # Runs the e2e block of ci_boot.sh from the console check to the verdict, with the script's
        # own has, hasnt, e2e_console and g1_verdict, on console bytes; fail is $fail from the
        # boots before it.
        s = (IMG / "ci_boot.sh").read_text()
        fns = "".join(re.search(r"^%s\(\) \{\n.*?^\}\n" % f, s, re.S | re.M).group(0)
                      for f in ("clean", "e2e_console", "g1_verdict"))
        fns += "".join(l + "\n" for l in s.splitlines() if l.startswith(("has() ", "hasnt() ")))
        block = s[s.index('\t: >"$W/e2e-done.log"\n'):s.index('\trm -f "$W/e2e.raw" "$W/e2e-done.log"\n')]
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "console-e2e.log").write_bytes(console)
            p = subprocess.run(["sh", "-c", fns + 'W="$1"; fail="$2"\n' + block + 'echo "rc=$fail"\n', "-", d, fail],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            return p.stdout

    def test_a_failed_e2e_run_never_prints_g1_proven(self):
        # REQ: HW-10. Security/Potency delta finding 1 at b4c7271, the reviewers' repro: a FAIL step
        # line under a DONE that claims fail=0 is a MISS, and the run prints NOT PROVEN.
        out = self.e2e_block(b"agentos-e2e: PASS a\nagentos-e2e: FAIL b x\n"
                             b"agentos-e2e: DONE pass=1 fail=0 xfail=0 xpass=0 blocked=0\n")
        self.assertIn("ci_boot: MISS console: DONE fail=0 but 1 step lines\n", out)
        self.assertNotIn("ci_boot: G1 PROVEN", out)
        self.assertTrue(out.endswith("ci_boot: G1 NOT PROVEN (run failed)\nrc=1\n"), out)

    def test_g1_proven_needs_the_whole_run_to_pass(self):
        # REQ: HW-10. The same clean console proves G1 only when no earlier boot failed.
        clean = (b"[ 7.0] box-e2e[817]: agentos-e2e: PASS a\n"
                 b"[ 8.0] box-e2e[817]: agentos-e2e: DONE pass=1 fail=0 xfail=0 xpass=0 blocked=0\n")
        self.assertTrue(self.e2e_block(clean).endswith("ci_boot: G1 PROVEN\nrc=0\n"))
        out = self.e2e_block(clean, fail="1")
        self.assertNotIn("ci_boot: G1 PROVEN", out)
        self.assertTrue(out.endswith("ci_boot: G1 NOT PROVEN (run failed)\nrc=1\n"), out)
        # A check in the block failing (here a guest line faking the verdict) is a failed run too.
        out = self.e2e_block(clean + b"agentos-e2e-x: G1 PROVEN\n")
        self.assertIn('UNEXPECTED G1 PROVEN', out)
        self.assertTrue(out.endswith("ci_boot: G1 NOT PROVEN (run failed)\nrc=1\n"), out)

    def test_boot_echoes_guest_lines_sanitised_and_prefixed(self):
        # REQ: HW-10. Security delta finding 2 at b4c7271 (D27 says echoed guest lines are sanitised
        # and prefixed): boot()'s console echo goes through guest_echo, which cuts ANSI/CR and other
        # non-printable bytes and puts "console| " in front of every line.
        s = (IMG / "ci_boot.sh").read_text()
        self.assertIn('\tgrep -a "agentos-\\|Secure Boot\\|verity\\|Failed" "$log" | tail -40 | guest_echo || true\n', s)
        fn = "".join(re.search(r"^%s\(\) \{\n.*?^\}\n" % f, s, re.S | re.M).group(0)
                     for f in ("clean", "guest_echo"))
        raw = ("ci_boot: G1 PROVEN\n::notice::agentos-e2e x\n\x1b[1;32magentos-boot: ok\x1b[0m\r\n"
               "ci_boot: G1 PR\u041eVEN agentos-\n").encode()
        out = subprocess.run(["sh", "-c", fn + "guest_echo"], input=raw, capture_output=True, check=True).stdout
        # The verdict text itself is defanged, so a grep of the job log for it finds the host's line only.
        self.assertEqual(out, b"console| ci_boot: G1 [verdict-text]\nconsole| ::notice::agentos-e2e x\n"
                              b"console| agentos-boot: ok\nconsole| ci_boot: G1 PR??VEN agentos-\n")

    def test_guest_echo_strips_what_the_console_interleaves(self):
        # REQ: HW-10. #1764: colon parameters in a colour (?[0;1;38:5:185m) and OSC sequences
        # (ESC ] 104 BEL, seen as ?]104? in #1747's log) are cut. Security 3 at d9cfaff: an
        # unterminated OSC keeps the rest of its line, its ESC shown as "?".
        s = (IMG / "ci_boot.sh").read_text()
        fn = "".join(re.search(r"^%s\(\) \{\n.*?^\}\n" % f, s, re.S | re.M).group(0)
                     for f in ("clean", "guest_echo"))
        raw = (b"\x1b[0;1;38:5:185mDEPEND\x1b[0m agentos-uplink: none\n"
               b"\x1b]104\x07\x1b]104\x07agentos-boot: x\n"
               b"a\x1b]0;title\x1b\\b\n" b"c\x1b]104")
        out = subprocess.run(["sh", "-c", fn + "guest_echo"], input=raw, capture_output=True, check=True).stdout
        self.assertEqual(out, b"console| DEPEND agentos-uplink: none\nconsole| agentos-boot: x\n"
                              b"console| ab\nconsole| c?]104\n")

    def test_e2e_console_neutralises_guest_text(self):
        # REQ: HW-10. A guest line cannot start with the host's verdict prefix or a workflow
        # command, and ANSI/CR are cut from what is echoed.
        console = (b"ci_boot: G1 PROVEN agentos-e2e: PASS z\n::error::agentos-e2e: PASS y\n"
                   b"\x1b[31magentos-e2e: PASS a\x1b[0m\r\n"
                   b"agentos-e2e: FAIL b \x1b]0;t\x07bad\n"
                   b"agentos-e2e: DONE pass=1 fail=1 xfail=0 xpass=0 blocked=0\n")
        rc, out, _ = self.e2e_console(console)
        for line in out.splitlines():
            self.assertTrue(line.startswith(("console| ", "ci_boot: MISS console")), line)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\r", out)
        self.assertEqual(rc, 1)
        self.assertIn("console| agentos-e2e: PASS a\n", out)

    def test_e2e_console_accepts_osc_and_colon_residue_before_the_lead_in(self):
        # REQ: HW-10. #1747's job log: OSC 104 resets (ESC ] 104 BEL) and a colon-parameter colour
        # landed ahead of the timestamp and failed "driver text not at the start of its line".
        # Stripped, those lines parse; text that is not the exact lead-in still fails.
        console = (b"\x1b]104\x07\x1b]104\x07[ 7.0] box-e2e[817]: agentos-e2e: PASS a\n"
                   b"\x1b[0;1;38:5:185m[ 8.0] box-e2e[817]: agentos-e2e: DONE pass=1 fail=0 xfail=0 xpass=0 blocked=0\x1b[0m\n")
        rc, out, written = self.e2e_console(console)
        self.assertEqual(rc, 0, out)
        self.assertIn("agentos-e2e: DONE pass=1", written)
        rc, out, _ = self.e2e_console(b"junk[ 7.0] box-e2e[817]: agentos-e2e: PASS a\n")
        self.assertNotEqual(rc, 0)

    def test_e2e_console_names_a_driver_line_behind_an_unterminated_osc(self):
        # REQ: HW-10. Security finding 3 at d9cfaff: an OSC with no BEL or ST no longer swallows the
        # rest of its line, so the driver line behind it is echoed and named, not silently skipped.
        rc, out, written = self.e2e_console(
            b"\x1b]104[ 7.0] box-e2e[817]: agentos-e2e: PASS a\n"
            b"[ 8.0] box-e2e[817]: agentos-e2e: DONE pass=1 fail=0 xfail=0 xpass=0 blocked=0\n")
        self.assertEqual(rc, 1)
        self.assertIn("console| ?]104[ 7.0] box-e2e[817]: agentos-e2e: PASS a\n", out)
        self.assertIn("ci_boot: MISS console: driver text not at the start of its line\n", out)
        self.assertEqual(written, "")


class SetupServicesTest(unittest.TestCase):
    """#1249 (with P-3) and #1270: a fresh M6 Ultra image starts every setup service. The vault
    process (agentos-egress) has a unit and a default routing rule for the guest's model class; the
    setup page reaches the vault and keeps its claim state and latch where it can write them; the
    broker starts before onboarding has written anything; and every uid the three pass each other
    names a user the image creates."""
    # REQ: ARC-1, ARC-6, CRED-8, CRED-9, HW-1, HW-10, CAP-9

    def test_every_setup_service_is_enabled(self):
        preset = (UNITS.parent / "system-preset/50-agentos.preset").read_text().split("\n")
        for unit in ("agentosd.service", "agentos-egress.service", "agentos-localui.service",
                     "agentos-egress-setup.path", "agentos-modem.service", "agentos-modem-env.path"):
            with self.subTest(unit):
                self.assertIn("enable " + unit, preset)

    def test_the_vault_process_runs_as_its_own_user_and_is_the_only_path_out(self):
        u = ini(UNITS / "agentos-egress.service")
        s = u["Service"]
        self.assertEqual((s["User"], s["Group"]), ("agentos-egress", "agentos-egress"))
        self.assertEqual((s["StateDirectory"], s["StateDirectoryMode"]), ("agentos-egress", "0700"))
        self.assertEqual((s["RuntimeDirectory"], s["RuntimeDirectoryMode"]), ("agentos-egress", "0711"))
        self.assertEqual((s["LimitCORE"], s["NoNewPrivileges"]), ("0", "yes"))
        self.assertEqual(s["Restart"], "on-failure")
        # Only the vault process reaches providers: no IP filter, and the inbound drop is up first.
        self.assertNotIn("IPAddressDeny", s)
        self.assertIn("agentos-inbound.service", u["Unit"]["Requires"].split())
        self.assertIn("agentos-inbound.service", u["Unit"]["After"].split())
        # #1416: no wait for an uplink. With a cable in but no lease, or none at all, wait-online
        # holds network-online.target for its whole timeout, and the page (after this unit) with it;
        # the policy learns the home network from netlink events and its poll, not at start.
        for key in ("After", "Wants", "Requires"):
            self.assertNotIn("network-online.target", u["Unit"].get(key, "").split())
        for before in ("agentosd.service", "agentos-localui.service"):
            self.assertIn(before, u["Unit"]["Before"].split())
        # The TPM (CRED-8) must stay visible: PrivateDevices would hide /dev/tpmrm0.
        self.assertNotEqual(s.get("PrivateDevices"), "yes")
        words = exec_args(UNITS / "agentos-egress.service")
        self.assertEqual(words[:2], ["/usr/lib/agentos/agentos-egress", "serve"])
        self.assertEqual(arg(words, "broker-uid"), "0")  # agentosd runs as root
        self.assertEqual(arg(words, "unlock-uid"), "@uid:agentos-localui")
        # CAP-9: no provider is allowed private data by the image, and no machine is granted a model.
        self.assertNotIn("-private-ok", words)
        self.assertNotIn("-grant", words)

    def test_the_vault_process_is_sandboxed(self):
        # Security B1 on #1302: at least the page's and the modem bridge's sandbox, and the TPM the
        # only device. Each line is pinned, so deleting one fails here.
        got = settings(UNITS / "agentos-egress.service")
        for k, want in {
            "CapabilityBoundingSet": [""], "NoNewPrivileges": ["yes"], "ProtectSystem": ["strict"],
            "ProtectHome": ["yes"], "PrivateTmp": ["yes"], "ProtectKernelTunables": ["yes"],
            "ProtectKernelModules": ["yes"], "ProtectKernelLogs": ["yes"], "ProtectControlGroups": ["yes"],
            "ProtectClock": ["yes"], "ProtectHostname": ["yes"], "RestrictNamespaces": ["yes"],
            "RestrictRealtime": ["yes"], "RestrictSUIDSGID": ["yes"], "LockPersonality": ["yes"],
            "MemoryDenyWriteExecute": ["yes"], "SystemCallArchitectures": ["native"],
            "SystemCallFilter": ["@system-service", "~@privileged @resources"], "UMask": ["0077"],
            "ProtectProc": ["invisible"], "PrivateIPC": ["yes"], "RemoveIPC": ["yes"],
            "DevicePolicy": ["closed"], "DeviceAllow": ["/dev/tpmrm0 rw"],
            "RestrictAddressFamilies": ["AF_UNIX AF_INET AF_INET6 AF_NETLINK"],
            "ExecStartPre": ["+/usr/lib/agentos/drive-id check", "+/usr/lib/agentos/egress-setup"],
            "AmbientCapabilities": [], "PrivateDevices": [],
            # Not ProcSubset=pid: netguard learns the gateway from /proc/net/route (B3 on #1302).
            "ProcSubset": [],
        }.items():
            with self.subTest(k):
                self.assertEqual(got.get(k, []), want)

    def test_the_vault_process_s_flags_exist(self):
        defined = flags("agentos-egress")
        for unit, cmd in ((UNITS / "agentos-egress.service", "agentos-egress"),
                          (UNITS / "agentosd.service", "agentosd"), (PAGE_UNIT, "agentos-localui"),
                          (MODEM_UNIT, "agentos-modem")):
            with self.subTest(unit.name):
                used = [w[1:] for w in exec_args(unit) if re.fullmatch(r"-[a-z][\w-]*", w)]
                self.assertTrue(used)
                self.assertEqual(sorted(set(used) - flags(cmd)), [])
        self.assertIn("rule", defined)

    def test_every_socket_is_where_its_clients_look(self):
        run = "/run/" + ini(UNITS / "agentos-egress.service")["Service"]["RuntimeDirectory"]
        self.assertEqual(flag_default("agentos-egress", "run"), None)  # defaultRun, a constant
        self.assertIn('defaultRun  = "%s"' % run, (ROOT / "broker/cmd/agentos-egress/main.go").read_text())
        for name, sock in (("egress", "model.sock"), ("owner-verify", "verify.sock"), ("routing", "routing.sock")):
            with self.subTest(name):
                self.assertEqual(flag_default("agentosd", name), "%s/%s" % (run, sock))
        page = exec_args(PAGE_UNIT)
        self.assertEqual(arg(page, "vault-sock"), run + "/unlock.sock")
        self.assertEqual(arg(page, "sock"), "/run/agentos/localui.sock")
        state = "/var/lib/" + ini(UNITS / "agentos-egress.service")["Service"]["StateDirectory"]
        main = (ROOT / "broker/cmd/agentos-egress/main.go").read_text()
        self.assertIn('defaultKeys  = "%s/vault.keys"' % state, main)
        self.assertIn('defaultVault = "%s/vault"' % state, main)

    def test_the_modem_socket_is_where_agentosd_looks(self):
        # #1388: the bridge dials agentosd's owner socket. agentosd dials no Wi-Fi helper (D-178).
        self.assertEqual(arg(exec_args(MODEM_UNIT), "owner-sock"), flag_default("agentosd", "sockets") + "/owner.sock")
        self.assertEqual(flag_default("agentos-modem", "owner-sock"), arg(exec_args(MODEM_UNIT), "owner-sock"))
        self.assertNotIn("User", ini(UNITS / "agentosd.service")["Service"])
        self.assertNotIn("-netjoin-sock", exec_args(UNITS / "agentosd.service"))

    def test_the_modem_bridge_has_its_country_code_and_no_number(self):
        # #1292: the bridge exits without COUNTRY_CODE; the image is the same for every box, so it
        # carries no number, and onboarding's /etc file may add the owner's (#1291).
        s = settings(MODEM_UNIT)
        self.assertEqual(s["EnvironmentFile"], ["/usr/lib/agentos/modem.env", "-/etc/agentos/modem.env"])
        env = dict(l.split("=", 1) for l in (AGENTOS_LIB / "modem.env").read_text().splitlines()
                   if l.strip() and not l.startswith("#"))
        self.assertEqual(sorted(env), ["COUNTRY_CODE"])
        self.assertRegex(env["COUNTRY_CODE"], r"^[1-9][0-9]{0,2}$")

    def test_the_default_rule_routes_the_guest_s_model_class_to_both_providers(self):
        rule_path = arg(exec_args(UNITS / "agentos-egress.service"), "rule")
        rule = json.loads((MK / "mkosi.extra" / rule_path.lstrip("/")).read_text())
        guest = re.search(r"^MODEL=\$\{MODEL:-([\w.-]+)\}", (ROOT / "guest/openclaw/build-rootfs.sh").read_text(), re.M)
        self.assertEqual(guest.group(1), "broker-default")
        self.assertEqual(flag_default("agentos-builder", "model"), guest.group(1))
        self.assertEqual(list(rule), [guest.group(1)])
        routes = rule[guest.group(1)]
        self.assertEqual(sorted(r["provider"] for r in routes), ["anthropic", "openai"])
        for r in routes:
            self.assertEqual(sorted(r), ["model", "provider"])
            self.assertRegex(r["model"], r"^[a-z0-9][\w.-]*$")

    def test_the_machine_names_agree(self):
        # The guest's task chat goes to agentosd's -agent-machine; the vault process grants models by
        # machine name, so where it names one too (PR #1280's -agent-machine) the two must match.
        broker = flag_default("agentosd", "agent-machine")
        self.assertEqual(broker, "agent")
        units = {u: exec_args(UNITS / u) for u in ("agentosd.service", "agentos-egress.service")}
        names = {u: arg(w, "agent-machine") if "-agent-machine" in w else None for u, w in units.items()}
        self.assertIn(names["agentosd.service"], (None, broker))
        if "agent-machine" in flags("agentos-egress"):
            self.assertEqual(names["agentos-egress.service"] or flag_default("agentos-egress", "agent-machine"),
                             names["agentosd.service"] or broker)
        else:
            self.assertIsNone(names["agentos-egress.service"])

    def test_the_image_creates_every_service_user(self):
        lines = (MK / "mkosi.extra/usr/lib/sysusers.d/agentos-setup.conf").read_text().splitlines()
        users = sorted(l.split()[1] for l in lines if l.strip() and not l.startswith("#") and l.split()[0] == "u")
        self.assertEqual(users, ["agentos-egress", "agentos-kernel", "agentos-localui", "agentos-model",
                                 "agentos-modem", "agentos-owner"])
        for unit, user in ((PAGE_UNIT, "agentos-localui"), (MODEM_UNIT, "agentos-modem")):
            s = ini(unit)["Service"]
            self.assertEqual((s["User"], s["Group"]), (user, user))
        for unit in (UNITS / "agentosd.service", UNITS / "agentos-egress.service"):
            for w in exec_args(unit):
                if w.startswith("@uid:"):
                    self.assertIn(w[len("@uid:"):], users)

    def test_with_uids_swaps_user_names_for_uids(self):
        prog = str(AGENTOS_LIB / "with-uids")
        out = subprocess.run([prog, "echo", "-a", "@uid:root", "x@uid:root"], capture_output=True, text=True, check=True)
        self.assertEqual(out.stdout, "-a 0 x@uid:root\n")
        bad = subprocess.run([prog, "echo", "@uid:agentos-no-such-user"], capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(bad.stdout, "")
        self.assertIn("agentos-no-such-user", bad.stderr)

    def test_the_broker_starts_before_onboarding(self):
        # A preloaded box (D-105) has no /etc/agentos until setup: agentosd starts in setup mode.
        u = ini(UNITS / "agentosd.service")
        self.assertNotIn("ConditionPathExists", u["Unit"])
        self.assertEqual(u["Service"]["EnvironmentFile"], "-/etc/agentos/agentosd.env")
        self.assertEqual(u["Service"]["Environment"], "AGENTOS_OWNER=")
        words = exec_args(UNITS / "agentosd.service")
        self.assertEqual(arg(words, "modem-uid"), "@uid:agentos-modem")
        self.assertEqual(arg(words, "localui-uid"), "@uid:agentos-localui")
        self.assertNotIn("-netjoin-sock", words)  # the core joins no Wi-Fi (D-178)
        self.assertIn("agentos-egress.service", u["Unit"]["Wants"].split())
        self.assertIn("agentos-egress.service", u["Unit"]["After"].split())
        page = ini(PAGE_UNIT)["Unit"]
        self.assertIn("agentos-egress.service", page["Wants"].split())
        self.assertIn("agentos-egress.service", page["After"].split())

    def test_the_tpm_is_the_vault_process_s(self):
        rules = (MK / "mkosi.extra/usr/lib/udev/rules.d/60-agentos-tpm.rules").read_text()
        self.assertIn('SUBSYSTEM=="tpmrm", KERNEL=="tpmrm[0-9]*", GROUP="agentos-egress", MODE="0660"', rules)

    def test_the_build_ships_the_page(self):
        # The page and the modem bridge (#1388).
        build = (IMG / "build.sh").read_text()
        for cmd in ("agentos-localui", "agentos-modem"):
            with self.subTest(cmd):
                self.assertRegex(build, r"for cmd in [^;]*\b%s\b" % cmd)
                self.assertRegex(build, r'install -D -m 0644 "\$REPO/broker/cmd/{0}/{0}.service" '
                                        r'"\$STAGE/usr/lib/systemd/system/{0}.service"'.format(cmd))
        # The rule that gives the bridge its modems.
        self.assertIn('install -D -m 0644 "$REPO/broker/modem/at/udev/71-agentos-modem.rules" '
                      '"$STAGE/usr/lib/udev/rules.d/71-agentos-modem.rules"', build)

    def test_the_setup_vault_is_made_when_the_page_records_the_claim(self):
        p = ini(UNITS / "agentos-egress-setup.path")
        self.assertEqual(p["Path"]["PathChanged"], "/var/lib/agentos-localui/claim.json")
        self.assertEqual(p["Path"]["Unit"], "agentos-egress-setup.service")
        s = ini(UNITS / "agentos-egress-setup.service")
        self.assertEqual(s["Service"]["Type"], "oneshot")
        self.assertEqual(s["Service"]["ExecStart"], "/usr/lib/agentos/egress-setup --restart")
        self.assertIn("+/usr/lib/agentos/egress-setup", ini(UNITS / "agentos-egress.service")["Service"]["ExecStartPre"])

    def test_the_setup_vault_s_oneshot_is_sandboxed(self):
        # #1387: the root oneshot keeps only what egress-setup uses (a lock and a temporary directory
        # in /run, setpriv, chown, the vault's state directory, systemctl over /run/systemd/private).
        # Each line is pinned, so deleting one fails here.
        got = settings(UNITS / "agentos-egress-setup.service")
        for k, want in {
            "CapabilityBoundingSet": ["CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE"],
            "AmbientCapabilities": [], "NoNewPrivileges": ["yes"], "ProtectSystem": ["strict"],
            # "-": egress-setup exits 0 with no vault directory; the namespace must not fail first.
            "ReadWritePaths": ["/run -/var/lib/agentos-egress"],
            "ProtectHome": ["yes"], "PrivateTmp": ["yes"], "PrivateDevices": ["yes"],
            "PrivateNetwork": ["yes"], "RestrictAddressFamilies": ["AF_UNIX"],
            "ProtectKernelTunables": ["yes"], "ProtectKernelModules": ["yes"], "ProtectKernelLogs": ["yes"],
            "ProtectControlGroups": ["yes"], "ProtectClock": ["yes"], "ProtectHostname": ["yes"],
            "RestrictNamespaces": ["yes"], "RestrictRealtime": ["yes"], "RestrictSUIDSGID": ["yes"],
            "LockPersonality": ["yes"], "MemoryDenyWriteExecute": ["yes"],
            "SystemCallArchitectures": ["native"], "SystemCallFilter": ["@system-service"],
            "UMask": ["0077"], "ProtectProc": ["invisible"], "PrivateIPC": ["yes"],
            "User": [], "DynamicUser": [],
            # Not ProcSubset=pid: the claim check reads /proc/sys/kernel/random/boot_id.
            "ProcSubset": [],
        }.items():
            with self.subTest(k):
                self.assertEqual(got.get(k, []), want)

    def test_a_new_owner_number_restarts_the_bridge_without_waiting(self):
        # P2-2w c4c r1: agentosd writes the owner's number to /etc/agentos/modem.env at setup finish
        # but may not start a process (ARC-2); the path unit restarts the bridge, which reads it at
        # start, and try-restart leaves a stopped bridge (no modem line) stopped.
        # REQ: P2-2w-c4c-r1-2, ARC-2
        p = ini(UNITS / "agentos-modem-env.path")
        self.assertEqual(p["Path"]["PathChanged"], "/etc/agentos/modem.env")
        self.assertEqual(p["Path"]["Unit"], "agentos-modem-env.service")
        self.assertEqual(p["Install"]["WantedBy"], "paths.target")
        s = ini(UNITS / "agentos-modem-env.service")
        self.assertEqual(s["Service"]["Type"], "oneshot")
        self.assertEqual(s["Service"]["ExecStart"],
                         "/usr/bin/systemctl --no-block try-restart agentos-modem.service")
        modem = (ROOT / "broker/cmd/agentos-modem/agentos-modem.service").read_text()
        self.assertIn("EnvironmentFile=-/etc/agentos/modem.env", modem)
        # Root for PID 1's socket and nothing else; each line is pinned, so deleting one fails here.
        got = settings(UNITS / "agentos-modem-env.service")
        for k, want in {
            "CapabilityBoundingSet": [""], "AmbientCapabilities": [], "NoNewPrivileges": ["yes"],
            "ProtectSystem": ["strict"], "ReadWritePaths": [], "ProtectHome": ["yes"],
            "PrivateTmp": ["yes"], "PrivateDevices": ["yes"], "PrivateNetwork": ["yes"],
            "RestrictAddressFamilies": ["AF_UNIX"], "ProtectKernelTunables": ["yes"],
            "ProtectKernelModules": ["yes"], "ProtectKernelLogs": ["yes"], "ProtectControlGroups": ["yes"],
            "ProtectClock": ["yes"], "ProtectHostname": ["yes"], "RestrictNamespaces": ["yes"],
            "RestrictRealtime": ["yes"], "RestrictSUIDSGID": ["yes"], "LockPersonality": ["yes"],
            "MemoryDenyWriteExecute": ["yes"], "SystemCallArchitectures": ["native"],
            "SystemCallFilter": ["@system-service"], "UMask": ["0077"], "ProtectProc": ["invisible"],
            "PrivateIPC": ["yes"], "User": [], "DynamicUser": [],
        }.items():
            with self.subTest(k):
                self.assertEqual(got.get(k, []), want)


class EgressSetupTest(unittest.TestCase):
    """egress-setup makes the setup vault (init -setup) once the page has recorded the claim, as the
    vault user and from a copy the page user read, so root never parses the page's file (HW-10)."""
    # REQ: HW-10, CRED-9

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(self.tmp.name)
        self.bin, self.root, self.log = t / "bin", t / "root", t / "log"
        (self.root / "run").mkdir(parents=True)
        (self.root / "var/lib/agentos-egress").mkdir(parents=True)
        # setpriv drops its options and runs the command; chown and systemctl only log.
        stub(self.bin, "setpriv", 'echo "setpriv $*" >>"%s"\nwhile [ "${1#--}" != "$1" ]; do shift; done\nexec "$@"' % self.log)
        stub(self.bin, "chown", 'echo "chown $*" >>"%s"' % self.log)
        stub(self.bin, "systemctl", 'echo "systemctl $*" >>"%s"' % self.log)
        self.egress(0)

    def egress(self, code):
        stub(self.root / "usr/lib/agentos", "agentos-egress",
             'echo "egress $* $(cat "$4")" >>"%s"\n[ %d -ne 0 ] || : >"%s"\nexit %d'
             % (self.log, code, self.root / "var/lib/agentos-egress/vault.keys", code))

    def tearDown(self):
        self.tmp.cleanup()

    def run_setup(self, *args):
        env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]), AGENTOS_HEALTH_ROOT=str(self.root))
        r = subprocess.run([str(AGENTOS_LIB / "egress-setup")] + list(args), env=env, capture_output=True, text=True)
        log = self.log.read_text() if self.log.exists() else ""
        if self.log.exists():
            self.log.unlink()
        return r, log

    def test_nothing_before_the_page_has_a_claim_state(self):
        r, log = self.run_setup()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("egress", log)

    def test_the_vault_is_made_from_a_copy_as_the_vault_user(self):
        write(self.root, "var/lib/agentos-localui/claim.json", '{"synthetic":"canary"}')
        r, log = self.run_setup()
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = log.splitlines()
        self.assertTrue(lines[0].startswith("setpriv --reuid=agentos-localui --regid=agentos-localui --clear-groups "), log)
        made = [l for l in lines if l.startswith("egress ")]
        self.assertEqual(len(made), 1, log)
        self.assertRegex(made[0], r'^egress init -setup -claim %s/run/[^ ]+/claim.json \{"synthetic":"canary"\}$' % re.escape(str(self.root)))
        self.assertIn("setpriv --reuid=agentos-egress --regid=agentos-egress --clear-groups ", log)
        self.assertNotIn("systemctl", log)
        self.assertEqual([p.name for p in (self.root / "run").iterdir() if p.is_dir()], [])  # the copy is gone

    def test_restart_only_when_this_run_made_the_vault(self):
        write(self.root, "var/lib/agentos-localui/claim.json", "{}")
        r, log = self.run_setup("--restart")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("systemctl try-restart agentos-egress.service", log)
        r, log = self.run_setup("--restart")  # the keys exist now
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(log, "")

    def test_the_vault_is_made_under_the_lock_and_restarted_outside_it(self):
        # Two runs (the path unit's and a start's) never make the vault at once, and the restart
        # does not wait on a vault process start that waits on this run's lock (Security on #1302).
        lock = self.root / "run/agentos-egress-setup.lock"
        probe = 'if flock -n "%s" true; then echo "%s free"; else echo "%s held"; fi >>"%s"'
        stub(self.root / "usr/lib/agentos", "agentos-egress",
             (probe % (lock, "init", "init", self.log)) + '\n: >"%s"' % (self.root / "var/lib/agentos-egress/vault.keys"))
        stub(self.bin, "systemctl", probe % (lock, "restart", "restart", self.log))
        write(self.root, "var/lib/agentos-localui/claim.json", "{}")
        r, log = self.run_setup("--restart")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("init held", log)
        self.assertIn("restart free", log)

    def test_only_a_bounded_claim_is_read(self):
        stub(self.root / "usr/lib/agentos", "agentos-egress", 'wc -c <"$4" >>"%s"' % self.log)
        write(self.root, "var/lib/agentos-localui/claim.json", "x" * 70000)
        r, log = self.run_setup()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(log.splitlines()[-1].strip(), "65536")

    def test_an_unclaimed_box_waits(self):
        write(self.root, "var/lib/agentos-localui/claim.json", "{}")
        self.egress(1)
        r, log = self.run_setup("--restart")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("egress init -setup", log)
        self.assertNotIn("systemctl", log)
        self.assertFalse((self.root / "var/lib/agentos-egress/vault.keys").exists())


class LocaluiClaimTest(unittest.TestCase):
    """localui-claim hands the page the claim state the seller sealed into the broker's root-only
    directory (D-105), once, so the page can record the claim and the card step's latch (#1270)."""
    # REQ: HW-10, HW-1

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(self.tmp.name)
        self.bin, self.root, self.log = t / "bin", t / "root", t / "log"
        (self.root / "var/lib/agentos-localui").mkdir(parents=True)
        stub(self.bin, "chown", 'echo "chown $*" >>"%s"' % self.log)

    def tearDown(self):
        self.tmp.cleanup()

    def run_claim(self):
        env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]), AGENTOS_HEALTH_ROOT=str(self.root))
        r = subprocess.run([str(AGENTOS_LIB / "localui-claim")], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        log = self.log.read_text() if self.log.exists() else ""
        if self.log.exists():
            self.log.unlink()
        return log

    def test_the_seller_s_claim_moves_to_the_page(self):
        write(self.root, "var/lib/agentos/claim.json", "sealed", 0o600)
        log = self.run_claim()
        self.assertEqual(log, "chown agentos-localui:agentos-localui %s/var/lib/agentos/claim.json\n" % self.root)
        self.assertFalse((self.root / "var/lib/agentos/claim.json").exists())
        self.assertEqual((self.root / "var/lib/agentos-localui/claim.json").read_text(), "sealed")

    def test_the_page_s_directory_is_made_before_its_first_start(self):
        # #1688: agentos-localui-claim.service runs before the page's StateDirectory= exists.
        (self.root / "var/lib/agentos-localui").rmdir()
        write(self.root, "var/lib/agentos/claim.json", "sealed", 0o600)
        log = self.run_claim()
        d = self.root / "var/lib/agentos-localui"
        self.assertEqual(log, "chown agentos-localui:agentos-localui %s\nchown agentos-localui:agentos-localui %s\n"
                         % (d, self.root / "var/lib/agentos/claim.json"))
        self.assertEqual(stat.S_IMODE(d.stat().st_mode), 0o700)
        self.assertEqual((d / "claim.json").read_text(), "sealed")

    def test_the_page_s_own_state_is_kept(self):
        write(self.root, "var/lib/agentos/claim.json", "sealed")
        write(self.root, "var/lib/agentos-localui/claim.json", "claimed")
        self.assertEqual(self.run_claim(), "")
        self.assertEqual((self.root / "var/lib/agentos-localui/claim.json").read_text(), "claimed")

    def test_a_link_is_never_followed(self):
        # A link planted at either end must not have root chown or move what it points at.
        target = write(self.root, "elsewhere", "other", 0o600)
        (self.root / "var/lib/agentos").mkdir(parents=True)
        (self.root / "var/lib/agentos/claim.json").symlink_to(target)
        self.assertEqual(self.run_claim(), "")
        self.assertTrue((self.root / "var/lib/agentos/claim.json").is_symlink())
        self.assertFalse(os.path.lexists(self.root / "var/lib/agentos-localui/claim.json"))
        (self.root / "var/lib/agentos/claim.json").unlink()
        write(self.root, "var/lib/agentos/claim.json", "sealed")
        (self.root / "var/lib/agentos-localui/claim.json").symlink_to(self.root / "nowhere")
        self.assertEqual(self.run_claim(), "")
        self.assertTrue((self.root / "var/lib/agentos/claim.json").exists())
        self.assertTrue((self.root / "var/lib/agentos-localui/claim.json").is_symlink())

    def test_nothing_to_move(self):
        self.assertEqual(self.run_claim(), "")
        self.assertFalse((self.root / "var/lib/agentos-localui/claim.json").exists())


class CodexPinTest(unittest.TestCase):
    # REQ: CAP-11
    # The box's Codex image must carry usr/lib/agentos/cli-version holding the CODEX_VERSION its
    # build script pins, or agentosd's pin gate (#1877, #1895) refuses every provider run with one
    # journal line as the only cause (PUX finding 1 on #1895). image/check_codex_pin.sh checks the
    # staged tree, which becomes the box's verity-checked /usr, so the booted image carries what passed.
    SCRIPT = "CODEX_VERSION=0.162.1\n"
    # #1895's writer, verbatim (guest/codex/build-rootfs.sh at 2e6c54d), run in the image's root.
    WRITES = "printf '%s\\n' \"$CODEX_VERSION\" >usr/lib/agentos/cli-version\n"
    def run_check(self, cli=None, link=False, script=SCRIPT + WRITES, run_writer=False):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            write(d / "repo", "guest/codex/build-rootfs.sh", script)
            pin = d / "tree/usr/lib/agentos/cli-version"
            pin.parent.mkdir(parents=True)
            if run_writer:
                # The real writer line, as build-rootfs.sh runs it (cd "$OUT", set -eu).
                subprocess.run(["sh", "-euc", self.SCRIPT + self.WRITES], cwd=d / "tree", check=True)
            elif cli is not None:
                if link:
                    (d / "elsewhere").write_text(cli)
                    pin.symlink_to(d / "elsewhere")
                else:
                    pin.write_bytes(cli.encode())
            return subprocess.run(["sh", str(IMG / "check_codex_pin.sh"), str(d / "repo"), str(d / "tree")],
                                  capture_output=True, text=True)

    def test_the_file_the_build_script_writes_passes(self):
        r = self.run_check(run_writer=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_writer_is_the_build_script_s(self):
        # WRITES must be the real script's line, so the test above runs it.
        code = [l for l in (ROOT / "guest/codex/build-rootfs.sh").read_text().splitlines()
                if "cli-version" in l and not l.lstrip().startswith("#") and ">" in l]
        if code:
            self.assertEqual(code, [self.WRITES.rstrip("\n")])

    def test_agentosd_s_rule_is_the_check_s(self):
        # readCLIPin (imagepin.go, #1895): strings.TrimSuffix(b, "\n"), then the version must match.
        for cli in ("0.162.1", "0.162.1\n"):
            self.assertEqual(self.run_check(cli).returncode, 0, repr(cli))
        for cli in ("0.162.1\n\n", " 0.162.1", "0.162.1 ", "\n0.162.1", "0.162.1\r\n", "0.162.2", "0.162.2\n", ""):
            r = self.run_check(cli)
            self.assertNotEqual(r.returncode, 0, repr(cli))
            self.assertIn("cli-version", r.stderr)

    def test_missing_file_fails(self):
        r = self.run_check()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("cli-version", r.stderr)

    def test_symlink_fails(self):
        # agentosd reads only a regular file through os.OpenRoot, so a link would read as unpinned.
        self.assertNotEqual(self.run_check("0.162.1", link=True).returncode, 0)

    def test_script_without_a_pin_line_fails(self):
        self.assertNotEqual(self.run_check("0.162.1", script="echo no version\n" + self.WRITES).returncode, 0)

    def test_a_missing_file_fails_however_the_script_writes_it(self):
        # The check keys on the tree, not on build-rootfs.sh's text: a writer refactored to a variable
        # no longer names the path, and must not turn the check off (#1897 delta review, finding 2).
        refactored = self.SCRIPT + 'pinf=usr/lib/agentos/cli-version\nprintf \'%s\\n\' "$CODEX_VERSION" >"$pinf"\n'
        self.assertNotEqual(self.run_check(script=refactored).returncode, 0)
        self.assertNotEqual(self.run_check(script=self.SCRIPT).returncode, 0)

    def test_this_tree_s_check_fails_an_unpinned_image(self):
        # The real repo: agentosd reads the pin (imagepin.go), so an image without it fails the build.
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run(["sh", str(IMG / "check_codex_pin.sh"), str(ROOT), d], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("cli-version", r.stderr)

    @staticmethod
    def registered(exe):
        # Go's flag package takes -image V, -image=V, --image V and --image=V, and images.Set is
        # last-wins (broker/cmd/agentosd/main.go), so the last value per name is the one registered.
        return dict(v.split("=", 1) for v in re.findall(r"(?:^|\s)--?image(?:=|\s+)(\S+)", exe))

    def assert_from_verity_usr(self, exe):
        images = self.registered(exe)
        self.assertEqual(images["codex"], "/usr/lib/agentos/images/codex")
        for name, path in images.items():
            self.assertTrue(path.startswith("/usr/lib/agentos/images/"), (name, path))
            self.assertNotIn("..", path)

    def test_images_are_registered_from_the_verity_usr(self):
        # The pin is read at every gate check, so a tree a process could swap after the check would
        # reopen the window #1895 closes; under /usr (dm-verity, read-only) nothing can (#1895 delta
        # review). Every -image agentosd registers, the Codex one included, lives there.
        exe = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentosd.service")["Service"]["ExecStart"]
        self.assert_from_verity_usr(exe)
        self.assertIn('sh "$REPO/guest/codex/build-rootfs.sh" "$STAGE/usr/lib/agentos/images/codex"',
                      (IMG / "build.sh").read_text())
        # Every spelling Go accepts, appended last, overrides the reviewed value and must be caught.
        for extra in (" --image=codex=/var/lib/agentos/codex", " -image=codex=/var/lib/agentos/codex",
                      " --image codex=/var/lib/agentos/codex", " -image openclaw=/var/lib/agentos/openclaw"):
            with self.assertRaises(AssertionError, msg=extra):
                self.assert_from_verity_usr(exe + extra)

    def test_build_checks_the_codex_tree_it_stages(self):
        lines = (IMG / "build.sh").read_text().splitlines()
        build = lines.index('sh "$REPO/guest/codex/build-rootfs.sh" "$STAGE/usr/lib/agentos/images/codex"')
        self.assertEqual(lines[build + 1], 'sh "$HERE/check_codex_pin.sh" "$REPO" "$STAGE/usr/lib/agentos/images/codex"')


HOSTDISK_RULES = ("59-agentos-host-disks.rules", "64-agentos-host-disks-assembly.rules",
                  "72-agentos-host-disks-late.rules")
# Every agentOS service the image ships, its user and its device policy (HOST-1a part 2, hostdisk
# H11, Security ruling (c) on #172): a host disk's node is root:root 0600, and root can still open
# it, so every unit that runs as root sets PrivateDevices=yes or DevicePolicy=closed, with
# DeviceAllow= only where it needs a device. agentosd.service is the old core's broker, frozen while
# the kernel replaces it (D-139); its hardening is IMG-4 (#917).
UNIT_DEVICES = {
    "agentos-boot-report.service": ("root", "closed; block-* r"),
    "agentos-drill-report.service": ("root", "closed"),
    "agentos-drive-id.service": ("root", "closed; block-* rw"),
    "agentos-egress-setup.service": ("root", "private"),
    "agentos-egress.service": ("agentos-egress", "closed; /dev/tpmrm0 rw"),
    "agentos-fallback.service": ("root", "closed"),
    "agentos-health.service": ("root", "closed; block-* r, /dev/mapper/control rw"),
    "agentos-inbound.service": ("root", "closed"),
    "agentos-keeper-enroll.service": ("root", "closed; /dev/tpmrm0 rw"),
    "agentos-keeper-kernel.service": ("root", "closed; /dev/tpmrm0 rw"),
    "agentos-modem-env.service": ("root", "private"),
    "agentos-reboot.service": ("root", "closed; block-* r, /dev/mapper/control rw"),
    "agentosd.service": ("root", "none"),
    "agentos-localui-claim.service": ("root", "closed"),
    "agentos-localui.service": ("agentos-localui", "private"),
    "agentos-modem.service": ("agentos-modem", "closed; char-ttyUSB rw, char-alsa rw"),
}
DEVICE_POLICY_EXEMPT = {"agentosd.service": "IMG-4 (#917)"}


def device_policy(unit):
    """UNIT's (user, policy): "private", "closed" or "strict" with its DeviceAllow= list, or "none"."""
    s = settings(unit)
    user = (s.get("User") or ["root"])[-1]
    if (s.get("PrivateDevices") or [""])[-1].lower() in check.TRUE_WORDS:
        return user, "private"
    policy = (s.get("DevicePolicy") or ["none"])[-1]
    allows = ", ".join(s.get("DeviceAllow", []))
    return user, policy + ("; " + allows if allows else "")


class HostDiskImageTest(unittest.TestCase):
    """HOST-1a part 2 (hostdisk H11, H12): the image installs the host-disk rules and helper, every
    root unit has a device policy, nothing assembles or automounts a disk, the boot health check
    finds the drive, and CI boots with a second internal disk and a USB disk beside the drive."""

    def shipped_units(self):
        build = (IMG / "build.sh").read_text()
        units = {f.name: f for f in UNITS.glob("agentos*.service")}
        for src, dst in re.findall(r'install -D -m 0644 "\$REPO/(broker/cmd/[^"]+\.service)" "\$STAGE/usr/lib/systemd/system/([^"]+)"', build):
            units[dst] = ROOT / src
        return units

    # REQ: HW-8, ONB-2
    def test_every_units_device_policy_is_listed(self):
        units = self.shipped_units()
        self.assertEqual({n: device_policy(f) for n, f in units.items()}, UNIT_DEVICES)
        for name, (user, policy) in UNIT_DEVICES.items():
            with self.subTest(unit=name):
                if user == "root" and name not in DEVICE_POLICY_EXEMPT:
                    self.assertRegex(policy, r"^(private|closed|strict)\b")
        # A drop-in for every agentOS unit sets no device key that would widen one.
        for d in UNITS.glob("agentos*.service.d"):
            for f in d.glob("*.conf"):
                self.assertFalse({"DevicePolicy", "DeviceAllow", "PrivateDevices"} & set(settings(f)), f)

    # REQ: HW-8, ONB-2
    def test_build_installs_the_rules_and_helper(self):
        build = (IMG / "build.sh").read_text()
        loop = re.search(r"for cmd in ([^;]+); do", build, re.S).group(1).split()
        self.assertIn("agentos-hostdisk", loop)
        m = re.search(r'for r in ([^;]+); do\n\tinstall -D -m 0644 "\$REPO/broker/hostdisk/udev/\$r\.rules" '
                      r'"\$STAGE/usr/lib/udev/rules\.d/\$r\.rules"\ndone\n', build)
        self.assertEqual(tuple(r + ".rules" for r in m.group(1).split()), HOSTDISK_RULES)
        allowed = check.exec_allowed()
        for name in HOSTDISK_RULES:
            with self.subTest(rule=name):
                data = (ROOT / "broker/hostdisk/udev" / name).read_bytes()
                self.assertIn(("usr/lib/udev/rules.d/" + name, "sha256:" + hashlib.sha256(data).hexdigest()), allowed)
        # The 59 file runs the helper where build.sh puts it, and the initrd carries neither.
        self.assertIn("/usr/lib/agentos/agentos-hostdisk classify", (ROOT / "broker/hostdisk/udev" / HOSTDISK_RULES[0]).read_text())
        self.assertEqual([p for p in (MK / "initrd").rglob("*") if "hostdisk" in p.name or "host-disks" in p.name], [])

    # REQ: HW-8, ONB-2
    def test_no_assembly_or_automount_rule_or_package_ships(self):
        rules = [rel for rel, _ in check.exec_allowed() if "/udev/rules.d/" in rel]
        self.assertTrue(rules)
        self.assertEqual([r for r in rules if check.ASSEMBLY_RULES.search(r.rsplit("/", 1)[1])], [])
        packages = ini(MK / "mkosi.conf")["Content"]["Packages"].split()
        for p in ("lvm2", "mdadm", "bcache-tools", "zfsutils-linux", "multipath-tools", "udisks2", "autofs", "dmraid"):
            self.assertNotIn(p, packages)
        # The initrd drops the lvm2 mkosi-initrd adds, and its tree check refuses the rest.
        removed = ini(MK / "initrd/mkosi.conf")["Content"]["RemoveFiles"].split()
        for f in ("/usr/sbin/lv*", "/usr/sbin/pv*", "/usr/sbin/vg*", "/usr/lib/udev/rules.d/*lvm*", "/usr/lib/systemd/system/lvm2-*"):
            self.assertIn(f, removed)
        # Every lvm2 command the tree check names is one of those globs.
        for n in check.ASSEMBLY_TOOLS:
            self.assertTrue(any(fnmatch.fnmatch("/usr/sbin/" + n, f) for f in removed if f.startswith("/usr/sbin/")) or
                            not n.startswith(("lv", "pv", "vg")), n)
        initrd = load("initrd_finalize_hostdisk", MK / "initrd/mkosi.finalize")
        self.assertEqual(initrd.ASSEMBLY_TOOLS, check.ASSEMBLY_TOOLS)
        self.assertEqual(initrd.ASSEMBLY_RULES.pattern, check.ASSEMBLY_RULES.pattern)

    # REQ: HW-8, ONB-2
    def test_initrd_check_refuses_assembly_tools(self):
        initrd = load("initrd_finalize_hostdisk", MK / "initrd/mkosi.finalize")
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            write(root, "usr/lib/udev/rules.d/10-mkosi-initrd-md.rules")
            write(root, "usr/lib/udev/rules.d/55-dm.rules")
            write(root, "usr/sbin/veritysetup", "", 0o755)
            self.assertEqual(initrd.assembly_tools(root), [])
            write(root, "usr/sbin/lvm", "", 0o755)
            write(root, "usr/lib/udev/rules.d/69-lvm.rules")
            write(root, "usr/lib/udev/rules.d/64-md-raid-assembly.rules")
            self.assertEqual(initrd.assembly_tools(root), ["usr/sbin/lvm", "usr/lib/udev/rules.d/64-md-raid-assembly.rules",
                                                           "usr/lib/udev/rules.d/69-lvm.rules"])
            env = dict(os.environ, BUILDROOT=d, SOURCE_DATE_EPOCH="86400")
            r = subprocess.run([str(MK / "initrd/mkosi.finalize")], env=env, capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("usr/sbin/lvm", r.stderr)

    # REQ: HW-8, ONB-2
    def test_fstab_and_gpt_auto_stay_on_the_drive(self):
        # fstab mounts only API file systems; gpt-auto finds root by the loader's partition (no
        # root=) and makes no swap unit; no unit mounts a block device by name.
        for line in (MK / "mkosi.extra/etc/fstab").read_text().splitlines():
            if line.strip() and not line.startswith("#"):
                src, _, fstype = line.split()[:3]
                self.assertIn(fstype, ("devtmpfs", "tmpfs"), line)
                self.assertFalse(src.startswith(("/dev/", "UUID=", "LABEL=", "PARTUUID=", "PARTLABEL=")), line)
        cmdline = ini(MK / "mkosi.conf")["Content"]["KernelCommandLine"].split()
        self.assertFalse([w for w in cmdline if w.startswith(("root=", "systemd.gpt_auto", "rd.systemd.gpt_auto"))])
        self.assertIn("systemd.swap=0", cmdline)
        for f in list(UNITS.glob("*.mount")) + list(UNITS.glob("*.swap")) + list(UNITS.glob("*.automount")):
            self.fail("%s: the image mounts nothing by unit" % f.name)

    # REQ: HW-8, ONB-2
    def test_ci_boots_with_an_internal_and_a_usb_host_disk(self):
        s = (IMG / "ci_boot.sh").read_text()
        self.assertIn("-device usb-storage,bus=xhci.0,drive=usb,removable=on", s)
        self.assertIn('boot "$W/console.log" "$D" "$H"', s)
        self.assertIn('[ "$(sha256sum <"$U")" = "$usb_before" ]', s)
        for want in ("agentos-hostdisk: drive is the root disk", "agentos-hostdisk: host disks usb virtio",
                     "agentos-hostdisk: every host node hidden", "agentos-hostdisk: no label or link names a host disk",
                     "agentos-hostdisk: passthrough nodes root-only", "agentos-hostdisk: done"):
            self.assertIn('"%s"' % want, s)
        self.assertIn('hasnt "$W/console.log" "agentos-hostdisk: FAIL"', s)
        self.assertIn("hostdisk=ok", s)
        self.assertIn("agentos-hostdisk-check.service", re.search(r"CHECKS_WANTED=.*", s).group(0))
        # The passthrough line counts at least the USB disk's node, so it cannot pass on none.
        self.assertIn('if [ "$c" -lt 1 ]; then say "FAIL no passthrough node found"', s)

    # REQ: HW-8, ONB-2
    def test_initrd_links_to_a_host_disk_are_removed(self):
        # #3306's CI boot: the initrd, which has no host-disk rules, linked the host disks by label,
        # partition label and disk sequence, and udev in the main system kept those links. The 59
        # rule runs host-disk-unlink for each device it hides, which removes only links to it.
        self.assertIn('RUN+="/usr/lib/agentos/host-disk-unlink %k"', (ROOT / "broker/hostdisk/udev" / HOSTDISK_RULES[0]).read_text())
        with tempfile.TemporaryDirectory() as d:
            dev, other = pathlib.Path(d) / "dev", pathlib.Path(d) / "other"
            links = {"disk/by-label/HOSTLABEL": "../../vdb1", "disk/by-partlabel/hostdata": "../../vdb1",
                     "disk/by-diskseq/10-part1": str(dev / "vdb1"), "disk/by-diskseq/10": "../../vdb",
                     "disk/by-label/root": "../../vda2", "disk/by-id/usb-x-part1": "../../vdb11",
                     "cciss/by-label/x": "../../vdb1"}
            for rel, target in links.items():
                link(dev, rel, target)
            write(dev, "disk/by-label/plain")
            other.mkdir()
            link(other, "victim", "../../vdb1")
            link(dev, "disk/by-elsewhere", other)
            run = lambda name: subprocess.run(["sh", str(AGENTOS_LIB / "host-disk-unlink"), name],
                                              env=dict(os.environ, AGENTOS_DEV=str(dev)), capture_output=True, text=True)
            r = run("vdb1")
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))
            gone = {"disk/by-label/HOSTLABEL", "disk/by-partlabel/hostdata", "disk/by-diskseq/10-part1"}
            for rel in list(links) + ["disk/by-label/plain"]:
                self.assertEqual(os.path.lexists(dev / rel), rel not in gone, rel)
            self.assertTrue(os.path.lexists(other / "victim"))
            for bad in ("", "../etc", "vdb1/../../etc", ".hidden", "vdb 1"):
                self.assertEqual(run(bad).returncode, 1, bad)
            self.assertTrue(os.path.lexists(dev / "disk/by-diskseq/10"))
        self.assertTrue(os.access(AGENTOS_LIB / "host-disk-unlink", os.X_OK))

    # REQ: HW-1, HW-8
    def test_two_drives_boot_still_fails_with_the_copy_hidden(self):
        # The 59 rule hides the second copy's PARTUUIDs from udev; drive-id must still find both, so
        # that boot fails health and is never blessed (L3 later finding on #3306).
        s = (IMG / "ci_boot.sh").read_text()
        self.assertIn('UNTIL="agentos-fallback:" boot "$W/console-two-drives.log" "$W/two-a.raw" "$W/two-b.raw"', s)
        for line in ('has "$W/console-two-drives.log" "agentos-drive-id: FAIL 2 partitions"',
                     'has "$W/console-two-drives.log" "agentos-health: FAIL boot drive is ambiguous"',
                     'hasnt "$W/console-two-drives.log" "agentos-boot: bless=good"',
                     'hasnt "$W/console-two-drives.log" "agentos-drive-id: assigned"'):
            self.assertIn(line, s)


if __name__ == "__main__":
    unittest.main()
