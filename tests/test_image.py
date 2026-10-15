# Tests for the device image build (P2-1): the build-time tree check, the release manifest,
# the counted boot entry, the boot health check, and the image's static configuration.
# The image itself is built and booted under Secure Boot by .github/workflows/image.yml.
# REQ: HW-1, HW-5, UPD-1, UPD-1a
import ast
import base64
import contextlib
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
# page's and the access point loader's units, which image/build.sh installs from their commands'
# directories.
NODUMP = ("usr/lib/systemd/coredump.conf.d/50-agentos-nodump.conf",
          "usr/lib/systemd/system.conf.d/50-agentos-nodump.conf",
          "usr/lib/sysctl.d/99-agentos-nodump.conf",
          "usr/lib/systemd/system/agentosd.service",
          "usr/lib/systemd/system/agentos-egress.service",
          "usr/lib/systemd/system/agentos-localui.service",
          "usr/lib/systemd/system/agentos-ap.service")
NODUMP_SRC = {"usr/lib/systemd/system/agentos-localui.service":
              ROOT / "broker/cmd/agentos-localui/agentos-localui.service",
              "usr/lib/systemd/system/agentos-ap.service": ROOT / "broker/cmd/agentos-ap/agentos-ap.service"}


def nodump(root):
    for rel in NODUMP:
        write(root, rel, NODUMP_SRC.get(rel, MK / "mkosi.extra" / rel).read_text())


BT_BLOCK = "usr/lib/modprobe.d/agentos-no-bluetooth.conf"


def radio(root):
    # Stand-ins for firmware-mediatek's MT7922 files (#1415), and the image's Bluetooth block.
    for rel in check.RADIO_FIRMWARE:
        write(root, rel, "fw")
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
        radio(self.root)
        uplink(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    # REQ: DEV-2, CH-9
    def test_distro_network_files_are_refused(self):
        # #1478: agentos_inbound has only an input hook, so nothing may turn on forwarding. Debian's
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
    def test_tree_without_the_radio_firmware_is_refused(self):
        # #1415: without firmware-mediatek's MT7922 files mt7921e brings up no wlan0, so the setup
        # network (CH-7, HW-10) is never served on the M6 Ultra. Each file is required.
        for rel in check.RADIO_FIRMWARE:
            f = self.root / rel
            f.unlink()
            self.assertIn(rel, " ".join(check.violations(self.root)))
            write(self.root, rel, "fw")
        self.assertEqual(check.violations(self.root), [])

    # REQ: CH-7, HW-10
    def test_radio_firmware_names_are_the_ones_mt7921e_requests(self):
        # MT7922_FIRMWARE_WM and MT7922_ROM_PATCH in the kernel's mt792x.h. Pinned literally: the
        # same package ships MT7961 files, so a wrong name here would still build.
        self.assertEqual(check.RADIO_FIRMWARE, (
            "usr/lib/firmware/mediatek/WIFI_RAM_CODE_MT7922_1.bin",
            "usr/lib/firmware/mediatek/WIFI_MT7922_patch_mcu_1_1_hdr.bin"))

    # REQ: CH-7, HW-10
    def test_radio_firmware_must_be_a_nonempty_file_in_the_tree(self):
        # An empty file, a directory, a dangling link, a loop, or a link whose absolute target exists
        # only on the build host is no firmware on the booted box.
        rel = check.RADIO_FIRMWARE[0]
        f = self.root / rel
        host = write(pathlib.Path(self.tmp.name + "-host"), "fw.bin", "fw")
        self.addCleanup(shutil.rmtree, self.tmp.name + "-host")
        cases = {
            "empty": lambda: f.write_bytes(b""),
            "directory": lambda: f.mkdir(),
            "dangling": lambda: f.symlink_to("missing.bin"),
            "loop": lambda: f.symlink_to(f.name),
            "host target": lambda: f.symlink_to(host),
            "escapes the tree": lambda: f.symlink_to("../" * 12 + str(host).lstrip("/")),
        }
        for name, make in cases.items():
            with self.subTest(name):
                if f.is_symlink() or f.is_file():
                    f.unlink()
                elif f.is_dir():
                    f.rmdir()
                make()
                self.assertIn(rel, " ".join(check.violations(self.root)))
        f.unlink()

    # REQ: CH-7, HW-10
    def test_radio_firmware_links_resolve_inside_the_tree(self):
        # Debian's firmware packages link some names to others; an absolute target means the image's.
        rel = check.RADIO_FIRMWARE[0]
        f = self.root / rel
        write(self.root, "usr/lib/firmware/mediatek/real.bin", "fw")
        for target in ("real.bin", "/usr/lib/firmware/mediatek/real.bin", "/lib/firmware/mediatek/real.bin"):
            with self.subTest(target):
                f.unlink()
                f.symlink_to(target)
                if target.startswith("/lib/"):
                    (self.root / "lib").symlink_to("usr/lib")
                self.assertEqual(check.violations(self.root), [])

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

    def test_compressed_radio_firmware_counts(self):
        # The kernel loader also finds name.xz and name.zst, if Debian ever ships them compressed.
        for i, rel in enumerate(check.RADIO_FIRMWARE):
            (self.root / rel).unlink()
            write(self.root, rel + (".xz", ".zst")[i % 2], "fw")
        self.assertEqual(check.violations(self.root), [])

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
        stub(self.lib, "runsc", 'echo "runsc version release-20260928.0"')
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

    def run_health(self):
        env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]),
                   AGENTOS_LIB=str(self.lib), AGENTOS_HEALTH_ROOT=str(self.root))
        return subprocess.run(["sh", str(MK / "mkosi.extra/usr/lib/agentos/health")], env=env,
                              capture_output=True, text=True)

    def test_pass(self):
        r = self.run_health()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("agentos-health: PASS", r.stdout)
        self.assertIn("secure_boot=on", r.stdout)
        self.assertIn("inbound=drop", r.stdout)
        self.assertIn("swap=off dumps=off", r.stdout)
        self.assertIn("forward=off", r.stdout)

    def test_kernel_without_forced_forwarding_passes(self):
        # Kernels before 6.17 have no force_forwarding switch; its absence is not a failure.
        (self.root / "proc/sys/net/ipv6/conf/eth0/force_forwarding").unlink()
        r = self.run_health()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

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
            "ipv4 device switches unreadable": lambda: shutil.rmtree(self.root / "proc/sys/net/ipv4/conf"),
            "ipv6 default unreadable": lambda: (self.root / "proc/sys/net/ipv6/conf/default/forwarding").unlink(),
        }
        for name, breakit in cases.items():
            with self.subTest(name):
                self.tearDown()
                self.setUp()
                breakit()
                r = self.run_health()
                self.assertEqual(r.returncode, 1, name)
                self.assertIn("agentos-health: FAIL", r.stdout)


class ApExemptTest(unittest.TestCase):
    """DEV-net-f, DEV-net-g (DEV-2, CH-7): the access point's interface, and only it, joins the
    inbound exempt set, only while agentos_ap holds it, and leaves the set when the access point
    stops; any failure fails and never touches the table otherwise."""
    # REQ: DEV-2, CH-7, DEV-net-f, DEV-net-g

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(self.tmp.name)
        self.bin, self.sys, self.log = t / "bin", t / "sys", t / "nft.log"
        (self.sys / "class/net/wlap0/phy80211").mkdir(parents=True)
        (self.sys / "class/net/wlan1/phy80211").mkdir(parents=True)
        (self.sys / "class/net/eth0").mkdir(parents=True)
        self.nft()

    def tearDown(self):
        self.tmp.cleanup()

    def nft(self, fail="", ap="wlap0", members='"lo"'):
        # Logs each call, and the script of "nft -f -"; FAIL names the call ("list set",
        # "list chain", "add", "get", "-f") that fails. "list chain" prints agentos_ap's input chain
        # for AP, as nft prints it (absent when AP is empty); "list set" prints MEMBERS.
        stub(self.bin, "nft", r"""echo "$*" >>"%(log)s"
[ "$1" = -f ] && sed 's/^/  /' >>"%(log)s"
case "$1 $2" in "%(fail)s" | "%(fail)s "*) echo "nft: $1 failed" >&2; exit 1 ;; esac
case "$1 $2" in
"list chain") [ -n "%(ap)s" ] || exit 1
  printf '\t\tiifname "%(ap)s" udp dport { 53, 67 } accept\n\t\tiifname "%(ap)s" drop\n'
  printf '\t\tiifname != "%(ap)s" tcp dport 80 ip daddr 10.42.0.1 drop\n' ;;
"list set") echo "elements = { %(members)s }" ;;
esac
exit 0""" % dict(log=self.log, fail=fail or "none", ap=ap, members=members.replace('"', '\\"')))

    def run_exempt(self, *args):
        env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]), AGENTOS_SYSFS=str(self.sys))
        return subprocess.run(["sh", str(MK / "mkosi.extra/usr/lib/agentos/ap-exempt"), *args], env=env,
                              capture_output=True, text=True)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_adds_the_access_point_then_checks_it_is_there(self):
        r = self.run_exempt("wlap0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("agentos-ap-exempt: OK wlap0", r.stdout)
        self.assertEqual(self.calls(), [
            "list set inet agentos_inbound exempt",
            "list chain inet agentos_ap input",
            'add element inet agentos_inbound exempt { "wlap0" }',
            'get element inet agentos_inbound exempt { "wlap0" }',
        ])

    def test_failures_fail_bring_up_and_never_open_the_table(self):
        for verb in ("list set", "list chain", "add", "get"):
            with self.subTest(failing=verb):
                self.log.unlink(missing_ok=True)
                self.nft(verb)
                r = self.run_exempt("wlap0")
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("agentos-ap-exempt: FAIL", r.stdout)
                self.assertIn("stays closed", r.stdout)
                for c in self.calls():
                    self.assertNotRegex(c, r"^(-f|delete|destroy|flush|replace|insert|reset)\b")
                if verb.startswith("list"):
                    self.assertFalse([c for c in self.calls() if c.startswith("add")],
                                     "added with %s failing" % verb)

    def test_only_the_loaders_access_point_is_admitted(self):
        # DEV-net-g (a), (c), acceptance 4: an interface is added only while agentos_ap ends its
        # input chain in a drop for that interface, so a second radio the loader did not create
        # as the access point (wlan1), or the access point before agentos_ap loads, stays dropped.
        for iface, ap in (("wlan1", "wlap0"), ("wlap0", ""), ("wlap0", "wlap00"), ("wlap0", "wlap")):
            with self.subTest(iface=iface, agentos_ap=ap):
                self.log.unlink(missing_ok=True)
                self.nft(ap=ap)
                r = self.run_exempt(iface)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("agentos_ap is not loaded for %s" % iface, r.stdout)
                self.assertFalse([c for c in self.calls() if c.startswith("add")])

    def test_only_a_wireless_interface_is_added(self):
        # The uplink, a tether or a second NIC is not wireless; bad names never reach nft.
        for args in (("eth0",), ("usb0",), ("",), ("lo",), ("wlap0;x",), ("a" * 16,), ("-f",), ("../wlap0",),
                     ("wlap0", "eth0"), ()):
            with self.subTest(args=args):
                self.log.unlink(missing_ok=True)
                r = self.run_exempt(*args)
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertIn("agentos-ap-exempt: FAIL", r.stdout)
                self.assertEqual(self.calls(), [])

    def test_remove_takes_the_interface_out_and_checks_it_is_gone(self):
        # DEV-net-g (b): one add-then-delete transaction, so a second stop is not an error and no
        # other element is touched, then a check. The interface need not exist any more (gone).
        for iface in ("wlap0", "gone0"):
            with self.subTest(iface=iface):
                self.log.unlink(missing_ok=True)
                r = self.run_exempt("--remove", iface)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("agentos-ap-exempt: OK removed %s" % iface, r.stdout)
                self.assertEqual(self.calls(), [
                    "list set inet agentos_inbound exempt",
                    "-f -",
                    '  add element inet agentos_inbound exempt { "%s" }' % iface,
                    '  delete element inet agentos_inbound exempt { "%s" }' % iface,
                    "list set inet agentos_inbound exempt",
                ])

    def test_a_failed_remove_says_so(self):
        cases = {"list set": dict(fail="list set"), "-f": dict(fail="-f"),
                 "still there": dict(members='"lo", "wlap0"')}
        for name, kw in cases.items():
            with self.subTest(name):
                self.log.unlink(missing_ok=True)
                self.nft(**kw)
                r = self.run_exempt("--remove", "wlap0")
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("agentos-ap-exempt: FAIL", r.stdout)
                self.assertIn("may still be exempt", r.stdout)
                for c in self.calls():
                    self.assertNotRegex(c, r"^ *(destroy|flush|replace|insert|reset|delete (table|chain|set|rule))\b")
        # A similar name in the set is not the interface.
        self.nft(members='"lo", "wlap00"')
        self.assertEqual(self.run_exempt("--remove", "wlap0").returncode, 0)

    def test_remove_refuses_names_that_are_not_an_access_point(self):
        for args in (("--remove", "lo"), ("--remove", ""), ("--remove", "wl;x"), ("--remove", "-f"),
                     ("--remove",), ("--remove", "wlap0", "eth0")):
            with self.subTest(args=args):
                self.log.unlink(missing_ok=True)
                r = self.run_exempt(*args)
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertIn("agentos-ap-exempt: FAIL", r.stdout)
                self.assertEqual(self.calls(), [])

    def test_unit_orders_after_the_inbound_table_and_follows_the_interface(self):
        u = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentos-ap-exempt@.service")
        unit, svc = u["Unit"], u["Service"]
        self.assertIn("agentos-inbound.service", unit["Requires"].split())
        self.assertIn("agentos-inbound.service", unit["After"].split())
        # Bound to the interface: it stops, and so removes it, when the interface goes, and runs
        # again on the next bring-up of a recreated one.
        self.assertEqual(unit["BindsTo"], "sys-subsystem-net-devices-%i.device")
        self.assertIn("sys-subsystem-net-devices-%i.device", unit["After"].split())
        self.assertEqual(svc["Type"], "oneshot")
        self.assertEqual(svc["RemainAfterExit"], "yes")
        self.assertEqual(svc["ExecStart"], "/usr/lib/agentos/ap-exempt %I")
        # DEV-net-g (b): stopping the access point takes its interface out of the set.
        self.assertEqual(svc["ExecStop"], "/usr/lib/agentos/ap-exempt --remove %I")
        f = MK / "mkosi.extra/usr/lib/agentos/ap-exempt"
        self.assertTrue(f.stat().st_mode & stat.S_IXUSR)

    def test_network_manager_needs_the_inbound_drop_first(self):
        # LATER DEV-net-e l3: if the image adopts NetworkManager, it must require the drop as
        # systemd-networkd does.
        pkgs = ini(MK / "mkosi.conf")["Content"]["Packages"].split()
        f = MK / "mkosi.extra/usr/lib/systemd/system/NetworkManager.service.d/agentos-inbound.conf"
        if "network-manager" not in pkgs:
            self.assertFalse(f.exists())
            return
        d = ini(f)["Unit"]
        self.assertIn("agentos-inbound.service", d["Requires"].split())
        self.assertIn("agentos-inbound.service", d["After"].split())


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

    # REQ: CH-7, HW-10
    def test_radio_firmware_comes_from_the_pinned_snapshot(self):
        # #1415: firmware-mediatek is in Debian's non-free-firmware component. The image enables it,
        # in mkosi.conf and in the build's apt sources, from the same snapshot as main, and installs
        # the package.
        c = ini(MK / "mkosi.conf")
        self.assertEqual(c["Distribution"]["Repositories"].split(","), ["main", "non-free-firmware"])
        self.assertIn("firmware-mediatek", c["Content"]["Packages"].split())
        mirror = c["Distribution"]["Mirror"].rstrip("/")
        text = (MK / "mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources").read_text()
        stanzas = [dict(l.split(": ", 1) for l in s.splitlines() if l and not l.startswith("#"))
                   for s in text.split("\n\n")]
        stanzas = [s for s in stanzas if s]
        for s in stanzas:
            self.assertEqual(s["Components"].split(), ["main", "non-free-firmware"], s["URIs"])
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
        radio(self.root)
        uplink(self.root)

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
                                        "LimitCORE=0", "LimitCORE=0", "LimitCORE=0", "LimitCORE=0")):
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
        write(self.root, "etc/fstab", "# no swap here\nUUID=x / ext4 defaults 0 1\n")
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
        self.assertIn("rootflags=prjquota", c["KernelCommandLine"].split())
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
# The units image/build.sh installs from their commands' directories.
AP_UNIT = ROOT / "broker/cmd/agentos-ap/agentos-ap.service"
MODEM_UNIT = ROOT / "broker/cmd/agentos-modem/agentos-modem.service"
NETJOIN_UNIT = ROOT / "broker/cmd/agentos-netjoin/agentos-netjoin.service"


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
        radio(self.root)
        uplink(self.root)

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
            # A mask still reads as nothing.
            with self.subTest(rel=rel, target="/dev/null"):
                f = link(self.root, rel, "/dev/null")
                self.assertEqual(check.violations(self.root), [])
                f.unlink()
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
        # #1702 item 3: a compromise of the fuzz user, the page's user or a login user then becomes
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
            "var/lib/agentos-fuzz", "var/lib/agentos-localui", "var/lib/agentos-egress", "home", "run/user",
            "var/lib/private")))

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
                 "r /run/sysctlx.d", "L /etc/y - - - - /run/agentos", "C! /etc/pam.d - - - -",
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
                 "systemd/resolved.conf.d", "systemd/system-generators", "credstore", "credstore.encrypted")
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
    "f /etc/agentos/modem.env - - - - COUNTRY_CODE=1", "f /lib/firmware/x.bin")
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
        radio(self.root)
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
        self.assertFalse(self.refused("L /etc/y - - - - /run/agentos\n"))
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
        radio(root)
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
    radio(root)
    uplink(root)
    write(root, "usr/lib/tmpfiles.d/agentos.conf", AGENTOS_TMPFILES.read_text())
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
    through pathlib). mkosi.finalize may touch the file system only in the four tree primitives
    (tree_lstat, tree_listdir, tree_readlink, tree_read), none of which follows a link on the build
    host, and in the two functions that read the repository's tmpfiles.allow, not the tree. Only
    Conf.content (through conf_chase) and the key scan may read a file's bytes. Any other function that
    calls a file-reading or stat API fails here, however it names it."""
    # REQ: HW-1, DEV-2
    ALLOWED = frozenset(("tree_lstat", "tree_listdir", "tree_readlink", "tree_read",
                         "tmpfiles_allow_path", "tmpfiles_allowed"))
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
    advertisement; the radio (access point, home Wi-Fi station) and every virtual link are not
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
        # The access point loader owns wlan0 (10-agentos-wlan.link); the home Wi-Fi station is #936's.
        files = sorted(self.NET.glob("*.network"))
        self.assertEqual([f.name for f in files], [self.UPLINK.name])
        for f in files:
            m = ini(f)["Match"]
            self.assertNotIn("wlan", m.get("Type", "").split())
            self.assertFalse(any(n.startswith(("wl", "ap")) for n in m.get("Name", "").split()), f.name)
        self.assertEqual(ini(self.NET / "10-agentos-wlan.link")["Match"]["Type"], "wlan")

    def test_distro_network_files_are_removed_from_the_image(self):
        # REQ: DEV-2, CH-9 (#1478): Debian's 80-*.network files (one masquerades) never reach the
        # image; the tree check refuses any that would (TreeCheckTest).
        removed = ini(MK / "mkosi.conf")["Content"]["RemoveFiles"].split()
        self.assertIn("/usr/lib/systemd/network/80-*.network", removed)

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
        self.assertEqual(lines[0], "agentos-uplink: enp1s0 192.0.2.10/24")
        self.assertTrue(lines[1].startswith("agentos-boot: bless=good"), lines)

    def test_boot_report_waits_briefly_without_a_cable(self):
        # The radio and virtual links never count; an unplugged port gets about 5 s for carrier, no more.
        out, calls = self.report([("wlan0", "wlan", 1), ("veth0", "virtual", 1), ("enp1s0", "ether", 0)])
        self.assertEqual(out.splitlines()[0], "agentos-uplink: none")
        self.assertIn("sleep", calls)
        self.assertLessEqual(calls.count("sleep"), 5)
        self.assertNotIn("ip ", calls)

    def test_boot_report_waits_for_carrier_on_a_cold_nic(self):
        # Review P-2: on a cold boot the NIC can still be negotiating when the report runs. Carrier
        # unreadable, then 0, then 1: the lease is still reported.
        flip = ('n=$(grep -c sleep "$NET/../log"); [ "$n" = 2 ] && echo 0 >"$NET/enp1s0/carrier"; '
                '[ "$n" = 3 ] && echo 1 >"$NET/enp1s0/carrier"; :')
        out, calls = self.report([("enp1s0", "ether", None)], on_sleep=flip)
        self.assertEqual(out.splitlines()[0], "agentos-uplink: enp1s0 192.0.2.10/24")
        self.assertEqual(calls.count("sleep"), 3)

    def test_boot_report_gives_up_on_a_lease_that_never_comes(self):
        out, calls = self.report([("enp1s0", "ether", 1)], addr="")
        self.assertEqual(out.splitlines()[0], "agentos-uplink: none")
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
        self.assertTrue("for port in 22 80 443 18789; do\n\thas \"$W/console.log.probe\" \"agentos-probe: $port dropped\"" in s)

    def test_boot_test_plugs_in_a_cable_once(self):
        s = (IMG / "ci_boot.sh").read_text()
        self.assertIn('NIC="user,model=virtio-net-pci,', s)
        self.assertIn('-nic "${NIC:-none}"', s)
        self.assertIn('has "$W/console.log" "agentos-uplink: "', s)
        self.assertIn('hasnt "$W/console.log" "agentos-uplink: none"', s)
        self.assertIn('has "$W/console-reboot.log" "agentos-uplink: none"', s)

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
        self.assertIn('\thasnt "$W/console-e2e.log" "G1 PROVEN"\n', e2e)
        self.assertIn('\thasnt "$W/console-e2e.log" "G1 NOT PROVEN"\n', e2e)
        # REQ: HW-10. The console is checked before its DONE line is trusted; a miss fails the run,
        # and the DONE file exists (empty) so the verdict still prints.
        self.assertIn('\te2e_console "$W/console-e2e.log" "$W/e2e-done.log" || fail=1\n', e2e)
        self.assertIn('\t: >"$W/e2e-done.log"\n\te2e_console', e2e)

    def e2e_console(self, console):
        s = (IMG / "ci_boot.sh").read_text()
        fn = re.search(r"^e2e_console\(\) \{\n.*?^\}\n", s, re.S | re.M).group(0)
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
                      for f in ("e2e_console", "g1_verdict"))
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
        fn = re.search(r"^guest_echo\(\) \{\n.*?^\}\n", s, re.S | re.M).group(0)
        raw = ("ci_boot: G1 PROVEN\n::notice::agentos-e2e x\n\x1b[1;32magentos-boot: ok\x1b[0m\r\n"
               "ci_boot: G1 PR\u041eVEN agentos-\n").encode()
        out = subprocess.run(["sh", "-c", fn + "guest_echo"], input=raw, capture_output=True, check=True).stdout
        self.assertEqual(out, b"console| ci_boot: G1 PROVEN\nconsole| ::notice::agentos-e2e x\n"
                              b"console| agentos-boot: ok\nconsole| ci_boot: G1 PR??VEN agentos-\n")

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
                     "agentos-egress-setup.path", "agentos-ap.service", "agentos-modem.service",
                     "agentos-netjoin.service"):
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
                          (AP_UNIT, "agentos-ap"), (MODEM_UNIT, "agentos-modem"),
                          (NETJOIN_UNIT, "agentos-netjoin")):
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

    def test_the_modem_and_netjoin_sockets_are_where_agentosd_looks(self):
        # #1388: the bridge dials agentosd's owner socket, and agentosd dials the helper's.
        self.assertEqual(arg(exec_args(MODEM_UNIT), "owner-sock"), flag_default("agentosd", "sockets") + "/owner.sock")
        self.assertEqual(flag_default("agentos-modem", "owner-sock"), arg(exec_args(MODEM_UNIT), "owner-sock"))
        nj = ini(NETJOIN_UNIT)["Service"]
        run = "/run/" + nj["RuntimeDirectory"]
        self.assertEqual(arg(exec_args(NETJOIN_UNIT), "dir"), run)
        self.assertEqual(arg(exec_args(NETJOIN_UNIT), "agentosd-uid"), "0")  # agentosd runs as root
        self.assertNotIn("User", ini(UNITS / "agentosd.service")["Service"])
        sock = re.search(r'^const Socket = "([\w.-]+)"$', (ROOT / "broker/netjoin/netjoin.go").read_text(), re.M)
        self.assertEqual(arg(exec_args(UNITS / "agentosd.service"), "netjoin-sock"), "%s/%s" % (run, sock.group(1)))

    def test_the_access_point_serves_the_page_s_network(self):
        # #825: the loader brings the access point up on the interface and address the page binds,
        # and reads the latch the page writes.
        ap, page = exec_args(AP_UNIT), exec_args(PAGE_UNIT)
        self.assertEqual(ap[0], "/usr/lib/agentos/agentos-ap")
        for name in ("iface", "addr", "card-latch"):
            with self.subTest(name):
                self.assertEqual(arg(ap, name), arg(page, name))
                self.assertEqual(flag_default("agentos-ap", name), arg(page, name))
        u = ini(AP_UNIT)
        # Root (nft, the exempt unit, the radio's address), with no dumps of the setup password.
        self.assertNotIn("User", u["Service"])
        self.assertEqual(u["Service"]["LimitCORE"], "0")
        # Never without the inbound drop, and up before the page that listens on it.
        self.assertIn("agentos-inbound.service", u["Unit"]["Requires"].split())
        self.assertIn("agentos-inbound.service", u["Unit"]["After"].split())
        self.assertIn("agentos-localui.service", u["Unit"]["Before"].split())
        self.assertEqual("/run/" + u["Service"]["RuntimeDirectory"], flag_default("agentos-ap", "dir"))

    def test_the_access_point_s_programs_ship_and_stay_off_on_their_own(self):
        # Debian's hostapd and dnsmasq do the access point's work (localui.Hostapd); the loader
        # starts them, so neither's own service runs. dnsmasq-base ships no service at all.
        pkgs = ini(MK / "mkosi.conf")["Content"]["Packages"].split()
        for p in ("hostapd", "dnsmasq-base", "iproute2", "wireless-regdb"):
            with self.subTest(p):
                self.assertIn(p, pkgs)
        self.assertNotIn("dnsmasq", pkgs)
        preset = (UNITS.parent / "system-preset/50-agentos.preset").read_text().split("\n")
        self.assertIn("disable hostapd.service", preset)
        # The radio keeps its kernel name (wlan0), which the loader and the page are given.
        link = ini(MK / "mkosi.extra/usr/lib/systemd/network/10-agentos-wlan.link")
        self.assertEqual(link["Match"]["Type"], "wlan")
        self.assertEqual(link["Link"]["NamePolicy"], "keep kernel")

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
        self.assertEqual(users, ["agentos-egress", "agentos-hostapd", "agentos-localui", "agentos-modem", "agentos-netjoin"])
        for unit, user in ((PAGE_UNIT, "agentos-localui"), (MODEM_UNIT, "agentos-modem"),
                           (NETJOIN_UNIT, "agentos-netjoin")):
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
        self.assertIn("-netjoin-sock", words)
        self.assertIn("agentos-egress.service", u["Unit"]["Wants"].split())
        self.assertIn("agentos-egress.service", u["Unit"]["After"].split())
        page = ini(PAGE_UNIT)["Unit"]
        self.assertIn("agentos-egress.service", page["Wants"].split())
        self.assertIn("agentos-egress.service", page["After"].split())

    def test_the_tpm_is_the_vault_process_s(self):
        rules = (MK / "mkosi.extra/usr/lib/udev/rules.d/60-agentos-tpm.rules").read_text()
        self.assertIn('SUBSYSTEM=="tpmrm", KERNEL=="tpmrm[0-9]*", GROUP="agentos-egress", MODE="0660"', rules)

    def test_the_build_ships_the_page(self):
        # The page, the access point loader (#825), and the modem bridge and netjoin helper (#1388).
        build = (IMG / "build.sh").read_text()
        for cmd in ("agentos-localui", "agentos-ap", "agentos-modem", "agentos-netjoin"):
            with self.subTest(cmd):
                self.assertRegex(build, r"for cmd in [^;]*\b%s\b" % cmd)
                self.assertRegex(build, r'install -D -m 0644 "\$REPO/broker/cmd/{0}/{0}.service" '
                                        r'"\$STAGE/usr/lib/systemd/system/{0}.service"'.format(cmd))
        # The helper's only privilege (netjoin L8.2), and the rule that gives the bridge its modems.
        self.assertIn('install -D -m 0644 "$REPO/broker/cmd/agentos-netjoin/50-agentos-netjoin.rules" '
                      '"$STAGE/usr/share/polkit-1/rules.d/50-agentos-netjoin.rules"', build)
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


def fuzz_targets(broker):
    """(pkg, name) for every Go fuzz target in broker's *_test.go files, skipping raw strings
    (a generated source in a test, like loop7's planted target, is not a target) and testdata."""
    out = set()
    for f in pathlib.Path(broker).rglob("*_test.go"):
        if "testdata" in f.parts:
            continue
        text = re.sub(r"`[^`]*`", "", f.read_text())
        for name in re.findall(r"^func (Fuzz\w*)\(\w+ \*testing\.F\)", text, re.M):
            out.add((f.parent.relative_to(broker).as_posix(), name))
    return out


class FuzzManifestTest(unittest.TestCase):
    # REQ: LOOP-7, LOOP-9
    # P3-4b-3a requirement 4: the image ships a binary for every fuzz target in the tree, listed in
    # the manifest agentosd reads; a new target without a binary fails here.

    def manifest(self):
        return json.loads((IMG / "fuzz-targets.json").read_text())["targets"]

    def test_manifest_lists_every_fuzz_target(self):
        listed = {(t["pkg"], t["name"]) for t in self.manifest()}
        found = fuzz_targets(ROOT / "broker")
        self.assertTrue(found)
        self.assertEqual(sorted(found - listed), [], "fuzz targets with no binary in the image")
        self.assertEqual(sorted(listed - found), [], "manifest entries with no fuzz target")
        for t in self.manifest():
            self.assertEqual(sorted(t), ["binary", "name", "pkg"])
            self.assertEqual(t["binary"], t["pkg"].replace("/", "_") + ".test")
            self.assertRegex(t["pkg"], r"^[a-z0-9]+(/[a-z0-9]+)*$")

    def test_scan_finds_a_new_target_and_skips_generated_source(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            write(d, "a/x_test.go", "package a\nfunc FuzzNew(f *testing.F) {}\n")
            write(d, "b/y_test.go", "package b\nvar src = `\nfunc FuzzPlanted(f *testing.F) {\n` + c + `}`\n")
            write(d, "c/testdata/z_test.go", "package c\nfunc FuzzData(f *testing.F) {}\n")
            self.assertEqual(fuzz_targets(d), {("a", "FuzzNew")})

    def test_build_ships_binaries_seeds_and_manifest(self):
        b = (IMG / "build.sh").read_text()
        self.assertIn('install -D -m 0644 "$REPO/image/fuzz-targets.json" "$FUZZ/manifest.json"', b)
        self.assertIn("FUZZ=$STAGE/usr/lib/agentos/fuzz", b)
        self.assertRegex(b, r"go test -c -trimpath [^\n]*-fuzz=\.")
        self.assertIn("-test.list '^Fuzz'", b)  # a binary's targets must match the manifest
        self.assertIn('"$FUZZ/corpus/$pkg/$name"', b)


class FuzzConfineTest(unittest.TestCase):
    # REQ: LOOP-1, LOOP-7
    # P3-4b-3r-confine requirement 2: fuzz children run as an unprivileged system user the image
    # creates; it owns LOOP-7's state and reaches it through the broker's 0700 state directory by an
    # ACL entry granting search only. The user is the one agentosd looks up.
    # P3-4b-3r-confine-r2 moved the state out of the broker's directory and took the ACL away.

    def test_the_image_creates_the_fuzz_user(self):
        lines = (MK / "mkosi.extra/usr/lib/sysusers.d/agentos-fuzz.conf").read_text().splitlines()
        users = [l.split() for l in lines if l.strip() and not l.startswith("#")]
        self.assertEqual([u[:3] for u in users], [["u", "agentos-fuzz", "-"]])
        learn = (ROOT / "broker/cmd/agentosd/learn.go").read_text()
        self.assertRegex(learn, r'fuzzUser\s*=\s*"agentos-fuzz"')

    def tmpfiles(self):
        return [l.split() for l in (MK / "mkosi.extra/usr/lib/tmpfiles.d/agentos.conf").read_text().splitlines()
                if l.strip() and not l.startswith("#")]

    # REQ: LOOP-7, RES-4
    # P3-4b-3r-confine-r2 requirement 1: the fuzz user's tree is its own, beside the broker's 0700 state
    # directory rather than in it, and the user is granted nothing there: a search entry would open every
    # file below it whose own mode lets others read it (#588 L3 3, Security R3).
    def test_the_fuzz_user_is_granted_nothing_in_the_broker_s_state(self):
        lines = self.tmpfiles()
        self.assertIn(["d", "/var/lib/agentos", "0700", "root", "root", "-"], lines)
        self.assertFalse([l for l in lines if l[1].startswith("/var/lib/agentos/")])
        for l in lines:
            if l[1] == "/var/lib/agentos" or l[1].startswith("/var/lib/agentos/"):
                for e in (l[6].split(",") if l[0].startswith("a") and len(l) > 6 else []):
                    if e.startswith(("u:agentos-fuzz:", "user:agentos-fuzz:", "g:agentos-fuzz:", "group:agentos-fuzz:")):
                        self.assertEqual(e.rsplit(":", 1)[1], "---", "the fuzz user is granted %s on %s" % (e, l[1]))
        # agentosd creates the fuzz state (loop7.Load) and gives it to the user (Jail.Own): a tmpfiles line
        # would also run at image build and ship it.
        self.assertFalse([l for l in lines if l[1] == "/var/lib/agentos-fuzz" or l[1].startswith("/var/lib/agentos-fuzz/")])
        learn = (ROOT / "broker/cmd/agentosd/learn.go").read_text()
        self.assertRegex(learn, r'fuzzState\s*=\s*"/var/lib/agentos-fuzz"')
        # Nothing else on the box is given to the fuzz user.
        shared = ("/var/lib/agentos", "/tmp", "/var/tmp", "/dev/shm")
        others = [l for l in lines if "agentos-fuzz" in " ".join(l) and l[1] not in shared]
        self.assertEqual(others, [])

    def test_the_image_does_not_ship_the_fuzz_state(self):
        with tempfile.TemporaryDirectory() as d:
            nodump(pathlib.Path(d))
            radio(pathlib.Path(d))
            uplink(pathlib.Path(d))
            self.assertEqual(check.violations(d), [])
            os.makedirs(os.path.join(d, "var/lib/agentos-fuzz"))
            self.assertEqual(check.violations(d), ["var/lib/agentos-fuzz: fuzz state; created on the box, never shipped"])

    # REQ: LOOP-1, RES-4
    # P3-4b-3r-confine-r4 requirement 3: the fuzz user cannot write the shared world-writable directories,
    # which its quota does not cover; the entry names that user only, so no other user loses them.
    def test_the_fuzz_user_cannot_write_the_shared_temp_dirs(self):
        lines = self.tmpfiles()
        for d in ("/tmp", "/var/tmp", "/dev/shm"):
            self.assertEqual([l for l in lines if l[1] == d], [["a+", d, "-", "-", "-", "-", "u:agentos-fuzz:---"]])


if __name__ == "__main__":
    unittest.main()
