# The image's inbound rules on a stand-in home network (DEV-net-e 2a, A14 acceptance 1). Two network
# namespaces play the box and the home network, joined by two links: eth0, the box's uplink, and
# usb0, an interface nothing names (a USB tether, a second NIC). The box loads the file the image
# loads at boot, then: no home host opens a connection to a box port on either link, over IPv4 or
# IPv6; the box's own connections and loopback still work; and a router advertisement on eth0 still
# gives the box a global IPv6 address, through which it reaches the router (neighbour discovery with
# the router's global source passes). Needs root, ip and nft; skipped otherwise. CI runs it under
# sudo in the checks job. Addresses are documentation ranges (RFC 5737, RFC 3849).
# REQ: DEV-2, DEV-net-e
#
# AccessPointThroughTheDrop adds the access point (DEV-net-f): a third namespace plays the owner's
# phone on ap0, the box's access-point link, which agentos-ap-exempt puts in the inbound exempt set.
# REQ: CH-7, DEV-net-f
# It runs the access point's whole lifecycle (DEV-net-g, A14): the box loads agentos_ap (CH-9) for
# ap0 as localui.BringUp does, from the script it hands nft (broker/localui/testdata), before the
# exempt step; stopping the access point takes ap0 out of the set and then unloads agentos_ap, as
# the unit's ExecStop and localui.BringDown do. The access point's link uses the private range
# agentos_ap requires (10.42.0.0/24); the home links stay on documentation ranges.
# REQ: DEV-2, DEV-net-g
#
# UplinkByNetworkd reruns the drop against the image's wired uplink (P2-1, #1416): real
# systemd-networkd runs on both sides, the home side as the router (DHCP server and router
# advertisements), the box side on the [Network] section the image ships in
# 20-agentos-uplink.network (its [Match] names eth0 here, since the shipped one leaves out veth
# links on purpose). The box takes its lease and its IPv6 address with the drop loaded first, as
# the image orders networkd after agentos-inbound; no home host opens a box port at either address
# or at the box's IPv6 link-local address, and each address opens once the drop is gone (the
# control). The box still reaches the router. Also needs unshare and systemd-networkd.
# REQ: DEV-2, DEV-net-e, ONB-3
#
# NoRoutingThroughTheDrop is I21, the box routes nothing (#2824): with forwarding turned on in the
# box (as a NetworkManager shared profile does, with NetworkManager's own accept-and-masquerade
# table loaded beside it), a home host on eth0 reaches nothing on usb0's side, over IPv4 or IPv6,
# routed or bridged; and the access point's passthrough, which agentos_ap governs, still forwards.
# REQ: DEV-2, CH-9
import configparser
import errno
import fcntl
import ipaddress
import os
import pathlib
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = ROOT / "image/mkosi/mkosi.extra/usr/lib/agentos/inbound.nft"
BOX, HOME = "agentos-t-box", "agentos-t-home"
PORT = 18789
# Some sandboxes run a kernel without IPv6; the IPv6 half then skips. CI's runners have it, and CI
# sets AGENTOS_REQUIRE_IPV6=1 so that a runner without it fails instead of skipping (#1479).
IPV6 = os.path.isdir("/proc/sys/net/ipv6")
PREFIX = "2001:db8:1::"
ROUTER6 = PREFIX + "2"

# Accept on PORT, or argv[2] (dual-stack where the kernel has IPv6) and answer each connection with one byte.
LISTEN = """
import socket, sys
if sys.argv[1] == "6":
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::" if sys.argv[1] == "6" else "0.0.0.0", int(sys.argv[2]) if len(sys.argv) > 2 else %d)); s.listen(16)
while True:
    c, _ = s.accept(); c.sendall(b"x"); c.close()
""" % PORT

# Connect to argv[1] on PORT, or argv[2]; exit 0 if a byte comes back within the timeout.
CONNECT = """
import socket, sys
try:
    c = socket.create_connection((sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else %d), timeout=1.5)
    sys.exit(0 if c.recv(1) == b"x" else 1)
except OSError:
    sys.exit(1)
""" % PORT

# Send one router advertisement on argv[1] for PREFIX/64: hop limit 255, from the link-local
# address, with the on-link and autonomous flags so the box configures an address itself.
ADVERTISE = """
import socket, struct, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, sys.argv[1].encode())
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, socket.if_nametoindex(sys.argv[1]))
ra = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, 1800, 0, 0)
pio = struct.pack("!BBBBIII", 3, 4, 64, 0xC0, 86400, 14400, 0) + socket.inet_pton(socket.AF_INET6, "%s")
s.sendto(ra + pio, ("ff02::1", 0, 0, socket.if_nametoindex(sys.argv[1])))
""" % PREFIX


def sh(*args, ns=None, check=True):
    cmd = (["ip", "netns", "exec", ns] if ns else []) + list(args)
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def reaches(ns, addr, port=PORT):
    return sh("python3", "-c", CONNECT, addr, str(port), ns=ns, check=False).returncode == 0


class IPv6Present(unittest.TestCase):
    # REQ: DEV-2
    def test_ipv6_is_here_when_required(self):
        # The IPv6 inbound and privacy assertions only run with IPv6; where it is required, its
        # absence is a failure, never a quiet skip.
        if os.environ.get("AGENTOS_REQUIRE_IPV6") == "1":
            self.assertTrue(IPV6, "AGENTOS_REQUIRE_IPV6=1 but the kernel has no IPv6")
        elif not IPV6:
            self.skipTest("kernel without IPv6")


@unittest.skipUnless(os.geteuid() == 0 and shutil.which("ip") and shutil.which("nft"),
                     "needs root, ip and nft")
class InboundOnAHomeNetwork(unittest.TestCase):
    def setUp(self):
        self.procs = []
        self.addCleanup(self.cleanup)
        for ns in (BOX, HOME):
            sh("ip", "netns", "add", ns)
            sh("ip", "link", "set", "lo", "up", ns=ns)
        for box, home, v4 in (("eth0", "h0", "192.0.2"), ("usb0", "h1", "198.51.100")):
            sh("ip", "link", "add", box, "netns", BOX, "type", "veth", "peer", "name", home, "netns", HOME)
            for ns, dev, host in ((BOX, box, 1), (HOME, home, 2)):
                if IPV6:
                    sh("sysctl", "-qw", "net.ipv6.conf.%s.accept_dad=0" % dev, ns=ns)
                sh("ip", "addr", "add", "%s.%d/24" % (v4, host), "dev", dev, ns=ns)
                sh("ip", "link", "set", dev, "up", ns=ns)
        if IPV6:
            # A runner whose new namespaces inherit forwarding=1 would ignore router
            # advertisements at accept_ra=1; 2 takes them either way, as a host does.
            sh("sysctl", "-qw", "net.ipv6.conf.eth0.forwarding=0", ns=BOX)
            sh("sysctl", "-qw", "net.ipv6.conf.eth0.accept_ra=2", ns=BOX)
            sh("sysctl", "-qw", "net.ipv6.conf.eth0.autoconf=1", ns=BOX)
            sh("ip", "-6", "addr", "add", ROUTER6 + "/64", "dev", "h0", "nodad", ns=HOME)
        self.listen(BOX)
        self.listen(HOME)
        if IPV6:
            self.wait_linklocal()

    def listen(self, ns):
        p = subprocess.Popen(["ip", "netns", "exec", ns, "python3", "-c", LISTEN, "6" if IPV6 else "4"])
        self.procs.append(p)
        for _ in range(50):
            if sh("ss", "-Htln", "sport = :%d" % PORT, ns=ns, check=False).stdout.strip():
                return
            time.sleep(0.1)
        self.fail("listener in %s did not start" % ns)

    def wait_linklocal(self):
        for _ in range(50):
            out = sh("ip", "-6", "-o", "addr", "show", "scope", "link", "tentative", ns=HOME).stdout
            if "h0" in sh("ip", "-6", "-o", "addr", "show", "scope", "link", ns=HOME).stdout and not out:
                return
            time.sleep(0.1)

    def cleanup(self):
        for p in self.procs:
            p.kill()
            p.wait()
        for ns in (BOX, HOME):
            sh("ip", "netns", "del", ns, check=False)

    def global6(self):
        out = sh("ip", "-6", "-o", "addr", "show", "dev", "eth0", "scope", "global", ns=BOX).stdout
        for f in out.split():
            if "/" in f and ipaddress.ip_interface(f).network == ipaddress.ip_network(PREFIX + "/64"):
                return f.split("/")[0]
        return None

    def load(self):
        r = sh("nft", "-f", str(RULES), ns=BOX, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_home_hosts_reach_no_box_port_on_any_link(self):
        # Without the rules the stand-in network works, so a failed connection below is the drop.
        self.assertTrue(reaches(HOME, "192.0.2.1"), "control: box not reachable before the rules load")
        self.assertTrue(reaches(HOME, "198.51.100.1"), "control: usb0 not reachable before the rules load")
        self.load()
        for addr in ("192.0.2.1", "198.51.100.1"):
            with self.subTest(home_to=addr):
                self.assertFalse(reaches(HOME, addr), "a home host reached box port %d at %s" % (PORT, addr))
        # The box's own connections and loopback still work.
        self.assertTrue(reaches(BOX, "127.0.0.1"))
        self.assertTrue(reaches(BOX, "192.0.2.2"))
        self.assertTrue(reaches(BOX, "198.51.100.2"))

    @unittest.skipUnless(IPV6, "kernel without IPv6")
    def test_the_box_keeps_ipv6_and_drops_it_inbound(self):
        self.load()
        # Advertise once a second, as a router does after a link comes up, so an advertisement
        # sent before the box's link was ready does not decide the test.
        for i in range(100):
            if i % 10 == 0:
                sh("python3", "-c", ADVERTISE, "h0", ns=HOME)
            if self.global6():
                break
            time.sleep(0.1)
        addr6 = self.global6()
        self.assertIsNotNone(addr6, "the box got no global IPv6 address from the router advertisement:\n"
                             + sh("ip", "-6", "addr", "show", "dev", "eth0", ns=BOX).stdout
                             + sh("sysctl", "net.ipv6.conf.eth0", ns=BOX, check=False).stdout
                             + sh("nft", "list", "ruleset", ns=BOX).stdout)
        self.assertFalse(reaches(HOME, addr6), "a home host reached box port %d at %s" % (PORT, addr6))
        # Reaching the router's global address needs its neighbour advertisement, which it sends
        # from that global address.
        self.assertTrue(reaches(BOX, ROUTER6), "box cannot reach the router over IPv6")

LAN, FAR = "agentos-t-lan", "agentos-t-far"
LAN_NET6, FAR_NET6 = "2001:db8:a::", "2001:db8:b::"

# What NetworkManager loads for ipv4.method=shared on usb0 (nm-shared-<iface>): accept forwarding
# to and from the link and masquerade it. A drop in agentos_inbound must outlast it.
NM_SHARED = """table ip nm-shared-usb0 {
  chain filter_forward {
    type filter hook forward priority filter; policy accept;
    iifname "usb0" accept
    oifname "usb0" accept
  }
  chain nat_postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 198.51.100.0/24 ip daddr != 198.51.100.0/24 masquerade
  }
}
"""


@unittest.skipUnless(os.geteuid() == 0 and shutil.which("ip") and shutil.which("nft"),
                     "needs root, ip and nft")
class NoRoutingThroughTheDrop(unittest.TestCase):
    """The box between two networks, eth0 to LAN and usb0 to FAR, with forwarding on."""

    def setUp(self):
        self.procs = []
        self.addCleanup(self.cleanup)
        for ns in (BOX, LAN, FAR):
            sh("ip", "netns", "add", ns)
            sh("ip", "link", "set", "lo", "up", ns=ns)
        for box, ns, peer, v4, v6 in (("eth0", LAN, "l0", "192.0.2", LAN_NET6), ("usb0", FAR, "f0", "198.51.100", FAR_NET6)):
            sh("ip", "link", "add", box, "netns", BOX, "type", "veth", "peer", "name", peer, "netns", ns)
            for n, dev, host in ((BOX, box, 1), (ns, peer, 2)):
                sh("ip", "addr", "add", "%s.%d/24" % (v4, host), "dev", dev, ns=n)
                if IPV6:
                    sh("ip", "-6", "addr", "add", "%s%d/64" % (v6, host), "dev", dev, "nodad", ns=n)
                sh("ip", "link", "set", dev, "up", ns=n)
            sh("ip", "route", "add", "default", "via", v4 + ".1", ns=ns)
            if IPV6:
                sh("ip", "-6", "route", "add", "default", "via", v6 + "1", ns=ns)
        sh("sysctl", "-qw", "net.ipv4.ip_forward=1", ns=BOX)
        if IPV6:
            sh("sysctl", "-qw", "net.ipv6.conf.all.forwarding=1", ns=BOX)
        p = subprocess.Popen(["ip", "netns", "exec", FAR, "python3", "-c", LISTEN, "6" if IPV6 else "4"])
        self.procs.append(p)
        for _ in range(50):
            if sh("ss", "-Htln", "sport = :%d" % PORT, ns=FAR, check=False).stdout.strip():
                break
            time.sleep(0.1)
        else:
            self.fail("listener in %s did not start" % FAR)

    def cleanup(self):
        for p in self.procs:
            p.kill()
            p.wait()
        for ns in (BOX, LAN, FAR):
            sh("ip", "netns", "del", ns, check=False)

    def nft(self, text):
        r = subprocess.run(["ip", "netns", "exec", BOX, "nft", "-f", "-"], input=text, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def far(self):
        return ["198.51.100.2"] + ([FAR_NET6 + "2"] if IPV6 else [])

    def test_forwarding_turned_on_routes_nothing(self):
        for addr in self.far():
            self.assertTrue(reaches(LAN, addr), "control: the box does not route to %s before the rules" % addr)
        self.nft(NM_SHARED)
        self.nft(RULES.read_text())
        for addr in self.far():
            with self.subTest(lan_to=addr):
                self.assertFalse(reaches(LAN, addr), "the box routed a home host to %s" % addr)
        # The box's own connections on either link still work.
        self.assertTrue(reaches(BOX, "198.51.100.2"))

    def test_a_bridge_forwards_nothing(self):
        # A bridge profile enslaving both links: frames between them never reach the inet hooks.
        for dev in ("eth0", "usb0"):
            sh("ip", "addr", "flush", "dev", dev, ns=BOX)
        sh("ip", "addr", "flush", "dev", "f0", ns=FAR)
        sh("ip", "addr", "add", "192.0.2.3/24", "dev", "f0", ns=FAR)
        sh("ip", "link", "add", "br0", "type", "bridge", ns=BOX)
        for dev in ("eth0", "usb0"):
            sh("ip", "link", "set", dev, "master", "br0", ns=BOX)
        sh("ip", "link", "set", "br0", "up", ns=BOX)
        for _ in range(50):
            if reaches(LAN, "192.0.2.3"):
                break
            time.sleep(0.1)
        else:
            self.fail("control: the bridge does not forward before the rules")
        self.nft(RULES.read_text())
        self.assertFalse(reaches(LAN, "192.0.2.3"), "the box bridged a home host to another link")


AP_EXEMPT = ROOT / "image/mkosi/mkosi.extra/usr/lib/agentos/ap-exempt"
PHONE = "agentos-t-phone"
LOCALUI = ROOT / "broker/localui/testdata"
AP_LOAD, AP_REMOVE, AP_UNLOAD = (LOCALUI / f for f in (
    "agentos_ap-ap0.nft", "exempt-remove-ap0.nft", "agentos_ap-unload.nft"))
UI = 80
AP_BOX, AP_V4 = "10.42.0.1", "10.42.0"
# agentos_ap for ap0 with passthrough to the uplink eth0, as localui.NftRules renders it (its
# private-range refusal shortened to the ranges this test uses; 192.0.2.0/24 is not among them).
AP_PASSTHROUGH = """table inet agentos_ap {
  chain input {
    type filter hook input priority filter; policy accept;
    iifname "ap0" ip saddr 10.42.0.0/24 ip daddr 10.42.0.1 tcp dport 80 accept
    iifname "ap0" udp dport { 53, 67 } accept
    iifname "ap0" tcp dport 53 accept
    iifname "ap0" drop
    iifname != "ap0" tcp dport 80 ip daddr 10.42.0.1 drop
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
    iifname "ap0" oifname "eth0" ip saddr 10.42.0.0/24 ip daddr != { 10.0.0.0/8, 198.51.100.0/24 } accept
    iifname "eth0" oifname "ap0" ct state established,related accept
    iifname "ap0" drop
    oifname "ap0" drop
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "eth0" ip saddr 10.42.0.0/24 masquerade
  }
}
"""


@unittest.skipUnless(os.geteuid() == 0 and shutil.which("ip") and shutil.which("nft"),
                     "needs root, ip and nft")
class AccessPointThroughTheDrop(unittest.TestCase):
    """The box's own Wi-Fi joins the exempt set while agentos_ap holds it, and leaves it when the
    access point stops; the uplink, an unnamed link and a second radio stay dropped."""

    def setUp(self):
        self.procs = []
        self.addCleanup(self.cleanup)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        # A stand-in /sys: only ap0 and wl1 are wireless interfaces (the veth links are not).
        self.sysfs = pathlib.Path(tmp.name)
        for w in ("ap0", "wl1"):
            (self.sysfs / "class/net" / w / "phy80211").mkdir(parents=True)
        for ns in (BOX, HOME, PHONE):
            sh("ip", "netns", "add", ns)
            sh("ip", "link", "set", "lo", "up", ns=ns)
        for box, peer_ns, peer, v4 in (("eth0", HOME, "h0", "192.0.2"), ("usb0", HOME, "h1", "198.51.100")):
            self.link(box, peer_ns, peer, v4)
        self.link("ap0", PHONE, "p0", AP_V4)
        self.listen(BOX, PORT)
        self.listen(BOX, UI)

    def link(self, box, peer_ns, peer, v4):
        sh("ip", "link", "add", box, "netns", BOX, "type", "veth", "peer", "name", peer, "netns", peer_ns)
        for ns, dev, host in ((BOX, box, 1), (peer_ns, peer, 2)):
            sh("ip", "addr", "add", "%s.%d/24" % (v4, host), "dev", dev, ns=ns)
            sh("ip", "link", "set", dev, "up", ns=ns)

    def listen(self, ns, port):
        p = subprocess.Popen(["ip", "netns", "exec", ns, "python3", "-c", LISTEN, "4", str(port)])
        self.procs.append(p)
        for _ in range(50):
            if sh("ss", "-Htln", "sport = :%d" % port, ns=ns, check=False).stdout.strip():
                return
            time.sleep(0.1)
        self.fail("listener in %s did not start" % ns)

    def cleanup(self):
        for p in self.procs:
            p.kill()
            p.wait()
        for ns in (BOX, HOME, PHONE):
            sh("ip", "netns", "del", ns, check=False)

    def nft_file(self, f):
        r = sh("nft", "-f", str(f), ns=BOX, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)

    def load(self):
        self.nft_file(RULES)

    def exempt(self, *args):
        env = dict(os.environ, AGENTOS_SYSFS=str(self.sysfs))
        return subprocess.run(["ip", "netns", "exec", BOX, "sh", str(AP_EXEMPT), *args], env=env,
                              capture_output=True, text=True)

    def bring_up(self):
        # localui.BringUp: agentos_ap first, then the exempt unit.
        self.load()
        self.nft_file(AP_LOAD)
        r = self.exempt("ap0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("agentos-ap-exempt: OK ap0", r.stdout)

    def bring_down(self):
        # The unit's ExecStop, then localui.BringDown's own removal and the unload.
        r = self.exempt("--remove", "ap0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("agentos-ap-exempt: OK removed ap0", r.stdout)
        self.nft_file(AP_REMOVE)
        self.nft_file(AP_UNLOAD)

    def exempt_set(self):
        return sh("nft", "list", "set", "inet", "agentos_inbound", "exempt", ns=BOX).stdout

    def tables(self):
        return sh("nft", "list", "tables", ns=BOX).stdout.split()

    def assert_home_shut_out(self):
        # A14: no home-network host opens a connection to a box port, on the uplink or an unnamed link.
        for addr in ("192.0.2.1", "198.51.100.1"):
            for port in (PORT, UI):
                with self.subTest(home_to=addr, port=port):
                    self.assertFalse(reaches(HOME, addr, port), "a home host reached box port %d at %s" % (port, addr))

    def test_the_phone_reaches_the_box_only_on_the_access_point(self):
        self.assertTrue(reaches(PHONE, AP_BOX, UI), "control: phone cannot reach the box before the rules")
        self.load()
        self.nft_file(AP_LOAD)
        # Before bring-up adds it, the drop is final: the phone joins but the page never loads.
        self.assertFalse(reaches(PHONE, AP_BOX, UI))
        r = self.exempt("ap0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("agentos-ap-exempt: OK ap0", r.stdout)
        self.assertTrue(reaches(PHONE, AP_BOX, UI), "the phone on the access point cannot reach the page")
        # agentos_ap holds the exempt interface to the page, DHCP and DNS (CH-9).
        self.assertFalse(reaches(PHONE, AP_BOX, PORT), "the phone reached a box port other than the page")
        self.assert_home_shut_out()
        self.assertIn('"ap0"', self.exempt_set())
        for other in ("eth0", "usb0"):
            self.assertNotIn('"%s"' % other, self.exempt_set())
        # The same phone, on the same link, under a name that is not the access point's: dropped.
        sh("ip", "link", "set", "ap0", "down", ns=BOX)
        sh("ip", "link", "set", "ap0", "name", "wl9", ns=BOX)
        sh("ip", "link", "set", "wl9", "up", ns=BOX)
        self.assertFalse(reaches(PHONE, AP_BOX, UI), "a non-exempt interface admitted the phone")

    def test_a_recreated_access_point_is_let_through_again(self):
        self.bring_up()
        self.assertTrue(reaches(PHONE, AP_BOX, UI))
        # The interface goes: the unit, bound to it, stops and takes it out of the set.
        sh("ip", "link", "del", "ap0", ns=BOX)
        r = self.exempt("--remove", "ap0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.link("ap0", PHONE, "p0", AP_V4)
        self.assertFalse(reaches(PHONE, AP_BOX, UI), "a recreated interface was admitted before bring-up")
        # Bring-up runs again for the new interface.
        r = self.exempt("ap0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(reaches(PHONE, AP_BOX, UI), "the recreated access point is not let through")
        self.assertEqual(self.exempt_set().count('"ap0"'), 1)
        self.assert_home_shut_out()

    def test_bring_up_fails_closed(self):
        # No table: bring-up fails and creates nothing (it never loads or opens rules itself).
        r = self.exempt("ap0")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("agentos-ap-exempt: FAIL", r.stdout)
        self.assertEqual(sh("nft", "list", "ruleset", ns=BOX).stdout.strip(), "")
        # DEV-net-g (a): the inbound table without agentos_ap: the access point is refused.
        self.load()
        before = sh("nft", "list", "ruleset", ns=BOX).stdout
        r = self.exempt("ap0")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("agentos_ap is not loaded for ap0", r.stdout)
        self.assertEqual(sh("nft", "list", "ruleset", ns=BOX).stdout, before)
        # With agentos_ap: the uplink and an unnamed link are not wireless, so they are refused,
        # and the tables are left exactly as they were.
        self.nft_file(AP_LOAD)
        before = sh("nft", "list", "ruleset", ns=BOX).stdout
        for iface in ("eth0", "usb0", "lo0", "lo", "ap0;x", ""):
            with self.subTest(iface=iface):
                r = self.exempt(iface)
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertIn("agentos-ap-exempt: FAIL", r.stdout)
        self.assertEqual(sh("nft", "list", "ruleset", ns=BOX).stdout, before)
        self.assert_home_shut_out()
        self.assertFalse(reaches(PHONE, AP_BOX, UI))

    def test_a_stopped_access_point_is_closed(self):
        # DEV-net-g (b), acceptance 1 and 5: after the access point stops, ap0 is not exempt, the
        # inbound drop is still loaded (removal opened nothing), agentos_ap is gone, and the phone
        # reaches no box port. A second stop is not an error.
        self.bring_up()
        self.assertTrue(reaches(PHONE, AP_BOX, UI))
        self.bring_down()
        self.assertNotIn('"ap0"', self.exempt_set())
        self.assertIn('"lo"', self.exempt_set())
        self.assertIn("agentos_inbound", self.tables())
        self.assertNotIn("agentos_ap", self.tables())
        for port in (UI, PORT):
            with self.subTest(port=port):
                self.assertFalse(reaches(PHONE, AP_BOX, port), "the phone reached port %d after the stop" % port)
        self.assert_home_shut_out()
        self.bring_down()
        self.assertFalse(reaches(PHONE, AP_BOX, UI))

    def test_only_the_loaders_interface_is_admitted(self):
        # DEV-net-g (c), acceptance 4: a second wireless interface the loader did not create as the
        # access point (wl1, here joined to the home network) is refused while agentos_ap is
        # loaded for ap0, and the home host behind it reaches no box port.
        self.link("wl1", HOME, "h2", "203.0.113")
        self.bring_up()
        before = sh("nft", "list", "ruleset", ns=BOX).stdout
        r = self.exempt("wl1")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("agentos_ap is not loaded for wl1", r.stdout)
        self.assertEqual(sh("nft", "list", "ruleset", ns=BOX).stdout, before)
        for port in (PORT, UI):
            with self.subTest(port=port):
                self.assertFalse(reaches(HOME, "203.0.113.1", port), "a host behind wl1 reached port %d" % port)
        self.assertTrue(reaches(PHONE, AP_BOX, UI), "the access point itself stopped working")

    def test_passthrough_still_forwards_through_the_access_point(self):
        # agentos_ap governs ap0's forwarding (passthrough); agentos_inbound's forward drop leaves
        # an exempt interface to it, and drops the same path once ap0 leaves the set.
        sh("ip", "route", "add", "default", "via", AP_BOX, ns=PHONE)
        sh("ip", "route", "add", AP_V4 + ".0/24", "via", "192.0.2.1", ns=HOME)  # the control has no NAT
        sh("sysctl", "-qw", "net.ipv4.ip_forward=1", ns=BOX)
        self.listen(HOME, PORT)
        self.assertTrue(reaches(PHONE, "192.0.2.2"), "control: the box does not forward before the rules")
        self.load()
        r = subprocess.run(["ip", "netns", "exec", BOX, "nft", "-f", "-"], input=AP_PASSTHROUGH,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(reaches(PHONE, "192.0.2.2"), "the box forwarded from an access point not in the set")
        r = self.exempt("ap0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(reaches(PHONE, "192.0.2.2"), "the forward drop blocked the access point's passthrough")
        self.assertFalse(reaches(HOME, "198.51.100.1"), "a home host reached a box port")

    def test_single_radio_home_wifi_after_the_access_point(self):
        # DEV-net-g acceptance 3, the single-radio failure path: the access point comes up, stops,
        # and the same radio (ap0) joins the home Wi-Fi (a documentation-range network). No home
        # host opens a connection to any box port.
        self.bring_up()
        self.assertTrue(reaches(PHONE, AP_BOX, UI))
        self.bring_down()
        sh("ip", "link", "del", "ap0", ns=BOX)
        self.link("ap0", HOME, "h2", "203.0.113")
        for port in (PORT, UI):
            with self.subTest(port=port):
                self.assertFalse(reaches(HOME, "203.0.113.1", port),
                                 "a home host reached box port %d on the radio after the access point" % port)
        self.assert_home_shut_out()
        # Potency: had ap0 stayed exempt with agentos_ap gone (the defect), the home host would
        # have reached the box.
        sh("nft", "add", "element", "inet", "agentos_inbound", "exempt", '{ "ap0" }', ns=BOX)
        self.assertTrue(reaches(HOME, "203.0.113.1", PORT), "control: the test cannot see the defect")


UPLINK = ROOT / "image/mkosi/mkosi.extra/usr/lib/systemd/network/20-agentos-uplink.network"
NETWORKD = "/usr/lib/systemd/systemd-networkd"
ROUTER4 = "192.0.2.1"

# The home router: a static address, a DHCP pool (192.0.2.100-109) and, with IPv6, advertisements
# of PREFIX.
ROUTER_NETWORK = """[Match]
Name=h0

[Network]
Address=%s/24
DHCPServer=yes
%s
[DHCPServer]
PoolOffset=100
PoolSize=10
""" % (ROUTER4, "Address=%s/64\nIPv6SendRA=yes\n\n[IPv6Prefix]\nPrefix=%s/64\n" % (ROUTER6, PREFIX) if IPV6 else "")


def box_network():
    """The shipped uplink file with its [Match] on eth0 and everything else as shipped."""
    text = UPLINK.read_text()
    shipped = configparser.ConfigParser(strict=False, interpolation=None)
    shipped.optionxform = str
    shipped.read_string(text)
    body = text[text.index("[Network]"):]
    return "[Match]\nName=eth0\n\n" + body, shipped


@unittest.skipUnless(os.geteuid() == 0 and all(shutil.which(t) for t in ("ip", "nft", "unshare"))
                     and os.access(NETWORKD, os.X_OK) and os.path.isdir("/etc/systemd/network"),
                     "needs root, ip, nft, unshare and systemd-networkd")
class UplinkByNetworkd(unittest.TestCase):
    def setUp(self):
        self.procs = []
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(self.cleanup)
        for ns in (BOX, HOME):
            sh("ip", "netns", "add", ns)
        sh("ip", "link", "add", "eth0", "netns", BOX, "type", "veth", "peer", "name", "h0", "netns", HOME)
        if IPV6:
            for ns, dev in ((BOX, "eth0"), (HOME, "h0")):
                sh("sysctl", "-qw", "net.ipv6.conf.%s.accept_dad=0" % dev, ns=ns)
            sh("sysctl", "-qw", "net.ipv6.conf.eth0.forwarding=0", ns=BOX)
        self.listen(BOX)
        self.listen(HOME)

    def listen(self, ns):
        p = subprocess.Popen(["ip", "netns", "exec", ns, "python3", "-c", LISTEN, "6" if IPV6 else "4"])
        self.procs.append(p)
        for _ in range(50):
            if sh("ss", "-Htln", "sport = :%d" % PORT, ns=ns, check=False).stdout.strip():
                return
            time.sleep(0.1)
        self.fail("listener in %s did not start" % ns)

    def networkd(self, ns, network):
        """systemd-networkd in ns, in its own mount namespace: only this .network file, its own
        /run, with a udev database saying every link is ready."""
        conf = pathlib.Path(self.tmp, ns)
        conf.mkdir()
        (conf / "10-test.network").write_text(network)
        (conf / "10-test.network").chmod(0o644)
        conf.chmod(0o755)
        setup = ("mount -t tmpfs -o mode=0755 tmpfs /run && mkdir -p /run/systemd/netif /run/udev/data "
                 "&& chown systemd-network:systemd-network /run/systemd/netif "
                 # Each link marked initialized, as udev would: there is no udev in a namespace.
                 "&& for l in /sys/class/net/*; do echo I:1 > /run/udev/data/n$(cat $l/ifindex); done "
                 "&& mount --bind \"$1\" /etc/systemd/network && exec %s" % NETWORKD)
        env = {k: v for k, v in os.environ.items() if k != "NOTIFY_SOCKET"}
        env["SYSTEMD_LOG_LEVEL"] = "info"
        log = open(os.path.join(self.tmp, ns + ".log"), "w")
        p = subprocess.Popen(["ip", "netns", "exec", ns, "unshare", "-m", "--propagation", "private",
                              "sh", "-c", setup, "networkd", str(conf)],
                             env=env, stdout=log, stderr=subprocess.STDOUT)
        log.close()
        self.procs.append(p)

    def cleanup(self):
        for p in self.procs:
            p.kill()
            p.wait()
        for ns in (BOX, HOME):
            sh("ip", "netns", "del", ns, check=False)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def logs(self):
        out = ""
        for ns in (HOME, BOX):
            path = os.path.join(self.tmp, ns + ".log")
            if os.path.exists(path):
                text = pathlib.Path(path).read_text()
                out += "--- networkd in %s\n%s\n...\n%s" % (ns, text[:600], text[-3000:])
        return out + sh("ip", "addr", ns=BOX, check=False).stdout + sh("nft", "list", "ruleset", ns=BOX).stdout

    def address(self, family, network):
        out = sh("ip", family, "-o", "addr", "show", "dev", "eth0", "scope", "global", ns=BOX).stdout
        for f in out.split():
            if "/" in f and ipaddress.ip_interface(f).network == ipaddress.ip_network(network):
                return f.split("/")[0]
        return None

    def wait_for(self, family, network):
        for _ in range(300):
            a = self.address(family, network)
            if a:
                return a
            time.sleep(0.1)
        self.fail("the box got no %s address on %s from the home router:\n%s" % (family, network, self.logs()))

    def test_the_shipped_uplink_takes_a_lease_behind_the_drop(self):
        body, shipped = box_network()
        # The file under test is the shipped one: physical Ethernet only, DHCP for both families.
        self.assertEqual(shipped["Match"]["Type"], "ether")
        self.assertEqual(shipped["Network"]["DHCP"], "yes")
        r = sh("nft", "-f", str(RULES), ns=BOX, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.networkd(HOME, ROUTER_NETWORK)
        self.networkd(BOX, body)
        addr4 = self.wait_for("-4", "192.0.2.0/24")
        self.assertNotEqual(addr4, ROUTER4)
        self.assertIn(int(addr4.split(".")[3]), range(100, 110), "not from the router's pool: " + addr4)
        targets = [addr4]
        if IPV6:
            targets.append(self.wait_for("-6", PREFIX + "/64"))
            # The box's link-local address: any host on the same link can aim at it without a lease
            # or a router (review, Security release 1).
            ll = sh("ip", "-6", "-o", "addr", "show", "dev", "eth0", "scope", "link", ns=BOX).stdout.split()
            targets.append(next(f for f in ll if f.startswith("fe80:")).split("/")[0] + "%h0")
            # REQ: DEV-2 (#1479): no global address carries the MAC (EUI-64); the stable one is
            # RFC 7217's and outgoing connections get a temporary one.
            mac = sh("cat", "/sys/class/net/eth0/address", ns=BOX).stdout.strip().split(":")
            eui = bytes([int(mac[0], 16) ^ 2] + [int(x, 16) for x in mac[1:3]] + [0xff, 0xfe]
                        + [int(x, 16) for x in mac[3:]])
            for _ in range(100):
                glob = sh("ip", "-6", "-o", "addr", "show", "dev", "eth0", "scope", "global", ns=BOX).stdout
                if "temporary" in glob:
                    break
                time.sleep(0.1)
            self.assertIn("temporary", glob, "no temporary IPv6 address:\n" + glob)
            for f in glob.split():
                if f.startswith(PREFIX[:4]) and "/" in f:
                    iid = ipaddress.ip_interface(f).ip.packed[8:]
                    self.assertNotEqual(iid, eui, "an address carries the MAC: " + f)
        for addr in targets:
            with self.subTest(home_to=addr):
                self.assertFalse(reaches(HOME, addr), "a home host reached box port %d at %s" % (PORT, addr))
        # The uplink is useful: the box reaches the router on each family.
        self.assertTrue(reaches(BOX, ROUTER4), "box cannot reach the router over IPv4:\n" + self.logs())
        if IPV6:
            self.assertTrue(reaches(BOX, ROUTER6), "box cannot reach the router over IPv6:\n" + self.logs())
        # Potency: with the drop gone, the same home host reaches the box at every address it was
        # shut out of, IPv6 global and link-local included.
        sh("nft", "delete", "table", "inet", "agentos_inbound", ns=BOX)
        for addr in targets:
            with self.subTest(control=addr):
                self.assertTrue(reaches(HOME, addr), "control: the test cannot see the drop at " + addr)


# BootProbeOverIPv6 checks the boot test's IPv6 probe (image/probe_lan6.py, #1457 u1c) against a
# real kernel: a tap device in a namespace stands in for the box's second NIC, and the test relays
# its frames over TCP with QEMU's socket-netdev framing. With the image's drop loaded, the probe
# reaches the box at its link-local and SLAAC addresses (neighbour discovery answers) and every
# port reads dropped; without it, the same probe reads every port answered (a closed port's
# reset), so a probe whose frames the kernel would discard can never read "dropped".
# REQ: DEV-2, DEV-net-e
PROBE6 = ROOT / "image/probe_lan6.py"
LAN6 = "agentos-t-lan6"


@unittest.skipUnless(os.geteuid() == 0 and shutil.which("ip") and shutil.which("nft") and IPV6
                     and os.path.exists("/dev/net/tun"), "needs root, ip, nft, IPv6 and /dev/net/tun")
class BootProbeOverIPv6(unittest.TestCase):
    def setUp(self):
        self.stop = threading.Event()
        self.addCleanup(self.cleanup)
        sh("ip", "netns", "add", LAN6)
        sh("ip", "link", "set", "lo", "up", ns=LAN6)
        # IFF_TAP | IFF_NO_PI: whole Ethernet frames, as QEMU hands its socket peer.
        self.tap = os.open("/dev/net/tun", os.O_RDWR)
        fcntl.ioctl(self.tap, 0x400454CA, struct.pack("16sH", b"lan6", 0x0002 | 0x1000))
        sh("ip", "link", "set", "lan6", "netns", LAN6)
        for k, v in (("forwarding", 0), ("accept_ra", 2), ("autoconf", 1)):
            sh("sysctl", "-qw", "net.ipv6.conf.lan6.%s=%d" % (k, v), ns=LAN6)

    def cleanup(self):
        self.stop.set()
        os.close(self.tap)
        sh("ip", "netns", "del", LAN6, check=False)

    def relay(self, conn):
        while not self.stop.is_set():
            r = select.select([self.tap, conn], [], [], 0.2)[0]
            if self.tap in r:
                f = os.read(self.tap, 65536)
                conn.sendall(struct.pack("!I", len(f)) + f)
            if conn in r:
                data = conn.recv(65536)
                if not data:
                    return
                self.buf += data
                while len(self.buf) >= 4 and len(self.buf) >= 4 + struct.unpack("!I", self.buf[:4])[0]:
                    n = struct.unpack("!I", self.buf[:4])[0]
                    try:
                        os.write(self.tap, self.buf[4:4 + n])
                    except OSError as e:  # EIO while the link is down: the frame is lost, as on a wire
                        if e.errno != errno.EIO:
                            raise
                    self.buf = self.buf[4 + n:]

    def probe(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(20)
        with tempfile.TemporaryDirectory() as t:
            go = os.path.join(t, "go")
            open(go, "w").close()
            p = subprocess.Popen([sys.executable, str(PROBE6), "127.0.0.1:%d" % srv.getsockname()[1], go,
                                  "22", str(PORT)], stdout=subprocess.PIPE, text=True)
            conn, _ = srv.accept()
            srv.close()
            self.buf = b""
            t = threading.Thread(target=self.relay, args=(conn,))
            t.start()
            # The link comes up with the probe attached, so it sees the box claim its link-local address.
            sh("ip", "link", "set", "lan6", "up", ns=LAN6)
            try:
                out = p.communicate(timeout=180)[0]
            finally:
                self.stop.set()
                t.join()
                conn.close()
            return out.splitlines(), sh("ip", "-6", "-o", "addr", "show", "dev", "lan6", ns=LAN6).stdout

    def test_the_drop_holds_at_every_ipv6_address(self):
        r = sh("nft", "-f", str(RULES), ns=LAN6, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        out, addrs = self.probe()
        for line in ("fe80 reachable", "global reachable", "fe80 22 dropped", "fe80 %d dropped" % PORT,
                     "global 22 dropped", "global %d dropped" % PORT):
            self.assertIn("agentos-probe6: " + line, out, addrs)

    def test_control_without_the_drop_every_port_answers(self):
        out, addrs = self.probe()
        for line in ("fe80 reachable", "global reachable", "fe80 22 answered", "fe80 %d answered" % PORT,
                     "global 22 answered", "global %d answered" % PORT):
            self.assertIn("agentos-probe6: " + line, out, addrs)


if __name__ == "__main__":
    unittest.main()
