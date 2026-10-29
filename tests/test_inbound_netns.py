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
# routed or bridged.
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
        # Forwarding goes on first, as NetworkManager turns it on before the link carries traffic.
        sh("sysctl", "-qw", "net.ipv4.ip_forward=1", ns=BOX)
        if IPV6:
            sh("sysctl", "-qw", "net.ipv6.conf.all.forwarding=1", ns=BOX)
        for box, ns, peer, v4, v6 in (("eth0", LAN, "l0", "192.0.2", LAN_NET6), ("usb0", FAR, "f0", "198.51.100", FAR_NET6)):
            sh("ip", "link", "add", box, "netns", BOX, "type", "veth", "peer", "name", peer, "netns", ns)
            for n, dev, host in ((BOX, box, 1), (ns, peer, 2)):
                if IPV6:
                    sh("sysctl", "-qw", "net.ipv6.conf.%s.accept_dad=0" % dev, ns=n)
                sh("ip", "addr", "add", "%s.%d/24" % (v4, host), "dev", dev, ns=n)
                if IPV6:
                    sh("ip", "-6", "addr", "add", "%s%d/64" % (v6, host), "dev", dev, "nodad", ns=n)
                sh("ip", "link", "set", dev, "up", ns=n)
            sh("ip", "route", "add", "default", "via", v4 + ".1", ns=ns)
            if IPV6:
                sh("ip", "-6", "route", "add", "default", "via", v6 + "1", ns=ns)
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

    def routes(self, addr):
        # The control: a freshly linked network may need a moment for neighbour discovery.
        for _ in range(10):
            if reaches(LAN, addr):
                return True
            time.sleep(0.5)
        return False

    def diagnose(self):
        return "".join(sh(*c, ns=n, check=False).stdout
                       for n in (BOX, LAN, FAR) for c in (("ip", "-6", "addr"), ("ip", "-6", "route"), ("ip", "-6", "neigh"))) \
            + sh("sysctl", "net.ipv6.conf.all.forwarding", "net.ipv6.conf.eth0.forwarding",
                 "net.ipv6.conf.usb0.forwarding", ns=BOX, check=False).stdout

    def test_forwarding_turned_on_routes_nothing(self):
        for addr in self.far():
            self.assertTrue(self.routes(addr), "control: the box does not route to %s before the rules\n%s"
                            % (addr, self.diagnose()))
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


LINK_UNIT = ROOT / "image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-link.service"
EDGE = "agentos-t-edge"


def unit_command(unit, key):
    """The one KEY= command of UNIT, as the argv systemd runs, its "+" taken off."""
    import shlex
    lines = [l.split("=", 1)[1] for l in unit.read_text().splitlines() if l.startswith(key + "=")]
    assert len(lines) == 1, lines
    return shlex.split(lines[0].lstrip("+"))


@unittest.skipUnless(os.geteuid() == 0 and shutil.which("ip") and shutil.which("nft"),
                     "needs root, ip and nft")
class EdgeLinkOnTheLinkOnly(unittest.TestCase):
    """EDGE-link-core c2c (HW-15, HW-16): the box with the edge on agentos-link and the home network on
    eth0, the shipped rules loaded, and the link unit's own nft commands run as its unit runs them. The
    link's port answers the edge on the link, over its link-local address and over IPv4, only while the
    unit's start command has put the link in the link set; no other port answers there, and the link's
    port never answers on eth0."""
    # REQ: HW-15, HW-16
    LINK_PORT = 7443

    def setUp(self):
        self.procs = []
        self.addCleanup(self.cleanup)
        for ns in (BOX, HOME, EDGE):
            sh("ip", "netns", "add", ns)
            sh("ip", "link", "set", "lo", "up", ns=ns)
        for box, ns, peer, v4 in (("eth0", HOME, "h0", "192.0.2"), ("agentos-link", EDGE, "e0", "198.51.100")):
            sh("ip", "link", "add", box, "netns", BOX, "type", "veth", "peer", "name", peer, "netns", ns)
            for n, dev, host in ((BOX, box, 1), (ns, peer, 2)):
                sh("ip", "addr", "add", "%s.%d/24" % (v4, host), "dev", dev, ns=n)
                if IPV6 and box == "agentos-link":
                    sh("sysctl", "-qw", "net.ipv6.conf.%s.addr_gen_mode=1" % dev, ns=n)
                    sh("ip", "-6", "addr", "add", "fe80::%d/64" % host, "dev", dev, "nodad", ns=n)
                sh("ip", "link", "set", dev, "up", ns=n)
        for port in (PORT, self.LINK_PORT):
            p = subprocess.Popen(["ip", "netns", "exec", BOX, "python3", "-c", LISTEN, "6" if IPV6 else "4", str(port)])
            self.procs.append(p)
            for _ in range(50):
                if sh("ss", "-Htln", "sport = :%d" % port, ns=BOX, check=False).stdout.strip():
                    break
                time.sleep(0.1)
            else:
                self.fail("listener on %d did not start" % port)

    def cleanup(self):
        for p in self.procs:
            p.kill()
            p.wait()
        for ns in (BOX, HOME, EDGE):
            sh("ip", "netns", "del", ns, check=False)

    def run_unit(self, key):
        r = sh(*unit_command(LINK_UNIT, key), ns=BOX, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)

    def reply_on_link(self):
        """Whether the edge's reply to the box's own ping over the link reaches the box."""
        if not shutil.which("ping"):
            self.skipTest("ping is not installed")
        return sh("ping", "-c1", "-W2", "198.51.100.2", ns=BOX, check=False).returncode == 0

    def edge_addrs(self):
        return ["198.51.100.1"] + (["fe80::1%e0"] if IPV6 else [])

    def test_the_link_port_answers_on_the_link_alone_while_the_unit_runs(self):
        for addr in self.edge_addrs():
            self.assertTrue(reaches(EDGE, addr, self.LINK_PORT), "control: %s before the rules" % addr)
        self.assertTrue(reaches(HOME, "192.0.2.1", self.LINK_PORT), "control: eth0 before the rules")
        r = sh("nft", "-f", str(RULES), ns=BOX, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        # As the image boots: the link set is empty, so the link's port is closed everywhere.
        for addr in self.edge_addrs():
            self.assertFalse(reaches(EDGE, addr, self.LINK_PORT), "the empty link set admits %s" % addr)
        self.assertFalse(self.reply_on_link(), "a reply on the link passed with the link set empty")
        # The unit's start: the link's port answers the edge on the link, and nothing else does.
        self.run_unit("ExecStartPre")
        self.run_unit("ExecStartPre")
        listed = sh("nft", "list", "set", "inet", "agentos_inbound", "link", ns=BOX).stdout
        self.assertIn('elements = { "agentos-link" }', listed)
        for addr in self.edge_addrs():
            with self.subTest(edge_to=addr):
                self.assertTrue(reaches(EDGE, addr, self.LINK_PORT), "the edge cannot reach the link at %s" % addr)
                self.assertFalse(reaches(EDGE, addr, PORT), "the edge reached port %d at %s" % (PORT, addr))
        self.assertFalse(reaches(HOME, "192.0.2.1", self.LINK_PORT), "the link's port answered on eth0")
        self.assertFalse(reaches(HOME, "192.0.2.1", PORT))
        # Not even replies pass on the link: conntrack is not per interface, so the edge could forge one
        # into another flow (#3834 Security review). The box opens nothing over the link.
        self.assertFalse(self.reply_on_link(), "a reply on the link passed")
        if shutil.which("ping"):
            self.assertEqual(sh("ping", "-c1", "-W2", "192.0.2.2", ns=BOX, check=False).returncode, 0,
                             "control: replies on eth0")
        # The unit's stop: the link's port is closed again.
        self.run_unit("ExecStopPost")
        for addr in self.edge_addrs():
            self.assertFalse(reaches(EDGE, addr, self.LINK_PORT), "the link's port still open at %s after the stop" % addr)
        self.assertFalse(self.reply_on_link(), "a reply on the link passed after the stop")


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
