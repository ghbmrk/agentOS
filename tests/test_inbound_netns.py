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
import ipaddress
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = ROOT / "image/mkosi/mkosi.extra/usr/lib/agentos/inbound.nft"
BOX, HOME = "agentos-t-box", "agentos-t-home"
PORT = 18789
# Some sandboxes run a kernel without IPv6; the IPv6 half then skips. CI's runners have it.
IPV6 = os.path.isdir("/proc/sys/net/ipv6")
PREFIX = "2001:db8:1::"
ROUTER6 = PREFIX + "2"

# Accept on PORT (dual-stack where the kernel has IPv6) and answer each connection with one byte.
LISTEN = """
import socket, sys
if sys.argv[1] == "6":
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::" if sys.argv[1] == "6" else "0.0.0.0", %d)); s.listen(16)
while True:
    c, _ = s.accept(); c.sendall(b"x"); c.close()
""" % PORT

# Connect to argv[1] on PORT; exit 0 if a byte comes back within the timeout.
CONNECT = """
import socket, sys
try:
    c = socket.create_connection((sys.argv[1], %d), timeout=1.5)
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


def reaches(ns, addr):
    return sh("python3", "-c", CONNECT, addr, ns=ns, check=False).returncode == 0


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

AP_EXEMPT = ROOT / "image/mkosi/mkosi.extra/usr/lib/agentos/ap-exempt"
PHONE = "agentos-t-phone"


@unittest.skipUnless(os.geteuid() == 0 and shutil.which("ip") and shutil.which("nft"),
                     "needs root, ip and nft")
class AccessPointThroughTheDrop(unittest.TestCase):
    """The box's own Wi-Fi joins the exempt set; the uplink and an unnamed link stay dropped."""

    def setUp(self):
        self.procs = []
        self.addCleanup(self.cleanup)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        # A stand-in /sys: only ap0 is a wireless interface (the veth links are not).
        self.sysfs = pathlib.Path(tmp.name)
        (self.sysfs / "class/net/ap0/phy80211").mkdir(parents=True)
        for ns in (BOX, HOME, PHONE):
            sh("ip", "netns", "add", ns)
            sh("ip", "link", "set", "lo", "up", ns=ns)
        for box, peer_ns, peer, v4 in (("eth0", HOME, "h0", "192.0.2"), ("usb0", HOME, "h1", "198.51.100")):
            self.link(box, peer_ns, peer, v4)
        self.link("ap0", PHONE, "p0", "203.0.113")
        self.listen(BOX)

    def link(self, box, peer_ns, peer, v4):
        sh("ip", "link", "add", box, "netns", BOX, "type", "veth", "peer", "name", peer, "netns", peer_ns)
        for ns, dev, host in ((BOX, box, 1), (peer_ns, peer, 2)):
            sh("ip", "addr", "add", "%s.%d/24" % (v4, host), "dev", dev, ns=ns)
            sh("ip", "link", "set", dev, "up", ns=ns)

    def listen(self, ns):
        p = subprocess.Popen(["ip", "netns", "exec", ns, "python3", "-c", LISTEN, "4"])
        self.procs.append(p)
        for _ in range(50):
            if sh("ss", "-Htln", "sport = :%d" % PORT, ns=ns, check=False).stdout.strip():
                return
            time.sleep(0.1)
        self.fail("listener in %s did not start" % ns)

    def cleanup(self):
        for p in self.procs:
            p.kill()
            p.wait()
        for ns in (BOX, HOME, PHONE):
            sh("ip", "netns", "del", ns, check=False)

    def load(self):
        r = sh("nft", "-f", str(RULES), ns=BOX, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)

    def exempt(self, iface):
        env = dict(os.environ, AGENTOS_SYSFS=str(self.sysfs))
        return subprocess.run(["ip", "netns", "exec", BOX, "sh", str(AP_EXEMPT), iface], env=env,
                              capture_output=True, text=True)

    def exempt_set(self):
        return sh("nft", "list", "set", "inet", "agentos_inbound", "exempt", ns=BOX).stdout

    def assert_home_shut_out(self):
        # A14: no home-network host opens a connection to a box port, on the uplink or an unnamed link.
        for addr in ("192.0.2.1", "198.51.100.1"):
            with self.subTest(home_to=addr):
                self.assertFalse(reaches(HOME, addr), "a home host reached box port %d at %s" % (PORT, addr))

    def test_the_phone_reaches_the_box_only_on_the_access_point(self):
        self.assertTrue(reaches(PHONE, "203.0.113.1"), "control: phone cannot reach the box before the rules")
        self.load()
        # Before bring-up adds it, the drop is final: the phone joins but the page never loads.
        self.assertFalse(reaches(PHONE, "203.0.113.1"))
        r = self.exempt("ap0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("agentos-ap-exempt: OK ap0", r.stdout)
        self.assertTrue(reaches(PHONE, "203.0.113.1"), "the phone on the access point cannot reach the box")
        self.assert_home_shut_out()
        self.assertIn('"ap0"', self.exempt_set())
        for other in ("eth0", "usb0"):
            self.assertNotIn('"%s"' % other, self.exempt_set())
        # The same phone, on the same link, under a name that is not the access point's: dropped.
        sh("ip", "link", "set", "ap0", "down", ns=BOX)
        sh("ip", "link", "set", "ap0", "name", "wl9", ns=BOX)
        sh("ip", "link", "set", "wl9", "up", ns=BOX)
        self.assertFalse(reaches(PHONE, "203.0.113.1"), "a non-exempt interface admitted the phone")

    def test_a_recreated_access_point_is_let_through_again(self):
        self.load()
        self.assertEqual(self.exempt("ap0").returncode, 0)
        self.assertTrue(reaches(PHONE, "203.0.113.1"))
        sh("ip", "link", "del", "ap0", ns=BOX)
        self.link("ap0", PHONE, "p0", "203.0.113")
        # Bring-up runs again for the new interface; adding a member twice is not an error.
        r = self.exempt("ap0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(reaches(PHONE, "203.0.113.1"), "the recreated access point is not let through")
        self.assertEqual(self.exempt_set().count('"ap0"'), 1)
        self.assert_home_shut_out()

    def test_bring_up_fails_closed(self):
        # No table: bring-up fails and creates nothing (it never loads or opens rules itself).
        r = self.exempt("ap0")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("agentos-ap-exempt: FAIL", r.stdout)
        self.assertEqual(sh("nft", "list", "ruleset", ns=BOX).stdout.strip(), "")
        # With the table: the uplink and an unnamed link are not wireless, so they are refused,
        # and the table is left exactly as it was.
        self.load()
        before = sh("nft", "list", "ruleset", ns=BOX).stdout
        for iface in ("eth0", "usb0", "lo0", "ap0;x", ""):
            with self.subTest(iface=iface):
                r = self.exempt(iface)
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertIn("agentos-ap-exempt: FAIL", r.stdout)
        self.assertEqual(sh("nft", "list", "ruleset", ns=BOX).stdout, before)
        self.assert_home_shut_out()
        self.assertFalse(reaches(PHONE, "203.0.113.1"))


if __name__ == "__main__":
    unittest.main()
