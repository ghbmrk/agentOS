# The image boot test's network probes (#1457, P2-1 u1). probe_lan6.py, the router on the booted
# box's second NIC, is run here against a stand-in box over a socket pair: it reports a scope
# reachable only when the box answers neighbour discovery there (the positive control), reports
# nothing about ports at an unreachable scope, and tells a box that drops SYNs from one that answers
# them. ci_boot.sh is checked to run it at both scopes and every probed port, to probe LLMNR's 5355
# through the IPv4 forwards too, and to check the lease sits at 10.0.2.15, the forwards' target.
# The wait-online drop-in keeps an unplugged boot free of failed units (u1a). Addresses are
# documentation ranges (RFC 3849); MACs are locally administered.
# REQ: DEV-2, DEV-net-e
import configparser
import ipaddress
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "image"))
import probe_lan6 as p6  # noqa: E402

BOX_MAC = bytes.fromhex("02000000b0b0")
BOX_LL = ipaddress.IPv6Address("fe80::b0b0")
BOX_GLOBAL = ipaddress.IPv6Address("2001:db8:6::b0b0")
PORTS = [22, 18789]


def from_box(frame):
    return frame[:6] + BOX_MAC + frame[12:]


class Box(threading.Thread):
    """A stand-in box: claims a link-local and a SLAAC address, then answers what it is told to."""

    def __init__(self, sock, answer_ns, answer_tcp):
        super().__init__(daemon=True)
        self.sock, self.answer_ns, self.answer_tcp = sock, answer_ns, answer_tcp

    def send(self, frame):
        self.sock.sendall(struct.pack("!I", len(frame)) + frame)

    def run(self):
        for addr in (BOX_LL, BOX_GLOBAL):  # duplicate-address checks, from the unspecified address
            dmac, dst = p6.solicited(addr)
            ns = struct.pack("!BBHI", 135, 0, 0, 0) + addr.packed
            self.send(from_box(p6.packet(dmac, ipaddress.IPv6Address("::"), dst, p6.ICMP6, ns)))
        buf = b""
        while True:
            try:
                data = self.sock.recv(65536)
            except OSError:
                return
            if not data:
                return
            buf += data
            while len(buf) >= 4 and len(buf) >= 4 + struct.unpack("!I", buf[:4])[0]:
                n = struct.unpack("!I", buf[:4])[0]
                f, buf = buf[4:4 + n], buf[4 + n:]
                self.frame(f)

    def frame(self, f):
        nh, src, dst, p = f[20], ipaddress.IPv6Address(f[22:38]), ipaddress.IPv6Address(f[38:54]), f[54:]
        if nh == p6.ICMP6 and p[0] == 135 and self.answer_ns:
            target = ipaddress.IPv6Address(p[8:24])
            if target in (BOX_LL, BOX_GLOBAL):
                na = struct.pack("!BBHI", 136, 0, 0, 0x60000000) + target.packed
                self.send(from_box(p6.packet(f[6:12], target, src, p6.ICMP6, na)))
        elif nh == p6.TCP and self.answer_tcp:
            sport, dport = struct.unpack("!HH", p[:4])
            rst = struct.pack("!HHIIBBHHH", dport, sport, 0, 1, 5 << 4, 0x14, 0, 0, 0)
            self.send(from_box(p6.packet(f[6:12], dst, src, p6.TCP, rst, hops=64)))


class ProbeLan6(unittest.TestCase):
    def probe(self, answer_ns=True, answer_tcp=False):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        Box(b, answer_ns, answer_tcp).start()
        with tempfile.NamedTemporaryFile() as go:
            return p6.run(p6.Link(a), go.name, PORTS, wait=0.5, limit=10)

    def test_a_box_that_drops_every_syn_reads_dropped_at_both_scopes(self):
        self.assertEqual(self.probe(), [
            "agentos-probe6: fe80 reachable", "agentos-probe6: global reachable",
            "agentos-probe6: fe80 22 dropped", "agentos-probe6: fe80 18789 dropped",
            "agentos-probe6: global 22 dropped", "agentos-probe6: global 18789 dropped"])

    def test_a_box_that_answers_reads_answered(self):
        self.assertEqual(self.probe(answer_tcp=True)[2:], [
            "agentos-probe6: fe80 22 answered", "agentos-probe6: fe80 18789 answered",
            "agentos-probe6: global 22 answered", "agentos-probe6: global 18789 answered"])

    def test_without_the_positive_control_no_port_reads_dropped(self):
        # A box the probe cannot reach would drop every SYN too; that must not pass as the drop.
        self.assertEqual(self.probe(answer_ns=False),
                         ["agentos-probe6: fe80 unreachable", "agentos-probe6: global unreachable"])


class CiBoot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "image", "ci_boot.sh")) as f:
            cls.sh = f.read()

    def test_lease_is_checked_at_the_forwards_target(self):
        self.assertIn('grep -qF " 10.0.2.15/"', self.sh)

    def test_llmnr_is_forwarded_and_probed(self):
        self.assertIn("hostfwd=tcp:127.0.0.1:15355-:5355", self.sh)
        self.assertIn("15355:5355\" boot \"$W/console.log\"", self.sh)
        self.assertIn("for port in 22 80 443 18789 5355; do\n"
                      '\thas "$W/console.log.probe" "agentos-probe: $port dropped"', self.sh)

    def test_ipv6_probe_runs_on_a_second_nic_at_both_scopes(self):
        self.assertIn('${LAN:+-nic "$LAN"}', self.sh)
        self.assertIn('LAN="socket,model=virtio-net-pci,listen=127.0.0.1:18600"', self.sh)
        self.assertIn('PROBE6="127.0.0.1:18600 22 80 443 18789 5355"', self.sh)
        self.assertIn("for scope in fe80 global; do", self.sh)
        self.assertIn('has "$W/console.log.probe6" "agentos-probe6: $scope reachable"', self.sh)
        self.assertIn("\tfor port in 22 80 443 18789 5355; do\n"
                      '\t\thas "$W/console.log.probe6" "agentos-probe6: $scope $port dropped"', self.sh)


class WaitOnline(unittest.TestCase):
    def test_an_unplugged_boot_leaves_no_failed_unit(self):
        path = os.path.join(ROOT, "image", "mkosi", "mkosi.extra", "usr", "lib", "systemd", "system",
                            "systemd-networkd-wait-online.service.d", "agentos-unplugged.conf")
        c = configparser.ConfigParser(strict=False, interpolation=None)
        with open(path) as f:
            lines = f.read()
        self.assertIn("ExecStart=\nExecStart=-/usr/lib/systemd/systemd-networkd-wait-online --any --timeout=5",
                      lines)
        c.read_string(lines.replace("ExecStart=\n", "", 1))
        self.assertTrue(c["Service"]["ExecStart"].startswith("-"))


if __name__ == "__main__":
    unittest.main()
