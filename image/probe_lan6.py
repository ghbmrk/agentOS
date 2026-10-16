#!/usr/bin/env python3
"""Probe the booted image's inbound drop over IPv6, at its link-local and SLAAC addresses (ci_boot.sh).

QEMU's user network forwards IPv4 only, so the boot test gives the box a second wired NIC whose
other end is this script: QEMU's "-nic socket,listen=..." carries each Ethernet frame over TCP after
a 4-byte big-endian length. The script plays a home router on that link. It advertises a /64
(RFC 3849 documentation prefix), so the box configures addresses itself (SLAAC, I19), learns each
address the box claims from the box's duplicate-address checks, and answers neighbour
solicitations for its own addresses so the box could reply if it would.

Once FILE exists (the box has booted), each learned address gets a positive control first: a
neighbour solicitation that the box must answer (the drop lets neighbour discovery through), which
shows that probe frames reach the box's IPv6 stack at an address it holds. Only then is each port
sent a TCP SYN; a reset, a SYN-ACK or an ICMPv6 error back means the box answered.

Usage: probe_lan6.py HOST:PORT FILE PORT... Prints "agentos-probe6: SCOPE reachable|unreachable"
per scope (fe80: link-local, global: SLAAC), then "agentos-probe6: SCOPE PORT dropped|answered"
per port for a reachable scope: answered if any address of the scope answered.
"""
import ipaddress
import os
import random
import select
import socket
import struct
import sys
import time

MAC = bytes.fromhex("02000000c601")  # locally administered
LL = ipaddress.IPv6Address("fe80::c601")
PREFIX = ipaddress.IPv6Network("2001:db8:6::/64")
GLOBAL = ipaddress.IPv6Address("2001:db8:6::c601")
ALL_NODES = ipaddress.IPv6Address("ff02::1")
TCP, ICMP6 = 6, 58


def checksum(src, dst, nh, payload):
    data = src.packed + dst.packed + struct.pack("!IxxxB", len(payload), nh) + payload
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def packet(dmac, src, dst, nh, payload, hops=255):
    # payload carries a zero checksum at offset 2 (ICMPv6) or 16 (TCP); it is filled in here.
    at = 2 if nh == ICMP6 else 16
    c = checksum(src, dst, nh, payload)
    payload = payload[:at] + struct.pack("!H", c) + payload[at + 2:]
    ip = struct.pack("!IHBB", 0x60000000, len(payload), nh, hops) + src.packed + dst.packed
    return dmac + MAC + b"\x86\xdd" + ip + payload


def solicited(addr):
    node = ipaddress.IPv6Address(b"\xff\x02" + bytes(9) + b"\x01\xff" + addr.packed[13:])
    return b"\x33\x33" + node.packed[12:], node


def advert():
    ra = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, 1800, 0, 0)
    sll = struct.pack("!BB", 1, 1) + MAC
    pio = struct.pack("!BBBBIII", 3, 4, 64, 0xC0, 86400, 14400, 0) + PREFIX.network_address.packed
    return packet(b"\x33\x33\x00\x00\x00\x01", LL, ALL_NODES, ICMP6, ra + sll + pio)


def solicit(target):
    dmac, dst = solicited(target)
    src = LL if target.is_link_local else GLOBAL
    ns = struct.pack("!BBHI", 135, 0, 0, 0) + target.packed + struct.pack("!BB", 1, 1) + MAC
    return packet(dmac, src, dst, ICMP6, ns)


def neighbour_advert(dmac, dst, target):
    na = struct.pack("!BBHI", 136, 0, 0, 0x60000000) + target.packed + struct.pack("!BB", 2, 1) + MAC
    return packet(dmac, target, dst, ICMP6, na)


def syn(dmac, dst, sport, dport):
    src = LL if dst.is_link_local else GLOBAL
    tcp = struct.pack("!HHIIBBHHH", sport, dport, random.getrandbits(32), 0, 5 << 4, 0x02, 64240, 0, 0)
    return packet(dmac, src, dst, TCP, tcp, hops=64)


class Link:
    """One end of a QEMU socket netdev: frames in and out, and what the box has said so far."""

    def __init__(self, sock):
        self.sock, self.buf = sock, b""
        self.box_mac = None
        self.claimed = []  # addresses the box checked for duplicates, in order
        self.advertised = set()  # targets of the box's neighbour advertisements
        self.answers = set()  # (box address, port) the box answered over TCP or ICMPv6

    def send(self, frame):
        self.sock.sendall(struct.pack("!I", len(frame)) + frame)

    def pump(self, seconds):
        end = time.monotonic() + seconds
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return
            if select.select([self.sock], [], [], left)[0]:
                data = self.sock.recv(65536)
                if not data:
                    raise EOFError("the link closed")
                self.buf += data
                while len(self.buf) >= 4 and len(self.buf) >= 4 + struct.unpack("!I", self.buf[:4])[0]:
                    n = struct.unpack("!I", self.buf[:4])[0]
                    frame, self.buf = self.buf[4:4 + n], self.buf[4 + n:]
                    self.frame(frame)

    def frame(self, f):
        if len(f) < 54 or f[12:14] != b"\x86\xdd" or f[6:12] == MAC:
            return
        nh, src, dst, p = f[20], ipaddress.IPv6Address(f[22:38]), ipaddress.IPv6Address(f[38:54]), f[54:]
        self.box_mac = f[6:12]
        if not (src.is_unspecified or src.is_multicast) and src not in self.claimed:
            self.claimed.append(src)  # an address the box sends from (in case its DAD went unseen)
        if nh == ICMP6 and p[:1] == b"\x87" and len(p) >= 24:  # neighbour solicitation
            target = ipaddress.IPv6Address(p[8:24])
            if src.is_unspecified:
                if target not in self.claimed:
                    self.claimed.append(target)
            elif target in (LL, GLOBAL):
                self.send(neighbour_advert(f[6:12], src, target))
        elif nh == ICMP6 and p[:1] == b"\x88" and len(p) >= 24:  # neighbour advertisement
            self.advertised.add(ipaddress.IPv6Address(p[8:24]))
        elif nh == TCP and len(p) >= 4:
            self.answers.add((src, struct.unpack("!H", p[:2])[0]))
        elif nh == ICMP6 and p[:1] in (b"\x01", b"\x04") and len(p) >= 8 + 40 + 4:
            inner = p[8:]  # the box's error quotes the probe: its destination and TCP port
            if inner[6] == TCP:
                self.answers.add((ipaddress.IPv6Address(inner[24:40]), struct.unpack("!H", inner[42:44])[0]))


def scope(addr):
    if addr.is_link_local:
        return "fe80"
    return "global" if addr in PREFIX else None


def run(link, go, ports, wait=3.0, limit=120.0):
    end = time.monotonic() + limit
    # Advertise every 2 s, as a router does after a link comes up, until the box has booted and holds
    # an address in each scope (or the limit passes).
    while time.monotonic() < end:
        link.send(advert())
        link.pump(2)
        held = {scope(a) for a in link.claimed}
        if os.path.exists(go) and {"fe80", "global"} <= held:
            break
    link.pump(wait)  # duplicate-address detection takes about a second
    lines, reachable = [], {}
    for addr in link.claimed:
        if scope(addr):
            for _ in range(3):
                if addr in link.advertised:
                    break
                link.send(solicit(addr))
                link.pump(1)
            if addr in link.advertised:
                reachable.setdefault(scope(addr), []).append(addr)
    for s in ("fe80", "global"):
        lines.append("agentos-probe6: %s %s" % (s, "reachable" if s in reachable else "unreachable"))
    probes = [(a, p) for s in reachable for a in reachable[s] for p in ports]
    for i, (a, p) in enumerate(probes):
        link.send(syn(link.box_mac, a, 40000 + i, p))
    link.pump(wait)
    for s in ("fe80", "global"):
        for p in ports if s in reachable else ():
            hit = any((a, p) in link.answers for a in reachable[s])
            lines.append("agentos-probe6: %s %d %s" % (s, p, "answered" if hit else "dropped"))
    return lines


def connect(hostport, limit=60.0):
    host, port = hostport.rsplit(":", 1)
    end = time.monotonic() + limit
    while True:
        try:
            return socket.create_connection((host, int(port)), timeout=5)
        except OSError:
            if time.monotonic() > end:
                raise
            time.sleep(0.5)


def main(argv):
    hostport, go, ports = argv[0], argv[1], [int(p) for p in argv[2:]]
    for line in run(Link(connect(hostport)), go, ports):
        print(line, flush=True)


if __name__ == "__main__":
    main(sys.argv[1:])
