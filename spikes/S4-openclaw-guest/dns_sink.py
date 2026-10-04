#!/usr/bin/env python3
"""dns_sink.py <log>: answer every DNS query on 127.0.0.1:53 with NXDOMAIN, logging the name.

Shows which hostnames the guest tries to resolve when it has no network.
"""
import json
import socket
import sys
import time

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 53))
while True:
    q, addr = s.recvfrom(512)
    i, labels = 12, []
    while i < len(q) and q[i]:
        labels.append(q[i + 1:i + 1 + q[i]].decode(errors="replace"))
        i += 1 + q[i]
    qtype = int.from_bytes(q[i + 1:i + 3], "big") if i + 3 <= len(q) else 0
    with open(sys.argv[1], "a") as f:
        f.write(json.dumps({"t": round(time.time(), 3), "name": ".".join(labels), "qtype": qtype}) + "\n")
    flags = (0x8180 | 3) | (q[2] & 1) << 8  # response, recursion available, NXDOMAIN, keep RD
    s.sendto(q[:2] + flags.to_bytes(2, "big") + q[4:6] + b"\0\0\0\0\0\0" + q[12:i + 5], addr)
