#!/usr/bin/env python3
"""Bring loopback up inside a fresh network namespace (no `ip` binary needed)."""
import fcntl
import socket
import struct

SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
flags = struct.unpack("16sH14s", fcntl.ioctl(s, SIOCGIFFLAGS, struct.pack("16sH14s", b"lo", 0, b"")))[1]
fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14s", b"lo", flags | IFF_UP, b""))
