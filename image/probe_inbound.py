#!/usr/bin/env python3
"""Probe the booted image's inbound drop through QEMU user networking's hostfwd (ci_boot.sh).

QEMU's user network accepts the host's connection on the forwarded port itself, then opens one to
the guest. A guest that drops the SYN never answers, so the host's connection stays open and silent;
a guest that answers (a reset from a closed port, or a listener) makes QEMU send data or close it.

Usage: probe_inbound.py [--wait S] HOSTPORT:GUESTPORT... Prints, per port,
"agentos-probe: GUESTPORT dropped|answered|error"; error means the forward itself did not connect.
"""
import socket
import sys


def probe(port, wait):
    try:
        c = socket.create_connection(("127.0.0.1", port), timeout=5)
    except OSError:
        return "error"
    with c:
        try:
            c.sendall(b"GET / HTTP/1.0\r\n\r\n")
            c.settimeout(wait)
            c.recv(1)
            return "answered"
        except socket.timeout:
            return "dropped"
        except OSError:
            return "answered"


def main(argv):
    wait = 5.0
    if argv[:1] == ["--wait"]:
        wait, argv = float(argv[1]), argv[2:]
    for arg in argv:
        host, guest = arg.split(":")
        print("agentos-probe: %s %s" % (guest, probe(int(host), wait)), flush=True)


if __name__ == "__main__":
    main(sys.argv[1:])
