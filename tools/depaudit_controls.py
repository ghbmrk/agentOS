#!/usr/bin/env python3
"""Control scenarios for the dependency audit. An audit that finds nothing
means something only if the same audit catches deliberate traffic, so CI runs
these on every pass alongside the real scenarios.

  clean          loopback TCP, a Unix socket in its own TMPDIR, a file write; exits 0
  phones-home    DNS lookups (one forbidden name), a TCP connect and a UDP send to
                 documentation addresses, a host-wide Unix socket; exits 0
  needs-network  exits nonzero when it cannot reach the network
  host-socket    connects to the live socket at $DEPAUDIT_PROBE (outside the
                 sandbox's work directory); exits nonzero if it got through
  host-socket-dotdot   reaches $DEPAUDIT_PROBE_VISIBLE as $TMPDIR/../../...
  host-socket-symlink  reaches it through a symlink created in $TMPDIR
  host-socket-symlink-removed  same, then deletes the symlink before exiting
"""
import os
import socket
import sys
import tempfile
import threading


def clean():
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    threading.Thread(target=lambda: srv.accept()[0].sendall(b"STATUS ok"), daemon=True).start()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as c:
        assert c.recv(16) == b"STATUS ok"
    path = os.path.join(tempfile.mkdtemp(), "ctl.sock")
    u = socket.socket(socket.AF_UNIX)
    u.bind(path)
    u.listen()
    with socket.socket(socket.AF_UNIX) as c:
        c.connect(path)
    with open(os.path.join(tempfile.gettempdir(), "journal"), "w") as f:
        f.write("ok\n")


def attempt(fn):
    try:
        fn()
    except OSError:
        pass


def phones_home():
    attempt(lambda: socket.getaddrinfo("updates.vendor-cdn.example.net", 443))
    attempt(lambda: socket.getaddrinfo("telemetry.agentos.example", 443))
    attempt(lambda: socket.create_connection(("192.0.2.10", 443), timeout=2))
    attempt(lambda: socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).sendto(b"\x1b" + b"\0" * 47, ("2001:db8::1", 123)))
    attempt(lambda: socket.socket(socket.AF_UNIX).connect("/run/systemd/resolve/io.systemd.Resolve"))


def needs_network():
    try:
        socket.create_connection(("192.0.2.10", 443), timeout=2).close()
    except OSError as e:
        sys.exit("offline: %s" % e)


def host_socket():
    with socket.socket(socket.AF_UNIX) as s:
        try:
            s.connect(os.environ["DEPAUDIT_PROBE"])
        except OSError:
            return
    sys.exit("reached a host socket outside the sandbox")


def via(path):
    with socket.socket(socket.AF_UNIX) as s:
        try:
            s.connect(path)
        except OSError:
            pass


def host_socket_dotdot():
    tmp = tempfile.gettempdir()
    probe = os.environ["DEPAUDIT_PROBE_VISIBLE"]
    via(os.path.join(tmp, os.path.relpath(probe, tmp)))


def host_socket_symlink(remove=False):
    link = os.path.join(tempfile.gettempdir(), "l")
    probe = os.environ["DEPAUDIT_PROBE_VISIBLE"]
    os.symlink(os.path.dirname(probe), link)
    via(os.path.join(link, os.path.basename(probe)))
    if remove:
        os.unlink(link)


if __name__ == "__main__":
    {"clean": clean, "phones-home": phones_home, "needs-network": needs_network,
     "host-socket": host_socket, "host-socket-dotdot": host_socket_dotdot,
     "host-socket-symlink": host_socket_symlink,
     "host-socket-symlink-removed": lambda: host_socket_symlink(remove=True)}[sys.argv[1]]()
