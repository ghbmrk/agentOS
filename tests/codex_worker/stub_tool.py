# Stub tool for tests/test_codex_worker.py: an ordinary tool command run through agentos-toolsh.
# It tries the paths a tool holding the placeholder could use to reach the provider (the
# forwarder's loopback port, the egress socket, the CLI's auth.json and environment) and reports
# what it reached as one JSON object, echoing what it could read so the caller can look for the
# synthetic canary. argv: forwarder port.
import json
import os
import pathlib
import socket
import sys

SOCK = "/run/agentos/egress.sock"
AUTH = "/var/lib/agentos-codex/auth.json"


def reaches(family, addr):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect(addr)
            s.sendall(b"ping\n")
            return s.recv(8) == b"ok\n"
    except OSError:
        return False


def can_write(path):
    try:
        with open(path, "w") as f:
            f.write("probe\n")
        os.unlink(path)
        return True
    except OSError:
        return False


def sees_cli():
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                if b"stub_cli.py" in pathlib.Path("/proc", pid, "cmdline").read_bytes():
                    return True
            except OSError:
                pass
    return False


def main():
    port = int(sys.argv[1])
    try:
        auth_text = pathlib.Path(AUTH).read_text()
    except OSError:
        auth_text = None
    print(json.dumps({
        "tcp": reaches(socket.AF_INET, ("127.0.0.1", port)),
        "unix": reaches(socket.AF_UNIX, SOCK),
        "auth": auth_text is not None,
        "auth_text": auth_text,
        "environ": dict(os.environ),
        "parent": sees_cli(),
        "root_write": can_write("/etc/agentos-toolsh-probe"),
        "work_write": can_write("toolsh-probe"),
        "ifaces": sorted(name for _, name in socket.if_nameindex()),
    }))


if __name__ == "__main__":
    main()
