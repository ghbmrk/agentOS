# Stub tool for tests/test_codex_worker.py: an ordinary tool command run through agentos-toolsh.
# It tries the paths a tool holding the placeholder could use to reach the provider (the
# forwarder's loopback port, the egress socket, the CLI's auth.json and environment) and reports
# what it reached as one JSON object, echoing what it could read so the caller can look for the
# synthetic canary, and which of HOME, TMPDIR, /tmp and CODEX_HOME it can write. It also reports
# what would let it undo the sandbox: capabilities, a nested user namespace, the CLI's session,
# the worker's /tmp, descriptors the CLI left open.
# argv: "probe" and the forwarder port, or "beat" (append to ./beat until killed, at most 10s).
import ctypes
import json
import os
import pathlib
import socket
import sys
import time

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


def can_write_env(name):
    """Whether the directory the named variable points at is set and writable."""
    value = os.environ.get(name)
    return bool(value) and can_write(os.path.join(value, ".agentos-probe"))


def sees_cli():
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                if b"stub_cli.py" in pathlib.Path("/proc", pid, "cmdline").read_bytes():
                    return True
            except OSError:
                pass
    return False


def has_caps():
    for line in pathlib.Path("/proc/self/status").read_text().splitlines():
        if line.startswith("CapEff:"):
            return int(line.split()[1], 16) != 0
    return True


def nested_userns():
    pid = os.fork()
    if pid == 0:
        libc = ctypes.CDLL(None, use_errno=True)
        os._exit(0 if libc.unshare(0x10000000) == 0 else 1)  # CLONE_NEWUSER
    return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) == 0


def inherited_fds():
    fds = []
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd > 2:
            try:
                os.fstat(fd)  # the listing's own descriptor is closed by now
                fds.append(fd)
            except OSError:
                pass
    return fds


def interfaces():
    try:
        return sorted(name for _, name in socket.if_nameindex())
    except OSError:  # the CLI's own sandbox filters netlink sockets
        return None


def beat():
    end = time.monotonic() + 10
    while time.monotonic() < end:
        with open("beat", "a") as f:
            f.write(".")
        time.sleep(0.1)


def main():
    if sys.argv[1] == "beat":
        return beat()
    port = int(sys.argv[2])
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
        "home_write": can_write_env("HOME"),
        "tmpdir_write": can_write_env("TMPDIR"),
        "slash_tmp_write": can_write("/tmp/agentos-probe"),
        "codex_home_write": can_write("/var/lib/agentos-codex/probe"),
        "ifaces": interfaces(),
        "caps": has_caps(),
        "userns": nested_userns(),
        "session": os.getsid(0) == 0,  # 0: the session leader is outside the pid namespace
        "tmp": any(os.listdir(d) for d in ("/tmp", "/var/tmp")),
        "fds": inherited_fds(),
    }))


if __name__ == "__main__":
    main()
