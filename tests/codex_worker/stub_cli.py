# Stub Codex CLI for tests/test_codex_worker.py: plays the CLI inside a stub worker. It shows it
# reaches the forwarder's loopback port, the egress socket, the placeholder auth.json and its own
# environment, then runs the stub tool through agentos-toolsh as the real CLI runs a tool command,
# handing it open descriptors to auth.json and the egress socket and leaving scratch files in
# /tmp and /var/tmp, and prints one JSON object. Last it starts a tool that keeps writing to the
# workspace, kills the wrapper and reports whether the tool outlived it.
# argv: forwarder port, synthetic canary.
import json
import os
import pathlib
import socket
import subprocess
import sys
import time

SOCK = "/run/agentos/egress.sock"
AUTH = "/var/lib/agentos-codex/auth.json"
TOOLSH = "/usr/local/bin/agentos-toolsh"
STUB_TOOL = "/var/lib/agentos-stub-tool.py"  # mounted there by the test


def reaches(family, addr):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect(addr)
            s.sendall(b"ping\n")
            return s.recv(8) == b"ok\n"
    except OSError:
        return False


def outlives_wrapper():
    beat = pathlib.Path("beat")
    beat.unlink(missing_ok=True)
    p = subprocess.Popen([TOOLSH, sys.executable, "-I", STUB_TOOL, "beat"])
    deadline = time.monotonic() + 10
    while not beat.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    p.kill()  # toolsh exec'd bwrap, so this is the wrapper's bwrap
    p.wait()
    time.sleep(0.5)
    before = beat.stat().st_size if beat.exists() else 0
    time.sleep(1.5)
    after = beat.stat().st_size if beat.exists() else 0
    return after > before


def main():
    port, canary = int(sys.argv[1]), sys.argv[2]
    try:
        auth = canary in pathlib.Path(AUTH).read_text()
    except OSError:
        auth = False
    cli = {
        "tcp": reaches(socket.AF_INET, ("127.0.0.1", port)),
        "unix": reaches(socket.AF_UNIX, SOCK),
        "auth": auth,
        "env": os.environ.get("AGENTOS_SYNTHETIC_CANARY") == canary,
    }
    for d in ("/tmp", "/var/tmp"):
        pathlib.Path(d, "agentos-cli-scratch").write_text("cli scratch\n")
    held = os.open(AUTH if os.path.exists(AUTH) else "/etc/hostname", os.O_RDONLY)
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.connect(SOCK)
    r = subprocess.run([TOOLSH, sys.executable, "-I", STUB_TOOL, "probe", str(port)],
                       capture_output=True, text=True, timeout=30, pass_fds=(held, conn.fileno()))
    os.close(held)
    conn.close()
    try:
        tool = json.loads(r.stdout)
    except ValueError:
        tool = {"stderr": r.stderr[-2000:]}
    tool["exit"] = r.returncode
    tool["env"] = "AGENTOS_SYNTHETIC_CANARY" in tool.get("environ", {})
    tool["canary_anywhere"] = canary in r.stdout or canary in r.stderr
    tool.pop("environ", None)
    tool.pop("auth_text", None)
    tool["outlives"] = outlives_wrapper()
    print(json.dumps({"cli": cli, "tool": tool}))


if __name__ == "__main__":
    main()
