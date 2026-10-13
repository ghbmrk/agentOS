# Stub Codex CLI for tests/test_codex_worker.py: plays the CLI inside a stub worker. It shows it
# reaches the forwarder's loopback port, the egress socket, the placeholder auth.json and its own
# environment, then runs the stub tool through agentos-toolsh as the real CLI runs a tool command,
# and prints one JSON object. argv: forwarder port, synthetic canary.
import json
import os
import pathlib
import socket
import subprocess
import sys

SOCK = "/run/agentos/egress.sock"
AUTH = "/var/lib/agentos-codex/auth.json"
TOOLSH = "/usr/local/bin/agentos-toolsh"
STUB_TOOL = pathlib.Path(__file__).resolve().parent / "stub_tool.py"


def reaches(family, addr):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect(addr)
            s.sendall(b"ping\n")
            return s.recv(8) == b"ok\n"
    except OSError:
        return False


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
    r = subprocess.run([TOOLSH, sys.executable, "-I", str(STUB_TOOL), str(port)],
                       capture_output=True, text=True, timeout=30)
    try:
        tool = json.loads(r.stdout)
    except ValueError:
        tool = {"stderr": r.stderr[-2000:]}
    tool["exit"] = r.returncode
    tool["env"] = "AGENTOS_SYNTHETIC_CANARY" in tool.get("environ", {})
    tool["canary_anywhere"] = canary in r.stdout or canary in r.stderr
    tool.pop("environ", None)
    tool.pop("auth_text", None)
    print(json.dumps({"cli": cli, "tool": tool}))


if __name__ == "__main__":
    main()
