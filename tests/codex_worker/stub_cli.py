# Stub Codex CLI for tests/test_codex_worker.py: plays the CLI inside a stub worker. It shows it
# reaches the forwarder's loopback port, the egress socket, the placeholder auth.json and its own
# environment, then runs the stub tool through agentos-toolsh as the real CLI runs a tool command,
# handing it open descriptors to auth.json and the egress socket (low ones and ones above 9, which
# a wrapper closing only 3 to 9, as dash could, would leave open) and leaving scratch files in
# /tmp and /var/tmp, and prints one JSON object. Last it starts a tool that keeps writing to the
# workspace, kills the wrapper and reports whether the tool outlived it. It marks each phase on
# stderr, so a test that stalls can say where (#1542).
# argv: forwarder port, synthetic canary, and optionally --skip-outlives, which skips the last
# phase and leaves the outlives verdict out, for a run that asks only about descriptors, and
# --beat-wait=N, the seconds the last phase waits for its tool to start (default BEAT_WAIT).
import json
import os
import pathlib
import resource
import socket
import subprocess
import sys
import time

SOCK = "/run/agentos/egress.sock"
AUTH = "/var/lib/agentos-codex/auth.json"
TOOLSH = "/usr/local/bin/agentos-toolsh"
HIGH_FDS = (200, 1000)  # auth.json at n, the socket at n+1; above 9, where dash cannot reach
STUB_TOOL = "/var/lib/agentos-stub-tool.py"  # mounted there by the test
# A new network namespace can wait many seconds on the kernel tearing down old ones (CI runs
# this right after the netns tests), so the wait is long; a worker's deadline still bounds it.
BEAT_WAIT = 45


T0 = time.monotonic()


def phase(name):
    print(f"stub_cli: {time.monotonic() - T0:.1f}s {name}", file=sys.stderr, flush=True)


def reaches(family, addr):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect(addr)
            s.sendall(b"ping\n")
            return s.recv(8) == b"ok\n"
    except OSError:
        return False


def outlives_wrapper(wait):
    """Whether the beat tool outlived its killed wrapper; None, no verdict, if it never started."""
    beat = pathlib.Path("beat")
    beat.unlink(missing_ok=True)
    # No pipe of the worker's rides along: a tool that lingers must not hold its output open.
    # Its own process group, so a wrapper killed mid-setup leaves nothing behind (below).
    p = subprocess.Popen([TOOLSH, sys.executable, "-I", STUB_TOOL, "beat"],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + wait
    while not beat.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    started = beat.exists()
    phase("beat started" if started else "beat never started; no verdict")
    p.kill()  # toolsh exec'd bwrap, so this is the wrapper's bwrap
    p.wait()
    if started:
        time.sleep(0.5)
        before = beat.stat().st_size
        time.sleep(1.5)
        after = beat.stat().st_size
        phase("beat checked")
    # A wrapper killed before its tool started can leave its sandbox's first process stuck in
    # setup; in a pid namespace that holds the whole worker open (#1542). It has not yet left
    # the group for the tool's own session, so the group reaches it, and never the tool.
    try:
        os.killpg(p.pid, 9)
    except ProcessLookupError:
        pass
    return after > before if started else None


def main():
    port, canary, *flags = sys.argv[1:]
    port = int(port)
    skip = "--skip-outlives" in flags
    waits = [f for f in flags if f.startswith("--beat-wait=")]
    if len(flags) != skip + len(waits) or len(waits) > 1:
        print(f"stub_cli: unknown flags {flags}", file=sys.stderr)
        sys.exit(2)
    try:
        beat_wait = float(waits[0].partition("=")[2]) if waits else BEAT_WAIT
    except ValueError:
        print(f"stub_cli: bad flag {waits[0]}", file=sys.stderr)
        sys.exit(2)
    phase("started")
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
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    top = max(HIGH_FDS) + 2
    if soft < top:
        resource.setrlimit(resource.RLIMIT_NOFILE, (top, max(hard, top)))
    passed = [held, conn.fileno()]
    for high in HIGH_FDS:
        passed.append(os.dup2(held, high))
        passed.append(os.dup2(conn.fileno(), high + 1))
    phase("cli checked; probing")
    r = subprocess.run([TOOLSH, sys.executable, "-I", STUB_TOOL, "probe", str(port)],
                       capture_output=True, text=True, timeout=30, pass_fds=tuple(passed))
    phase(f"probe exited {r.returncode}")
    for fd in passed[2:]:
        os.close(fd)
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
    if skip:
        phase("outlives skipped")
    else:
        tool["outlives"] = outlives_wrapper(beat_wait)
    print(json.dumps({"cli": cli, "tool": tool}))


if __name__ == "__main__":
    main()
