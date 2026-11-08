#!/usr/bin/env python3
"""CI's camera decoder step (CAM-decoder-uid, #4134; #4392): the image's own systemd runs the shipped
agentos-camdecode.socket and agentos-camdecode@.service over TREE (image/offline_systemd.py Manager), so
the unit's settings act as on the box, PrivatePIDs= (systemd 257) among them, which the runner's systemd
ignores. TREE holds the units and the step's drop-in in /etc/systemd/system, CLERK_USER with the
runner's uid, and the session test's files under /usr. As CLERK_USER, two sessions open at once
(camdecode_sessions.py); another user is refused the socket; each session's test output, which the
drop-in sends to LOGS in TREE, must show its test passed.

The socket is in the manager's own /run, reached through a descriptor of its directory taken as root
(/proc/PID/root); the client connects through /proc/self/fd, as itself, so the socket's owner and mode
are what admit it.

Usage: camdecode_unit.py TREE CLERK_USER LOGS"""
import os
import pathlib
import pwd
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "image"))
import offline_systemd  # noqa: E402

TEST = "TestDecoderStartsInItsUnit"
SESSIONS = 2


def as_user(user, argv, fd):
    return subprocess.run(["setpriv", "--reuid=" + user, "--regid=" + user, "--clear-groups"] + argv,
                          pass_fds=(fd,), cwd="/", capture_output=True, text=True, timeout=600)


def check_logs(texts):
    """The failures in the sessions' test outputs TEXTS: one PASS of TEST each, and no SKIP or FAIL."""
    out = []
    if len(texts) != SESSIONS:
        out.append("%d session logs, want %d" % (len(texts), SESSIONS))
    for name, t in sorted(texts.items()):
        if t.count("--- PASS: %s" % TEST) != 1 or "--- SKIP" in t or "--- FAIL" in t:
            out.append("%s: %s did not pass once" % (name, TEST))
    return out


def main(tree, clerk, logs):
    uid = pwd.getpwnam(clerk).pw_uid
    m = offline_systemd.Manager(tree, os.path.join(tree, "usr"), "")
    try:
        m.ctl(["start", "agentos-camdecode.socket"])
        print("the image's systemd", m.manager(("Version",))["Version"])
        fd = os.open("/proc/%d/root/run/agentos-camdecode" % m.pid, os.O_RDONLY | os.O_DIRECTORY)
        sock = "/proc/self/fd/%d/conn.sock" % fd
        fails = []
        # The clerk's user cannot read the runner's checkout: the client goes as its text.
        client = (HERE / "camdecode_sessions.py").read_text()
        r = as_user(clerk, ["python3", "-I", "-c", client, sock, str(uid)], fd)
        print(r.stdout + r.stderr)
        if r.returncode != 0:
            fails.append("the clerk's sessions failed")
        r = as_user("nobody", ["python3", "-I", "-c", "import socket, sys; socket.socket(socket.AF_UNIX).connect(sys.argv[1])",
                               sock], fd)
        if r.returncode == 0:
            fails.append("nobody opened a decoder session")
        os.close(fd)
        d = pathlib.Path("/proc/%d/root" % m.pid) / logs.lstrip("/")
        texts = {p.name: p.read_text(errors="replace") for p in sorted(d.glob("*.log"))} if d.is_dir() else {}
        for name, t in sorted(texts.items()):
            print("== %s\n%s" % (name, t[-6000:]))
        fails += check_logs(texts)
        if fails:
            print(m.ctl(["list-units", "--all", "--no-pager", "agentos-camdecode*"], check=False).stdout)
            print(m.console())
        for f in fails:
            print("FAIL:", f)
        return 1 if fails else 0
    finally:
        m.stop()


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))
