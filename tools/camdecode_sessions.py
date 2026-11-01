#!/usr/bin/env python3
"""CI's camera decoder step (CAM-decoder-uid, #4134): open two decoder sessions at once on SOCK, as the
clerk's user, and check that each session's first line names a uid that is neither root, CLERK_UID nor the
other session's; then read each to its end, when its unit's test has finished.

Usage: camdecode_sessions.py SOCK CLERK_UID"""
import socket
import sys


def main(sock, clerk_uid):
    conns = []
    for _ in range(2):
        c = socket.socket(socket.AF_UNIX)
        c.settimeout(300)
        c.connect(sock)
        conns.append(c)
    uids = []
    for c in conns:
        line = c.makefile("rb").readline().decode("ascii", "replace").strip()
        print("session:", line)
        if not line.startswith("uid ") or not line[4:].isdigit():
            print("FAIL: no uid line")
            return 1
        uids.append(int(line[4:]))
    for c in conns:
        while c.recv(4096):
            pass
        c.close()
    if 0 in uids or clerk_uid in uids or uids[0] == uids[1]:
        print("FAIL: session uids %s, clerk's %d" % (uids, clerk_uid))
        return 1
    print("ok   two sessions, uids %s, neither root nor the clerk's %d" % (uids, clerk_uid))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], int(sys.argv[2])))
