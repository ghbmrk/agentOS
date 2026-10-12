#!/usr/bin/env python3
"""Score CTRL-spike measurements against QUESTION.md's pass rules.

Usage: check.py results/*.json   (exit 1 if any spike fails or is incomplete)
"""
import json
import sys

USB4_MIN_MBIT = 2350  # 94% of a 2.5GbE port 2; USB4 must at least match it
USB4_MIN_S = 60
AP_MIN_HELD_S = 600


def score(m):
    """Return (ok, [reasons]) for one measurement dict."""
    kind = m.get("spike")
    why = []
    if kind == "boot":
        if m.get("key_presses") != 0:
            why.append("key presses: %r (need 0)" % m.get("key_presses"))
        if m.get("boot_marker_seen") is not True:
            why.append("stick boot marker not seen")
    elif kind == "usb4":
        if not isinstance(m.get("duration_s"), (int, float)) or m["duration_s"] < USB4_MIN_S:
            why.append("ran %r s (need >= %d)" % (m.get("duration_s"), USB4_MIN_S))
        if not isinstance(m.get("mbit_per_s"), (int, float)) or m["mbit_per_s"] < USB4_MIN_MBIT:
            why.append("%r Mbit/s (need >= %d)" % (m.get("mbit_per_s"), USB4_MIN_MBIT))
        if m.get("stalls") != 0:
            why.append("stalls: %r (need 0)" % m.get("stalls"))
    elif kind == "ap":
        if m.get("ap_mode_listed") is not True:
            why.append("AP mode not listed by the radio")
        if m.get("akm") != ["SAE"]:
            why.append("key management %r (need only SAE)" % (m.get("akm"),))
        if m.get("client_isolation") is not True:
            why.append("client isolation off")
        if m.get("phone_joined") is not True:
            why.append("phone did not join")
        if not isinstance(m.get("held_s"), (int, float)) or m["held_s"] < AP_MIN_HELD_S:
            why.append("held %r s (need >= %d)" % (m.get("held_s"), AP_MIN_HELD_S))
    else:
        why.append("unknown spike %r" % kind)
    return not why, why


def main(paths):
    bad = 0
    for p in paths:
        with open(p) as f:
            m = json.load(f)
        ok, why = score(m)
        print("%s %s %s %s" % ("PASS" if ok else "FAIL", m.get("spike"), m.get("model"), "; ".join(why)))
        bad += not ok
    return 1 if bad or not paths else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
