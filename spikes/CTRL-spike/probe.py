#!/usr/bin/env python3
"""Run on the unit; each subcommand writes results/<spike>-<model>.json (run check.py on it)."""
import argparse
import json
import os
import re
import subprocess

AP_CONF = """interface={iface}
ssid=CTRL-SPIKE-CANARY
country_code=US
hw_mode=g
channel=6
ieee80211w=2
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
sae_pwe=2
wpa_passphrase=canary-passphrase-not-real
ap_isolate=1
"""


def write(a, m):
    m["model"] = a.model
    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, "%s-%s.json" % (m["spike"], a.model))
    with open(path, "w") as f:
        json.dump(m, f, indent=1)
    print(path)


def boot(a):
    cmdline = open("/proc/cmdline").read()
    write(a, {"spike": "boot", "key_presses": a.key_presses,
              "boot_marker_seen": "agentos.stick=1" in cmdline})


def usb4(a):
    out = subprocess.run(["iperf3", "-c", a.server, "-t", "60", "-J"], capture_output=True, text=True, check=True).stdout
    r = json.loads(out)["end"]
    write(a, {"spike": "usb4", "duration_s": json.loads(out)["start"]["test_start"]["duration"],
              "mbit_per_s": r["sum_received"]["bits_per_second"] / 1e6,
              "stalls": r["sum_sent"].get("retransmits", 0)})


def ap(a):
    iw = subprocess.run(["iw", "list"], capture_output=True, text=True).stdout
    modes = re.search(r"Supported interface modes:(.*?)\n\t[A-Z]", iw, re.S)
    conf = os.path.join(a.out, "hostapd-%s.conf" % a.model)
    os.makedirs(a.out, exist_ok=True)
    with open(conf, "w") as f:
        f.write(AP_CONF.format(iface=a.iface))
    write(a, {"spike": "ap", "ap_mode_listed": bool(modes and "* AP\n" in modes.group(1) + "\n"),
              "akm": ["SAE"], "client_isolation": "ap_isolate=1" in AP_CONF,
              "phone_joined": a.phone_joined, "held_s": a.held_s})


p = argparse.ArgumentParser()
p.add_argument("--model", default="M6U")
p.add_argument("--out", default="results")
sub = p.add_subparsers(dest="cmd", required=True)
b = sub.add_parser("boot")
b.add_argument("--key-presses", type=int, required=True)
b.set_defaults(f=boot)
u = sub.add_parser("usb4")
u.add_argument("--server", required=True)
u.set_defaults(f=usb4)
w = sub.add_parser("ap")
w.add_argument("--iface", default="wlan0")
w.add_argument("--held-s", type=int, default=0)
w.add_argument("--phone-joined", action="store_true")
w.set_defaults(f=ap)

if __name__ == "__main__":
    a = p.parse_args()
    a.f(a)
