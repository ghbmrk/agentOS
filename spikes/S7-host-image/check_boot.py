"""Assert S7 boot facts from a QEMU serial log (lines printed by mkosi.extra/usr/lib/s7/probe.sh)."""
import re
import sys

REQUIRED = {
    "secureboot": lambda v: "SecureBoot enabled" in v,
    "usr": lambda v: v == "/dev/mapper/usr",
    "usr_ro": lambda v: v == "ro",
    "bootdisk": lambda v: v == "usb",
    "tpm": lambda v: v == "/dev/tpmrm0",
    "mm": lambda v: "ModemManager" in v and "NetworkManager" in v,
}


def parse(text):
    facts = {}
    for m in re.finditer(r"S7: (\w+)=(.*?)\r?$", text, re.M):
        facts[m.group(1)] = m.group(2).strip()
    return facts


def check(text):
    facts = parse(text)
    failures = [k for k, ok in REQUIRED.items() if not ok(facts.get(k, ""))]
    return facts, failures


if __name__ == "__main__":
    facts, failures = check(open(sys.argv[1], errors="replace").read())
    for k, v in sorted(facts.items()):
        print(f"{k}: {v}")
    print("FAIL: " + ", ".join(failures) if failures else "PASS")
    sys.exit(1 if failures else 0)
