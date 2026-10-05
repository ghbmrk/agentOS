"""AgentOS S1/S2 test kit: runs once per boot, screenless.

Two boot entries share one kernel and /usr and differ only in `agentos.tk=`:
  rollback (+2 tries, sorts first): probe the PC, then reboot WITHOUT blessing the entry;
  good     (+3 tries): reached only when systemd-boot falls back. Records the verdict, runs S2 if
           enabled, re-arms both counters for the next PC, and powers off.
So a PC that powers itself off a few minutes after the power button has booted from USB, survived
two warm reboots, and rolled back automatically. Results go to the drive's FAT partition TESTKIT.
Nothing written there identifies the PC or a person: no serials, MACs, IMEI/ICCID, or phone numbers."""
import hashlib
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

VENDOR_GUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
STATE = "/var/lib/testkit/state.json"
STICK = "/run/testkit/stick"
TRIES = {"rollback": 2, "good": 3}


def sh(cmd, timeout=600):
    try:
        r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception as e:  # a probe must never stop the run
        return "error: %s" % e


def read(path, default=""):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def efivar(name):
    try:
        with open("/sys/firmware/efi/efivars/%s-%s" % (name, VENDOR_GUID), "rb") as f:
            return f.read()[4:].decode("utf-16-le").rstrip("\0")
    except OSError:
        return ""


def clean(s, n=24):
    return re.sub(r"[^A-Za-z0-9_-]+", "-", s).strip("-")[:n] or "unknown"


def entry_mode(cmdline):
    m = re.search(r"\bagentos\.tk=(\w+)", cmdline)
    return m.group(1) if m else "good"


def machine_id():
    dmi = "/sys/class/dmi/id/"
    u = read(dmi + "product_uuid").lower()
    if not u or set(u) <= set("f0-"):
        u = read(dmi + "sys_vendor") + read(dmi + "product_name") + read(dmi + "board_name")
    return hashlib.sha256(u.encode()).hexdigest()[:8]


def valid_number(n):
    """E.164 only: also keeps the number safe to pass to mmcli, and stops a typo texting a stranger."""
    return re.fullmatch(r"\+\d{7,15}", n) is not None


def boot_times():
    """Firmware and loader time from systemd-boot's variables, then kernel start to this probe."""
    init, exe = efivar("LoaderTimeInitUSec"), efivar("LoaderTimeExecUSec")
    up = float(read("/proc/uptime", "0 0").split()[0])
    if init.isdigit() and exe.isdigit():
        return "firmware %.1f s, boot menu %.1f s, kernel to probe %.1f s" % (
            int(init) / 1e6, (int(exe) - int(init)) / 1e6, up)
    return "kernel to probe %.1f s" % up


def entry_name(name, tries):
    """Boot Loader Specification counter: NAME+LEFT[-DONE].conf"""
    return "%s+%d.conf" % (name, tries)


def rearm_names(files):
    """Map current entry file names to their re-armed names (only those that change)."""
    out = {}
    for f in files:
        m = re.match(r"(agentos-tk-(rollback|good))(\+\d+(-\d+)?)?\.conf$", f)
        if m:
            new = entry_name(m.group(1), TRIES[m.group(2)])
            if new != f:
                out[f] = new
    return out


def decide(entry, st, machine):
    """Pure state machine. Returns (new_state, actions)."""
    fresh = st.get("machine") != machine or st.get("done", True)
    if fresh:
        st = {"machine": machine, "rb_boots": 0, "done": False, "rearmed": False, "probed": False}
    else:
        st = dict(st)
    acts = ["new_run"] if fresh else []
    if not st["probed"]:
        st["probed"] = True
        acts.append("probe")
    if entry == "rollback":
        st["rb_boots"] += 1
        acts.append("reboot")
    elif st["rb_boots"] == 0 and not st["rearmed"]:
        # Counters were spent by an earlier, interrupted run: arm them and try the sequence once.
        st["rearmed"] = True
        acts += ["rearm", "reboot"]
    else:
        st["done"] = True
        acts += ["verdict", "s2", "rearm", "poweroff"]
    return st, acts


def verdict(st):
    n = st["rb_boots"]
    if n >= TRIES["rollback"]:
        return "PASS: fell back to the good entry after %d unblessed boots; warm reboots stayed on USB" % n
    if n:
        return "PARTIAL: good entry reached after %d unblessed boot(s), expected %d" % (n, TRIES["rollback"])
    return "FAIL: the rollback entry was never selected"


# ---- side effects -------------------------------------------------------------------------------

def boot_disk():
    """(disk, partitions) of the disk systemd-boot was started from."""
    puuid = efivar("LoaderDevicePartUUID").lower()
    tree = json.loads(sh("lsblk -J -o NAME,PKNAME,PARTLABEL,PARTUUID,TYPE,TRAN,MODEL") or "{}")
    devs = []

    def walk(ns):
        for n in ns:
            devs.append(n)
            walk(n.get("children", []))
    walk(tree.get("blockdevices", []))
    esp = next((d for d in devs if (d.get("partuuid") or "").lower() == puuid and puuid), None)
    disk = esp and next((d for d in devs if d["name"] == esp.get("pkname")), None)
    parts = [d for d in devs if disk and d.get("pkname") == disk["name"]]
    return disk, parts


def mount_stick(parts):
    p = next((d for d in parts if d.get("partlabel") == "TESTKIT"), None)
    if not p:
        return None
    os.makedirs(STICK, exist_ok=True)
    if sh("findmnt -n %s" % STICK) == "":
        sh("mount -o rw,sync /dev/%s %s" % (p["name"], STICK))
    return STICK if os.path.isdir(STICK + "/results") or sh("mkdir -p %s/results" % STICK) == "" else None


def esp_path():
    p = sh("bootctl --print-esp-path")
    return p if p.startswith("/") and os.path.isdir(p + "/loader") else None


def entries(esp):
    try:
        return sorted(os.listdir(esp + "/loader/entries"))
    except (OSError, TypeError):
        return []


def rearm(esp):
    d = esp + "/loader/entries"
    for old, new in rearm_names(entries(esp)).items():
        os.rename(os.path.join(d, old), os.path.join(d, new))
    sh("sync")


def usb_speed(disk):
    """Negotiated link of the boot disk, from sysfs."""
    if not disk:
        return "unknown"
    p = os.path.realpath("/sys/block/%s" % disk["name"])
    if disk.get("tran") == "nvme":
        return "PCIe (external drive: USB4/Thunderbolt tunnel)"
    while p != "/":
        if os.path.exists(p + "/speed") and os.path.exists(p + "/idVendor"):
            return read(p + "/speed") + " Mbps (" + read(p + "/version").strip() + ")"
        p = os.path.dirname(p)
    return "not USB (%s)" % disk.get("tran")


def read_verify():
    """Read all of /usr through dm-verity (S7 surprise 2): any bad read is a hard error."""
    sh("sync; echo 3 > /proc/sys/vm/drop_caches")
    size = int(sh("blockdev --getsize64 /dev/mapper/usr") or 0)
    t = time.monotonic()
    out = sh("dd if=/dev/mapper/usr of=/dev/null bs=4M status=none; echo rc=$?", timeout=1800)
    dt = time.monotonic() - t
    errs = sh("journalctl -k -b --no-pager | grep -ciE 'verity.*(corrupt|error)'")
    ok = out.endswith("rc=0") and errs.strip() == "0"
    return "%s, %d MiB in %.1f s (%.0f MB/s), verity errors in kernel log: %s" % (
        "PASS" if ok else "FAIL", size >> 20, dt, size / dt / 1e6 if dt else 0, errs)


# PE2: the RES-2 floor budget, MiB, and agentosd's default machine budgets (-agent-mem-mb,
# -replay-mem-mb, -headroom-mb; broker/cmd/agentosd/main.go). What remains after host, inference,
# browser and headroom is the agent-machine pool; it must hold the agent and one replay machine.
FLOOR = {"host": 1024, "inference": 2048, "browser": 512, "headroom": 600}
AGENT_MB, REPLAY_MB = 1536, 1024


def floor_fit(meminfo):
    """Whether the agent machine and one replay machine fit in this PC's pool (PE2), from /proc/meminfo."""
    m = re.search(r"MemTotal:\s+(\d+)", meminfo)
    if not m:
        return "unknown: MemTotal unreadable"
    total = int(m.group(1)) >> 10
    pool = total - sum(FLOOR.values())
    need = AGENT_MB + REPLAY_MB
    return "%s: pool %d MiB (MemTotal %d - host %d - inference %d - browser %d - headroom %d) for agent %d + one replay %d = %d; agentosd -capacity-mb %d here (its default: this, at most 4500)" % (
        "PASS" if pool >= need else "FAIL", pool, total, FLOOR["host"], FLOOR["inference"], FLOOR["browser"],
        FLOOR["headroom"], AGENT_MB, REPLAY_MB, need, min(pool + FLOOR["headroom"], 4500))


def probe(disk):
    dmi = "/sys/class/dmi/id/"
    tpm = read("/sys/class/tpm/tpm0/tpm_version_major")
    mem = re.search(r"MemTotal:\s+(\d+)", read("/proc/meminfo"))
    cpu = re.search(r"model name\s*:\s*(.*)", read("/proc/cpuinfo"))
    return [
        ("pc", "%s %s" % (read(dmi + "sys_vendor"), read(dmi + "product_name"))),
        ("board", "%s %s" % (read(dmi + "board_vendor"), read(dmi + "board_name"))),
        ("firmware", "%s %s %s" % (read(dmi + "bios_vendor"), read(dmi + "bios_version"), read(dmi + "bios_date"))),
        ("cpu", "%s, %d threads" % (cpu.group(1) if cpu else "?", os.cpu_count() or 0)),
        ("ram_gb", "%.1f" % (int(mem.group(1)) / 1048576) if mem else "?"),
        ("agent_and_replay_fit", floor_fit(read("/proc/meminfo"))),
        ("secure_boot", sh("mokutil --sb-state").splitlines()[0] if sh("mokutil --sb-state") else "?"),
        ("loader", efivar("LoaderInfo") or "not systemd-boot"),
        ("found_root_via_gpt_auto", "yes" if efivar("LoaderDevicePartUUID") else "no"),
        ("boot_disk", "%s, transport %s" % ((disk or {}).get("model") or "?", (disk or {}).get("tran"))),
        ("usb_link", usb_speed(disk)),
        ("tpm", "TPM %s.0 at /dev/tpmrm0" % tpm if tpm and os.path.exists("/dev/tpmrm0") else "none found"),
        ("boot_time", boot_times()),
        ("usr", "%s %s" % (sh("findmnt -no SOURCE /usr"), sh("veritysetup status usr | grep -m1 status").strip())),
        ("usr_read_verify", read_verify()),
        ("usb_devices", ", ".join(sorted({l.split("ID ")[1][:9] for l in sh("lsusb").splitlines() if "ID " in l}))),
    ]


class Report:
    def __init__(self, stick, run, name):
        self.path = stick and os.path.join(stick, "results", "%02d-%s.txt" % (run, name))

    def add(self, k, v):
        line = "%s: %s" % (k, v)
        print("TESTKIT " + line, flush=True)
        if self.path:
            with open(self.path, "a") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())


def load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".tmp", "w") as f:
        json.dump(obj, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(path + ".tmp", path)


def main():
    entry = entry_mode(read("/proc/cmdline"))
    disk, parts = boot_disk()
    stick = mount_stick(parts)
    esp = esp_path()
    old = load(STATE, {})
    st, acts = decide(entry, old, machine_id())
    if "new_run" in acts:
        st["run"] = 1 + len([f for f in os.listdir(stick + "/results") if f.endswith(".txt")]) if stick else 0
        st["name"] = clean(read("/sys/class/dmi/id/sys_vendor").split()[0] if read("/sys/class/dmi/id/sys_vendor")
                           else "pc") + "-" + clean(read("/sys/class/dmi/id/product_name"))
    rep = Report(stick, st["run"], st["name"])
    rep.add("boot", "%s entry (%s), entries now: %s" % (entry, efivar("LoaderEntrySelected"), " ".join(entries(esp))))
    if "probe" in acts:
        rep.add("run", "%d, %s UTC, test kit v%s" % (st["run"], time.strftime("%Y-%m-%d %H:%M"),
                                                    sh(". /usr/lib/os-release; echo $IMAGE_VERSION")))
        for k, v in probe(disk):
            rep.add(k, v)
    if "verdict" in acts:
        v = verdict(st)
        rep.add("rollback", v)
        rep.add("blessed", "good entry blessed: %s" % ("yes" if "agentos-tk-good.conf" in entries(esp) else "no"))
    if "rearm" in acts and esp:
        rearm(esp)
    if "s2" in acts and stick:
        conf = dict(re.findall(r"^\s*([A-Z_]+)\s*=\s*(\S*)", read(stick + "/s2.conf"), re.M))
        if conf.get("RUN_S2", "").lower() != "yes":
            rep.add("s2", "skipped (RUN_S2 is not yes in s2.conf)")
        elif not valid_number(conf.get("OWNER_NUMBER", "")):
            rep.add("s2", "skipped: OWNER_NUMBER must be + and country code then 7-15 digits, no spaces")
        else:
            import s2
            for k, v in s2.run(conf, os.path.join(stick, "private")):
                rep.add("s2_" + k, v)
    save(STATE, st)
    if "poweroff" in acts and stick:
        with open(os.path.join(stick, "results", "SUMMARY.csv"), "a") as f:
            f.write("%02d,%s,%s,%s\n" % (st["run"], st["name"], time.strftime("%Y-%m-%d"), verdict(st).split(":")[0]))
    sh("sync")
    if "reboot" in acts:
        sh("systemctl reboot")
    elif "poweroff" in acts:
        rep.add("done", "powering off")
        sh("systemctl poweroff")


if __name__ == "__main__":
    main()
