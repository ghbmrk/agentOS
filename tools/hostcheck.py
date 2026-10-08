#!/usr/bin/env python3
"""Host-untouched check (HOST-1e; spec A1, HW-8).

Records a host's state from outside the box, before it first boots and after
each phase of a session, and fails on any difference HW-8's disclosed list
(tools/hostcheck_hw8.json, keyed to broker/hostchange) does not allow:

  disk            SHA-256 of each internal disk, raw
  uefi            each persistent (non-volatile) UEFI variable
  tpm-nv          each TPM NV index: name (public area, written bit) and,
                  where it can be read without risking an authorization
                  failure, a hash of its data
  tpm-persistent  each persistent TPM object's name
  tpm-setting     hierarchy authorization flags and dictionary-attack settings
  rtc             hardware-clock writes (QEMU's RTC_CHANGE events)

Subcommands:
  snapshot  record one host state: disks by path, UEFI variables from an
            OVMF varstore or efivarfs, the TPM through a tpm2-tools TCTI
  diff      compare two snapshots against the HW-8 list
  qemu      the whole run on a QEMU/OVMF/swtpm host: two firmware-only boots
            (baseline and firmware noise), then each phase in its own QEMU
            process, a snapshot after each. The image is an input: the
            stand-in guest (tools/hostcheck_standin.sh) today, P2-1's later.

Exit status: 0 the host is as it was, 1 a difference HW-8 does not allow,
2 the check could not be made.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

CHUNK = 4 << 20
ALLOW = pathlib.Path(__file__).with_name("hostcheck_hw8.json")
KINDS = ("disk", "uefi", "tpm-nv", "tpm-persistent", "tpm-setting")
EFI_NON_VOLATILE = 0x1
NV_OWNERREAD, NV_READLOCKED, NV_WRITTEN = 1 << 17, 1 << 28, 1 << 29
TPM_SETTINGS = ("ownerAuthSet", "endorsementAuthSet", "lockoutAuthSet", "disableClear",
                "TPM2_PT_MAX_AUTH_FAIL", "TPM2_PT_LOCKOUT_INTERVAL", "TPM2_PT_LOCKOUT_RECOVERY")


class HostcheckError(Exception):
    pass


def run(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if p.returncode:
        raise HostcheckError(f"{cmd[0]} failed ({p.returncode}): {p.stderr.strip()[-500:]}")
    return p.stdout


# ---- sources ----

def hash_disk(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while b := f.read(CHUNK):
            h.update(b)
    return h.hexdigest()


def uefi_from_varstore(path):
    """Persistent variables in an OVMF varstore, read with virt-fw-vars."""
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "vars.json")
        run(["virt-fw-vars", "--input", str(path), "--output-json", out])
        doc = json.loads(pathlib.Path(out).read_text())
    vars_ = {}
    for v in doc["variables"]:
        attr = int(v["attr"])
        if attr & EFI_NON_VOLATILE:
            blob = v["data"] + "/" + v.get("time", "")
            vars_[f'{v["guid"].lower()}:{v["name"]}'] = {"attr": attr, "sha256": hashlib.sha256(blob.encode()).hexdigest()}
    return vars_


def uefi_from_efivarfs(directory):
    """Persistent variables as a live system sees them (an S1 PC, from a third system)."""
    vars_ = {}
    for p in sorted(pathlib.Path(directory).iterdir()):
        m = re.fullmatch(r"(.+)-([0-9a-fA-F-]{36})", p.name)
        if not m:
            continue
        b = p.read_bytes()
        attr = int.from_bytes(b[:4], "little")
        if attr & EFI_NON_VOLATILE:
            vars_[f"{m.group(2).lower()}:{m.group(1)}"] = {"attr": attr, "sha256": hashlib.sha256(b[4:]).hexdigest()}
    return vars_


def _handles(tcti, cap):
    return re.findall(r"^\s*-\s*(0x[0-9a-fA-F]+)", run(["tpm2_getcap", "-T", tcti, cap]), re.M)


def tpm_snapshot(tcti):
    """NV indices, persistent objects and settings. Reads NV data only with the
    owner hierarchy while its authorization is empty, so the check can never
    count an authorization failure against the host's TPM."""
    props = run(["tpm2_getcap", "-T", tcti, "properties-variable"])
    settings = {}
    for key in TPM_SETTINGS:
        m = re.search(rf"^\s*{key}:\s*(\S+)", props, re.M)
        if not m:
            raise HostcheckError(f"TPM property {key} not reported")
        settings[key] = int(m.group(1), 0)
    nv = {}
    for h in _handles(tcti, "handles-nv-index"):
        pub = run(["tpm2_nvreadpublic", "-T", tcti, h])
        name = re.search(r"^\s*name:\s*([0-9a-fA-F]+)", pub, re.M).group(1)
        attrs = int(re.search(r"attributes:\s*\n\s*friendly:.*\n\s*value:\s*(0x[0-9a-fA-F]+)", pub).group(1), 16)
        size = int(re.search(r"^\s*size:\s*(\d+)", pub, re.M).group(1))
        data = None
        if (attrs & NV_OWNERREAD and attrs & NV_WRITTEN and not attrs & NV_READLOCKED
                and not settings["ownerAuthSet"]):
            p = subprocess.run(["tpm2_nvread", "-T", tcti, "-C", "o", "-s", str(size), h],
                               capture_output=True)
            if p.returncode == 0:
                data = hashlib.sha256(p.stdout).hexdigest()
        nv[hex(int(h, 16))] = {"name": name, "attributes": attrs, "size": size, "data": data}
    persistent = {}
    for h in _handles(tcti, "handles-persistent"):
        out = run(["tpm2_readpublic", "-T", tcti, "-c", h])
        persistent[hex(int(h, 16))] = re.search(r"^name:\s*([0-9a-fA-F]+)", out, re.M).group(1)
    return {"tpm-nv": nv, "tpm-persistent": persistent, "tpm-setting": settings}


def snapshot(disks, varstore=None, efivarfs=None, tcti=None):
    s = {"disk": {name: hash_disk(p) for name, p in disks.items()}}
    if varstore:
        s["uefi"] = uefi_from_varstore(varstore)
    elif efivarfs:
        s["uefi"] = uefi_from_efivarfs(efivarfs)
    if tcti:
        s.update(tpm_snapshot(tcti))
    return s


# ---- diff against HW-8 ----

def load_allow(path=ALLOW):
    return json.loads(pathlib.Path(path).read_text())["rules"]


def diff(before, after):
    missing = [k for k in KINDS if (k in before) != (k in after) or k not in before]
    if missing:
        raise HostcheckError(f"snapshots do not both record {', '.join(missing)}")
    out = []
    for kind in KINDS:
        b, a = before[kind], after[kind]
        for key in sorted(set(b) | set(a)):
            if key not in a:
                out.append({"kind": kind, "key": key, "change": "removed", "before": b[key], "after": None})
            elif key not in b:
                out.append({"kind": kind, "key": key, "change": "added", "before": None, "after": a[key]})
            elif a[key] != b[key]:
                out.append({"kind": kind, "key": key, "change": "changed", "before": b[key], "after": a[key]})
    return out


def _matches(rule, f, flags):
    if rule["kind"] != f["kind"] or f["change"] not in rule["changes"]:
        return False
    if rule.get("requires") and rule["requires"] not in flags:
        return False
    if "key" in rule and not re.search(rule["key"], f["key"]):
        return False
    if "range" in rule:
        lo, hi = (int(x, 16) for x in rule["range"])
        if not lo <= int(f["key"], 16) <= hi:
            return False
    if "attributes" in rule and (f["after"]["attributes"] & ~NV_WRITTEN) != int(rule["attributes"], 16):
        return False
    if "size" in rule and f["after"]["size"] != rule["size"]:
        return False
    return True


def evaluate(before, after, allow, flags=(), noise=(), rtc_writes=()):
    """Sort every difference into flagged, disclosed (an HW-8 rule allows it)
    or noise (a UEFI variable the firmware changes on its own boots)."""
    report = {"flagged": [], "disclosed": [], "noise": []}
    for f in diff(before, after):
        rule = next((r for r in allow if _matches(r, f, set(flags))), None)
        if rule:
            report["disclosed"].append(dict(f, change_id=rule["change"]))
        elif f["kind"] == "uefi" and (f["kind"], f["key"]) in noise:
            report["noise"].append(f)
        else:
            report["flagged"].append(f)
    for w in rtc_writes:
        report["flagged"].append({"kind": "rtc", "key": w["phase"], "change": "written", "before": None, "after": w})
    report["pass"] = not report["flagged"]
    return report


# ---- QEMU host ----

class Qemu:
    """One QEMU process with OVMF, swtpm and the host's disks, driven through
    QMP (events: RTC_CHANGE, SHUTDOWN) and its serial console."""

    def __init__(self, args, work, label, boot=None):
        self.work, self.label = work, label
        self.events, self.console = [], bytearray()
        sock_dir = tempfile.mkdtemp(prefix="hc", dir="/tmp")  # unix socket paths stay short
        self.sock_dir = sock_dir
        tpm_sock = os.path.join(sock_dir, "tpm")
        self.swtpm = subprocess.Popen(["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={work / 'tpm'}",
                                       "--ctrl", f"type=unixio,path={tpm_sock}", "--terminate"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _wait_path(tpm_sock)
        accel = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
        cmd = ["qemu-system-x86_64", "-machine", "q35,smm=on", "-accel", accel, "-cpu", "max",
               "-smp", "2", "-m", "1024", "-nodefaults", "-display", "none", "-nic", "none",
               "-rtc", "base=utc,clock=host",
               "-global", "driver=cfi.pflash01,property=secure,value=on",
               "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={args.ovmf_code}",
               "-drive", f"if=pflash,format=raw,unit=1,file={work / 'vars.fd'}",
               "-chardev", f"socket,id=chrtpm,path={tpm_sock}",
               "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-crb,tpmdev=tpm0",
               "-chardev", f"socket,id=qmp,path={sock_dir}/qmp,server=on,wait=on",
               "-mon", "chardev=qmp,mode=control",
               "-chardev", f"socket,id=ser,path={sock_dir}/serial,server=on,wait=on",
               "-serial", "chardev:ser"]
        for i, (name, bus) in enumerate(args.host_disks_bus):
            path = work / "disks" / f"{name}.img"
            cmd += ["-drive", f"if=none,id=hd{i},format=raw,file={path}"]
            cmd += {"nvme": ["-device", f"nvme,drive=hd{i},serial=HOSTCHECK{i}"],
                    "virtio": ["-device", f"virtio-blk-pci,drive=hd{i}"],
                    "ahci": ["-device", f"ide-hd,drive=hd{i},bus=ide.{i}"]}[bus]
        if boot:
            cmd += boot
        self.proc = subprocess.Popen(cmd, stdout=open(work / f"qemu-{label}.log", "wb"), stderr=subprocess.STDOUT)
        self.qmp = _connect(f"{sock_dir}/qmp", self.proc)
        self.serial = _connect(f"{sock_dir}/serial", self.proc)  # QEMU starts once both are connected
        self.qmp_file = self.qmp.makefile("rwb")
        self.qmp_file.readline()  # greeting
        self._qmp_send({"execute": "qmp_capabilities"})
        threading.Thread(target=self._read_qmp, daemon=True).start()
        threading.Thread(target=self._read_serial, daemon=True).start()

    def _qmp_send(self, msg):
        self.qmp_file.write(json.dumps(msg).encode() + b"\n")
        self.qmp_file.flush()

    def _read_qmp(self):
        try:
            for line in self.qmp_file:
                msg = json.loads(line)
                if "event" in msg:
                    self.events.append(msg)
        except OSError:
            pass  # QEMU quit

    def _read_serial(self):
        with open(self.work / f"console-{self.label}.log", "ab") as log:
            try:
                while b := self.serial.recv(4096):
                    self.console += b
                    log.write(b)
                    log.flush()
            except OSError:
                pass

    def drive(self, steps, deadline):
        """Steps are (regex, action): wait for the regex on the console after
        the previous match, then send `serial:TEXT` or `qmp:COMMAND`."""
        pos = 0
        for pattern, action in steps:
            rx = re.compile(pattern.encode())
            while not (m := rx.search(self.console, pos)):
                if self.proc.poll() is not None:
                    raise HostcheckError(f"{self.label}: QEMU exited before {pattern!r}")
                if time.monotonic() > deadline:
                    raise HostcheckError(f"{self.label}: no {pattern!r} on the console in time")
                time.sleep(0.2)
            pos = m.end()
            if action and action.startswith("serial:"):
                self.serial.sendall(action[7:].encode())
            elif action:
                self._qmp_send({"execute": action[4:]})

    def wait(self, deadline):
        try:
            self.proc.wait(timeout=max(1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            self.proc.kill()
            raise HostcheckError(f"{self.label}: QEMU did not stop in time")
        finally:
            self.swtpm.wait(timeout=30)
            shutil.rmtree(self.sock_dir, ignore_errors=True)
        (self.work / f"events-{self.label}.json").write_text(json.dumps(self.events, indent=1))
        if self.proc.returncode:
            raise HostcheckError(f"{self.label}: QEMU exited {self.proc.returncode}")
        return rtc_by_post(self.events)


def _wait_path(path, timeout=30):
    end = time.monotonic() + timeout
    while not os.path.exists(path):
        if time.monotonic() > end:
            raise HostcheckError(f"{path} did not appear")
        time.sleep(0.05)


def _connect(path, proc, timeout=60):
    end = time.monotonic() + timeout
    while True:
        try:
            s = socket.socket(socket.AF_UNIX)
            s.connect(path)
            return s
        except OSError:
            s.close()
            if proc.poll() is not None or time.monotonic() > end:
                raise HostcheckError(f"QEMU socket {path} not ready")
            time.sleep(0.05)


def rtc_by_post(events):
    """RTC_CHANGE events split at each guest reset: one list per power-on
    self-test, since the firmware sets the clock's registers on every one."""
    posts = [[]]
    for e in events:
        if e["event"] == "RESET":
            posts.append([])
        elif e["event"] == "RTC_CHANGE":
            posts[-1].append(e)
    return posts


def guest_rtc_writes(posts, firmware_writes):
    """The writes after the firmware's own in each POST. The firmware writes
    first, so a guest write cannot hide among them."""
    return [e for post in posts for e in post[firmware_writes:]]


def qemu_tpm(work):
    """Read the host TPM from outside the guest: swtpm on the same state."""
    d = tempfile.mkdtemp(prefix="hc", dir="/tmp")
    sock = os.path.join(d, "s")
    p = subprocess.Popen(["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={work / 'tpm'}",
                          "--server", f"type=unixio,path={sock}", "--ctrl", f"type=unixio,path={sock}.ctrl",
                          "--flags", "not-need-init,startup-clear"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_path(sock)
        _wait_path(sock + ".ctrl")
        yield f"swtpm:path={sock}"
    finally:
        subprocess.run(["swtpm_ioctl", "--unix", sock + ".ctrl", "-s"], capture_output=True)
        p.wait(timeout=30)
        shutil.rmtree(d, ignore_errors=True)


def qemu_snapshot(args, work):
    disks = {name: work / "disks" / f"{name}.img" for name, _ in args.host_disks_bus}
    gen = qemu_tpm(work)
    tcti = next(gen)
    try:
        return snapshot(disks, varstore=work / "vars.fd", tcti=tcti)
    finally:
        next(gen, None)


# The stand-in guest's protocol: it prints HOSTCHECK-READY and reads one
# command line from the console. Firmware-only boots end at the UEFI shell or
# OVMF's "no bootable device" screen and are powered off over QMP.
FIRMWARE_ONLY = [(r"Shell> |No bootable option or device was found", "qmp:quit")]


def standin_phases(plant):
    return {
        "task": [("HOSTCHECK-READY", f"serial:task {plant or '-'}\n"), ("HOSTCHECK-DONE", None),
                 ("HOSTCHECK-READY", "serial:poweroff\n")],
        "restart": [("HOSTCHECK-READY", "serial:reboot\n"), ("HOSTCHECK-READY", "serial:poweroff\n")],
    }


def seed_tpm(work):
    """A host TPM that already holds an owner NV index, like a used PC's."""
    gen = qemu_tpm(work)
    tcti = next(gen)
    try:
        run(["tpm2_nvdefine", "-T", tcti, "0x1500020", "-C", "o", "-s", "8",
             "-a", "ownerread|ownerwrite|authread|authwrite"])
        run(["tpm2_nvwrite", "-T", tcti, "0x1500020", "-C", "o", "-i", "-"], input="HOSTSEED")
    finally:
        next(gen, None)


def cmd_qemu(args):
    work = pathlib.Path(args.work)
    work.mkdir(parents=True, exist_ok=False)
    (work / "disks").mkdir()
    (work / "tpm").mkdir()
    args.host_disks_bus = []
    for spec in args.host_disk:
        m = re.fullmatch(r"([a-z0-9]+)=([^,]+)(?:,bus=(nvme|virtio|ahci))?", spec)
        if not m:
            raise HostcheckError(f"bad --host-disk {spec!r}")
        shutil.copyfile(m.group(2), work / "disks" / f"{m.group(1)}.img")  # the input stays as it was
        args.host_disks_bus.append((m.group(1), m.group(3) or "nvme"))
    shutil.copyfile(args.ovmf_vars, work / "vars.fd")
    seed_tpm(work)
    if args.kernel:
        boot = ["-kernel", args.kernel, "-initrd", args.initrd, "-append", "console=ttyS0 rdinit=/init quiet"]
        phases = standin_phases(args.plant)
    else:
        boot = ["-drive", f"if=none,id=agentos,format=raw,file={args.image}",
                "-device", "qemu-xhci", "-device", "usb-storage,drive=agentos"]
        phases = {k: [tuple(s) for s in v] for k, v in json.loads(pathlib.Path(args.phases_file).read_text()).items()}
    timeout = args.timeout

    def boot_once(label, steps, with_drive):
        deadline = time.monotonic() + timeout
        q = Qemu(args, work, label, boot if with_drive else None)
        try:
            q.drive(steps, deadline)
            return q.wait(deadline)
        except BaseException:
            q.proc.kill()
            raise

    snaps, fw_rtc = {}, set()
    for label in ("firmware-1", "firmware-2"):
        fw_rtc.add(len(boot_once(label, FIRMWARE_ONLY, False)[0]))
        snaps[label] = qemu_snapshot(args, work)
    if len(fw_rtc) != 1:
        raise HostcheckError(f"the firmware writes the RTC a different number of times on each boot: {sorted(fw_rtc)}")
    firmware_writes = fw_rtc.pop()
    noise = {(f["kind"], f["key"]) for f in diff(snaps["firmware-1"], snaps["firmware-2"])}
    unstable = sorted(k for k in noise if k[0] != "uefi")
    if unstable:
        raise HostcheckError(f"host state changes on firmware-only boots: {unstable}")
    baseline = snaps["firmware-2"]
    report = {"baseline": baseline, "firmware_noise": sorted(k for _, k in noise),
              "firmware_rtc_writes_per_post": firmware_writes, "phases": []}
    for phase in args.phases.split(","):
        if phase not in phases:
            raise HostcheckError(f"unknown phase {phase!r}")
        rtc = [{"phase": phase, "offset": e["data"]["offset"]}
               for e in guest_rtc_writes(boot_once(phase, phases[phase], True), firmware_writes)]
        after = qemu_snapshot(args, work)
        r = evaluate(baseline, after, load_allow(), flags=args.flag, noise=noise, rtc_writes=rtc)
        report["phases"].append(dict(r, phase=phase, rtc_writes=rtc, snapshot=after))
    report["pass"] = all(p["pass"] for p in report["phases"])
    (work / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True))
    for p in report["phases"]:
        print(f"{p['phase']}: {'PASS' if p['pass'] else 'FAIL'}", file=sys.stderr)
        for f in p["flagged"]:
            print(f"  flagged {f['kind']} {f['key']} {f['change']}", file=sys.stderr)
        for f in p["disclosed"]:
            print(f"  disclosed ({f['change_id']}) {f['kind']} {f['key']} {f['change']}", file=sys.stderr)
    return 0 if report["pass"] else 1


def cmd_snapshot(args):
    disks = dict(d.split("=", 1) for d in args.disk)
    s = snapshot(disks, varstore=args.varstore, efivarfs=args.efivarfs, tcti=args.tcti)
    pathlib.Path(args.output).write_text(json.dumps(s, indent=1, sort_keys=True))
    return 0


def cmd_diff(args):
    before, after = (json.loads(pathlib.Path(p).read_text()) for p in (args.before, args.after))
    r = evaluate(before, after, load_allow(), flags=args.flag,
                 rtc_writes=[{"phase": "session", "offset": None}] if args.rtc_written else ())
    print(json.dumps(r, indent=1, sort_keys=True))
    return 0 if r["pass"] else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot")
    s.add_argument("--disk", action="append", default=[], metavar="NAME=PATH")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--varstore")
    g.add_argument("--efivarfs")
    s.add_argument("--tcti", required=True, help="e.g. device:/dev/tpmrm0")
    s.add_argument("-o", "--output", required=True)
    d = sub.add_parser("diff")
    d.add_argument("before")
    d.add_argument("after")
    d.add_argument("--flag", action="append", default=[], choices=["owner-boot-order"])
    d.add_argument("--rtc-written", action="store_true", help="the operator saw the hardware clock written")
    q = sub.add_parser("qemu")
    q.add_argument("--work", required=True, help="new directory for state, logs and report.json")
    src = q.add_mutually_exclusive_group(required=True)
    src.add_argument("--kernel", help="stand-in guest kernel (with --initrd)")
    src.add_argument("--image", help="a raw AgentOS drive image, attached as a USB disk (with --phases-file)")
    q.add_argument("--initrd")
    q.add_argument("--phases-file", help="JSON: phase -> [[regex, action], ...]")
    q.add_argument("--host-disk", action="append", required=True, metavar="NAME=PATH[,bus=nvme|virtio|ahci]")
    q.add_argument("--phases", default="task,restart")
    q.add_argument("--plant", default="", help="stand-in only: disk,uefi,nv,rtc (negative test)")
    q.add_argument("--flag", action="append", default=[], choices=["owner-boot-order"])
    q.add_argument("--ovmf-code", default="/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
                   help="an SMM build: without SMM, OVMF keeps variables in an NvVars file on the ESP")
    q.add_argument("--ovmf-vars", default="/usr/share/OVMF/OVMF_VARS_4M.fd")
    q.add_argument("--timeout", type=int, default=600, help="seconds per QEMU process")
    args = ap.parse_args(argv)
    if args.cmd == "qemu" and bool(args.kernel) != bool(args.initrd):
        ap.error("--kernel needs --initrd")
    if args.cmd == "qemu" and args.image and not args.phases_file:
        ap.error("--image needs --phases-file")
    try:
        return {"snapshot": cmd_snapshot, "diff": cmd_diff, "qemu": cmd_qemu}[args.cmd](args)
    except HostcheckError as e:
        print(f"hostcheck: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
