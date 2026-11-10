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
            The phase named `unclean` is one boot cut off by a power cut (QMP
            quit as soon as the guest answers a fresh liveness check on its
            console) with no orderly shutdown or reboot in it, and is the only
            one judged with the unclean-end flag, so MOR may stay set after it
            alone (HW-8).

Exit status: 0 the host is as it was, 1 a difference HW-8 does not allow,
2 the check could not be made.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import secrets
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


# ---- the VM stack (CI-hostcheck-image-tools, #4906, #5055) ----
# With --tools-root, qemu, swtpm and OVMF come from a root installed from pinned apt sources (CI
# builds it from the image's Debian snapshot with mmdebstrap), never the host's own packages, so a
# runner package update cannot change what hostcheck boots. The root's own loader runs each
# binary on the root's own libraries (--inhibit-cache: not the host's ld.so.cache), as
# tests/test_image.py image_tool does for systemd and kmod (#4776); paths stay the host's.
# --library-path still falls back to the loader's built-in host directories, so the loader also
# records every shared object it looks for or loads (LD_DEBUG), and a path outside the root, from
# a search, a dlopen or a preload, fails the run (#5055).
TOOLS_LOADER = "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
TOOLS_LIBS = ("usr/lib/x86_64-linux-gnu", "usr/lib/x86_64-linux-gnu/swtpm")
TOOLS = {"qemu-system-x86_64": "usr/bin/qemu-system-x86_64", "swtpm": "usr/bin/swtpm",
         "swtpm_ioctl": "usr/bin/swtpm_ioctl"}
TOOLS_OVMF = ("usr/share/OVMF/OVMF_CODE_4M.secboot.fd", "usr/share/OVMF/OVMF_VARS_4M.fd")
STACK = ("qemu-system-x86", "ovmf", "swtpm", "swtpm-tools")
# glibc's LD_DEBUG lines: "PID:\ttrying file=PATH" for each search candidate, and
# "PID:\tfile=NAME [NS];  TAIL" for each object mapped, NAME a path when given as one (a soname
# is searched, so its candidates are trying lines). Any other line naming a file= fails the
# audit, so a loader whose format differs cannot pass by being unread. The loader prints a name
# as it is, so a line after a name that lacks the PID of the record's own suffix is the rest of a
# name holding a newline, and fails (another PID's line is a forked child's, and may not name a
# file); a name may hold " [N];  " itself, so every split before a whole TAIL is a candidate (#5231).
LOADER_LINE = re.compile(r"\s*(\d+):\s+(.*)")
LOADER_TRYING = re.compile(r"trying file=(.+)")
LOADER_SPLIT = re.compile(r"(?=( \[\d+\];  ))")  # a lookahead: a split may overlap the one before it
LOADER_TAIL = re.compile(r"(?:needed by|dynamically loaded by) .* \[\d+\](?: \(relocation dependency\))?"
                         r"|generating link map|destroying link map")
LOADER_REOPEN = ("opening file=", "closing file=")  # an object already mapped, or let go


def _root_file(root, rel):
    p = os.path.join(root, rel)
    if os.path.islink(p) or not os.path.isfile(p):  # an absolute link would reach the host's copy
        raise HostcheckError(f"{rel} is not a file in the tools root {root}")
    return p


def tool_argv(root, name):
    """argv prefix that runs NAME: the host's on PATH without a root, else the root's."""
    if not root:
        return [name]
    return [_root_file(root, TOOLS_LOADER), "--inhibit-cache",
            "--library-path", ":".join(os.path.join(os.path.abspath(root), d) for d in TOOLS_LIBS),
            "--argv0", name, _root_file(root, TOOLS[name])]


def tool_env(root, ld_log):
    """The stack's environment: the host's without a root. With one, nothing of the host's but PATH:
    QEMU's module directory in the root (run through the loader, QEMU would look beside the loader),
    and the loader's record of what it loads, in LD_LOG.PID (a child the process starts writes its own)."""
    if not root:
        return None
    return dict(loader_env(ld_log), QEMU_MODULE_DIR=os.path.join(root, "usr/lib/x86_64-linux-gnu/qemu"))


def loader_env(ld_log):
    """PATH alone of the host's, and the loader's record of what it loads, in LD_LOG.PID: the
    environment of any tool run from a root that audit_records then checks (tests/test_image.py's
    image_tool too)."""
    return {"PATH": "/usr/sbin:/usr/bin", "LD_DEBUG": "libs,files", "LD_DEBUG_OUTPUT": str(ld_log)}


def loader_paths(text, pid):
    """The paths in process PID's LD_DEBUG record that the loader looked for or mapped, or the first
    line it could not read as either."""
    paths, named = [], False  # named: the line before named a path read here, so it may go on
    for line in text.split("\n"):
        m = LOADER_LINE.fullmatch(line)
        if not m:
            if line.strip(" \t"):
                raise HostcheckError(f"unreadable loader record line: {line!r}")
            named = False
            continue
        if m.group(1) != pid:
            # A child forked without an exec writes into its parent's record under its own PID (its
            # exit's "calling fini" lines). It may not name a file, nor go on a name read here.
            if "file=" in m.group(2) or named:
                raise HostcheckError(f"the loader's record of PID {pid} holds a line of PID {m.group(1)} that names "
                                     f"a file or follows a name: {line!r}")
            continue
        body, named = m.group(2), False
        if "file=" not in body or body.startswith(LOADER_REOPEN):
            continue
        named = True
        if t := LOADER_TRYING.fullmatch(body):
            paths.append(t.group(1))
            continue
        rest = body[len("file="):] if body.startswith("file=") else ""
        names = [rest[:s.start()] for s in LOADER_SPLIT.finditer(rest) if LOADER_TAIL.fullmatch(rest, s.end(1))]
        if not names:
            raise HostcheckError(f"unreadable loader record line: {line!r}")
        paths += [n for n in names if "/" in n]
    return paths


def audit_loads(root, ld_log, pid):
    """Fail unless stack process PID left a record, and audit_records passes."""
    if not root:
        return
    path = pathlib.Path(f"{ld_log}.{pid}")
    if not path.is_file():
        raise HostcheckError(f"the loader kept no record of what it loaded ({path})")
    audit_records(root, ld_log)


def audit_records(root, ld_log):
    """Fail unless there is a record LD_LOG.*, and every one (each process's and any child's) names
    only paths in ROOT, at least one each."""
    if not root:
        return
    log = pathlib.Path(ld_log)
    recs = sorted(p for p in log.parent.iterdir() if p.name.startswith(log.name + "."))
    if not recs:
        raise HostcheckError(f"the loader kept no record of what it loaded ({log}.*)")
    base = os.path.realpath(root) + os.sep
    outside = set()
    for rec in recs:
        pid = rec.name[len(log.name) + 1:]
        if not pid.isdigit():
            raise HostcheckError(f"{rec} is no loader record: its suffix is not a PID")
        seen = loader_paths(rec.read_bytes().decode(errors="surrogateescape"), pid)  # realpath gets the bytes back
        if not seen:
            raise HostcheckError(f"the loader's record {rec} names no shared object")
        outside |= {p for p in seen if not os.path.isabs(p) or not os.path.realpath(p).startswith(base)}
    if outside:
        raise HostcheckError(f"a binary run from the tools root {root} looked for or loaded shared objects outside the "
                             f"tools root (add the directory to its library path, or the package to the root): "
                             f"{sorted(outside)[:5]}")


def qemu_data_args(root):
    """QEMU's firmware/ROM directory in the root: run through the loader, QEMU would look for it
    relative to the loader's path."""
    return ["-L", os.path.join(root, "usr/share/qemu")] if root else []


def foreign_data_dirs(root, listing):
    """The directories in QEMU's `-L help` LISTING outside ROOT that exist on the host: QEMU would
    take a ROM the root lacks from them."""
    base = os.path.realpath(root) + os.sep
    return [d for d in listing.splitlines()
            if d.strip() and not os.path.realpath(d).startswith(base) and os.path.exists(d)]


def stack_popen(args, name, argv, **kw):
    """Start stack tool NAME with ARGV; stack_done checks what its loader loaded once it ends."""
    return subprocess.Popen(tool_argv(args.tools_root, name) + argv, env=tool_env(args.tools_root, args.ld_log), **kw)


def stack_done(args, proc):
    audit_loads(args.tools_root, args.ld_log, proc.pid)


def resolve_tools(args):
    """OVMF defaults to the root's when a root is given, else the host's."""
    base = args.tools_root or "/"
    if args.ovmf_code is None:
        args.ovmf_code = os.path.join(base, TOOLS_OVMF[0])
    if args.ovmf_vars is None:
        args.ovmf_vars = os.path.join(base, TOOLS_OVMF[1])


def stack_versions(root):
    """The installed version of each STACK package in ROOT's dpkg status, for the report."""
    if not root:
        return "runner"
    path = pathlib.Path(root, "var/lib/dpkg/status")
    try:
        status = path.read_text(errors="replace")
    except OSError as e:
        raise HostcheckError(f"the tools root {root} has no dpkg status ({path}): {e.strerror}")
    found = {}
    for stanza in status.split("\n\n"):
        f = dict(re.findall(r"^([A-Za-z-]+): (.*)$", stanza, re.M))
        if f.get("Package") in STACK and f.get("Status", "").endswith(" installed"):
            found[f["Package"]] = f.get("Version")
    missing = [p for p in STACK if not found.get(p)]
    if missing:
        raise HostcheckError(f"not installed in the tools root {root}: {missing}")
    return {p: found[p] for p in STACK}


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
    if "key" in rule and not re.fullmatch(rule["key"], f["key"]):  # `$` alone admits a trailing newline
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
    QMP (events: RTC_CHANGE, RESET, SHUTDOWN, and the STOP that marks each OS
    start) and its serial console."""

    def __init__(self, args, work, label, boot=None):
        self.work, self.label = work, label
        self.events, self.console = [], bytearray()
        self.os_marks = 0  # STOP events the os steps asked for
        sock_dir = tempfile.mkdtemp(prefix="hc", dir="/tmp")  # unix socket paths stay short
        self.sock_dir = sock_dir
        tpm_sock = os.path.join(sock_dir, "tpm")
        self.args = args
        self.swtpm = stack_popen(args, "swtpm", ["socket", "--tpm2", "--tpmstate", f"dir={work / 'tpm'}",
                                                 "--ctrl", f"type=unixio,path={tpm_sock}", "--terminate"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _wait_path(tpm_sock)
        accel = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
        cmd = qemu_data_args(args.tools_root) + ["-machine", "q35,smm=on", "-accel", accel, "-cpu", "max",
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
        self.proc = stack_popen(args, "qemu-system-x86_64", cmd, stdout=open(work / f"qemu-{label}.log", "wb"),
                                stderr=subprocess.STDOUT)
        self.qmp = _connect(f"{sock_dir}/qmp", self.proc)
        self.serial = _connect(f"{sock_dir}/serial", self.proc)  # QEMU starts once both are connected
        self.qmp_file = self.qmp.makefile("rwb")
        self.qmp_file.readline()  # greeting
        self._qmp_send({"execute": "qmp_capabilities"})
        self.qmp_reader = threading.Thread(target=self._read_qmp, daemon=True)
        self.qmp_reader.start()
        threading.Thread(target=self._read_serial, daemon=True).start()

    def _qmp_send(self, msg):
        self.qmp_file.write(json.dumps(msg).encode() + b"\n")
        self.qmp_file.flush()

    def _read_qmp(self):
        self.qmp_error = None
        try:
            for line in self.qmp_file:
                msg = json.loads(line)
                if "event" in msg:
                    self.events.append(msg)
        except OSError:
            pass  # QEMU quit
        except Exception as e:  # noqa: BLE001 - any other end leaves events unread: _qmp_done fails the boot
            self.qmp_error = e

    def _qmp_done(self):
        """Once QEMU has exited: fail unless the reader read every event QEMU sent, to EOF."""
        self.qmp_reader.join(timeout=30)
        if self.qmp_reader.is_alive() or self.qmp_error is not None:
            raise HostcheckError(f"{self.label}: QMP events not read to the end "
                                 f"({'reader still running' if self.qmp_reader.is_alive() else self.qmp_error!r})")

    def _read_serial(self):
        with open(self.work / f"console-{self.label}.log", "ab") as log:
            try:
                while b := self.serial.recv(4096):
                    self.console += b
                    log.write(b)
                    log.flush()
            except OSError:
                pass

    def _await(self, pattern, pos, deadline):
        rx = re.compile(pattern.encode())
        while not (m := rx.search(self.console, pos)):
            if self.proc.poll() is not None:
                raise HostcheckError(f"{self.label}: QEMU exited before {pattern!r}")
            if time.monotonic() > deadline:
                raise HostcheckError(f"{self.label}: no {pattern!r} on the console in time")
            time.sleep(POLL)
        return m.end()

    def drive(self, steps, deadline):
        """Steps are (regex, action): wait for the regex on the console after
        the previous match, then send `serial:TEXT` or `qmp:COMMAND`; for
        `os`, mark the OS's start in QEMU's own event stream (a STOP, then
        cont): RTC writes from then until the next reset are the guest's, and
        its regex is the OS's first output. POWER_CUT quits QEMU as soon as
        the guest has answered a liveness check sent after the regex matched."""
        pos = 0
        for pattern, action in steps:
            pos = self._await(pattern, pos, deadline)
            if action and action.startswith("serial:"):
                self.serial.sendall(action[7:].encode())
            elif action == "os":
                self.os_marks += 1
                self._qmp_send({"execute": "stop"})
                self._qmp_send({"execute": "cont"})
            elif action == POWER_CUT:
                nonce = secrets.token_hex(8)
                self.serial.sendall(f"alive {nonce}\n".encode())
                pos = self._await(f"{ALIVE} {nonce}", pos, min(deadline, time.monotonic() + ALIVE_WAIT))
                self._qmp_send({"execute": "quit"})
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
        stack_done(self.args, self.swtpm)
        stack_done(self.args, self.proc)
        self._qmp_done()
        if self.proc.returncode:
            raise HostcheckError(f"{self.label}: QEMU exited {self.proc.returncode}")
        if (stops := sum(e["event"] == "STOP" for e in self.events)) != self.os_marks:
            raise HostcheckError(f"{self.label}: {stops} STOP events for {self.os_marks} OS starts, "
                                 "so the OS starts cannot be told from them")
        return guest_rtc_writes(self.events)


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


# A guest that could not do what a phase asked of it (the stand-in's mor_clear or a planted write)
# says so on its console; the phase does not pass, and the line is shown with its result.
GUEST_ERROR = re.compile(rb"HOSTCHECK-[A-Z]+-FAILED[^\r\n]*")


def guest_errors(console):
    return [m.group().decode(errors="replace") for m in GUEST_ERROR.finditer(console)]


def with_guest_errors(result, errors):
    """A phase's result with the guest's own failures: a phase whose guest failed does not pass."""
    return dict(result, guest_errors=errors, **{"pass": result["pass"] and not errors})


def guest_rtc_writes(events):
    """The RTC_CHANGE events after an OS start (the STOP its os step asked for)
    and before the next reset. The firmware sets the clock's registers on
    every power-on self-test, before the OS starts. QEMU throttles the event
    to one a second, so it can arrive after a later event, but it keeps the
    last write's timestamp: every stamp here is QEMU's own clock."""
    stamp = lambda e: e["timestamp"]["seconds"] + e["timestamp"]["microseconds"] / 1e6
    out, guest = [], False
    for e in sorted(events, key=stamp):  # stable: a tie keeps QEMU's order
        if e["event"] == "STOP":
            guest = True
        elif e["event"] == "RESET":
            guest = False
        elif e["event"] == "RTC_CHANGE" and guest:
            out.append(e)
    return out


def qemu_tpm(args, work):
    """Read the host TPM from outside the guest: swtpm on the same state."""
    d = tempfile.mkdtemp(prefix="hc", dir="/tmp")
    sock = os.path.join(d, "s")
    p = stack_popen(args, "swtpm", ["socket", "--tpm2", "--tpmstate", f"dir={work / 'tpm'}",
                                    "--server", f"type=unixio,path={sock}", "--ctrl", f"type=unixio,path={sock}.ctrl",
                                    "--flags", "not-need-init,startup-clear"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_path(sock)
        _wait_path(sock + ".ctrl")
        yield f"swtpm:path={sock}"
    finally:
        stop = stack_popen(args, "swtpm_ioctl", ["--unix", sock + ".ctrl", "-s"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stop.wait(timeout=30)
        p.wait(timeout=30)
        shutil.rmtree(d, ignore_errors=True)
    stack_done(args, stop)
    stack_done(args, p)


def qemu_snapshot(args, work):
    disks = {name: work / "disks" / f"{name}.img" for name, _ in args.host_disks_bus}
    gen = qemu_tpm(args, work)
    tcti = next(gen)
    try:
        return snapshot(disks, varstore=work / "vars.fd", tcti=tcti)
    finally:
        next(gen, None)


# The stand-in guest's protocol: it prints HOSTCHECK-READY and reads one
# command line from the console. Firmware-only boots end at the UEFI shell or
# OVMF's "no bootable device" screen and are powered off over QMP.
FIRMWARE_ONLY = [(r"Shell> |No bootable option or device was found", "qmp:quit")]
# HW-8 allows MOR left set only after a power cut or forced reset. The phase of this name is one
# boot cut off by a QMP quit with the guest still running, and only its snapshot is judged with the
# flag; every orderly phase, including one after it, must find MOR cleared again. Its steps may send
# the guest text, but the guest's own shutdown or reboot shows in QEMU's events, and any fails it.
# A halt shows in no event, so the cut sends `alive NONCE` and quits only once the guest has printed
# ALIVE NONCE: a guest that halted or hung never answers, and the run fails naming the line.
UNCLEAN_PHASE, UNCLEAN_FLAG, POWER_CUT = "unclean", "unclean-end", "power-cut"
ALIVE, ALIVE_WAIT, POLL = "HOSTCHECK-ALIVE", 30, 0.02


def phase_flags(name, steps, flags):
    """The run flags phase NAME is judged with."""
    if name != UNCLEAN_PHASE:
        return list(flags)
    actions = [action for _, action in steps]
    if not actions or actions[-1] != POWER_CUT:
        raise HostcheckError(f"phase {name!r} must end in {POWER_CUT!r}, a power cut of a guest that "
                             f"answers {ALIVE}")
    if actions[0] != "os" or actions.count("os") != 1:
        raise HostcheckError(f"phase {name!r} must be one boot: its first step os and no other")
    if bad := [a for a in actions[1:-1] if a and not a.startswith("serial:")]:
        raise HostcheckError(f"phase {name!r} may only send the guest text before its power cut, not {bad}")
    return list(flags) + [UNCLEAN_FLAG]


def power_cut_only(name, events):
    """Fail unless phase NAME's boot ended in the QMP quit, its last event and only shutdown, with no
    reset after the OS started (firmware resets before it are the firmware's). The OS start is the
    STOP its os step asked for, and QEMU sends RESET, STOP and SHUTDOWN unthrottled, in the order they
    happen: their order in the stream is the order, with no clock read."""
    last = events[-1] if events else {}
    if last.get("event") != "SHUTDOWN" or last.get("data", {}).get("reason") != "host-qmp-quit":
        raise HostcheckError(f"phase {name!r} did not end in the QMP quit's SHUTDOWN, so not in a power cut")
    if sum(e["event"] == "SHUTDOWN" for e in events) != 1:
        raise HostcheckError(f"phase {name!r} shut down more than once, so not in a power cut")
    started = False
    for e in events:
        started = started or e["event"] == "STOP"
        if e["event"] == "RESET" and started:
            reason = e.get("data", {}).get("reason")
            raise HostcheckError(f"phase {name!r} rebooted ({reason}), so not in a power cut")


def standin_phases(plant):
    os_start = ("Linux version", "os")  # the kernel's first line
    return {
        "task": [os_start, ("HOSTCHECK-READY", f"serial:task {plant or '-'}\n"), ("HOSTCHECK-DONE", None),
                 ("HOSTCHECK-READY", "serial:poweroff\n")],
        "restart": [os_start, ("HOSTCHECK-READY", "serial:reboot\n"),
                    os_start, ("HOSTCHECK-READY", "serial:poweroff\n")],
        UNCLEAN_PHASE: [os_start, ("HOSTCHECK-READY", POWER_CUT)],
    }


def seed_tpm(args, work):
    """A host TPM that already holds an owner NV index, like a used PC's."""
    gen = qemu_tpm(args, work)
    tcti = next(gen)
    try:
        run(["tpm2_nvdefine", "-T", tcti, "0x1500020", "-C", "o", "-s", "8",
             "-a", "ownerread|ownerwrite|authread|authwrite"])
        run(["tpm2_nvwrite", "-T", tcti, "0x1500020", "-C", "o", "-i", "-"], input="HOSTSEED")
    finally:
        next(gen, None)


def boot_once(args, work, label, steps, boot):
    """One QEMU process driven through STEPS: its guest RTC writes, guest errors and QMP events."""
    deadline = time.monotonic() + args.timeout
    q = Qemu(args, work, label, boot)
    try:
        q.drive(steps, deadline)
        rtc = q.wait(deadline)
    except BaseException:
        q.proc.kill()
        raise
    return {"rtc": rtc, "errors": guest_errors(q.console), "events": q.events}


def cmd_qemu(args):
    resolve_tools(args)
    stack = stack_versions(args.tools_root)
    for name in TOOLS:
        tool_argv(args.tools_root, name)  # a missing root tool fails before any state is made
    work = pathlib.Path(args.work)
    work.mkdir(parents=True, exist_ok=False)
    (work / "ld").mkdir()
    args.ld_log = work / "ld" / "stack"
    if args.tools_root:
        listing = stack_popen(args, "qemu-system-x86_64", qemu_data_args(args.tools_root) + ["-L", "help"],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        out = listing.communicate(timeout=60)[0]
        stack_done(args, listing)
        if listing.returncode or not out.strip():
            raise HostcheckError(f"qemu-system-x86_64 -L help failed ({listing.returncode})")
        if foreign := foreign_data_dirs(args.tools_root, out):
            raise HostcheckError(f"QEMU would take a ROM the tools root lacks from the host's {foreign}: remove them")
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
    seed_tpm(args, work)
    if args.kernel:
        boot = ["-kernel", args.kernel, "-initrd", args.initrd, "-append", "console=ttyS0 rdinit=/init"]
    else:
        boot = ["-drive", f"if=none,id=agentos,format=raw,file={args.image}",
                "-device", "qemu-xhci", "-device", "usb-storage,drive=agentos"]
    if args.phases_file:
        phases = {k: [tuple(s) for s in v] for k, v in json.loads(pathlib.Path(args.phases_file).read_text()).items()}
    else:
        phases = standin_phases(args.plant)
    snaps = {}
    for label in ("firmware-1", "firmware-2"):
        boot_once(args, work, label, FIRMWARE_ONLY, None)
        snaps[label] = qemu_snapshot(args, work)
    noise = {(f["kind"], f["key"]) for f in diff(snaps["firmware-1"], snaps["firmware-2"])}
    unstable = sorted(k for k in noise if k[0] != "uefi")
    if unstable:
        raise HostcheckError(f"host state changes on firmware-only boots: {unstable}")
    baseline = snaps["firmware-2"]
    report = {"baseline": baseline, "firmware_noise": sorted(k for _, k in noise),
              "phases": [], "stack": stack}
    for phase in args.phases.split(","):
        if phase not in phases:
            raise HostcheckError(f"unknown phase {phase!r}")
        if not any(action == "os" for _, action in phases[phase]):
            raise HostcheckError(f"phase {phase!r} has no os step, so guest RTC writes could not be told apart")
        flags = phase_flags(phase, phases[phase], args.flag)
        ran = boot_once(args, work, phase, phases[phase], boot)
        if phase == UNCLEAN_PHASE:
            power_cut_only(phase, ran["events"])
        rtc = [{"phase": phase, "offset": e["data"]["offset"]} for e in ran["rtc"]]
        after = qemu_snapshot(args, work)
        r = evaluate(baseline, after, load_allow(), flags=flags, noise=noise, rtc_writes=rtc)
        report["phases"].append(dict(with_guest_errors(r, ran["errors"]), phase=phase, rtc_writes=rtc, snapshot=after))
    audit_records(args.tools_root, args.ld_log)  # once more, for a record written after its process was checked
    report["pass"] = all(p["pass"] for p in report["phases"])
    (work / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True))
    for p in report["phases"]:
        print(f"{p['phase']}: {'PASS' if p['pass'] else 'FAIL'}", file=sys.stderr)
        for e in p["guest_errors"]:
            print(f"  guest {e}", file=sys.stderr)
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
    d.add_argument("--flag", action="append", default=[], choices=["owner-boot-order", UNCLEAN_FLAG],
                   help=f"{UNCLEAN_FLAG}: the session ended in a power cut or forced reset")
    d.add_argument("--rtc-written", action="store_true", help="the operator saw the hardware clock written")
    q = sub.add_parser("qemu")
    q.add_argument("--work", required=True, help="new directory for state, logs and report.json")
    src = q.add_mutually_exclusive_group(required=True)
    src.add_argument("--kernel", help="stand-in guest kernel (with --initrd)")
    src.add_argument("--image", help="a raw agentOS drive image, attached as a USB disk (with --phases-file)")
    q.add_argument("--initrd")
    q.add_argument("--phases-file", help="JSON: phase -> [[regex, action], ...], in place of the stand-in's; "
                   f"action os marks the OS's first output in each boot, {POWER_CUT} ends the unclean phase")
    q.add_argument("--host-disk", action="append", required=True, metavar="NAME=PATH[,bus=nvme|virtio|ahci]")
    q.add_argument("--phases", default="task,restart",
                   help=f"comma list; {UNCLEAN_PHASE!r} ends in a power cut (stand-in: task,restart,unclean)")
    q.add_argument("--plant", default="", help="stand-in only: disk,uefi,nv,rtc (negative test)")
    q.add_argument("--flag", action="append", default=[], choices=["owner-boot-order"])
    q.add_argument("--tools-root", help="a root holding qemu, swtpm and OVMF from pinned apt sources "
                   "(CI: the image's Debian snapshot); default: the host's own")
    q.add_argument("--ovmf-code", help="an SMM build: without SMM, OVMF keeps variables in an NvVars file "
                   "on the ESP (default: OVMF_CODE_4M.secboot.fd in the tools root, else /usr/share/OVMF)")
    q.add_argument("--ovmf-vars", help="default: OVMF_VARS_4M.fd beside it")
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
