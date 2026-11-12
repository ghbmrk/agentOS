# HOST-1e host-untouched check (spec A1, HW-8): snapshot, diff against
# HW-8's disclosed list, and the QEMU/OVMF/swtpm run with a Windows-like
# second disk. REQ: HW-8
#
# The unit tests run everywhere. The QEMU tests boot the stand-in guest and
# need qemu, OVMF, swtpm, tpm2-tools and virt-fw-vars; they run when
# HOSTCHECK_QEMU=1 (the `hostcheck` CI job) and fail rather than skip there if
# a tool is missing. HOSTCHECK_KERNEL names the guest kernel; HOSTCHECK_TOOLS_ROOT, if set,
# a root holding qemu, swtpm and OVMF (CI: the image's Debian snapshot, #4906).
import argparse
import hashlib
import http.server
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import hostcheck  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
from test_workflows import job_steps  # noqa: E402

GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
SYSTEMD = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
SHIM = "605dab50-e046-4300-abb6-3dd810dd8b23"
MOR = "e20939be-32d4-41be-a150-897f85d49829:MemoryOverwriteRequestControl"
COUNTER_ATTRS = 0x02040014  # authwrite|counter|authread|no_da, as tpmseal makes it


def snap(**over):
    s = {
        "disk": {"win": "aa" * 32},
        "uefi": {f"{GLOBAL}:BootOrder": {"attr": 7, "sha256": "11"},
                 f"{GLOBAL}:Boot0000": {"attr": 7, "sha256": "22"}},
        "tpm-nv": {"0x1500020": {"name": "n1", "attributes": 0x20060006, "size": 8, "data": "d1"}},
        "tpm-persistent": {},
        "tpm-setting": {"lockoutAuthSet": 0, "TPM2_PT_MAX_AUTH_FAIL": 3},
    }
    for k, v in over.items():
        s[k.replace("_", "-")] = v
    return s


def flagged(report):
    return {(f["kind"], f["key"], f["change"]) for f in report["flagged"]}


class DiffTest(unittest.TestCase):
    def setUp(self):
        self.allow = hostcheck.load_allow()

    def check(self, before, after, **kw):
        return hostcheck.evaluate(before, after, self.allow, **kw)

    def test_identical_passes(self):
        r = self.check(snap(), snap())
        self.assertTrue(r["pass"])
        self.assertEqual(r["flagged"], [])

    def test_disk_write_flagged(self):
        r = self.check(snap(), snap(disk={"win": "bb" * 32}))
        self.assertFalse(r["pass"])
        self.assertEqual(flagged(r), {("disk", "win", "changed")})

    def test_new_uefi_variable_flagged(self):
        after = snap()
        after["uefi"]["0000-x:Canary"] = {"attr": 7, "sha256": "33"}
        self.assertEqual(flagged(self.check(snap(), after)), {("uefi", "0000-x:Canary", "added")})

    def test_removed_and_changed_uefi_variable_flagged(self):
        after = snap()
        del after["uefi"][f"{GLOBAL}:Boot0000"]
        after["uefi"][f"{GLOBAL}:BootOrder"] = {"attr": 7, "sha256": "99"}
        self.assertEqual(flagged(self.check(snap(), after)),
                         {("uefi", f"{GLOBAL}:Boot0000", "removed"),
                          ("uefi", f"{GLOBAL}:BootOrder", "changed")})

    def test_boot_order_disclosed_only_when_owner_changed_it(self):
        after = snap()
        after["uefi"][f"{GLOBAL}:BootOrder"] = {"attr": 7, "sha256": "99"}
        after["uefi"][f"{GLOBAL}:Boot0003"] = {"attr": 7, "sha256": "44"}
        self.assertFalse(self.check(snap(), after)["pass"])
        r = self.check(snap(), after, flags={"owner-boot-order"})
        self.assertTrue(r["pass"], r)
        self.assertEqual({d["change_id"] for d in r["disclosed"]}, {"boot-order"})

    def test_mok_and_other_shim_variables_are_not_disclosed(self):
        after = snap()
        after["uefi"]["605dab50-e046-4300-abb6-3dd810dd8b23:MokList"] = {"attr": 7, "sha256": "1"}
        self.assertFalse(self.check(snap(), after, flags={"owner-boot-order"})["pass"])

    def test_loader_token_and_sbat_level_disclosed(self):
        after = snap()
        after["uefi"][f"{SYSTEMD}:LoaderSystemToken"] = {"attr": 7, "sha256": "1"}
        after["uefi"][f"{SHIM}:SbatLevel"] = {"attr": 7, "sha256": "2"}
        r = self.check(snap(), after)
        self.assertTrue(r["pass"], r)
        self.assertEqual({d["change_id"] for d in r["disclosed"]},
                         {"loader-system-token", "sbat-level"})

    def test_new_nv_index_flagged(self):
        after = snap()
        after["tpm-nv"]["0x1500016"] = {"name": "n2", "attributes": 0x20060006, "size": 8, "data": "x"}
        self.assertEqual(flagged(self.check(snap(), after)), {("tpm-nv", "0x1500016", "added")})

    def test_written_existing_nv_index_flagged(self):
        after = snap()
        after["tpm-nv"]["0x1500020"] = dict(after["tpm-nv"]["0x1500020"], data="d2")
        self.assertEqual(flagged(self.check(snap(), after)), {("tpm-nv", "0x1500020", "changed")})

    def test_vault_counter_disclosed_only_in_its_shape(self):
        ok = snap()
        ok["tpm-nv"]["0x18a0b0c"] = {"name": "c", "attributes": COUNTER_ATTRS | hostcheck.NV_WRITTEN,
                                     "size": 8, "data": None}
        r = self.check(snap(), ok)
        self.assertTrue(r["pass"], r)
        self.assertEqual([d["change_id"] for d in r["disclosed"]], ["tpm-vault-counter"])
        for bad in ({"attributes": COUNTER_ATTRS | 1 << 17},  # owner-readable: not tpmseal's
                    {"size": 16}):
            after = snap()
            after["tpm-nv"]["0x18a0b0c"] = dict(ok["tpm-nv"]["0x18a0b0c"], **bad)
            self.assertFalse(self.check(snap(), after)["pass"], bad)
        outside = snap()
        outside["tpm-nv"]["0x1c00000"] = ok["tpm-nv"]["0x18a0b0c"]
        self.assertFalse(self.check(snap(), outside)["pass"])
        # A counter the PC already had is never redefined.
        before = snap()
        before["tpm-nv"]["0x18a0b0c"] = dict(ok["tpm-nv"]["0x18a0b0c"], name="old")
        self.assertFalse(self.check(before, ok)["pass"])

    def test_srk_disclosed_only_when_added(self):
        after = snap(tpm_persistent={"0x81000001": "srk"})
        r = self.check(snap(), after)
        self.assertTrue(r["pass"], r)
        replaced = self.check(snap(tpm_persistent={"0x81000001": "windows"}), after)
        self.assertEqual(flagged(replaced), {("tpm-persistent", "0x81000001", "changed")})
        other = self.check(snap(), snap(tpm_persistent={"0x81000002": "x"}))
        self.assertFalse(other["pass"])

    def test_lockout_settings_disclosed(self):
        after = snap(tpm_setting={"lockoutAuthSet": 1, "TPM2_PT_MAX_AUTH_FAIL": 32})
        self.assertTrue(self.check(snap(), after)["pass"])
        owner = snap(tpm_setting={"lockoutAuthSet": 0, "TPM2_PT_MAX_AUTH_FAIL": 3, "ownerAuthSet": 1})
        self.assertFalse(self.check(snap(tpm_setting=dict(owner["tpm-setting"], ownerAuthSet=0)), owner)["pass"])

    def test_rtc_write_flagged(self):
        r = self.check(snap(), snap(), rtc_writes=[{"phase": "task", "offset": 0}])
        self.assertFalse(r["pass"])
        self.assertEqual(flagged(r), {("rtc", "task", "written")})

    def test_rtc_writes_after_the_os_starts_in_each_post_are_the_guests(self):
        # OVMF sets the clock's registers on every power-on self-test, and
        # QEMU throttles RTC_CHANGE to one event a second, so how many events
        # the firmware's writes make varies (CI saw 1 and 2). A write is the
        # guest's when it comes after the OS started (the STOP its os step
        # asks QEMU for) and before the next reset.
        ev = lambda t, name, **d: {"event": name, "timestamp": {"seconds": t, "microseconds": 0}, "data": d}
        events = [ev(1, "RTC_CHANGE", offset=0), ev(2, "RTC_CHANGE", offset=-1), ev(6, "RESET"),
                  ev(7, "RTC_CHANGE", offset=0), ev(12, "RTC_CHANGE", offset=0), ev(20, "SHUTDOWN")]
        marked = lambda *ts: sorted(events + [ev(t, "STOP") for t in ts], key=lambda e: e["timestamp"]["seconds"])
        self.assertEqual(hostcheck.guest_rtc_writes(marked(3, 8)), [events[4]])
        self.assertEqual(hostcheck.guest_rtc_writes(marked(3, 13)), [])
        self.assertEqual(hostcheck.guest_rtc_writes(events), [])
        self.assertEqual(hostcheck.guest_rtc_writes(marked(0.5)), [events[0], events[1]])

    def test_a_throttled_rtc_event_counts_where_its_timestamp_puts_it(self):
        # #5256 item 2: QEMU holds back an RTC_CHANGE within a second of the last one and sends it
        # later with its write's timestamp, so it can arrive after the reboot that followed the
        # write. Ordered by arrival it would fall in the firmware's window and pass; by QEMU's one
        # clock it is the guest's. The same holds for a firmware write sent after the OS's mark.
        ev = lambda t, name, **d: {"event": name, "timestamp": {"seconds": t, "microseconds": 0}, "data": d}
        write = ev(9, "RTC_CHANGE", offset=5)
        self.assertEqual(hostcheck.guest_rtc_writes([ev(3, "STOP"), ev(10, "RESET"), write]), [write])
        firmware = ev(2, "RTC_CHANGE", offset=0)
        self.assertEqual(hostcheck.guest_rtc_writes([ev(3, "STOP"), firmware, ev(20, "SHUTDOWN")]), [])

    def test_firmware_noise_excluded_for_uefi_only(self):
        noisy = f"eb704011-1402-11d3-8e77-00a0c969723b:MTC"
        before, after = snap(), snap(disk={"win": "cc" * 32})
        before["uefi"][noisy] = {"attr": 7, "sha256": "1"}
        after["uefi"][noisy] = {"attr": 7, "sha256": "2"}
        r = self.check(before, after, noise={("uefi", noisy), ("disk", "win")})
        self.assertEqual(flagged(r), {("disk", "win", "changed")})
        self.assertEqual([n["key"] for n in r["noise"]], [noisy])

    def test_missing_part_is_an_error_not_a_pass(self):
        after = snap()
        del after["tpm-nv"]
        with self.assertRaises(hostcheck.HostcheckError):
            self.check(snap(), after)

    def test_mor_set_disclosed_only_after_an_unclean_end(self):
        # The EFI stub sets MOR at every boot; an orderly shutdown clears it (#4794).
        before = snap()
        before["uefi"][MOR] = {"attr": 7, "sha256": "00"}
        after = snap()
        after["uefi"][MOR] = {"attr": 7, "sha256": "01"}
        self.assertEqual(flagged(self.check(before, after)), {("uefi", MOR, "changed")})
        self.assertEqual(flagged(self.check(before, after, flags={"owner-boot-order"})),
                         {("uefi", MOR, "changed")})
        r = self.check(before, after, flags={"unclean-end"})
        self.assertTrue(r["pass"], r)
        self.assertEqual([d["change_id"] for d in r["disclosed"]], ["mor"])

    def test_unclean_end_allows_nothing_but_mor_changed(self):
        before = snap()
        before["uefi"][MOR] = {"attr": 7, "sha256": "00"}
        for name, edit, want in [
            ("mor created", lambda a: a["uefi"].__setitem__(MOR, {"attr": 7, "sha256": "01"}), "added"),
            ("mor removed", lambda a: a["uefi"].pop(MOR), "removed"),
        ]:
            with self.subTest(name):
                b = before if want != "added" else snap()
                after = json.loads(json.dumps(b))
                edit(after)
                self.assertEqual(flagged(self.check(b, after, flags={"unclean-end"})), {("uefi", MOR, want)})
        # Neighbours present before and changed after, so only the rule's key can reject them.
        neighbours = ["bb983ccf-151d-40e1-a07b-4a17be168292:MemoryOverwriteRequestControlLock",  # MORLock
                      f"{MOR}Lock", f"{GLOBAL}:MemoryOverwriteRequestControl",
                      f"x{MOR}"]
        for key in neighbours:
            with self.subTest(key):
                b = json.loads(json.dumps(before))
                b["uefi"][key] = {"attr": 7, "sha256": "00"}
                after = json.loads(json.dumps(b))
                after["uefi"][MOR] = {"attr": 7, "sha256": "01"}
                after["uefi"][key] = {"attr": 7, "sha256": "01"}
                self.assertEqual(flagged(self.check(b, after, flags={"unclean-end"})), {("uefi", key, "changed")})


class PhaseFlagsTest(unittest.TestCase):
    def test_only_the_unclean_phase_gets_the_flag(self):
        phases = hostcheck.standin_phases("")
        self.assertEqual(hostcheck.phase_flags("task", phases["task"], ["owner-boot-order"]), ["owner-boot-order"])
        self.assertEqual(hostcheck.phase_flags("restart", phases["restart"], []), [])
        self.assertEqual(hostcheck.phase_flags("unclean", phases["unclean"], []), ["unclean-end"])

    def test_unclean_phase_must_end_in_a_power_cut(self):
        orderly = hostcheck.standin_phases("")["task"]
        # #5256 item 3: a bare QMP quit could fire after the guest halted or before it ran anything;
        # only the power cut, which waits for the guest's fresh answer, ends the phase.
        for steps in (orderly, [], [("Linux version", "os"), ("HOSTCHECK-READY", "qmp:system_powerdown")],
                      [("Linux version", "os"), ("HOSTCHECK-READY", "qmp:quit")]):
            with self.subTest(steps=steps):
                with self.assertRaises(hostcheck.HostcheckError):
                    hostcheck.phase_flags("unclean", steps, [])

    def test_unclean_phase_holds_no_orderly_end(self):
        # M12: an unclean phase that shuts down or reboots in order before its quit would leave MOR
        # cleared yet be judged unclean, so a later MOR left set would pass as disclosed.
        os_start, cut = ("Linux version", "os"), ("HOSTCHECK-READY", "power-cut")
        hostcheck.phase_flags("unclean", [os_start, ("HOSTCHECK-READY", "serial:task -\n"), ("DONE", None), cut], [])
        for steps in ([os_start, ("HOSTCHECK-READY", "qmp:system_powerdown"), cut],
                      [os_start, ("HOSTCHECK-READY", "qmp:system_reset"), cut],
                      [os_start, ("HOSTCHECK-READY", "serial:reboot\n"), os_start, cut],
                      [("HOSTCHECK-READY", "serial:reboot\n"), os_start, cut],
                      [cut]):
            with self.subTest(steps=steps):
                with self.assertRaises(hostcheck.HostcheckError):
                    hostcheck.phase_flags("unclean", steps, [])

    def test_an_orderly_end_the_guest_makes_fails_the_unclean_phase(self):
        # The guest can shut down or reboot on its own; QEMU's events show it.
        ev = lambda name, t, reason: {"event": name, "timestamp": {"seconds": t, "microseconds": 0},
                                      "data": {"guest": reason != "host-qmp-quit", "reason": reason}}
        cut, os_mark = ev("SHUTDOWN", 30, "host-qmp-quit"), {"event": "STOP", "timestamp": {"seconds": 10,
                                                                                            "microseconds": 0}}
        hostcheck.power_cut_only("unclean", [ev("RESET", 5, "guest-reset"), os_mark, cut])
        for events in ([os_mark, ev("SHUTDOWN", 20, "guest-shutdown")],
                       [os_mark, ev("SHUTDOWN", 20, "guest-shutdown"), cut],
                       [os_mark, ev("RESET", 20, "guest-reset"), cut],
                       [os_mark, ev("RESET", 10, "host-qmp-system-reset"), cut],
                       [ev("SHUTDOWN", 20, "host-signal")],
                       # No quit seen (a reader that lost events), a quit not last, or two quits.
                       [], [ev("RESET", 5, "guest-reset")], [cut, ev("RTC_CHANGE", 31, None)], [cut, cut]):
            with self.subTest(events=events):
                with self.assertRaisesRegex(hostcheck.HostcheckError, "not in a power cut"):
                    hostcheck.power_cut_only("unclean", [os_mark] + events if events[:1] != [os_mark] else events)

    def test_a_reset_is_placed_by_its_place_in_qemus_stream_not_by_a_clock(self):
        # #5256 item 2: RESET, STOP and SHUTDOWN reach QMP unthrottled, in the order they happen, so
        # their order decides; a timestamp that says otherwise (a stepped clock) changes nothing.
        ev = lambda name, t, **d: {"event": name, "timestamp": {"seconds": t, "microseconds": 0}, "data": d}
        cut = ev("SHUTDOWN", 30, reason="host-qmp-quit")
        hostcheck.power_cut_only("unclean", [ev("RESET", 50, reason="guest-reset"), ev("STOP", 10), cut])
        with self.assertRaisesRegex(hostcheck.HostcheckError, "rebooted"):
            hostcheck.power_cut_only("unclean", [ev("STOP", 10), ev("RESET", 5, reason="guest-reset"), cut])

    def test_a_qmp_reader_that_stops_early_fails_the_boot(self):
        # A line the reader cannot parse ends it before EOF: later events (a guest shutdown) would be
        # lost and the phase judged on what came before, so the boot fails instead.
        def reader(stream):
            q = hostcheck.Qemu.__new__(hostcheck.Qemu)
            q.label, q.events, q.qmp_file = "unclean", [], stream
            q.qmp_reader = unittest.mock.Mock(is_alive=lambda: False)
            q._read_qmp()
            return q

        import io
        quit_ = b'{"event": "SHUTDOWN", "data": {"reason": "host-qmp-quit"}}\n'
        q = reader(io.BytesIO(b'{"return": {}}\n' + quit_))
        q._qmp_done()
        self.assertEqual([e["event"] for e in q.events], ["SHUTDOWN"])
        q = reader(io.BytesIO(b'not json\n{"event": "SHUTDOWN", "data": {"reason": "guest-shutdown"}}\n' + quit_))
        self.assertEqual(q.events, [])
        with self.assertRaisesRegex(hostcheck.HostcheckError, "not read to the end"):
            q._qmp_done()
        with tempfile.TemporaryDirectory() as d:  # wait() checks it for every boot
            q.work, q.sock_dir, q.os_marks = pathlib.Path(d), os.path.join(d, "s"), 0
            q.args = argparse.Namespace(tools_root=None, ld_log=None)
            q.proc = unittest.mock.Mock(returncode=0)
            q.swtpm = unittest.mock.Mock()
            with self.assertRaisesRegex(hostcheck.HostcheckError, "not read to the end"):
                q.wait(time.monotonic() + 5)

        class Broken(io.BytesIO):
            def __iter__(self):
                raise OSError("reset")  # QEMU gone: EOF by another name
        reader(Broken())._qmp_done()
        q = reader(io.BytesIO(quit_))
        q.qmp_reader = unittest.mock.Mock(is_alive=lambda: True)
        with self.assertRaisesRegex(hostcheck.HostcheckError, "reader still running"):
            q._qmp_done()

    def test_operator_cannot_flag_a_whole_qemu_run_unclean(self):
        with self.assertRaises(SystemExit):
            hostcheck.main(["qemu", "--work", "/nonexistent/x", "--kernel", "k", "--initrd", "i",
                            "--host-disk", "w=/dev/null", "--flag", "unclean-end"])


class CmdQemuTest(unittest.TestCase):
    """cmd_qemu's own wiring, with QEMU and the snapshots stubbed (M9)."""

    def run_qemu(self, phases, file_phases, events, flags=(), source=("--image", "/x/agentos.img"), on_boot=None, stubs=None):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "vars.fd").write_bytes(b"")
            (d / "phases.json").write_text(json.dumps(file_phases))
            seen, judged = [], []

            def boot_once(args, work, label, steps, boot):
                seen.append((label, steps, boot))
                if on_boot:
                    on_boot(args, label)
                return {"rtc": [], "errors": [], "events": events.get(label, [])}

            evaluate = hostcheck.evaluate

            def spy(before, after, allow, flags=(), **kw):
                judged.append(list(flags))
                return evaluate(before, after, allow, flags=flags, **kw)

            argv = ["qemu", "--work", str(d / "work"), *source, "--phases-file",
                    str(d / "phases.json"), "--host-disk", "w=/dev/null", "--ovmf-vars", str(d / "vars.fd"),
                    "--phases", phases] + [a for f in flags for a in ("--flag", f)]
            with unittest.mock.patch.multiple(hostcheck, boot_once=boot_once, seed_tpm=lambda a, w: None,
                                              qemu_snapshot=lambda a, w: snap(), evaluate=spy, **(stubs or {})):
                rc = hostcheck.main(argv)
            report = d / "work" / "report.json"
            return rc, seen, judged, json.loads(report.read_text()) if report.exists() else None

    PHASES = {"task": [["Linux version", "os"], ["READY", "serial:task\n"], ["READY", "serial:poweroff\n"]],
              "unclean": [["Linux version", "os"], ["READY", "power-cut"]]}
    CUT = {"event": "SHUTDOWN", "timestamp": {"seconds": 30, "microseconds": 0},
           "data": {"guest": False, "reason": "host-qmp-quit"}}

    def test_flags_reach_each_phase_and_unclean_end_the_unclean_phase_alone(self):
        rc, seen, judged, report = self.run_qemu("task,unclean,task", self.PHASES, {"unclean": [self.CUT]},
                                                 flags=["owner-boot-order"])
        self.assertEqual(rc, 0, report)
        self.assertEqual([s[0] for s in seen], ["firmware-1", "firmware-2", "task", "unclean", "task"])
        self.assertEqual([s[2] for s in seen[:2]], [None, None])  # firmware-only boots have no drive
        self.assertTrue(all(s[2] for s in seen[2:]))
        self.assertEqual(seen[3][1], [tuple(x) for x in self.PHASES["unclean"]])
        self.assertEqual(judged, [["owner-boot-order"], ["owner-boot-order", "unclean-end"], ["owner-boot-order"]])
        rc, _, judged, _ = self.run_qemu("unclean", self.PHASES, {"unclean": [self.CUT]})
        self.assertEqual((rc, judged), (0, [["unclean-end"]]))

    def test_a_phases_file_replaces_the_stand_ins_phases(self):
        # The halting-guest QEMU test boots the stand-in with its own unclean phase (#5256).
        _, seen, _, _ = self.run_qemu("unclean", self.PHASES, {"unclean": [self.CUT]},
                                      source=("--kernel", "k", "--initrd", "i"))
        self.assertEqual(seen[2][1], [tuple(x) for x in self.PHASES["unclean"]])
        self.assertEqual(seen[2][2][:2], ["-kernel", "k"])

    def test_an_unclean_phase_from_a_phases_file_with_an_orderly_end_is_refused(self):
        # The row's failure path: a phases file whose unclean phase powers off in order before the quit.
        shaped = dict(self.PHASES, unclean=[["Linux version", "os"], ["READY", "qmp:system_powerdown"],
                                            ["X", "power-cut"]])
        rc, seen, judged, report = self.run_qemu("unclean", shaped, {})
        self.assertEqual((rc, judged, report), (2, [], None))
        self.assertEqual([s[0] for s in seen], ["firmware-1", "firmware-2"])  # refused before it boots
        # A guest that powers off on its own, told by the console alone, is caught by QEMU's events.
        off = {"event": "SHUTDOWN", "timestamp": {"seconds": 20, "microseconds": 0},
               "data": {"guest": True, "reason": "guest-shutdown"}}
        rc, _, judged, report = self.run_qemu("unclean", self.PHASES, {"unclean": [off, self.CUT]})
        self.assertEqual((rc, judged, report), (2, [], None))


    def test_a_record_written_after_its_process_was_checked_fails_the_run(self):
        # #5231: stack_done checks the records as each stack process ends; one written after that (by a
        # child still running) is caught by one more sweep before report.json is written.
        class Listing:
            pid, returncode = 1, 0

            def communicate(self, timeout=None):
                return os.path.join(root, "usr/share/qemu") + "\n", None

        with tempfile.TemporaryDirectory() as root:
            fake_root(root)
            for where, want in ((root, 0), ("/lib/x86_64-linux-gnu", 2)):
                def late(args, label):
                    if label == "unclean":
                        pathlib.Path(f"{args.ld_log}.9").write_bytes(os.fsencode(f"{where}/libc.so.6\0"))
                with self.subTest(where):
                    rc, _, _, report = self.run_qemu(
                        "unclean", self.PHASES, {"unclean": [self.CUT]}, on_boot=late,
                        source=("--image", "/x/agentos.img", "--tools-root", root),
                        stubs=dict(stack_popen=lambda *a, **kw: Listing(), stack_done=lambda a, p: None))
                    self.assertEqual((rc, report is None), (want, want == 2))


class DriveTest(unittest.TestCase):
    """Qemu.drive against a scripted console: the OS mark and the power cut's liveness check (#5256)."""

    def qemu(self, answer):
        q = hostcheck.Qemu.__new__(hostcheck.Qemu)
        q.label, q.console, q.os_marks, q.sent = "unclean", bytearray(b"Linux version 6\r\nHOSTCHECK-READY\r\n"), 0, []
        q.proc = unittest.mock.Mock(poll=lambda: None)
        q._qmp_send = lambda msg: q.sent.append(("qmp", msg["execute"]))

        def sendall(data):
            q.sent.append(("serial", data))
            if reply := answer(data.decode()):
                q.console += reply.encode()
        q.serial = unittest.mock.Mock(sendall=sendall)
        return q

    def drive(self, q, steps=(("Linux version", "os"), ("HOSTCHECK-READY", "power-cut"))):
        with unittest.mock.patch.object(hostcheck, "ALIVE_WAIT", 0.2):
            q.drive(list(steps), time.monotonic() + 60)

    def test_the_os_start_is_a_stop_in_qemus_own_stream(self):
        q = self.qemu(lambda line: f"{line.replace('alive', 'HOSTCHECK-ALIVE')}\r\n")
        self.drive(q)
        self.assertEqual(q.os_marks, 1)
        self.assertEqual(q.sent[:2], [("qmp", "stop"), ("qmp", "cont")])

    def test_the_power_cut_quits_only_after_a_fresh_answer(self):
        q = self.qemu(lambda line: f"echo {line}HOSTCHECK-ALIVE {line.split()[1]}\r\n")
        self.drive(q)
        (kind, challenge), quit_ = q.sent[2:]
        self.assertEqual(kind, "serial")
        self.assertRegex(challenge, rb"^alive [0-9a-f]{16}\n$")
        self.assertEqual(quit_, ("qmp", "quit"))
        nonces = set()
        for _ in range(3):
            q = self.qemu(lambda line: f"HOSTCHECK-ALIVE {line.split()[1]}\r\n")
            self.drive(q)
            nonces.add(q.sent[2][1])
        self.assertEqual(len(nonces), 3)

    def test_a_guest_that_does_not_answer_is_not_cut_and_fails_naming_the_line(self):
        # A halted guest prints nothing; the kernel's echo of the challenge, an answer printed before
        # it, or one with another nonce are not answers.
        for name, console, answer in [
                ("halted", b"", lambda line: None),
                ("tty echo", b"", lambda line: line),
                ("stale", b"HOSTCHECK-ALIVE 0123456789abcdef\r\n", lambda line: None),
                ("wrong nonce", b"", lambda line: "HOSTCHECK-ALIVE 0123456789abcdef\r\n")]:
            with self.subTest(name):
                q = self.qemu(answer)
                q.console += console
                start = time.monotonic()
                with self.assertRaisesRegex(hostcheck.HostcheckError, r"unclean: no 'HOSTCHECK-ALIVE [0-9a-f]{16}'"):
                    self.drive(q)
                self.assertNotIn(("qmp", "quit"), q.sent)
                self.assertLess(time.monotonic() - start, 30)  # ALIVE_WAIT bounds it, not the run's deadline

    def test_each_step_waits_for_a_match_after_the_last(self):
        # The restart phase waits for the OS's first line twice; one boot's line must not serve both.
        q = self.qemu(lambda line: None)
        with self.assertRaisesRegex(hostcheck.HostcheckError, "no 'Linux version' on the console in time"):
            q.drive([("Linux version", "os"), ("Linux version", "os")], time.monotonic() + 0.3)
        self.assertEqual(q.os_marks, 1)

    def test_stop_events_must_match_the_os_marks(self):
        # A STOP QEMU sent on its own (a disk error) would pass for an OS start.
        with tempfile.TemporaryDirectory() as d:
            for marks, events, ok in ((1, [{"event": "STOP"}], True), (1, [], False),
                                      (1, [{"event": "STOP"}, {"event": "STOP"}], False)):
                with self.subTest(marks=marks, events=events):
                    q = hostcheck.Qemu.__new__(hostcheck.Qemu)
                    q.label, q.work, q.sock_dir, q.os_marks = "task", pathlib.Path(d), os.path.join(d, "s"), marks
                    q.events = [dict(e, timestamp={"seconds": 1, "microseconds": 0}) for e in events]
                    q.args = argparse.Namespace(tools_root=None, ld_log=None)
                    q.proc, q.swtpm = unittest.mock.Mock(returncode=0), unittest.mock.Mock()
                    q.qmp_reader, q.qmp_error = unittest.mock.Mock(is_alive=lambda: False), None
                    if ok:
                        self.assertEqual(q.wait(time.monotonic() + 5), [])
                    else:
                        with self.assertRaisesRegex(hostcheck.HostcheckError, "STOP events for 1 OS starts"):
                            q.wait(time.monotonic() + 5)


class AllowListTest(unittest.TestCase):
    def test_entries_name_owner_guide_changes(self):
        # Every disclosed change the check allows is one the owner's guide
        # lists (broker/hostchange), and every UEFI or TPM item there has a
        # rule, so the check and the guide cannot drift apart.
        src = (ROOT / "broker" / "hostchange" / "hostchange.go").read_text()
        guide = {m.group(1): m.group(2) for m in re.finditer(r'\{"([a-z-]+)",\s*(UEFI|TPM|Windows)\}', src)}
        self.assertIn("boot-order", guide)
        allow = hostcheck.load_allow()
        ids = {r["change"] for r in allow}
        self.assertLessEqual(ids, set(guide))
        self.assertEqual(ids, {i for i, k in guide.items() if k in ("UEFI", "TPM")})

    # Keys each keyed rule must disclose; a rule added without one fails the test below.
    EXAMPLES = {"boot-order": [f"{GLOBAL}:BootOrder", f"{GLOBAL}:Boot0000", f"{GLOBAL}:Boot00FF"],
                "loader-system-token": [f"{SYSTEMD}:LoaderSystemToken"],
                "sbat-level": [f"{SHIM}:SbatLevel"],
                "mor": [MOR],
                "tpm-srk": ["0x81000001"],
                "tpm-lockout": ["lockoutAuthSet", "TPM2_PT_MAX_AUTH_FAIL", "TPM2_PT_LOCKOUT_INTERVAL",
                                "TPM2_PT_LOCKOUT_RECOVERY"]}

    def test_every_rule_key_is_anchored_and_flags_its_neighbours(self):
        # An unanchored or loosened key would disclose a variable or setting next to the one HW-8 names.
        allow = hostcheck.load_allow()
        flags = {"owner-boot-order", "unclean-end"}
        keyed = [r for r in allow if "key" in r]
        self.assertEqual({r["change"] for r in keyed}, set(self.EXAMPLES))
        self.assertTrue(all("range" in r for r in allow if "key" not in r))
        empty = {k: {} for k in hostcheck.KINDS}
        for rule in keyed:
            self.assertTrue(rule["key"].startswith("^") and rule["key"].endswith("$"), rule["key"])
            for key in self.EXAMPLES[rule["change"]]:
                guid, sep, name = key.rpartition(":")
                near = [f"x{key}", f"{key}x", f" {key}", f"{key}\n", key.lower() if key != key.lower() else key.upper()]
                if sep:
                    near += [f"{SYSTEMD if guid != SYSTEMD else SHIM}:{name}", f"{guid}:{name}x", f"{guid}:x{name}"]
                for change in rule["changes"]:
                    for k, want in [(key, "disclosed")] + [(n, "flagged") for n in near]:
                        with self.subTest(rule=rule["change"], key=k, change=change):
                            b, a = json.loads(json.dumps(empty)), json.loads(json.dumps(empty))
                            if change != "added":
                                b[rule["kind"]][k] = 0
                            if change != "removed":
                                a[rule["kind"]][k] = 1
                            r = hostcheck.evaluate(b, a, allow, flags=flags)
                            self.assertEqual([f["key"] for f in r[want]], [k], r)


class SourcesTest(unittest.TestCase):
    def test_disk_hash_sees_last_byte(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d, "disk.img")
            p.write_bytes(b"\0" * (hostcheck.CHUNK + 5))
            h1 = hostcheck.hash_disk(p)
            with open(p, "r+b") as f:
                f.seek(-1, os.SEEK_END)
                f.write(b"\1")
            self.assertNotEqual(h1, hostcheck.hash_disk(p))

    def test_efivarfs_keeps_only_non_volatile(self):
        with tempfile.TemporaryDirectory() as d:
            pathlib.Path(d, f"BootOrder-{GLOBAL}").write_bytes((7).to_bytes(4, "little") + b"\0\0")
            pathlib.Path(d, f"BootCurrent-{GLOBAL}").write_bytes((6).to_bytes(4, "little") + b"\0\0")
            v = hostcheck.uefi_from_efivarfs(d)
            self.assertEqual(set(v), {f"{GLOBAL}:BootOrder"})
            self.assertEqual(v[f"{GLOBAL}:BootOrder"]["attr"], 7)


# CI-hostcheck-image-tools (#4906, #5055): the VM stack hostcheck boots (qemu, swtpm, OVMF) comes
# from a root installed from the image's pinned Debian snapshot, never the runner's archive, and a
# shared object it looks for or loads outside that root fails the run, so a runner package update
# cannot change a result.
PINNED = ("qemu-system-x86", "ovmf", "swtpm", "swtpm-tools")


def fake_root(d, versions=None, skip=()):
    """A tools root with the loader, the three binaries and OVMF as regular files."""
    for rel in (hostcheck.TOOLS_LOADER, *hostcheck.TOOLS.values(), *hostcheck.TOOLS_OVMF):
        if rel in skip:
            continue
        f = pathlib.Path(d, rel)
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"x")
    status = pathlib.Path(d, "var/lib/dpkg/status")
    status.parent.mkdir(parents=True, exist_ok=True)
    versions = {p: "1:1.0-1" for p in PINNED} if versions is None else versions
    status.write_text("\n\n".join(f"Package: {p}\nStatus: install ok installed\nVersion: {v}"
                                  for p, v in versions.items()) + "\n")
    return d


def qemu_argv(work, root, kernel="k", initrd="i"):
    return ["qemu", "--work", str(work), "--kernel", kernel, "--initrd", initrd,
            "--host-disk", "w=/dev/null", "--tools-root", root]


class ToolsRootTest(unittest.TestCase):
    def test_no_root_runs_the_path_tools(self):
        self.assertEqual(hostcheck.tool_argv(None, "swtpm"), ["swtpm"])
        self.assertEqual(hostcheck.qemu_data_args(None), [])
        self.assertIsNone(hostcheck.tool_env(None, "/x/ld"))
        hostcheck.audit_loads(None, "/nonexistent/ld", 1)  # the runner's own tools: nothing to audit

    def test_root_tools_run_on_the_roots_loader_and_libraries(self):
        with tempfile.TemporaryDirectory() as d:
            fake_root(d)
            for name, rel in hostcheck.TOOLS.items():
                argv = hostcheck.tool_argv(d, name)
                self.assertEqual(argv[:2], [os.path.join(d, hostcheck.TOOLS_LOADER), "--inhibit-cache"])
                self.assertEqual(argv[-3:], ["--argv0", name, os.path.join(d, rel)])
                libs = argv[argv.index("--library-path") + 1].split(":")
                self.assertTrue(libs and all(lib.startswith(d + os.sep) for lib in libs), libs)
            self.assertEqual(hostcheck.qemu_data_args(d), ["-L", os.path.join(d, "usr/share/qemu")])

    def test_the_stack_gets_none_of_the_hosts_environment(self):
        with tempfile.TemporaryDirectory() as d, unittest.mock.patch.dict(
                os.environ, {"LD_PRELOAD": "/x/evil.so", "LD_DEBUG": "", "QEMU_MODULE_DIR": "/usr/lib"}):
            self.assertEqual(hostcheck.tool_env(d, "/w/ld/stack"), {
                "PATH": "/usr/sbin:/usr/bin", "QEMU_MODULE_DIR": os.path.join(d, "usr/lib/x86_64-linux-gnu/qemu"),
                "LD_AUDIT": hostcheck.auditor(), "AGENTOS_LOADER_RECORD": "/w/ld/stack"})

    def test_missing_or_linked_tool_is_an_error_not_the_runners(self):
        for rel in (hostcheck.TOOLS_LOADER, hostcheck.TOOLS["swtpm"]):
            with self.subTest(rel=rel), tempfile.TemporaryDirectory() as d:
                fake_root(d, skip=(rel,))
                with self.assertRaises(hostcheck.HostcheckError):
                    hostcheck.tool_argv(d, "swtpm")
                os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
                os.symlink("/usr/bin/true", os.path.join(d, rel))  # an absolute link reads the runner's
                with self.assertRaises(hostcheck.HostcheckError):
                    hostcheck.tool_argv(d, "swtpm")

    def test_qemu_rom_directories_outside_the_root_must_not_exist(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as host:
            mine = os.path.join(d, "usr/share/qemu")
            os.makedirs(mine)
            listing = f"{mine}\n{d}/usr/lib/share/qemu\n/nonexistent/share/qemu\n{host}\n"
            self.assertEqual(hostcheck.foreign_data_dirs(d, listing), [host])
            os.symlink(host, os.path.join(d, "usr/share/seabios"))  # a link in the root out to the host
            self.assertEqual(hostcheck.foreign_data_dirs(d, f"{d}/usr/share/seabios\n"), [f"{d}/usr/share/seabios"])
            self.assertEqual(hostcheck.foreign_data_dirs(d, f"{mine}\n/nonexistent\n"), [])

    def test_tools_are_checked_before_any_state_is_made(self):
        for name, rel in hostcheck.TOOLS.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                fake_root(d, skip=(rel,))
                work = pathlib.Path(d, "work")
                self.assertEqual(hostcheck.main(qemu_argv(work, d)), 2)
                self.assertFalse(work.exists())

    def test_ovmf_defaults_follow_the_root(self):
        with tempfile.TemporaryDirectory() as d:
            fake_root(d)
            a = argparse.Namespace(tools_root=d, ovmf_code=None, ovmf_vars=None)
            hostcheck.resolve_tools(a)
            self.assertEqual((a.ovmf_code, a.ovmf_vars), tuple(os.path.join(d, r) for r in hostcheck.TOOLS_OVMF))
            a = argparse.Namespace(tools_root=d, ovmf_code="/x/code.fd", ovmf_vars=None)
            hostcheck.resolve_tools(a)
            self.assertEqual(a.ovmf_code, "/x/code.fd")
        a = argparse.Namespace(tools_root=None, ovmf_code=None, ovmf_vars=None)
        hostcheck.resolve_tools(a)
        self.assertEqual((a.ovmf_code, a.ovmf_vars), ("/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
                                                      "/usr/share/OVMF/OVMF_VARS_4M.fd"))

    def test_report_names_the_stack_it_booted(self):
        with tempfile.TemporaryDirectory() as d:
            fake_root(d, versions={"qemu-system-x86": "1:10.0.2+ds-2", "ovmf": "2025.02-8",
                                   "swtpm": "0.7.3-1", "swtpm-tools": "0.7.3-1"})
            self.assertEqual(hostcheck.stack_versions(d)["ovmf"], "2025.02-8")
        with tempfile.TemporaryDirectory() as d:
            fake_root(d, versions={"qemu-system-x86": "1", "ovmf": "1", "swtpm": "1"})
            with self.assertRaises(hostcheck.HostcheckError):  # swtpm-tools not installed
                hostcheck.stack_versions(d)
        self.assertEqual(hostcheck.stack_versions(None), "runner")

    def test_only_installed_packages_count(self):
        # A package removed with its config files kept stays in dpkg's status, not installed.
        with tempfile.TemporaryDirectory() as d:
            fake_root(d)
            status = pathlib.Path(d, "var/lib/dpkg/status")
            text = status.read_text().replace("Package: ovmf\nStatus: install ok installed",
                                              "Package: ovmf\nStatus: deinstall ok config-files")
            self.assertIn("config-files", text)
            status.write_text(text)
            with self.assertRaisesRegex(hostcheck.HostcheckError, "ovmf"):
                hostcheck.stack_versions(d)

    def test_a_root_without_dpkg_status_names_the_path(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(hostcheck.HostcheckError, re.escape(os.path.join(d, "var/lib/dpkg/status"))):
                hostcheck.stack_versions(d)
            self.assertEqual(hostcheck.main(qemu_argv(pathlib.Path(d, "work"), d)), 2)


class LoaderAuditTest(unittest.TestCase):
    """#5055: run through the root's loader with --library-path, a library the root lacks still loads
    from the host's directories, so the loader's record of every search and load is checked. The
    probe is the host's ls, which links more than libc (libselinux on Ubuntu), in a root that holds
    the host's loader and libc (and, for the control, every library ls needs)."""

    PROBE = "/usr/bin/ls"

    def root(self, d, with_deps):
        out = subprocess.run(["ldd", self.PROBE], capture_output=True, text=True, check=True).stdout
        libs = [a or b for a, b in re.findall(r"=> (/\S+)|^\s*(/\S+)", out, re.M)]
        keep = [lib for lib in libs if with_deps or re.search(r"/(ld-linux-x86-64\.so\.2|libc\.so\.6)$", lib)]
        self.assertGreater(len(libs), len(keep) if not with_deps else 2, libs)
        for lib in keep:
            dst = pathlib.Path(d, "usr/lib/x86_64-linux-gnu", os.path.basename(lib))
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(os.path.realpath(lib), dst)
        pathlib.Path(d, "usr/bin").mkdir(parents=True)
        shutil.copy(self.PROBE, pathlib.Path(d, hostcheck.TOOLS["swtpm"]))
        return libs

    def run_probe(self, d, ld_log):
        args = argparse.Namespace(tools_root=d, ld_log=ld_log)
        p = hostcheck.stack_popen(args, "swtpm", [d], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = p.communicate(timeout=60)
        self.assertEqual(p.returncode, 0, err)  # it starts: the run would have passed without the record
        hostcheck.stack_done(args, p)

    def test_the_root_alone_serves_the_stack(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as log:
            self.root(d, with_deps=True)
            self.run_probe(d, os.path.join(log, "stack"))

    def test_a_library_the_root_lacks_fails_the_run(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as log:
            self.root(d, with_deps=False)
            with self.assertRaisesRegex(hostcheck.HostcheckError, r"outside the tools root.*libselinux"):
                self.run_probe(d, os.path.join(log, "stack"))

    def test_a_link_out_of_the_root_fails_the_run(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as log:
            libs = self.root(d, with_deps=True)
            sel = next(lib for lib in libs if "libselinux" in lib)
            dst = pathlib.Path(d, "usr/lib/x86_64-linux-gnu", os.path.basename(sel))
            dst.unlink()
            dst.symlink_to(os.path.realpath(sel))  # absolute: the host's copy
            with self.assertRaisesRegex(hostcheck.HostcheckError, "outside the tools root"):
                self.run_probe(d, os.path.join(log, "stack"))

    def test_a_missing_empty_or_cut_record_fails_the_run(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(hostcheck.HostcheckError, "kept no record"):
                hostcheck.audit_loads(d, os.path.join(d, "stack"), 42)
            pathlib.Path(d, "stack.43").write_bytes(os.fsencode(f"{d}/libc.so.6\0"))  # another process's only
            with self.assertRaisesRegex(hostcheck.HostcheckError, "kept no record"):
                hostcheck.audit_loads(d, os.path.join(d, "stack"), 42)
            os.unlink(os.path.join(d, "stack.43"))
            for data, why in ((b"", "names no shared object"), (b"\0linux-vdso.so.1\0libc.so.6\0", "names no shared object"),
                              (os.fsencode(d) + b"/libc.so.6", "ends inside a name")):
                with self.subTest(data):
                    pathlib.Path(d, "stack.42").write_bytes(data)
                    with self.assertRaisesRegex(hostcheck.HostcheckError, why):
                        hostcheck.audit_loads(d, os.path.join(d, "stack"), 42)

    def test_a_child_the_stack_starts_is_audited(self):
        # The probe is the host's dash in the root (libc alone); it runs the host's true, whose own
        # loader and libc are the runner's. Only the child's record shows it.
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as log:
            libs = self.root(d, with_deps=True)
            dash = os.path.realpath("/bin/sh")
            self.assertIn("libc.so.6", subprocess.run(["ldd", dash], capture_output=True, text=True).stdout)
            shutil.copy(dash, pathlib.Path(d, hostcheck.TOOLS["swtpm"]))
            args = argparse.Namespace(tools_root=d, ld_log=os.path.join(log, "stack"))
            p = hostcheck.stack_popen(args, "swtpm", ["-c", "/usr/bin/true; exit 0"])
            self.assertEqual(p.wait(timeout=60), 0)
            self.assertEqual(len(os.listdir(log)), 2, os.listdir(log))
            with self.assertRaisesRegex(hostcheck.HostcheckError, "outside the tools root"):
                hostcheck.stack_done(args, p)
            self.assertTrue(libs)

    def test_records_are_read_as_whole_names(self):
        # #5231: names are NUL-ended, so a name holding a newline, a record-shaped line or " [N];  " is one
        # name, read whole, as bytes; a relative name (the process's cwd, unknown here) fails.
        with tempfile.TemporaryDirectory() as d:
            up = "/.." * 12
            rec = pathlib.Path(d, "stack.7")
            for name in (f"{d}/a\n      7:\ttrying file={d}/b{up}/lib/libc.so.6",
                         f"{d}/a [0];  generating link map{up}/lib/libc.so.6",
                         f"{d}/../lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libbar.so.2", "./libx.so"):
                with self.subTest(name):
                    rec.write_bytes(os.fsencode(f"{d}/usr/lib/libc.so.6\0{name}\0"))
                    with self.assertRaisesRegex(hostcheck.HostcheckError, "outside the tools root"):
                        hostcheck.audit_loads(d, os.path.join(d, "stack"), 7)
            rec.write_bytes(os.fsencode(f"\0libc.so.6\0{d}/a\n\n 1:\tq [0];  needed by\0{d}/usr/lib/libc.so.6\0"))
            hostcheck.audit_loads(d, os.path.join(d, "stack"), 7)
            pathlib.Path(d, "stack.8").write_bytes(b"/lib/x86_64-linux-gnu/libc.so.6\0")  # a child's, beside it
            with self.assertRaisesRegex(hostcheck.HostcheckError, "outside the tools root"):
                hostcheck.audit_loads(d, os.path.join(d, "stack"), 7)
            os.unlink(os.path.join(d, "stack.8"))
            cwd = os.getcwd()  # a relative name fails even when it would resolve inside the root
            try:
                os.chdir(d)
                rec.write_bytes(b"./libx.so\0")
                with self.assertRaisesRegex(hostcheck.HostcheckError, "outside the tools root"):
                    hostcheck.audit_loads(d, os.path.join(d, "stack"), 7)
            finally:
                os.chdir(cwd)
            os.symlink("/usr/lib", os.path.join(os.fsencode(d), b"\xff"))  # not UTF-8: realpath gets its bytes
            rec.write_bytes(os.fsencode(d) + b"/\xff/libc.so.6\0")
            with self.assertRaisesRegex(hostcheck.HostcheckError, "outside the tools root"):
                hostcheck.audit_loads(d, os.path.join(d, "stack"), 7)

    DLOPEN = ("#define _GNU_SOURCE\n#include <dlfcn.h>\nint main(int c, char **v) {\n"  # a 2nd argument: a new namespace
              "  return c < 2 || c > 3 || !(c == 3 ? dlmopen(LM_ID_NEWLM, v[1], RTLD_NOW) : dlopen(v[1], RTLD_NOW)); }\n")

    def dlopen_root(self, d):
        """A root of the host's loader and libc whose `swtpm` dlopens its one argument."""
        self.root(d, with_deps=False)
        src = pathlib.Path(d, "dl.c")
        src.write_text(self.DLOPEN)
        subprocess.run(["cc", "-o", os.path.join(d, hostcheck.TOOLS["swtpm"]), str(src)], check=True)

    def test_every_forged_name_fails_through_the_real_loader(self):
        # #5310's review repros, each a name in the root that LD_DEBUG's text let pass: the loader maps the
        # runner's libm through it, and the record names it whole, so its real path fails the run. The same
        # names leading to the root's own libc pass.
        libm = next(p for p in ("/usr/lib/x86_64-linux-gnu/libm.so.6", "/lib/x86_64-linux-gnu/libm.so.6")
                    if os.path.isfile(p))
        names = ("L [0];  needed by y [2]; ",  # L3 and Security round 1: a name holding its own split
                 "X [0];  generating link map\n 1:\topening file=q",  # Security round 1: newline, another PID
                 "Y [0];  generating link map\n\n 1:\tq",  # Security round 3: a blank line, then another PID
                 "Z\n      7:\ttrying file=libc.so.6", b"\xff")  # a record line; not UTF-8
        for name in names:
            for target, ok in ((libm, False), ("usr/lib/x86_64-linux-gnu/libc.so.6", True)):
                with self.subTest(name=name, ok=ok), tempfile.TemporaryDirectory() as d, \
                        tempfile.TemporaryDirectory() as log:
                    self.dlopen_root(d)
                    path = os.path.join(os.fsencode(d), os.fsencode(name))
                    os.symlink(target, path)
                    args = argparse.Namespace(tools_root=d, ld_log=os.path.join(log, "stack"))
                    p = hostcheck.stack_popen(args, "swtpm", [path])
                    self.assertEqual(p.wait(timeout=60), 0)  # it loaded: only the record tells
                    if ok:
                        hostcheck.stack_done(args, p)
                        continue
                    with self.assertRaisesRegex(hostcheck.HostcheckError, "outside the tools root"):
                        hostcheck.stack_done(args, p)
        # A search the runner's directories end, for a name found nowhere (an optional library), fails too:
        # a runner update could add the library there.
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as log:
            self.dlopen_root(d)
            args = argparse.Namespace(tools_root=d, ld_log=os.path.join(log, "stack"))
            p = hostcheck.stack_popen(args, "swtpm", ["libagentos-absent.so.9"])
            self.assertEqual(p.wait(timeout=60), 1)  # not found: the tool goes on without it
            with self.assertRaisesRegex(hostcheck.HostcheckError, "outside the tools root.*libagentos-absent"):
                hostcheck.stack_done(args, p)
        # dlmopen into a new namespace by path asks no search of the module, only maps: la_objopen names it.
        for target, ok in ((libm, False), (None, True)):
            with self.subTest(dlmopen=target), tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as log:
                self.dlopen_root(d)
                args = argparse.Namespace(tools_root=d, ld_log=os.path.join(log, "stack"))
                p = hostcheck.stack_popen(args, "swtpm", [target or os.path.join(d, hostcheck.TOOLS_LIBS[0], "libc.so.6"), "new"])
                self.assertEqual(p.wait(timeout=60), 0)
                if ok:
                    hostcheck.stack_done(args, p)
                    continue
                with self.assertRaisesRegex(hostcheck.HostcheckError, "outside the tools root.*libm"):
                    hostcheck.stack_done(args, p)
        # A path that leaves the root by ".." is named as given, so its real path fails too.
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as log:
            self.dlopen_root(d)
            os.makedirs(os.path.join(d, "a [0];  needed by ", "x"))
            args = argparse.Namespace(tools_root=d, ld_log=os.path.join(log, "stack"))
            p = hostcheck.stack_popen(args, "swtpm", [os.path.join(d, "a [0];  needed by ", "x") + "/.." * 40 + libm])
            self.assertEqual(p.wait(timeout=60), 0)
            with self.assertRaisesRegex(hostcheck.HostcheckError, "outside the tools root"):
                hostcheck.stack_done(args, p)

    def test_a_forked_child_passes_and_a_process_without_its_record_stops(self):
        # #5310 round 2: a child forked without an exec (bash's subshell) is normal output, not a failure.
        # The probe is the host's bash in the root with every library it links.
        bash = os.path.realpath(shutil.which("bash"))
        out = subprocess.run(["ldd", bash], capture_output=True, text=True, check=True).stdout
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as log:
            for lib in [a or b for a, b in re.findall(r"=> (/\S+)|^\s*(/\S+)", out, re.M)]:
                dst = pathlib.Path(d, "usr/lib/x86_64-linux-gnu", os.path.basename(lib))
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(os.path.realpath(lib), dst)
            pathlib.Path(d, "usr/bin").mkdir(parents=True)
            shutil.copy(bash, pathlib.Path(d, hostcheck.TOOLS["swtpm"]))
            args = argparse.Namespace(tools_root=d, ld_log=os.path.join(log, "stack"))
            p = hostcheck.stack_popen(args, "swtpm", ["-c", "( echo sub >/dev/null; ); echo done"],
                                      stdout=subprocess.DEVNULL)
            self.assertEqual(p.wait(timeout=60), 0)
            hostcheck.stack_done(args, p)
            # The module stops a process that has no record to write to, rather than run it unrecorded.
            # Nor one whose record path is relative or cannot be written.
            for record in (None, "stack", os.path.join(log, "absent", "stack")):
                with self.subTest(record=record):
                    env = hostcheck.tool_env(d, os.path.join(log, "other"))
                    if record is None:
                        del env["AGENTOS_LOADER_RECORD"]
                    else:
                        env["AGENTOS_LOADER_RECORD"] = record
                    p = subprocess.run(hostcheck.tool_argv(d, "swtpm") + ["-c", "exit 0"], env=env, cwd=log)
                    self.assertEqual(p.returncode, 127)

    def test_records_alone_need_one_and_read_every_one(self):
        # #5231: audit_records, for tools with no PID to name (tests/test_image.py image_tool), needs a record.
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(hostcheck.HostcheckError, "kept no record"):
                hostcheck.audit_records(d, os.path.join(d, "tool"))
            pathlib.Path(d, "toolbox.3").write_bytes(os.fsencode(f"{d}/libc.so.6\0"))
            with self.assertRaisesRegex(hostcheck.HostcheckError, "kept no record"):  # another prefix's
                hostcheck.audit_records(d, os.path.join(d, "tool"))
            pathlib.Path(d, "tool.3").write_bytes(os.fsencode(f"{d}/libc.so.6\0"))
            hostcheck.audit_records(d, os.path.join(d, "tool"))
            pathlib.Path(d, "tool.4").write_bytes(b"/lib/x86_64-linux-gnu/libc.so.6\0")
            with self.assertRaisesRegex(hostcheck.HostcheckError, "outside the tools root"):
                hostcheck.audit_records(d, os.path.join(d, "tool"))
        hostcheck.audit_records(None, "/nonexistent/tool")


class StandinTest(unittest.TestCase):
    """The stand-in guest clears MOR's ClearMemory bit, and only it, on every way out but the negative
    test's halt (#4794, #5055, #5256).
    The EFI stub sets the bit again at each boot and a later poweroff clears it too, so a QEMU run
    cannot see a reboot that skips the clear: the script's lines are pinned and the function runs here."""

    def setUp(self):
        src = (ROOT / "tools" / "hostcheck_standin.sh").read_text()
        self.init = re.search(r"^cat >\"\$root/init\" <<'EOF'\n(.*?)^EOF$", src, re.S | re.M).group(1)
        self.func = re.search(r"^mor_clear\(\) \{\n.*?^\}\n", self.init, re.S | re.M).group(0)

    def exits(self, init):
        return [ln.strip() for ln in init.splitlines() if re.search(r"\b(reboot|poweroff|halt)\b.*-f\b", ln)]

    def test_every_exit_clears_mor_first(self):
        self.assertEqual(self.exits(self.init), [
            'read -r cmd arg || { sync; mor_clear "$MOR"; exec poweroff -f; }',
            'reboot) sync; mor_clear "$MOR"; reboot -f ;;',
            'poweroff) sync; mor_clear "$MOR"; poweroff -f ;;',
            'halt) sync; halt -f ;;'])  # the halting guest's: it must leave MOR set (#5256)
        self.assertIn("\nMOR=/sys/firmware/efi/efivars/MemoryOverwriteRequestControl-"
                      "e20939be-32d4-41be-a150-897f85d49829\n", self.init)
        for old, new in (('reboot) sync; mor_clear "$MOR"; ', "reboot) sync; "),
                         ('poweroff) sync; mor_clear "$MOR"; ', "poweroff) sync; "),
                         ('{ sync; mor_clear "$MOR"; exec', "{ sync; exec")):
            with self.subTest(old):
                self.assertNotEqual(self.exits(self.init.replace(old, new)), self.exits(self.init))

    def clear(self, data, failing=()):
        with tempfile.TemporaryDirectory() as d:
            stubs = pathlib.Path(d, "bin")
            stubs.mkdir()
            for tool, rc in (("chattr", 0), *((t, 1) for t in failing)):  # efivarfs's immutable flag
                pathlib.Path(stubs, tool).write_text(f"#!/bin/sh\nexit {rc}\n")
                pathlib.Path(stubs, tool).chmod(0o755)
            var = pathlib.Path(d, "mor")
            if data is not None:
                var.write_bytes(data)
            p = subprocess.run(["sh", "-c", self.func + 'mor_clear "$1"', "sh", str(var)], capture_output=True,
                               text=True, env={"PATH": f"{stubs}:/usr/bin:/bin"})
            self.assertEqual(p.returncode, 0, p.stderr)
            return (var.read_bytes() if data is not None else None), p.stdout.strip()

    def test_only_the_clear_memory_bit_is_cleared(self):
        attrs = b"\x07\x00\x00\x00"
        for before, after in ((0x01, 0x00), (0x03, 0x02), (0xff, 0xfe), (0x02, 0x02), (0x00, 0x00)):
            with self.subTest(before=before):
                self.assertEqual(self.clear(attrs + bytes([before])), (attrs + bytes([after]), ""))
        self.assertEqual(self.clear(None), (None, ""))  # firmware without the variable

    def test_a_failed_clear_says_so(self):
        self.assertEqual(self.clear(b"\x07\x00\x00\x00"), (b"\x07\x00\x00\x00", "HOSTCHECK-MOR-FAILED size"))
        self.assertEqual(self.clear(b"\x07\x00\x00\x00\x01", failing=("dd",))[1], "HOSTCHECK-MOR-FAILED write")

    def test_hostcheck_shows_a_guest_failure(self):
        console = b"HOSTCHECK-READY\r\nHOSTCHECK-MOR-FAILED write\r\nHOSTCHECK-PLANT-FAILED nv\r\nHOSTCHECK-DONE\r\n"
        self.assertEqual(hostcheck.guest_errors(console), ["HOSTCHECK-MOR-FAILED write", "HOSTCHECK-PLANT-FAILED nv"])
        self.assertEqual(hostcheck.guest_errors(b"HOSTCHECK-READY\r\nHOSTCHECK-DONE\r\n"), [])
        ok = {"pass": True, "flagged": []}
        self.assertEqual(hostcheck.with_guest_errors(ok, []), dict(ok, guest_errors=[]))
        self.assertEqual(hostcheck.with_guest_errors(ok, ["HOSTCHECK-MOR-FAILED write"]),
                         {"pass": False, "flagged": [], "guest_errors": ["HOSTCHECK-MOR-FAILED write"]})
        self.assertFalse(hostcheck.with_guest_errors({"pass": False}, [])["pass"])


# The tools root step, line for line (blank and comment lines aside): the image's snapshot stanza
# alone, selected by its snapshot URI, exactly one of it, and the four stack packages from it (#5055).
ROOT_STEP = [
    "- name: QEMU, OVMF and swtpm, from the image's Debian snapshot",
    "run: |",
    'src="$RUNNER_TEMP/snapshot.sources"',
    "awk -v RS= -v ORS='\\n\\n' '/\\nURIs: https:\\/\\/snapshot\\.debian\\.org\\//' \\",
    'image/mkosi/mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources > "$src"',
    '[ "$(grep -c \'^URIs:\' "$src")" = 1 ] || { echo "want one snapshot stanza, got:" >&2; cat "$src" >&2; exit 1; }',
    'cat "$src"',
    "sudo mmdebstrap --mode=root --variant=essential --include=qemu-system-x86,ovmf,swtpm,swtpm-tools trixie \\",
    '"$RUNNER_TEMP/hostcheck-tools" "$src"',
    'sudo chroot "$RUNNER_TEMP/hostcheck-tools" dpkg-query -W qemu-system-x86 ovmf swtpm swtpm-tools',
]
# A command that installs or fetches packages for the runner: apt, apt-get or aptitude, or dpkg.
APT = re.compile(r"\b(?:apt|apt-get|aptitude)\s.*\b(?:install|reinstall|download)\b")
DPKG = re.compile(r"\bdpkg\s(?:.*\s)?(?:-[A-Za-z]*i\b|--install\b|--unpack\b)")
# CI-hostcheck-mirror-wording (#5525): a curl command; curl honours -q (read no .curlrc) only as its first
# argument, so a .curlrc from CURL_HOME, XDG_CONFIG_HOME or HOME could otherwise add options the
# bound checks never see (retry-all-errors, say).
CURL = re.compile(r"(?<![\w.+/-])curl(?![\w.+-])")


# CI-hostcheck-fetch-retry (#5321): the hostcheck job's guest-kernel fetch, as ci.yml must hold it; each
# source's retry bound comes from BOUND.
KERNEL_FETCH = ("curl -q --proto '=https' -fsSL \"${bound[@]}\" --retry-connrefused --connect-timeout 30 "
                "-o \"$deb\" \"$url\" && { src=$url; break; }")
# CI-hostcheck-mirror-bound (#5470): the mirror's short bound, so a 5xx mirror falls through in seconds;
# then #5321's full schedule, for the snapshot.
MIRROR_BOUND = "bound=(--retry 2 --retry-max-time 20 --max-time 60)"
SNAPSHOT_BOUND = "bound=(--retry 8 --retry-max-time 600 --max-time 180)"
# CI-hostcheck-kernel-mirror (#5463): this repository's release asset first, the snapshot second, then
# the pin decides; the lines from the source loop to the hash check, in order.
KERNEL_SOURCES = [
    "src=",
    MIRROR_BOUND,
    'for url in "$KERNEL_MIRROR_URL" "$KERNEL_URL"; do',
    KERNEL_FETCH,
    'echo "::warning::the guest kernel did not download from $url"',
    SNAPSHOT_BOUND,
    "done",
    '[ -n "$src" ] || { echo "::error::the guest kernel did not download from either source"; exit 1; }',
    'got=$(sha256sum "$deb" | cut -d\' \' -f1)',
    'echo "guest kernel: $src sha256 $got (pinned: $KERNEL_SHA256)"',
    '[ "$got" = "$KERNEL_SHA256" ] || { echo "::error::the guest kernel hashes to $got, pinned $KERNEL_SHA256"; exit 1; }',
]


class HostcheckJobTest(unittest.TestCase):
    """ci.yml's hostcheck job takes the VM stack and guest kernel from pinned snapshots, not the runner's archive."""

    def setUp(self):
        self.ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()

    def problems(self, text):
        out = []
        steps = job_steps(text, "hostcheck")
        # Every runner package command, its continuation lines joined.
        lines = [line for _, b in steps for line in b.replace("\\\n", " ").splitlines()
                 if not line.strip().startswith("#")]
        runner_apt = "\n".join(line for line in lines if APT.search(line))
        for pkg in PINNED:
            if re.search(rf"(?<![\w.+-]){re.escape(pkg)}(?![\w.+-])", runner_apt):
                out.append(f"{pkg} installed from the runner's archive")
        if any(DPKG.search(line) for line in lines):
            out.append("the job installs a package file with dpkg")
        if any(not line[m.end():].startswith(" -q ") for line in lines for m in CURL.finditer(line)):
            out.append("a curl in the job reads a config file (-q is not its first argument, #5525)")
        root = [b for _, b in steps if re.search(r"(?m)^\s*(?:run:\s*)?(?:sudo\s+)?mmdebstrap\s", b)]
        if len(root) != 1:
            out.append("no single mmdebstrap step builds the tools root")
        elif [ln.strip() for ln in root[0].splitlines() if ln.strip() and not ln.strip().startswith("#")] != ROOT_STEP:
            out.append("the tools root step is not the pinned one (the image's snapshot stanza alone, the stack from it)")
        out += self.kernel_problems(steps, runner_apt)
        run = [b for _, b in steps if "tests.test_hostcheck" in b]
        if len(run) != 1 or not re.search(r"HOSTCHECK_TOOLS_ROOT: \$\{\{ runner\.temp \}\}/hostcheck-tools", run[0]):
            out.append("the hostcheck run does not name the tools root")
        return out

    def select(self, sources):
        """Run the pinned step's selection and guard on SOURCES: (exit status, selected stanzas)."""
        with tempfile.TemporaryDirectory() as d:
            src = pathlib.Path(d, "image/mkosi/mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources")
            src.parent.mkdir(parents=True)
            src.write_text(sources)
            script = "\n".join(ROOT_STEP[2:6]).replace("\\\n", " ")
            p = subprocess.run(["bash", "-e", "-c", script], cwd=d, capture_output=True, text=True,
                               env={"PATH": os.environ["PATH"], "RUNNER_TEMP": d})
            return p.returncode, pathlib.Path(d, "snapshot.sources").read_text()

    def test_the_root_reads_the_images_snapshot_stanza_alone(self):
        sources = (ROOT / "image/mkosi/mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources").read_text()
        rc, got = self.select(sources)
        self.assertEqual(rc, 0, got)
        fields = [ln for ln in got.splitlines() if ln and not ln.startswith("#")]
        uris = [ln for ln in fields if ln.startswith("URIs:")]
        self.assertEqual(len(uris), 1, got)
        self.assertRegex(uris[0], r"\AURIs: https://snapshot\.debian\.org/archive/debian/\d{8}T\d{6}Z/\Z")  # one, dated
        self.assertFalse([ln for ln in fields if "security" in ln], got)
        self.assertIn("Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg", fields)
        # A second stanza on the snapshot (its security archive, say) joins the selection: the guard stops it.
        two = sources.replace("URIs: http://security.debian.org/debian-security",
                              "URIs: https://snapshot.debian.org/archive/debian-security/20261001T000000Z/")
        self.assertNotEqual(two, sources)
        self.assertNotEqual(self.select(two)[0], 0)
        self.assertNotEqual(self.select(sources.replace("snapshot.debian.org", "deb.debian.org"))[0], 0)

    def kernel_problems(self, steps, runner_apt):
        """#4994: the guest kernel is one exact package from a dated Ubuntu snapshot, hash-checked."""
        out = []
        if re.search(r"linux-image", runner_apt) or any("apt-cache" in b for _, b in steps):
            out.append("the guest kernel comes from the runner's archive")
        k = [b for _, b in steps if "HOSTCHECK_KERNEL=" in b]
        if len(k) != 1:
            return out + ["no single step names the guest kernel"]
        b = k[0]
        env = dict(re.findall(r"^          (KERNEL_\w+): (\S+)$", b, re.M))
        url = re.fullmatch(r"https://snapshot\.ubuntu\.com/ubuntu/\d{8}T\d{6}Z/pool/main/l/linux-signed/"
                           r"linux-image-(\d+\.\d+\.\d+-\d+)-generic_[\w.+~-]+_amd64\.deb",
                           env.get("KERNEL_URL", ""))
        if not url:
            out.append("the guest kernel URL is not one package in a dated Ubuntu snapshot")
        if not re.fullmatch(r"[0-9a-f]{64}", env.get("KERNEL_SHA256", "")):
            out.append("the guest kernel has no SHA-256 pin")
        if not url or env.get("KERNEL_VMLINUZ") != f"boot/vmlinuz-{url.group(1)}-generic":
            out.append("the guest kernel path is not the pinned package's vmlinuz")
        # #5463: the mirror is this repository's release of exactly that package, tagged by its version.
        deb = env.get("KERNEL_URL", "").rsplit("/", 1)[-1]
        ver = re.fullmatch(r"linux-image-[\w.+~-]+_([\w.+~-]+)_amd64\.deb", deb)
        if not ver or env.get("KERNEL_MIRROR_URL") != ("https://github.com/ghbmrk/agentOS/releases/download/"
                                                       f"guest-kernel-{ver.group(1)}/{deb}"):
            out.append("the guest kernel mirror is not this repository's release of the pinned package")
        lines = [ln.strip() for ln in b.splitlines()]
        start = lines.index(KERNEL_SOURCES[0]) if KERNEL_SOURCES[0] in lines else -1
        if start < 0 or lines[start:start + len(KERNEL_SOURCES)] != KERNEL_SOURCES:
            out.append("the guest kernel is not fetched from the mirror, then the snapshot, then hash-checked")
        if sum("curl " in ln for ln in lines) != 1:
            out.append("the guest kernel has a fetch outside the source loop")
        want = ['got=$(sha256sum "$deb" | cut -d\' \' -f1)',
                '[ "$got" = "$KERNEL_SHA256" ] || { echo "::error::the guest kernel hashes to $got, pinned '
                '$KERNEL_SHA256"; exit 1; }',
                'dpkg-deb -x "$deb" "$RUNNER_TEMP/k"',
                'test -f "$RUNNER_TEMP/k/$KERNEL_VMLINUZ"',
                'echo "HOSTCHECK_KERNEL=$RUNNER_TEMP/k/$KERNEL_VMLINUZ" >> "$GITHUB_ENV"']
        idx = [lines.index(w) if w in lines else -1 for w in want]
        if -1 in idx or idx != sorted(idx):
            out.append("the guest kernel is not hash-checked before it is unpacked and named")
        if not any(ln.startswith("curl -q --proto '=https' ") and ln.endswith('-o "$deb" "$url" && { src=$url; break; }')
                   for ln in lines):
            out.append("the guest kernel is not fetched from the pinned URLs over HTTPS")
        if KERNEL_FETCH not in lines:
            out.append("the guest kernel fetch is not the bounded retry (#5321)")
        if [ln for ln in lines if ln.startswith("bound=")] != [MIRROR_BOUND, SNAPSHOT_BOUND]:
            out.append("the mirror is not tried on its short bound, then the snapshot on the full one (#5470)")
        return out

    def fetch(self, answers, mirror=(404,), body=b"ok", pin=None, timeout=60, curlrc=None):
        """Run the job's source loop and hash check against two local servers, the mirror giving MIRROR
        and the snapshot ANSWERS in turn (each serving BODY): (exit, snapshot statuses, stderr, mirror
        statuses; stderr carries stdout too). PIN defaults to BODY's SHA-256. CURLRC, if given, is
        written as .curlrc in a directory that CURL_HOME, XDG_CONFIG_HOME and HOME all name."""
        servers = []
        for want in (mirror, answers):
            served = []

            class H(http.server.BaseHTTPRequestHandler):
                def do_GET(self, want=want, served=served):
                    code = want[min(len(served), len(want) - 1)]
                    served.append(code)
                    self.send_response(code)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *a):
                    pass

            srv = http.server.HTTPServer(("127.0.0.1", 0), H)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            servers.append((srv, served))
        lines = [ln.strip() for _, b in job_steps(self.ci, "hostcheck") if "HOSTCHECK_KERNEL=" in b
                 for ln in b.splitlines()]
        start = lines.index("src=")
        end = next(i for i, ln in enumerate(lines) if ln.startswith('[ "$got" = "$KERNEL_SHA256" ]'))
        script = "\n".join(lines[start:end + 1]).replace("'=https'", "'=http'")
        (m, m_served), (s, s_served) = servers
        try:
            with tempfile.TemporaryDirectory() as d:
                rc = {}
                if curlrc is not None:
                    pathlib.Path(d, ".curlrc").write_text(curlrc)
                    rc = {"CURL_HOME": d, "XDG_CONFIG_HOME": d, "HOME": d}
                p = subprocess.run(["bash", "-e", "-c", 'deb="$D/k.deb"\n' + script],
                                   env={"PATH": os.environ["PATH"], "D": d, **rc,
                                        "KERNEL_SHA256": pin or hashlib.sha256(body).hexdigest(),
                                        "KERNEL_MIRROR_URL": f"http://127.0.0.1:{m.server_port}/k.deb",
                                        "KERNEL_URL": f"http://127.0.0.1:{s.server_port}/k.deb"},
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        finally:
            for srv, _ in servers:
                srv.shutdown()
                srv.server_close()
        return p.returncode, s_served, p.stdout, m_served

    def test_the_kernel_fetch_retries_an_outage_and_not_a_wrong_pin(self):
        # #5321: snapshot.ubuntu.com's 503/504 runs reddened hostcheck on PRs that never moved the pin.
        rc, served, err, _ = self.fetch([503, 504, 200])
        self.assertEqual((rc, served), (0, [503, 504, 200]), err)
        rc, served, err, _ = self.fetch([404, 200])  # a moved pin is the PR's fault: no retry
        self.assertEqual((rc, served), (1, [404]), err)
        self.assertIn("404", err)
        self.assertIn("did not download from either source", err)

    def test_the_kernel_comes_from_the_mirror_first_and_the_pin_decides(self):
        # #5463: the release asset first; the snapshot only when the asset does not download.
        rc, served, err, mirror = self.fetch([200], mirror=[200])
        self.assertEqual((rc, mirror, served), (0, [200], []), err)
        rc, served, err, mirror = self.fetch([200], mirror=[503, 200])  # the mirror's own retry
        self.assertEqual((rc, mirror, served), (0, [503, 200], []), err)
        rc, served, err, mirror = self.fetch([200], mirror=[404])  # no asset: the snapshot serves
        self.assertEqual((rc, mirror, served), (0, [404], [200]), err)
        self.assertIn("did not download from http://127.0.0.1:", err)
        # Bytes off the pin fail the step, from whichever host, and no other source is tried.
        rc, served, err, mirror = self.fetch([200], mirror=[200], pin="0" * 64)
        self.assertEqual((rc, mirror, served), (1, [200], []), err)
        self.assertIn("hashes to", err)
        rc, served, err, mirror = self.fetch([200], mirror=[404], pin="0" * 64)
        self.assertEqual((rc, mirror, served), (1, [404], [200]), err)

    def test_a_down_mirror_falls_through_in_seconds(self):
        # #5470: a mirror answering 5xx gets 3 tries (waits 1 s and 2 s), then the snapshot serves; on the
        # full #5321 schedule it would take 9 tries and 255 s, past this run's 30 s limit.
        t0 = time.monotonic()
        rc, served, err, mirror = self.fetch([200], mirror=[503], timeout=30)
        self.assertEqual((rc, mirror, served), (0, [503] * 3, [200]), err)
        self.assertLess(time.monotonic() - t0, 20, err)
        # The snapshot, the last source, keeps the full schedule behind a down mirror.
        rc, served, err, mirror = self.fetch([503, 504, 502, 200], mirror=[500])
        self.assertEqual((rc, mirror, served), (0, [500] * 3, [503, 504, 502, 200]), err)

    def test_the_kernel_fetch_reads_no_curlrc(self):
        # #5525: a .curlrc asking to retry every error would retry a 404 mirror; -q first ignores it.
        rc, served, err, mirror = self.fetch([200], mirror=[404, 200], curlrc="retry-all-errors\n")
        self.assertEqual((rc, mirror, served), (0, [404], [200]), err)
        # The same .curlrc does reach a curl without -q, so the case above tests -q, not the file.
        with tempfile.TemporaryDirectory() as d:
            pathlib.Path(d, ".curlrc").write_text("bogus-option-from-curlrc\n")
            env = {"PATH": os.environ["PATH"], "CURL_HOME": d, "XDG_CONFIG_HOME": d, "HOME": d}
            read = subprocess.run(["curl", "-sS", "--version"], env=env, capture_output=True, text=True)
            skipped = subprocess.run(["curl", "-q", "-sS", "--version"], env=env, capture_output=True, text=True)
        self.assertIn("bogus-option-from-curlrc", read.stderr)
        self.assertEqual(skipped.returncode, 0, skipped.stderr)

    def test_vm_stack_comes_from_the_snapshot(self):
        self.assertEqual(self.problems(self.ci), [])

    def test_check_catches_mutants(self):
        KEYRING = "python3-virt-firmware mmdebstrap debian-archive-keyring\n"  # the hostcheck job's install
        awk = "'/\\nURIs: https:\\/\\/snapshot\\.debian\\.org\\//'"
        for name, (old, new) in {
            "runner qemu": ("qemu-utils ", "qemu-utils qemu-system-x86 "),
            "runner ovmf": ("qemu-utils ", "qemu-utils ovmf "),
            "runner swtpm": ("qemu-utils ", "qemu-utils swtpm "),
            "runner apt": (KEYRING, KEYRING + "          sudo apt install -yq swtpm\n"),
            "runner apt-get": (KEYRING, KEYRING + "          sudo apt-get -yq install ovmf\n"),
            "runner aptitude": (KEYRING, KEYRING + "          sudo aptitude install -y qemu-system-x86\n"),
            "runner dpkg -i": (KEYRING, KEYRING + '          sudo dpkg -i "$RUNNER_TEMP"/*.deb\n'),
            "runner dpkg --install": (KEYRING, KEYRING + "          sudo dpkg --install q.deb\n"),
            "root without ovmf": ("--include=qemu-system-x86,ovmf,", "--include=qemu-system-x86,"),
            "root with more": ("--include=qemu-system-x86,", "--include=qemu-utils,qemu-system-x86,"),
            "one-line entry": ('"$RUNNER_TEMP/hostcheck-tools" "$src"',
                               '"$RUNNER_TEMP/hostcheck-tools" "deb [check-valid-until=no] $uri trixie main"'),
            "live security mirror": ('"$RUNNER_TEMP/hostcheck-tools" "$src"',
                                     '"$RUNNER_TEMP/hostcheck-tools" "$src" http://security.debian.org/debian-security'),
            "live archive mirror": ('"$RUNNER_TEMP/hostcheck-tools" "$src"',
                                    '"$RUNNER_TEMP/hostcheck-tools" "$src" http://deb.debian.org/debian'),
            "widened stanza pattern": (awk, "'/\\nURIs: /'"),
            "no stanza guard": ('[ "$(grep -c \'^URIs:\' "$src")" = 1 ] ||', "true ||"),
            "guard dropped": ("          [ \"$(grep -c '^URIs:' \"$src\")\" = 1 ]", "          # [ \"$(grep -c '^URIs:' \"$src\")\" = 1 ]"),
            "extra source line": ('          cat "$src"\n', '          cat "$src"\n          echo "deb http://deb.debian.org/debian trixie main" >> "$src"\n'),
            "second root step": ("      - name: KVM for the runner user", "      - name: more\n        run: mmdebstrap trixie /x\n      - name: KVM for the runner user"),
            "no root env": ("HOSTCHECK_TOOLS_ROOT: ${{ runner.temp }}/hostcheck-tools", "HOSTCHECK_X: x"),
            "runner kernel": ('dpkg-deb -x "$deb" "$RUNNER_TEMP/k"',
                              'apt-get download linux-image-generic && dpkg-deb -x "$deb" "$RUNNER_TEMP/k"'),
            "live archive": ("https://snapshot.ubuntu.com/ubuntu/2026", "http://archive.ubuntu.com/ubuntu/x"),
            "undated snapshot": ("ubuntu/20261107T000000Z/", "ubuntu/latest/"),
            "no hash pin": ("KERNEL_SHA256: b8", "KERNEL_SHA256: $X"),
            "hash unchecked": ('[ "$got" = "$KERNEL_SHA256" ] ||', 'true ||'),
            "globbed vmlinuz": ("KERNEL_VMLINUZ: boot/vmlinuz-6.8.0-149-generic", "KERNEL_VMLINUZ: boot/vmlinuz-*"),
            "other vmlinuz": ("KERNEL_VMLINUZ: boot/vmlinuz-6.8.0-149-generic",
                              "KERNEL_VMLINUZ: boot/vmlinuz-6.8.0-150-generic"),
            "plain http": ("curl -q --proto '=https' ", "curl -q "),
            "reads .curlrc": ("curl -q --proto ", "curl --proto "),
            "-q not first": ("curl -q --proto '=https' -fsSL ", "curl --proto '=https' -q -fsSL "),
            "curl elsewhere reads .curlrc": ("        run: |\n          if [ -e /dev/kvm ]; then\n",
                                             "        run: |\n          curl -fsSLO https://example.com/x\n"
                                             "          if [ -e /dev/kvm ]; then\n"),
            "fewer tries": ("--retry 8 ", "--retry 3 "),
            "unbounded": ("--retry-max-time 600 ", ""),
            "fixed delay": ("--retry 8 ", "--retry 8 --retry-delay 5 "),
            "retry a 404": ("--retry-connrefused ", "--retry-all-errors "),
            "no try timeout": (" --max-time 180)", ")"),
            "mirror on the full schedule": ("bound=(--retry 2 --retry-max-time 20 --max-time 60)",
                                            "bound=(--retry 8 --retry-max-time 600 --max-time 180)"),
            "mirror unbounded": ("          bound=(--retry 2 --retry-max-time 20 --max-time 60)\n", ""),
            "mirror more tries": ("bound=(--retry 2 ", "bound=(--retry 5 "),
            "mirror longer": ("--retry-max-time 20 ", "--retry-max-time 600 "),
            "mirror try longer": ("--max-time 60)", "--max-time 180)"),
            "snapshot on the short bound": ("            bound=(--retry 8 --retry-max-time 600 --max-time 180)\n", ""),
            "bound outside curl": ('-fsSL "${bound[@]}" ', "-fsSL "),
            "no mirror": ('for url in "$KERNEL_MIRROR_URL" "$KERNEL_URL"', 'for url in "$KERNEL_URL"'),
            "no second source": ('for url in "$KERNEL_MIRROR_URL" "$KERNEL_URL"', 'for url in "$KERNEL_MIRROR_URL"'),
            "snapshot first": ('for url in "$KERNEL_MIRROR_URL" "$KERNEL_URL"',
                               'for url in "$KERNEL_URL" "$KERNEL_MIRROR_URL"'),
            "third source": ('for url in "$KERNEL_MIRROR_URL" "$KERNEL_URL"',
                             'for url in "$KERNEL_MIRROR_URL" "$KERNEL_URL" "$X"'),
            "other mirror": ("https://github.com/ghbmrk/agentOS/releases/", "https://example.com/ghbmrk/agentOS/releases/"),
            "other mirror tag": ("download/guest-kernel-6.8.0-149.149/", "download/guest-kernel-6.8.0-150.150/"),
            "other mirror file": ("149.149/linux-image-6.8.0-149-generic_6.8.0-149.149_amd64.deb\n",
                                  "149.149/linux-image-6.8.0-150-generic_6.8.0-150.150_amd64.deb\n"),
            "no source guard": ('          [ -n "$src" ] ||', "          true ||"),
            "retry on a bad hash": ('-o "$deb" "$url" && { src=$url; break; }', '-o "$deb" "$url" && src=$url'),
            "a fetch outside the loop": ("          src=\n", '          src=\n          curl -fsSL -o "$deb" "$X"\n'),
            "kernel env elsewhere": ('echo "HOSTCHECK_KERNEL=$RUNNER_TEMP/k/$KERNEL_VMLINUZ" >> "$GITHUB_ENV"',
                                     'echo "HOSTCHECK_KERNEL=$(ls "$RUNNER_TEMP"/k/boot/vmlinuz-*)" >> "$GITHUB_ENV"'),
        }.items():
            with self.subTest(name):
                self.assertIn(old, self.ci)
                self.assertNotEqual(self.problems(self.ci.replace(old, new, 1)), [])

    def test_runner_package_commands_are_told_apart(self):
        for line in ("sudo apt install -yq swtpm", "apt-get -yq install x", "sudo aptitude install y",
                     "apt download z", "sudo apt-get reinstall q"):
            self.assertRegex(line, APT)
        for line in ("sudo dpkg -i a.deb", "dpkg --install a.deb", "dpkg -Ei a.deb", "dpkg --unpack a.deb"):
            self.assertRegex(line, DPKG)
        for line in ('dpkg-deb -x "$deb" "$RUNNER_TEMP/k"', "dpkg-query -W swtpm", "sudo apt-get update -q",
                     "sudo chroot r dpkg-query -W qemu-system-x86 ovmf swtpm swtpm-tools"):
            self.assertNotRegex(line, APT)
            self.assertNotRegex(line, DPKG)


QEMU = os.environ.get("HOSTCHECK_QEMU") == "1"


@unittest.skipUnless(QEMU, "set HOSTCHECK_QEMU=1 to boot the stand-in guest")
class QemuTest(unittest.TestCase):
    """The harness flags writes a guest really makes, seen from outside it."""

    @classmethod
    def setUpClass(cls):
        cls.tools_root = os.environ.get("HOSTCHECK_TOOLS_ROOT") or None
        for tool in ("qemu-system-x86_64", "swtpm", "swtpm_ioctl"):
            if cls.tools_root:
                hostcheck.tool_argv(cls.tools_root, tool)  # raises if the root lacks it
            elif not shutil.which(tool):
                raise AssertionError(f"{tool} missing")
        for tool in ("tpm2_getcap", "virt-fw-vars", "busybox", "mkntfs", "sfdisk"):
            if not shutil.which(tool):
                raise AssertionError(f"{tool} missing")
        kernel = os.environ.get("HOSTCHECK_KERNEL")
        if not kernel or not os.path.exists(kernel):
            raise AssertionError("HOSTCHECK_KERNEL must name a guest kernel")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = pathlib.Path(cls.tmp.name)
        subprocess.run(["sh", str(ROOT / "tools" / "hostcheck_standin.sh"), str(cls.dir / "standin")],
                       check=True)
        cls.kernel = kernel

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_check(self, name, phases, plant=""):
        work = self.dir / name
        cmd = [sys.executable, str(ROOT / "tools" / "hostcheck.py"), "qemu", "--work", str(work),
               "--kernel", self.kernel, "--initrd", str(self.dir / "standin" / "initrd.cpio"),
               "--host-disk", f"windows={self.dir / 'standin' / 'windows.img'},bus=virtio",
               "--phases", phases]
        if plant:
            cmd += ["--plant", plant]
        if self.tools_root:
            cmd += ["--tools-root", self.tools_root]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        report = work / "report.json"
        if not report.exists():
            self.fail(f"no report (exit {p.returncode}):\n{p.stdout[-3000:]}\n{p.stderr[-3000:]}")
        return p.returncode, json.loads(report.read_text())

    def test_clean_session_passes(self):
        # A task that reads the partition table, a restart and a shutdown
        # leave the host as it was; the input disk image is not modified.
        disk = self.dir / "standin" / "windows.img"
        before = hostcheck.hash_disk(disk)
        rc, report = self.run_check("clean", "task,restart")
        self.assertEqual(rc, 0, json.dumps(report, indent=1))
        self.assertEqual([p["phase"] for p in report["phases"]], ["task", "restart"])
        for p in report["phases"]:
            self.assertTrue(p["pass"], p)
            self.assertEqual(p["rtc_writes"], [])
            self.assertEqual(p["guest_errors"], [])
        self.assertTrue(report["baseline"]["tpm-nv"], "the stand-in host has an NV index to keep")
        self.assertEqual(report["stack"], hostcheck.stack_versions(self.tools_root))
        self.assertEqual(before, hostcheck.hash_disk(disk))

    def test_the_stack_loads_from_the_root_alone(self):
        # #5055: each tool starts on TOOLS_LIBS alone, and dropping swtpm's private library directory
        # fails the run rather than loading a copy from the runner's directories.
        if not self.tools_root:
            self.skipTest("the runner's own tools: nothing to audit")

        def start(name, log):
            args = argparse.Namespace(tools_root=self.tools_root, ld_log=os.path.join(log, "stack"))
            p = hostcheck.stack_popen(args, name, ["--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p.communicate(timeout=60)
            hostcheck.stack_done(args, p)
            return p.returncode

        with tempfile.TemporaryDirectory() as log:
            for name in hostcheck.TOOLS:
                self.assertEqual(start(name, log), 0, name)
            with unittest.mock.patch.object(hostcheck, "TOOLS_LIBS", ("usr/lib/x86_64-linux-gnu",)):
                with self.assertRaisesRegex(hostcheck.HostcheckError, "outside the tools root.*libswtpm_libtpms"):
                    start("swtpm", log)

    def test_unclean_end_leaves_only_mor_and_the_next_shutdown_clears_it(self):
        # A power cut leaves MOR as the EFI stub set it, disclosed (HW-8); the
        # orderly session after it clears it again (#4794).
        rc, report = self.run_check("unclean", "unclean,task")
        self.assertEqual(rc, 0, json.dumps(report, indent=1))
        unclean, task = report["phases"]
        self.assertTrue(unclean["pass"], unclean)
        self.assertEqual([(d["change_id"], d["key"]) for d in unclean["disclosed"]], [("mor", MOR)])
        self.assertTrue(task["pass"], task)
        self.assertNotIn("mor", [d["change_id"] for d in task["disclosed"]])

    def test_a_guest_that_halts_before_the_cut_fails_the_run(self):
        # #5256 item 1: a halt (CPUs stopped, no ACPI power-off) sends QEMU no event, and this one
        # skips the MOR clear, so a quit after it would pass as a power cut with MOR disclosed.
        phases = self.dir / "halt.json"
        phases.write_text(json.dumps({"unclean": [["Linux version", "os"], ["HOSTCHECK-READY", "serial:halt\n"],
                                                  ["System halted", "power-cut"]]}))
        work = self.dir / "halt"
        cmd = [sys.executable, str(ROOT / "tools" / "hostcheck.py"), "qemu", "--work", str(work),
               "--kernel", self.kernel, "--initrd", str(self.dir / "standin" / "initrd.cpio"),
               "--host-disk", f"windows={self.dir / 'standin' / 'windows.img'},bus=virtio",
               "--phases", "unclean", "--phases-file", str(phases)]
        if self.tools_root:
            cmd += ["--tools-root", self.tools_root]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        self.assertEqual(p.returncode, 2, p.stderr[-3000:])
        self.assertRegex(p.stderr, r"unclean: no 'HOSTCHECK-ALIVE [0-9a-f]{16}' on the console in time")
        self.assertFalse((work / "report.json").exists())
        self.assertIn(b"System halted", (work / "console-unclean.log").read_bytes())

    def test_planted_writes_flagged(self):
        rc, report = self.run_check("planted", "task", plant="disk,uefi,nv,rtc")
        self.assertEqual(rc, 1, json.dumps(report, indent=1))
        (phase,) = report["phases"]
        kinds = {(f["kind"], f["change"]) for f in phase["flagged"]}
        self.assertIn(("disk", "changed"), kinds)
        self.assertIn(("tpm-nv", "added"), kinds)
        self.assertIn(("rtc", "written"), kinds)
        uefi = [f["key"] for f in phase["flagged"] if f["kind"] == "uefi"]
        self.assertTrue(any(k.endswith(":HostcheckCanary") for k in uefi), uefi)
        self.assertEqual([f for f in phase["flagged"] if f["kind"] not in ("disk", "uefi", "tpm-nv", "rtc")], [])


if __name__ == "__main__":
    unittest.main()
