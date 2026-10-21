"""IMG-2: the initrd is reproducible, and the two-runner check fails on any initrd difference.

The image is built on two runners and compared by .github/workflows/image.yml's reproduce job;
these tests hold the pieces that job and the build rely on.
"""
# REQ: UPD-1a
import gzip
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMG = ROOT / "image"
MK = IMG / "mkosi"
WORKFLOW = ROOT / ".github/workflows/image.yml"


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


cm = load("compare_manifests", IMG / "compare_manifests.py")
pin = load("initrd_finalize", MK / "initrd/mkosi.finalize")


def newc(members):
    """A newc cpio archive of MEMBERS, (name, body, mtime) each, as cpio --format=newc writes it."""
    out = b""
    for i, (n, body, mtime) in enumerate(list(members) + [("TRAILER!!!", b"", 0)]):
        name = n.encode() + b"\0"
        hdr = b"070701" + b"".join(b"%08X" % v for v in (i, 0o100644, 0, 0, 1, mtime, len(body), 0, 0, 0, 0,
                                                          len(name), 0))
        out += hdr + name
        out += b"\0" * (-len(out) % 4) + body
        out += b"\0" * (-len(out) % 4)
    return out


BASE = [("usr", b"", 100), ("usr/lib/systemd/systemd", b"elf", 100), ("etc/shadow", b"root:!:20000::::::\n", 100)]


class InitrdDiffTest(unittest.TestCase):
    """The reproduce job names the member that differs, so the next fix is targeted."""

    def test_same_members_no_lines(self):
        self.assertEqual(cm.initrd_diff(newc(BASE), newc(BASE)), [])

    def test_content_and_header_differences_are_named(self):
        b = [BASE[0], ("usr/lib/systemd/systemd", b"elf", 101), ("etc/shadow", b"root:!:20001::::::\n", 100)]
        lines = cm.initrd_diff(newc(BASE), newc(b))
        self.assertIn("usr/lib/systemd/systemd: mtime 100/101", lines)
        self.assertIn("etc/shadow: content", lines)
        self.assertEqual(len(lines), 2)

    def test_members_only_on_one_side(self):
        lines = cm.initrd_diff(newc(BASE + [("var/log/dpkg.log", b"x", 1)]), newc(BASE))
        self.assertEqual(lines, ["only in a: var/log/dpkg.log"])

    def test_reads_compressed_and_concatenated_archives(self):
        # The entry's initrd is compressed archives back to back, as the kernel unpacks them.
        a = gzip.compress(newc(BASE[:1]), mtime=0) + b"\0" * 4 + newc(BASE[1:])
        names = [k for k, _, _ in cm.initrd_members(a)]
        self.assertEqual(names, [n for n, _, _ in BASE])
        self.assertEqual(cm.initrd_diff(a, newc(BASE[:1]) + newc(BASE[1:])), [])

    def test_repeated_name_kept_apart(self):
        names = [k for k, _, _ in cm.initrd_members(newc(BASE[:1]) + newc(BASE[:1]))]
        self.assertEqual(names, ["usr", "usr#2"])

    def test_bad_archive_raises(self):
        for bad in (b"junk", newc(BASE)[:-20], newc(BASE).replace(b"070701", b"07070X", 1)):
            with self.assertRaises(ValueError):
                cm.initrd_members(bad)

    def run_compare(self, a, b):
        with tempfile.TemporaryDirectory() as d:
            fa, fb = pathlib.Path(d) / "a", pathlib.Path(d) / "b"
            fa.write_bytes(a)
            fb.write_bytes(b)
            r = subprocess.run(["python3", str(IMG / "compare_manifests.py"), "--initrd", str(fa), str(fb)],
                               capture_output=True, text=True)
        return r.returncode, r.stdout

    def test_cli_same_bytes_pass(self):
        rc, out = self.run_compare(newc(BASE), newc(BASE))
        self.assertEqual(rc, 0, out)
        self.assertIn("same initrd", out)

    def test_cli_fails_on_any_byte_difference(self):
        rc, out = self.run_compare(newc(BASE), newc(BASE[:2] + [("etc/shadow", b"root:!:20001::::::\n", 100)]))
        self.assertEqual(rc, 1)
        self.assertIn("MISMATCH initrd", out)
        self.assertIn("etc/shadow: content", out)
        # Same members, different compressed bytes: still a failure, said as such.
        rc, out = self.run_compare(gzip.compress(newc(BASE), mtime=0), gzip.compress(newc(BASE), mtime=1))
        self.assertEqual(rc, 1)
        self.assertIn("every member alike", out)

    def test_cli_fails_on_missing_or_unreadable(self):
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run(["python3", str(IMG / "compare_manifests.py"), "--initrd", d + "/a", d + "/b"],
                               capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("MISMATCH initrd", r.stdout)
        rc, out = self.run_compare(b"junk", b"junk2")
        self.assertEqual(rc, 1)
        self.assertIn("unreadable initrd", out)


class ShadowPinTest(unittest.TestCase):
    """systemd-firstboot stamps root's entry with today's date; the initrd's finalize pins it."""

    def test_pins_every_last_change_field(self):
        text = "root:!:20381:0:99999:7:::\nsystemd-network:!*:20000::::::\n"
        self.assertEqual(pin.pin(text, 19000), "root:!:19000:0:99999:7:::\nsystemd-network:!*:19000::::::\n")

    def test_keeps_empty_field_and_missing_newline(self):
        self.assertEqual(pin.pin("root:!:::::::", 5), "root:!:::::::")
        self.assertEqual(pin.pin("", 5), "")

    def test_refuses_a_line_that_is_not_an_entry(self):
        for bad in ("root:!:1\n", ":!:1::::::\n", "root:!:1:::::::extra\n"):
            with self.assertRaises(ValueError):
                pin.pin(bad, 5)

    def test_finalize_rewrites_buildroot_keeping_mode(self):
        with tempfile.TemporaryDirectory() as d:
            etc = pathlib.Path(d) / "etc"
            etc.mkdir()
            (etc / "shadow").write_text("root:!:20381::::::\n")
            (etc / "shadow").chmod(0o640)
            env = dict(os.environ, BUILDROOT=d, SOURCE_DATE_EPOCH=str(19000 * 86400 + 5))
            r = subprocess.run([str(MK / "initrd/mkosi.finalize")], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual((etc / "shadow").read_text(), "root:!:19000::::::\n")
            self.assertEqual((etc / "shadow").stat().st_mode & 0o777, 0o640)
            self.assertFalse((etc / "shadow-").exists())

    def test_finalize_refuses_without_epoch(self):
        env = {k: v for k, v in os.environ.items() if k != "SOURCE_DATE_EPOCH"}
        env["BUILDROOT"] = "/nonexistent"
        r = subprocess.run([str(MK / "initrd/mkosi.finalize")], env=env, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SOURCE_DATE_EPOCH", r.stderr)


class InitrdConfigTest(unittest.TestCase):
    """The default initrd gets its own include, and drops what differs from build to build."""

    def test_include_is_wired(self):
        conf = (MK / "mkosi.conf").read_text()
        sect = conf[conf.index("[Config]"):conf.index("[Distribution]")]
        self.assertRegex(sect, r"(?m)^InitrdInclude=initrd/$")
        self.assertTrue((MK / "initrd/mkosi.conf").is_file())
        self.assertTrue(os.access(MK / "initrd/mkosi.finalize", os.X_OK))

    def test_build_time_logs_and_caches_are_removed(self):
        conf = (MK / "initrd/mkosi.conf").read_text()
        body = conf[conf.index("RemoveFiles="):]
        entries = [ln.strip() for ln in body.splitlines()[1:] if ln.startswith((" ", "\t")) and ln.strip()]
        self.assertEqual(entries, ["/var/log/*.log", "/var/cache/ldconfig/aux-cache"])


def compare_step():
    wf = WORKFLOW.read_text()
    job = wf[wf.index("  reproduce:"):]
    step = job[job.index("- name: Compare"):]
    script = step[step.index("run: |") + len("run: |"):]
    lines = []
    for ln in script.splitlines()[1:]:
        if ln and not ln.startswith(" " * 10):
            break
        lines.append(ln[10:])
    return "\n".join(lines) + "\n"


class ReproduceJobTest(unittest.TestCase):
    """The two-runner check is blocking for the initrd (IMG-2): the Compare step itself, run."""

    def setUp(self):
        if not shutil.which("jq"):
            self.skipTest("jq not installed")
        self.tmp = tempfile.TemporaryDirectory()
        self.d = pathlib.Path(self.tmp.name)
        self.initrd = newc(BASE)

    def tearDown(self):
        self.tmp.cleanup()

    def side(self, name, initrd):
        rec = self.d / "rec" / name
        (rec / "initrd/agentos").mkdir(parents=True)
        (rec / "initrd/agentos/initrd").write_bytes(initrd)
        (rec / "SHA256SUMS").write_text("x\n")
        (rec / "agentos_1.manifest").write_text(json.dumps({"packages": [{"name": "systemd", "version": "257"}]}))
        rel = {"usrhash": "ab" * 32, "boot_entry": {"sha256": "cd" * 32},
               "boot": {"agentos/vmlinuz": "ef" * 32, "agentos/initrd": hashlib.sha256(initrd).hexdigest()}}
        (rec / "agentos_1.release.json").write_text(json.dumps(rel))

    def run_step(self):
        (self.d / "image").symlink_to(IMG)
        return subprocess.run(["bash", "-e", "-c", compare_step()], cwd=self.d, capture_output=True, text=True)

    def test_same_initrd_passes(self):
        self.side("release-a", self.initrd)
        self.side("release-b", self.initrd)
        r = self.run_step()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("same agentos/initrd", r.stdout)

    def test_differing_initrd_fails_and_names_the_member(self):
        self.side("release-a", self.initrd)
        self.side("release-b", newc(BASE[:2] + [("etc/shadow", b"root:!:20001::::::\n", 100)]))
        r = self.run_step()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("MISMATCH agentos/initrd", r.stdout)
        self.assertIn("etc/shadow: content", r.stdout)

    def test_no_report_only_path_left(self):
        step = compare_step()
        self.assertNotIn("::warning::", step)
        self.assertNotRegex(step, r"report-only")

    def test_build_hands_the_initrds_to_the_job(self):
        build = (IMG / "build.sh").read_text()
        self.assertIn('dst = out / "initrd" / p', build)
        self.assertLess(build.index("finish_image.py\" \"$OUT\""), build.index('rm -rf "$OUT/initrd"'))
        wf = WORKFLOW.read_text()
        rec = wf[wf.index("- name: Release record"):]
        rec = rec[:rec.index("- uses:")]
        self.assertIn('cp -R "$RUNNER_TEMP"/out/initrd "$RUNNER_TEMP/rec/"', rec)


if __name__ == "__main__":
    unittest.main()
