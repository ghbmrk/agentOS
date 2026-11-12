# The camera decoder's build (IMG-camdecode-toolchain, #5582): image/libavcodec.sh and
# image/camdecode.sh unpack, configure, compile and link inside GUEST_BASE, the root
# image/guest-base.sh installs from the image's pinned apt sources, so no build host's tar, xz,
# patch, gcc, static libc or pkg-config decides agentos-camdecode's bytes (a runner image update
# between builds a and b would fail the image's reproduce job). The build half needs root, GUEST_BASE
# and the network: set AGENTOS_CAMDECODE_BUILD=1 (CI's broker-checks job does). Without it, only the
# refusals that run before the base is touched run.
# REQ: UPD-1a, NET-2
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
LIBAVCODEC = ROOT / "image/libavcodec.sh"
CAMDECODE = ROOT / "image/camdecode.sh"
HOST_TOOLS = ("tar", "xz", "patch")


def shims(d):
    """A PATH whose tar, xz and patch log their call to d/ran and fail: a build that runs one fails."""
    bin_ = pathlib.Path(d) / "shims"
    bin_.mkdir()
    for t in HOST_TOOLS:
        (bin_ / t).write_text(f'#!/bin/sh\necho "host {t} $*" >>"{d}/ran"\nexit 97\n')
        (bin_ / t).chmod(0o755)
    return f"{bin_}:{os.environ['PATH']}"


def base_gcc(base):
    """The Debian version of BASE's gcc, as its compiler stamps .comment."""
    major = re.fullmatch(r"(?:x86_64-linux-gnu-)?gcc-(\d+)", os.readlink(base / "usr/bin/gcc")).group(1)
    return subprocess.run(["dpkg-query", f"--admindir={base}/var/lib/dpkg", "-W", "-f", "${Version}", f"gcc-{major}"],
                          capture_output=True, text=True, check=True).stdout


class RefusalTest(unittest.TestCase):
    # REQ: UPD-1a
    def test_libavcodec_refuses_a_dir_outside_the_base_s_tmp(self):
        with tempfile.TemporaryDirectory(prefix="agentos-camdecode-") as d:
            keep = pathlib.Path(d) / "tmp/keep"
            keep.parent.mkdir()
            keep.write_text("x")
            for bad in ("/", "/tmp", "/tmp/agentos-", "/tmp/agentos-x/y", "/tmp/agentos-x/..", "tmp/agentos-x", "/opt/x"):
                with self.subTest(dir=bad):
                    r = subprocess.run(["sh", str(LIBAVCODEC), d, bad], capture_output=True, text=True)
                    self.assertEqual(r.returncode, 2, r.stderr)
                    self.assertIn("DIR must be /tmp/agentos-NAME", r.stderr)
                    self.assertTrue(keep.exists())

    # REQ: UPD-1a, NET-2
    def test_wrong_ffmpeg_tarball_is_refused_before_the_base_is_touched(self):
        with tempfile.TemporaryDirectory(prefix="agentos-camdecode-") as d:
            fake = pathlib.Path(d) / "ffmpeg.tar.xz"
            fake.write_bytes(b"not the pinned tarball")
            base = pathlib.Path(d) / "base"
            old = base / "tmp/agentos-libavcodec/old"
            old.parent.mkdir(parents=True)
            old.write_text("x")
            r = subprocess.run(["sh", str(LIBAVCODEC), str(base), "/tmp/agentos-libavcodec"],
                               env=dict(os.environ, FFMPEG_TARBALL=str(fake), PATH=shims(d)),
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("ffmpeg tarball hash", r.stderr)
            self.assertTrue(old.exists())
            self.assertFalse((pathlib.Path(d) / "ran").exists())

    # REQ: UPD-1a
    def test_camdecode_needs_a_base(self):
        with tempfile.TemporaryDirectory(prefix="agentos-camdecode-") as d:
            env = {k: v for k, v in os.environ.items() if k != "GUEST_BASE"}
            out = pathlib.Path(d) / "root"
            r = subprocess.run(["sh", str(CAMDECODE), str(out), str(pathlib.Path(d) / "lic")],
                               env=env, capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("GUEST_BASE", r.stderr)
            self.assertFalse(out.exists())


@unittest.skipUnless(os.environ.get("AGENTOS_CAMDECODE_BUILD") == "1", "set AGENTOS_CAMDECODE_BUILD=1 (root, GUEST_BASE) to build")
class BuildTest(unittest.TestCase):
    """Builds the decoder's root in GUEST_BASE with host tar, xz and patch that fail if run."""

    @classmethod
    def setUpClass(cls):
        cls.base = pathlib.Path(os.environ["GUEST_BASE"])
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="agentos-camdecode-"))
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.out, cls.lic = cls.tmp / "root", cls.tmp / "licenses"
        cls.r = subprocess.run(["sh", str(CAMDECODE), str(cls.out), str(cls.lic)],
                               env=dict(os.environ, PATH=shims(cls.tmp)), capture_output=True, text=True)

    def setUp(self):
        ran = self.tmp / "ran"
        self.assertFalse(ran.exists(), ran.read_text() if ran.exists() else "")
        self.assertEqual(self.r.returncode, 0, self.r.stderr[-2000:])

    # REQ: UPD-1a
    def test_no_host_tar_xz_or_patch_runs(self):
        # setUp holds the check: the shims log any call and fail the build.
        self.assertTrue((self.out / "agentos-camdecode").is_file())

    # REQ: UPD-1a, NET-2
    def test_decoder_is_compiled_by_the_base_s_toolchain(self):
        # Every object linked in, libavcodec's, cgo's and libc's static start-up among them, records
        # its compiler in .comment: all must be the base's Debian gcc (an Ubuntu runner's says "Ubuntu").
        b = (self.out / "agentos-camdecode").read_bytes()
        compilers = set(re.findall(rb"GCC: \(([^)\n]*)\)", b))
        self.assertEqual(compilers, {f"Debian {base_gcc(self.base)}".encode()})
        phdrs = subprocess.run(["readelf", "-lW", str(self.out / "agentos-camdecode")],
                               capture_output=True, text=True, check=True).stdout
        self.assertNotIn("INTERP", phdrs)

    # REQ: NET-2
    def test_root_holds_the_decoder_alone_and_the_licence_is_installed(self):
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ["agentos-camdecode", "dev", "proc", "sys"])
        self.assertEqual((self.out / "agentos-camdecode").stat().st_mode & 0o7777, 0o755)
        self.assertIn(b"GNU LESSER GENERAL PUBLIC LICENSE", (self.lic / "libavcodec/COPYING.LGPLv2.1").read_bytes())

    # REQ: UPD-1a
    def test_build_leaves_nothing_in_the_base(self):
        self.assertFalse((self.base / "tmp/agentos-camdecode").exists())

    # REQ: NET-2
    def test_built_decoder_runs(self):
        r = subprocess.run([str(self.out / "agentos-camdecode"), "-video", "8x6", "-thermal", "4x3"],
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        self.assertEqual((r.returncode, r.stderr), (0, b""))


if __name__ == "__main__":
    unittest.main()
