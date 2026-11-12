# The guests' shell, tools and libraries come from one pinned Debian root, never the build host
# (IMG-reproduce-pcre2, #5570): builds a and b on different runner images put different
# libpcre2-8.so.0 bytes in both guests, because build-rootfs.sh copied the runner's own copy with
# ldd. image/guest-base.sh installs the root from the image's apt sources; image/guest-userland.sh
# copies from it with the root's own loader and fails on anything that resolves outside it.
# REQ: UPD-1a
import os
import pathlib
import platform
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
USERLAND = ROOT / "image/guest-userland.sh"
SHIPPED_SH = ROOT / "image/guest-shipped.sh"
BASE_SH = ROOT / "image/guest-base.sh"
GUESTS = ("openclaw", "codex")
MULTIARCH = "usr/lib/x86_64-linux-gnu"
HOST_LD = pathlib.Path("/lib64/ld-linux-x86-64.so.2")


def host_libs(prog):
    """PROG's libraries as the host loader resolves them (only to stage a fake base)."""
    out = subprocess.run(["ldd", prog], capture_output=True, text=True, check=True).stdout
    return [l.split("=>")[1].split()[0] for l in out.splitlines() if "=>" in l]


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64" and HOST_LD.exists()
                     and shutil.which("ldd"), "needs an x86-64 glibc host to stage a base root")
class UserlandCopyTest(unittest.TestCase):
    """guest-userland.sh against a staged base root: a merged-/usr tree holding dash and bash."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="agentos-guest-userland-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.base = self.tmp / "base"
        lib = self.base / MULTIARCH
        lib.mkdir(parents=True)
        (self.base / "usr/bin").mkdir()
        (self.base / "bin").symlink_to("usr/bin")
        for prog in ("dash", "bash"):
            src = shutil.which(prog)
            if not src:
                self.skipTest("no %s on this host" % prog)
            shutil.copy(src, self.base / "usr/bin" / prog)
            for l in host_libs(src):
                shutil.copy(l, lib / pathlib.Path(l).name)
        (self.base / "usr/bin/sh").symlink_to("dash")
        shutil.copy(HOST_LD, lib / HOST_LD.name)
        self.out = self.tmp / "out"

    def stage_dpkg(self, unowned=()):
        """A dpkg database in the base: each program under usr/bin is its own package, every other
        file belongs to staged-libs, except the base paths in UNOWNED."""
        db = self.base / "var/lib/dpkg"
        shutil.rmtree(db, True)
        (db / "info").mkdir(parents=True)
        owners = {}
        for f in sorted(p for p in self.base.rglob("*") if p.is_file() and not p.is_symlink()):
            rel = "/" + str(f.relative_to(self.base))
            if rel.startswith("/var/lib/dpkg/") or rel in unowned:
                continue
            pkg = f.name if rel.startswith("/usr/bin/") else "staged-libs"
            owners.setdefault(pkg, []).append(rel)
        stanzas = []
        for pkg, files in owners.items():
            (db / "info" / (pkg + ".list")).write_text("\n".join(files) + "\n")
            stanzas.append("Package: %s\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\n"
                           "Maintainer: agentOS test <test@example.invalid>\nDescription: staged\n" % pkg)
        (db / "status").write_text("\n".join(stanzas))
        (self.base / "usr/lib/os-release").write_text('ID=debian\nVERSION_ID="13"\n')

    def run_userland(self, *paths, unowned=()):
        self.stage_dpkg(unowned)
        self.shipped = self.tmp / "shipped"
        return subprocess.run(["sh", str(USERLAND), str(self.base), str(self.out), *paths],
                              capture_output=True, text=True, env={**os.environ, "GUEST_SHIPPED": str(self.shipped)})

    def recorded(self):
        return set(self.shipped.read_text().split()) if self.shipped.exists() else set()

    def test_records_the_package_of_each_copied_file(self):
        # #5572: the image vulnerability check scans exactly the packages whose files a guest
        # carries; a program already in the root (Node, a pinned download) is no package's.
        (self.out / "usr/local/bin").mkdir(parents=True)
        shutil.copy(self.base / "usr/bin/bash", self.out / "usr/local/bin/tool")
        r = self.run_userland("/bin/sh", "/usr/local/bin/tool")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.recorded(), {"dash", "staged-libs"})
        st = self.tmp / "status"
        r = subprocess.run(["sh", str(SHIPPED_SH), "--status", str(self.base), str(st)], capture_output=True,
                           text=True, env={**os.environ, "GUEST_SHIPPED": str(self.shipped)})
        self.assertEqual(r.returncode, 0, r.stderr)
        status = (st / "agentos.dpkg-status").read_text()
        self.assertEqual(sorted(re.findall(r"(?m)^Package: (\S+)$", status)), ["dash", "staged-libs"])
        self.assertIn("Status: install ok installed", status)
        self.assertEqual((st / "agentos.os-release").read_text(), (self.base / "usr/lib/os-release").read_text())

    def test_a_copied_file_no_package_owns_fails(self):
        # Fail closed: a file with no owner would ship with no package scanned for it.
        r = self.run_userland("/bin/sh", unowned=("/usr/bin/dash",))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("/usr/bin/dash (/usr/bin/dash): no Debian package", r.stderr)
        self.assertFalse((self.out / "bin/sh").exists())

    def test_recording_needs_a_named_file_and_the_status_needs_a_record(self):
        env = {k: v for k, v in os.environ.items() if k != "GUEST_SHIPPED"}
        self.stage_dpkg()
        r = subprocess.run(["sh", str(USERLAND), str(self.base), str(self.out), "/bin/sh"], capture_output=True,
                           text=True, env=env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("GUEST_SHIPPED", r.stderr)
        empty = self.tmp / "empty"
        empty.write_text("")
        r = subprocess.run(["sh", str(SHIPPED_SH), "--status", str(self.base), str(self.tmp / "st")],
                           capture_output=True, text=True, env={**env, "GUEST_SHIPPED": str(empty)})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no package recorded", r.stderr)

    def test_copies_programs_and_their_libraries_from_the_base(self):
        r = self.run_userland("/bin/sh", "/bin/bash")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.out / "bin/sh").read_bytes(), (self.base / "usr/bin/dash").read_bytes())
        self.assertEqual((self.out / "lib64/ld-linux-x86-64.so.2").read_bytes(),
                         (self.base / MULTIARCH / HOST_LD.name).read_bytes())
        libs = sorted(p.name for p in (self.out / MULTIARCH).iterdir())
        self.assertIn("libc.so.6", libs)
        for name in libs:
            self.assertFalse((self.out / MULTIARCH / name).is_symlink(), name)
            self.assertEqual((self.out / MULTIARCH / name).read_bytes(), (self.base / MULTIARCH / name).read_bytes(), name)
        # Nothing else: no host path, no file the base did not hold.
        files = sorted(str(p.relative_to(self.out)) for p in self.out.rglob("*") if p.is_file())
        self.assertEqual(files, sorted(["bin/sh", "bin/bash", "lib64/ld-linux-x86-64.so.2"]
                                       + [MULTIARCH + "/" + n for n in libs]))
        # The copied shell runs on the copied loader and libraries alone.
        run = subprocess.run([str(self.out / "lib64/ld-linux-x86-64.so.2"), "--inhibit-cache", "--library-path",
                              str(self.out / MULTIARCH), str(self.out / "bin/bash"), "-c", "echo ok"],
                             capture_output=True, text=True)
        self.assertEqual(run.stdout, "ok\n", run.stderr)

    def test_a_library_missing_from_the_base_fails_though_the_host_has_it(self):
        # The #5570 path: the runner's own copy must never fill a gap in the base.
        victim = next(n for n in (pathlib.Path(l).name for l in host_libs(shutil.which("bash"))) if n != "libc.so.6")
        (self.base / MULTIARCH / victim).unlink()
        r = self.run_userland("/bin/bash")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(victim, r.stderr)

    def test_a_link_that_leaves_the_base_fails(self):
        # Debian ships absolute links; resolved on the host they would read the host's file.
        (self.base / "usr/bin/sh").unlink()
        (self.base / "usr/bin/sh").symlink_to(shutil.which("dash"))
        r = self.run_userland("/bin/sh")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("outside", r.stderr)
        self.assertFalse((self.out / "bin/sh").exists())

    def test_a_missing_program_fails(self):
        # The old loop skipped a missing tool; the guest would then lack it silently.
        r = self.run_userland("/bin/sh", "/bin/nonesuch")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("/bin/nonesuch", r.stderr)

    def test_a_program_already_in_the_root_keeps_its_bytes(self):
        # Node is a pinned download: only its libraries come from the base.
        (self.out / "usr/local/bin").mkdir(parents=True)
        own = self.out / "usr/local/bin/tool"
        shutil.copy(self.base / "usr/bin/bash", own)
        with open(own, "ab") as f:
            f.write(b"pinned-download-marker")
        r = self.run_userland("/usr/local/bin/tool")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(own.read_bytes().endswith(b"pinned-download-marker"))
        self.assertTrue((self.out / MULTIARCH / "libc.so.6").exists())

    def test_a_relative_path_fails(self):
        r = self.run_userland("bin/sh")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not an absolute path", r.stderr)

    def build(self, guest_path, *flags, lib=None):
        """A small program at GUEST_PATH in the base, linked with FLAGS, and (with LIB) needing
        libpin.so at the base path LIB. The linker sets PT_INTERP and RUNPATH as patchelf would."""
        src = self.tmp / "src"
        src.mkdir(exist_ok=True)
        (src / "pin.c").write_text("int pin(void) { return 7; }\n")
        (src / "main.c").write_text("int pin(void);\nint main(void) { return %s; }\n" % ("pin()" if lib else "0"))
        args = []
        if lib:
            (self.base / lib).mkdir(parents=True)
            subprocess.run(["cc", "-shared", "-fPIC", "-o", str(self.base / lib / "libpin.so"), str(src / "pin.c")],
                           check=True)
            args = ["-L", str(self.base / lib), "-lpin"]
        subprocess.run(["cc", "-o", str(self.base / guest_path.lstrip("/")), str(src / "main.c"), *args, *flags],
                       check=True)

    def test_a_program_asking_for_another_loader_fails(self):
        # A 32-bit or musl program would land in the guest with no loader and fail only there.
        self.build("/usr/bin/foreign", "-Wl,--dynamic-linker=/lib/ld-musl-x86_64.so.1")
        r = self.run_userland("/bin/foreign")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("/bin/foreign asks for loader /lib/ld-musl-x86_64.so.1", r.stderr)
        # The same program with the base's loader copies: the loader alone is refused.
        shutil.rmtree(self.out)
        self.build("/usr/bin/foreign")
        self.assertEqual(self.run_userland("/bin/foreign").returncode, 0)

    def test_a_library_inside_the_base_but_outside_its_library_directory_fails(self):
        # A RUNPATH into the base: put() sees no host path, so only the library-directory check stops it.
        self.build("/usr/bin/pinned", "-Wl,--enable-new-dtags", "-Wl,-rpath," + str(self.base / "opt/pin"),
                   lib="opt/pin")
        r = self.run_userland("/bin/pinned")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("/bin/pinned: libpin.so not found in %s/%s (got " % (self.base.resolve(), MULTIARCH), r.stderr)
        self.assertFalse((self.out / MULTIARCH / "libpin.so").exists())


class WiringTest(unittest.TestCase):
    """Every guest build reads the one base; nothing copies from the host."""

    def test_guest_builds_copy_only_from_guest_base(self):
        for g in GUESTS:
            with self.subTest(g):
                text = (ROOT / "guest" / g / "build-rootfs.sh").read_text()
                code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
                self.assertNotRegex(code, r"\bldd\b")
                self.assertNotIn("cp -L", code)
                self.assertRegex(code, r'sh "\$here/\.\./\.\./image/guest-userland\.sh" "(\$\{GUEST_BASE:\?|\$base")')
                if '"$base"' in code:
                    self.assertIn("base=${GUEST_BASE:?", code)

    def test_base_reads_the_image_s_own_apt_sources(self):
        text = BASE_SH.read_text()
        self.assertIn("/mkosi/mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources", text)
        self.assertIn("mmdebstrap --mode=root --variant=essential --include=libstdc++6,gcc,libc6-dev,libcap-dev trixie", text)
        self.assertIn("libpcre2-8-0", text)

    def test_codex_bwrap_is_compiled_in_the_base_not_on_the_host(self):
        # #5571: the only compiler call is the one run by chroot in GUEST_BASE, and no workflow
        # installs a host libcap-dev for it any more.
        text = (ROOT / "guest/codex/build-rootfs.sh").read_text()
        code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        calls = re.findall(r"(?<![\w./-])(?:cc|gcc|clang|c99|ld)(?= )", code)
        self.assertEqual(calls, ["gcc"])
        jail = code.index('chroot "$base" /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C')
        self.assertLess(jail, code.index("gcc "))
        self.assertEqual(code[jail:code.index("gcc ")].count("'"), 1)  # gcc runs in chroot's sh -c
        for wf in ("ci.yml", "image.yml"):
            with self.subTest(wf):
                self.assertNotIn("libcap-dev", (ROOT / ".github/workflows" / wf).read_text())

    def test_image_build_makes_the_base_before_both_guests_and_drops_it_after(self):
        b = (ROOT / "image/build.sh").read_text()
        base = b.index('sh "$HERE/guest-base.sh" "$OUT/guest-base" "$OUT/guest/agentos-guest.manifest"')
        export = b.index('export GUEST_BASE="$OUT/guest-base"')
        guests = [b.index('sh "$REPO/guest/%s/build-rootfs.sh"' % g) for g in GUESTS]
        drop = b.index('rm -rf --one-file-system "$GUEST_BASE"')
        mkosi = b.index('$MKOSI -C "$HERE/mkosi"')
        self.assertLess(base, export)
        self.assertLess(export, min(guests))
        self.assertLess(max(guests), drop)
        self.assertLess(drop, mkosi)
        # #5572: each guest build records its packages in one file, and their status is written
        # where the release record and tools/vulncheck.py read it, before the base is dropped.
        shipped = b.index('export GUEST_SHIPPED="$OUT/guest-base.shipped"')
        status = b.index('sh "$HERE/guest-shipped.sh" --status "$GUEST_BASE" "$OUT/guest"')
        self.assertLess(shipped, min(guests))
        self.assertLess(max(guests), status)
        self.assertLess(status, drop)

    def test_codex_records_what_its_bwrap_links(self):
        # #5572: the static bwrap carries libc6-dev's, libcap-dev's and gcc's archive code; the linker
        # lists every input (-t) and each one outside the build's /tmp is recorded as shipped.
        code = (ROOT / "guest/codex/build-rootfs.sh").read_text()
        self.assertIn("-l:libcap.a -o bwrap -Wl,-t >link.trace'", code)
        self.assertIn('sh "$here/../../image/guest-shipped.sh" "$base" $linked', code)
        self.assertLess(code.index("link.trace'"), code.index("guest-shipped.sh\" \"$base\" $linked"))

    def test_reproduce_compares_the_guest_packages(self):
        wf = (ROOT / ".github/workflows/image.yml").read_text()
        build, job = wf[:wf.index("  reproduce:")], wf[wf.index("  reproduce:"):]
        self.assertIn('cp -R "$RUNNER_TEMP"/out/guest "$RUNNER_TEMP/rec/"', build)
        self.assertRegex(build, r"install -y -q --no-install-recommends [^\n]*\\\n(?:[^\n]*\\\n)*[^\n]*\bmmdebstrap\b")
        line = "python3 image/compare_manifests.py rec/release-a/guest rec/release-b/guest || ok=0"
        self.assertIn(line, job)
        self.assertLess(job.index("ok=1"), job.index(line))
        self.assertLess(job.index(line), job.index("[ $ok = 1 ]"))

    def test_ci_guest_builds_name_a_base(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        unit = 'sudo sh image/guest-base.sh "$RUNNER_TEMP/guest-base" "$RUNNER_TEMP/guest-base.manifest"'
        rootfs = 'sudo GUEST_BASE="$RUNNER_TEMP/guest-base" GUEST_SHIPPED="$RUNNER_TEMP/guest-shipped" AGENTOS_CODEX_DOWNLOAD=1 python3 -m unittest tests.test_codex_rootfs'
        self.assertLess(ci.index(unit), ci.index(rootfs))
        self.assertIn("sudo sh image/guest-base.sh /tmp/guest-base /tmp/guest-base.manifest", ci)
        self.assertIn("GUEST_BASE=/tmp/guest-base GUEST_SHIPPED=/tmp/guest-shipped sh guest/openclaw/build-rootfs.sh /tmp/ocroot", ci)
        self.assertIn("GUEST_BASE=/tmp/guest-base \\\n            GUEST_SHIPPED=/tmp/guest-shipped-codex sh guest/codex/build-rootfs.sh /tmp/cxroot", ci)
        self.assertLess(ci.index("sudo sh image/guest-base.sh"), ci.index("sh guest/openclaw/build-rootfs.sh"))


if __name__ == "__main__":
    unittest.main()
