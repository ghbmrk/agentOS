import contextlib
import io
import pathlib
import sys
import os
import subprocess
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import risk_tier as rt  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent


class RiskTierTest(unittest.TestCase):
    def test_paths(self):
        cases = {
            "broker/vault/vault.go": "A",
            "broker/vault/vault_test.go": "A",
            "broker/egress/proxy.go": "A",
            "broker/go.sum": "A",
            "assurance/canary-targets.json": "A",
            "tools/canary.py": "A",
            "tools/risk_tier.py": "A",
            "broker/mail/deliver.go": "A",
            "broker/daemon/daemon.go": "A",
            "broker/cmd/agentosd/main.go": "A",
            "broker/sockprobe/probe.go": "A",
            # LOOP-7's verdicts and in-guest scripts (P3-4b-4b; Security #515 f4).
            "broker/loops/probe.go": "A",
            "broker/loops/machine.go": "A",
            "broker/probecmd/probecmd.go": "A",
            "broker/corpus/checks.go": "A",
            "broker/machprobe/machprobe.go": "A",
            "broker/loop7/loop7.go": "A",
            # REQ: OP-2 (W5-Db DB-1: Begin is the single gate on digest sends).
            "broker/digestqueue/queue.go": "A",
            "broker/recall/index.go": "B",
            "broker/newpkg/x.go": "B",
            "guest/openclaw/Dockerfile": "B",
            "guest/openclaw/src/x.ts": "B",
            "SPEC.md": "B",
            "docs/owners-guide.md": "C",
            "tools/trace.py": "C",
            "spikes/S8-provider-workers/README.md": "C",
            "BOARD.md": "C",
        }
        for path, want in cases.items():
            with self.subTest(path=path):
                self.assertEqual(rt.tier_of(path)[0], want)

    # RT-1a (briefs/RT-1.md; a local ID with no SPEC row, so no REQ marker)
    def test_image_ci_and_guest_build_paths_are_a(self):
        # Each path brief RT-1 lists under "Today", at the tier RT-1a gives it.
        paths = [
            "image/build.sh",
            "image/finish_image.py",
            "image/ci_boot.sh",
            "image/fuzz-targets.json",
            "image/mkosi/mkosi.conf",
            "image/mkosi/mkosi.finalize",
            "image/mkosi/mkosi.repart/10-root.conf",
            "image/mkosi/mkosi.extra/usr/lib/systemd/system/agentosd.service",
            "image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-health.service",
            "image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-fallback.service",
            "image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-drive-id.service",
            "image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-boot-report.service",
            ".github/workflows/image.yml",
            ".github/workflows/ci.yml",
            ".github/pull_request_template.md",
            ".claude/settings.json",
            "guest/openclaw/package-lock.json",
            "guest/openclaw/package.json",
            "guest/openclaw/build-rootfs.sh",
            "guest/openclaw/openclaw.json5",
            "guest/openclaw/launch.json",
            "guest/builder/launch.json",
            "guest/builder/build-rootfs.sh",
            "broker/cmd/agentos-modem/agentos-modem.service",
            "broker/recall/systemd/x.conf",
            "broker/recall/x.socket",
            "broker/recall/x.timer",
        ]
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(rt.tier_of(path)[0], "A")
        # Under spikes/, a unit file is a sketch, not something the image runs.
        self.assertEqual(rt.tier_of("spikes/S1/systemd/x.service")[0], "C")

    # RT-1a (briefs/RT-1.md; a local ID with no SPEC row, so no REQ marker)
    def test_every_image_file_and_unit_in_the_tree_is_a(self):
        # Walks the tree, so a new image file or unit cannot slip in below A.
        found = []
        for dirpath, dirs, files in os.walk(ROOT):
            rel = pathlib.Path(dirpath).relative_to(ROOT)
            dirs[:] = [d for d in dirs if not (rel == pathlib.Path(".") and d in (".git", "spikes"))]
            for f in files:
                p = (rel / f).as_posix()
                in_mkosi = p.startswith("image/mkosi/")
                unit = f.endswith((".service", ".socket", ".timer")) or (
                    "systemd" in rel.parts and f.endswith(".conf"))
                if in_mkosi or unit:
                    found.append(p)
        self.assertIn("image/mkosi/mkosi.extra/usr/lib/systemd/system/agentosd.service", found)
        self.assertIn("broker/cmd/agentos-localui/agentos-localui.service", found)
        below = [p for p in found if rt.tier_of(p)[0] != "A"]
        self.assertEqual(below, [])

    # RT-1b (briefs/RT-1.md; a local ID with no SPEC row, so no REQ marker)
    def test_explicit_c_list_and_unmatched_default_b(self):
        cases = {
            "newdir/x": "B",
            "newdir/x.md": "B",
            ".gitignore": "B",
            "docs/x.md": "C",
            "briefs/x.md": "C",
            "reviews/l3/README.md": "C",
            "decisions/D-001.md": "C",
            "tests/test_x.py": "C",
            "tools/trace.py": "C",
            "tools/ASSUMPTIONS.md": "C",
            "image/README.md": "C",
            "image/ASSUMPTIONS.md": "C",
            "README.md": "C",
            "LATER.md": "C",
            "CLAUDE.md": "C",
            "LEDGER.md": "C",
            "METRICS.md": "C",
            "TRACE.md": "C",
            "SPEC.md": "B",
            # A .md below the top level of image/ is not documentation-only.
            "image/mkosi/x.md": "A",
        }
        for path, want in cases.items():
            with self.subTest(path=path):
                self.assertEqual(rt.tier_of(path)[0], want)

    # RT-1a (briefs/RT-1.md; a local ID with no SPEC row, so no REQ marker)
    def test_moving_a_tier_a_file_out_keeps_tier_a(self):
        with tempfile.TemporaryDirectory() as d:
            def git(*args):
                subprocess.run(["git", "-C", d, *args], check=True, capture_output=True)
            git("init", "-q")
            git("config", "user.email", "t@example.invalid")
            git("config", "user.name", "t")
            os.makedirs(os.path.join(d, "image"))
            with open(os.path.join(d, "image", "build.sh"), "w") as f:
                f.write("echo build\n" * 20)
            git("add", ".")
            git("commit", "-qm", "base")
            os.makedirs(os.path.join(d, "docs"))
            git("mv", "image/build.sh", "docs/build.sh")
            git("commit", "-qm", "move")
            cwd = os.getcwd()
            os.chdir(d)
            try:
                paths = rt.changed_paths("HEAD~1", "HEAD")
            finally:
                os.chdir(cwd)
        self.assertIn("image/build.sh", paths)
        self.assertEqual(rt.tier_of_change(paths)[0], "A")

    def test_paths_git_would_quote_keep_tier_a(self):
        # git diff quotes names with non-ASCII bytes, quotes, tabs, backslashes
        # or newlines; the quoted form would match no A prefix and fall to B.
        names = ["image/mkosi/\u00e9", "image/a\tb", "image/a\\b", '.github/workflows/a"b.yml', "image/build\nx.sh"]
        with tempfile.TemporaryDirectory() as d:
            def git(*args):
                subprocess.run(["git", "-C", d, *args], check=True, capture_output=True)
            git("init", "-q")
            git("config", "user.email", "t@example.invalid")
            git("config", "user.name", "t")
            git("commit", "-q", "--allow-empty", "-m", "base")
            for n in names:
                os.makedirs(os.path.join(d, os.path.dirname(n)), exist_ok=True)
                with open(os.path.join(d, n), "w") as f:
                    f.write("x\n")
            git("add", ".")
            git("commit", "-qm", "add")
            cwd = os.getcwd()
            os.chdir(d)
            try:
                paths = rt.changed_paths("HEAD~1", "HEAD")
            finally:
                os.chdir(cwd)
        self.assertEqual(sorted(paths), sorted(names))
        for n in names:
            self.assertEqual(rt.tier_of(n)[0], "A", n)

    def test_highest_tier_wins(self):
        tier, why = rt.tier_of_change(["docs/a.md", "broker/recall/x.go", "broker/vault/y.go"])
        self.assertEqual((tier, why), ("A", ["broker/vault/y.go"]))
        self.assertEqual(rt.tier_of_change(["docs/a.md", "broker/route/r.go"])[0], "B")
        self.assertEqual(rt.tier_of_change([]), ("C", []))

    def test_every_tier_a_package_exists(self):
        # A renamed package must not silently drop to tier B.
        missing = [p for p in sorted(rt.TIER_A_BROKER) if not (ROOT / "broker" / p).is_dir()]
        self.assertEqual(missing, [])

    def test_markdown_output(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rt.main(["--markdown", "broker/vault/v.go"])
        self.assertIn("Risk tier A", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
