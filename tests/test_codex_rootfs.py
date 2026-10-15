# The Codex provider worker's rootfs build (S8-W1, #807 wiring half): build-rootfs.sh pins the
# official CLI by npm's integrity hash, installs the managed config and requirements as the
# repo has them, and puts no login in the image. The build needs the pinned tarball: set
# CODEX_TARBALL to a local copy, or AGENTOS_CODEX_DOWNLOAD=1 to fetch it (CI does). Without
# either, only the offline checks run. The runsc measurement stays #809's.
# REQ: CRED-5, CRED-1, A14, CAP-11
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CODEX = ROOT / "guest/codex"
SCRIPT = CODEX / "build-rootfs.sh"
VERSION = "0.162.1"
INTEGRITY = "sha512-cjK2mdHIfEepZ1lQ1MX3aTQC+8ncIsvnacl/6vI2dIIcfP8/MrhTQ2+qRlkXFNDzJSj1d36quIszP+3/4CUJWQ=="
VENDOR = "opt/codex/vendor/x86_64-unknown-linux-musl"
NEVER_ON = {
    "daemon_auto_start", "workspace_dependencies", "system_proxy_fallback", "in_app_browser",
    "browser_use_full_cdp_access", "tool_suggest", "guardian_approval",
}
INSTALLED = {
    "etc/codex/managed_config.toml": CODEX / "managed_config.toml",
    "etc/codex/requirements.toml": CODEX / "requirements.toml",
    "usr/lib/agentos/codex/launch.json": CODEX / "launch.json",
    "usr/local/bin/agentos-toolsh": CODEX / "agentos-toolsh",
}


def build(out, tarball):
    env = dict(os.environ, CODEX_TARBALL=tarball) if tarball else dict(os.environ)
    return subprocess.run(["sh", str(SCRIPT), str(out)], env=env, capture_output=True, text=True)


class RootfsScriptTest(unittest.TestCase):
    # REQ: CRED-5, A14
    def test_pin_is_exact_version_and_integrity(self):
        text = SCRIPT.read_text()
        self.assertIn(f"CODEX_VERSION={VERSION}\n", text)
        self.assertIn(f"CODEX_INTEGRITY={INTEGRITY}\n", text)
        # The pin must be the version the C rows were measured on (ASSUMPTIONS C1).
        self.assertIn(f"Codex CLI {VERSION}", (CODEX / "ASSUMPTIONS.md").read_text())

    # REQ: CRED-5, CRED-1
    def test_script_writes_no_login(self):
        text = SCRIPT.read_text()
        code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        self.assertNotRegex(code, r"auth\.json")
        self.assertNotRegex(code, r"OPENAI_API_KEY|access_token|refresh_token")

    # REQ: A14, CRED-5
    def test_script_installs_the_forwarder_launch_names(self):
        text = SCRIPT.read_text()
        launch = json.loads((CODEX / "launch.json").read_text())
        self.assertIn("usr" + launch["wrap"][0][4:], text)
        self.assertIn("./egress/cmd/agentos-codex-forwarder", text)

    # REQ: CRED-5, A14
    def test_wrong_tarball_is_refused_before_anything_is_installed(self):
        with tempfile.TemporaryDirectory(prefix="agentos-codex-rootfs-") as d:
            fake = pathlib.Path(d) / "fake.tgz"
            fake.write_bytes(b"not the pinned tarball")
            out = pathlib.Path(d) / "out"
            r = build(out, str(fake))
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("integrity", r.stderr)
            self.assertEqual(list(out.rglob("*")), [])

    # REQ: CRED-5
    def test_nonempty_output_directory_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="agentos-codex-rootfs-") as d:
            (pathlib.Path(d) / "x").write_text("x")
            r = build(d, None)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("not empty", r.stderr)


class RootfsBuildTest(unittest.TestCase):
    """Builds the rootfs from the pinned tarball and checks what is in it."""

    @classmethod
    def setUpClass(cls):
        tarball = os.environ.get("CODEX_TARBALL")
        if not tarball and os.environ.get("AGENTOS_CODEX_DOWNLOAD") != "1":
            raise unittest.SkipTest("set CODEX_TARBALL or AGENTOS_CODEX_DOWNLOAD=1 to build")
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="agentos-codex-rootfs-"))
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.out = cls.tmp / "rootfs"
        r = build(cls.out, tarball)
        if r.returncode != 0:
            raise AssertionError("build-rootfs.sh failed:\n" + r.stderr[-2000:])

    # REQ: CRED-5, CRED-1
    def test_no_login_in_the_image(self):
        self.assertEqual(list(self.out.rglob("auth.json")), [])
        home = self.out / "var/lib/agentos-codex"
        self.assertEqual(sorted(p.name for p in home.iterdir()), ["tmp"])
        self.assertEqual(list((home / "tmp").iterdir()), [])
        self.assertEqual(list((self.out / "var/lib/agentos-work").iterdir()), [])

    # REQ: CRED-5, A14
    def test_managed_layers_are_the_repo_files(self):
        for rel, src in INSTALLED.items():
            dst = self.out / rel
            self.assertEqual(dst.read_bytes(), src.read_bytes(), rel)
            self.assertEqual(dst.stat().st_mode & 0o7777, 0o755 if rel.endswith("toolsh") else 0o644, rel)
            if os.geteuid() == 0:
                self.assertEqual(dst.stat().st_uid, 0, rel)
        launch = json.loads((self.out / "usr/lib/agentos/codex/launch.json").read_text())
        self.assertEqual(launch["argv"][:3], ["codex", "exec", "--json"])

    # REQ: CRED-5, A14
    def test_installed_config_leaves_no_hosted_tool_on(self):
        from tests.test_codex_worker import hosted_tool_problems
        cfg = tomllib.loads((self.out / "etc/codex/managed_config.toml").read_text())
        self.assertEqual(hosted_tool_problems(cfg), [])

    # REQ: CRED-5, A14
    def test_cli_and_helpers_are_installed(self):
        link = self.out / "usr/local/bin/codex"
        self.assertEqual(os.readlink(link), "/" + VENDOR + "/bin/codex")
        for rel in ("bin/codex", "bin/codex-code-mode-host", "codex-resources/bwrap", "codex-path/rg"):
            f = self.out / VENDOR / rel
            self.assertTrue(f.is_file() and os.access(f, os.X_OK), rel)
        self.assertTrue(os.access(self.out / "usr/bin/bwrap", os.X_OK))
        self.assertFalse((self.out / VENDOR / "codex-resources/voice").exists())
        self.assertTrue((self.out / "bin/bash").is_file())

    # REQ: A14, A3
    def test_forwarder_is_installed_and_the_socket_directory_is_empty(self):
        self.assertTrue(os.access(self.out / "usr/local/bin/agentos-codex-forwarder", os.X_OK))
        self.assertEqual(os.listdir(self.out / "run/agentos"), [])

    # REQ: CRED-5, A14, CAP-11
    def test_cli_resolves_its_layout_and_loads_the_managed_layers(self):
        # codex doctor run over the built tree (chroot in a user, pid and network namespace: no
        # root needed, no network). --version does not exercise package discovery or the managed layers.
        manifest = json.loads((self.out / VENDOR / "codex-package.json").read_text())
        self.assertEqual(manifest["version"], VERSION)
        home = "/tmp/codex-home"
        r = subprocess.run(
            ["unshare", *([] if os.geteuid() == 0 else ["-r"]), "-npf", f"--mount-proc={self.out}/proc", "chroot", str(self.out), "/bin/sh", "-c",
             f"mkdir -p {home} && HOME={home} CODEX_HOME={home} /usr/local/bin/codex doctor --json"],
            capture_output=True, text=True, timeout=120)
        # Exit 1 is expected: no login and no network. The report is what is checked.
        try:
            checks = json.loads(r.stdout)["checks"]
        except ValueError:
            self.fail(f"codex doctor printed no report: {r.stderr[-500:]}")
        self.assertEqual(checks["config.load"]["status"], "ok", checks["config.load"])
        search = checks["runtime.search"]["details"]
        self.assertEqual(search["search provider"], "bundled", search)
        self.assertEqual(search["search command"], "/" + VENDOR + "/codex-path/rg")
        sandbox = checks["sandbox.helpers"]["details"]
        self.assertEqual(sandbox["approval policy"], "Never")
        self.assertEqual(sandbox["filesystem sandbox"], "restricted")
        self.assertEqual(sandbox["network sandbox"], "restricted")
        self.assertEqual(sandbox["managed filesystem source"], "system")
        self.assertEqual(checks["mcp.config"]["status"], "ok")
        cfg = checks["config.load"]["details"]
        self.assertEqual(cfg["model provider"], "agentos")
        self.assertEqual(cfg["mcp servers"], "0")
        # Every flag that is on by default in this pin and could start a process or reach a
        # service outside the tool sandbox is pinned off (C14).
        on = {f.strip() for f in cfg["enabled feature flags"].split(",")}
        self.assertEqual(on & NEVER_ON, set(), "managed_config.toml must pin these off")

    # REQ: CRED-5, A14
    def test_cli_reports_the_pinned_version(self):
        r = subprocess.run([str(self.out / VENDOR / "bin/codex"), "--version"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.stdout.strip(), f"codex-cli {VERSION}")


if __name__ == "__main__":
    unittest.main()
