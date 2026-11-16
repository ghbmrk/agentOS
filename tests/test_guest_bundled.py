# The guests' statically linked crypto copies (#5853): assurance/vulncheck.json "bundled" records each
# copy a guest's pinned binary carries apart from Debian's packages, and the OpenClaw build fails
# unless a record names the OpenSSL its node reports.
# REQ: EVL-5
import json
import os
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG = ROOT / "assurance" / "vulncheck.json"
OPENCLAW = ROOT / "guest" / "openclaw" / "build-rootfs.sh"
CODEX = ROOT / "guest" / "codex" / "build-rootfs.sh"
KEYS = {"holder", "copy", "build", "issue", "ids", "why"}


def pin(script, name):
    return re.search(r"^%s=(\S+)$" % name, script.read_text(), re.M).group(1)


def check_lines():
    """The OpenSSL check of the OpenClaw build: from its ossl= line through the line after the grep."""
    lines = OPENCLAW.read_text().splitlines()
    i = next(n for n, l in enumerate(lines) if l.startswith("ossl="))
    return "\n".join(lines[i:i + 3]) + "\n"


class Bundled(unittest.TestCase):
    def setUp(self):
        self.cfg = json.loads(CONFIG.read_text())
        self.bundled = self.cfg.get("bundled", [])

    def test_each_record_has_its_keys(self):
        self.assertTrue(self.bundled)
        for e in self.bundled:
            self.assertEqual(set(e), KEYS, e)
            self.assertTrue((ROOT / e["build"]).is_file(), e["build"])
            self.assertTrue(e["ids"] and e["why"], e)

    def test_the_pinned_node_and_codex_have_records(self):
        holders = {e["holder"] for e in self.bundled}
        self.assertIn("node@" + pin(OPENCLAW, "NODE_VERSION"), holders)
        self.assertIn("@openai/codex@%s-linux-x64" % pin(CODEX, "CODEX_VERSION"), holders)

    def test_the_build_checks_node_right_after_unpacking_it(self):
        text = OPENCLAW.read_text()
        self.assertLess(text.index('tar -xJf "$work/node.tar.xz"'), text.index("ossl=$(usr/local/bin/node -p process.versions.openssl)"))
        self.assertLess(text.index("ossl="), text.index("npm ci"))

    def run_check(self, reported, version="v24.22.3"):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "assurance").mkdir()
            (d / "assurance" / "vulncheck.json").write_text(CONFIG.read_text())
            node = d / "usr" / "local" / "bin" / "node"
            node.parent.mkdir(parents=True)
            node.write_text("#!/bin/sh\necho %s\n" % reported)
            node.chmod(0o755)
            script = "set -eu\nNODE_VERSION=%s\nrepo=%s\n%s" % (version, d, check_lines())
            return subprocess.run(["sh", "-c", script], cwd=d, capture_output=True, text=True,
                                  env={"PATH": os.environ["PATH"]})

    def test_the_check_passes_only_for_the_recorded_openssl(self):
        rec = next(e for e in self.bundled if e["holder"] == "node@" + pin(OPENCLAW, "NODE_VERSION"))
        version = rec["holder"].split("@", 1)[1]
        ok = self.run_check(rec["copy"].split("@", 1)[1], version)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        # A node whose OpenSSL differs from the record, or a node with no record, fails the build.
        self.assertNotEqual(self.run_check("3.5.10", version).returncode, 0)
        # A prefix of the recorded version matches only if the pattern lost a closing quote.
        copy = rec["copy"].split("@", 1)[1]
        self.assertNotEqual(self.run_check(copy.rsplit(".", 1)[0], version).returncode, 0)
        self.assertNotEqual(self.run_check(copy[:-1], version).returncode, 0)
        bad = self.run_check(rec["copy"].split("@", 1)[1], "v99.0.0")
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("record it in assurance/vulncheck.json", bad.stderr)


if __name__ == "__main__":
    unittest.main()
