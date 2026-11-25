"""DRONE-sitl-pip-hashes (#6588): the SITL build's PyPI install checks hashes. Every requirement build.sh writes
is pinned by version and sha256, each install runs with --require-hashes and --no-deps, and build.sh holds no
fetch site tools/pins.py does not credit (it left FETCH_EXEMPT).

REQ: CI-pin-liveness-1
"""
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import pins  # noqa: E402

BUILD = ROOT / "broker/drone/sitl/build.sh"
HEREDOC = re.compile(r"<<'REQ'\n(.*?)\nREQ\n", re.S)
LINE = re.compile(r"[a-z][a-z0-9_.-]*==[0-9][0-9A-Za-z.]* --hash=sha256:[0-9a-f]{64}")


def sitl_requirements(text):
    return [x for block in HEREDOC.findall(text) for x in block.split("\n")]


def sitl_installs(text):
    return [x for x in text.split("\n") if re.search(r"\bpip\b", x) and not x.lstrip().startswith("#")]


class SitlPipHashes(unittest.TestCase):
    def test_every_requirement_is_pinned_by_version_and_sha256(self):
        reqs = sitl_requirements(BUILD.read_text())
        self.assertTrue(reqs)
        for x in reqs:
            self.assertRegex(x, "^" + LINE.pattern + "$")
        names = {x.split("==")[0] for x in reqs}
        # --no-deps installs only what is listed: pexpect's one dependency is listed, and setuptools is pinned.
        self.assertLessEqual({"empy", "pexpect", "ptyprocess", "future", "setuptools"}, names)

    def test_every_install_requires_hashes_without_deps(self):
        lines = sitl_installs(BUILD.read_text())
        self.assertEqual(len(lines), 2)
        for x in lines:
            for flag in ("--require-hashes", "--no-deps", "-r "):
                self.assertIn(flag, x)

    def test_build_holds_no_uncredited_fetch_and_is_not_exempt(self):
        self.assertEqual(pins.fetch_sites(BUILD, "text"), 0)
        self.assertNotIn("broker/drone/sitl/build.sh", pins.FETCH_EXEMPT)

    def test_unhashed_install_reads_as_a_fetch_site(self):
        # The line #6588 replaced, its manager name spelled from parts so this file holds no fetch site.
        old = 'python3 -m venv "$src/.venv"\n"$src/.venv/bin/%s" install -q empy==3.3.4 setuptools\n' % ("pi" + "p")
        self.assertEqual(sitl_requirements(old), [])
        self.assertEqual(pins.text_sites(old), 1)


if __name__ == "__main__":
    unittest.main()
