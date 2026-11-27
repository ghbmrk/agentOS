"""CI-pin-build-isolation (#6706): a hashed pip install is credited only when it cannot fetch an unhashed
build backend.

REQ: CI-pin-liveness-1 (a pinned download is identified by its sha256, checked before use)

pip's `--require-hashes` checks the files it installs, not the isolated environment it builds an sdist
in: that environment installs the sdist's build backend from the index with no hash. tools/pins.py
credits a `--require-hashes` install only with `--no-build-isolation` or `--only-binary` `:all:` as its
last value, and counts every option line in a tracked requirements file, since such a line
(`--no-binary :all:`) can reopen sdists from inside the file.
"""
import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import pins  # noqa: E402

H = "--hash=sha256:" + "ab" * 32


class Credit(unittest.TestCase):
    def test_a_hashed_install_that_can_build_in_isolation_is_a_site(self):
        for text in ["pip install --require-hashes -r r.txt", "pip download --require-hashes -r r.txt",
                     "python3 -m pip install -q --no-deps --require-hashes -r r.txt",
                     "pip install --require-hashes --only-binary=:none: -r r.txt",
                     # The last `--only-binary` value decides; `:none:` or a name list after `:all:` reopens sdists.
                     "pip install --only-binary=:all: --only-binary=:none: --require-hashes -r r.txt",
                     "pip install --only-binary :all: --only-binary :none: --require-hashes -r r.txt",
                     "pip install --only-binary=:all: --only-binary x --require-hashes -r r.txt",
                     "pip install --only-binary x,:all: --require-hashes -r r.txt",
                     "pip install --only-binary x --require-hashes -r r.txt",
                     # `--no-index` is not credited: a requirements file's own `--find-links` line reopens a source.
                     "pip install --no-index --require-hashes -r r.txt"]:
            with self.subTest(text=text):
                self.assertEqual(pins.text_sites(text), 1)
        # Security and L3 release on #6723: a `-r` file is credited only under a name `scanned` reads, so a
        # tracked file's option lines are always counted.
        for text in ["pip install --no-build-isolation --require-hashes -r r.txt",
                     "pip install --only-binary=:all: --require-hashes -r tests/deps.txt",
                     "pip install --only-binary=:all: --require-hashes --requirement=deps.txt",
                     "pip install --only-binary=:all: --require-hashes -r requirements.txt.bak",
                     "pip install --only-binary=:all: --require-hashes -r myrequirements.txt",
                     'pip install --only-binary=:all: --require-hashes -r "$R"',
                     "pip install --only-binary=:all: --require-hashes -r x/vendor/requirements.txt",
                     "pip install --only-binary=:all: --require-hashes --requirement=vendor/requirements.txt"]:
            with self.subTest(text=text):
                self.assertEqual(pins.text_sites(text), 1)
        # A build flag on another command in the line earns the first command nothing.
        self.assertEqual(pins.text_sites("pip install --require-hashes -r r.txt; "
                                         "pip install --no-build-isolation --require-hashes -r requirements.txt"), 1)

    def test_an_install_that_cannot_build_in_isolation_is_credited(self):
        for text in ["pip install --no-build-isolation --require-hashes -r requirements.txt",
                     "pip install --require-hashes --no-deps --no-build-isolation -r requirements.txt",
                     "pip download --only-binary=:all: --require-hashes -r requirements.txt",
                     "pip install --only-binary :all: --require-hashes -r requirements.txt",
                     "pip install --only-binary=:none: --only-binary=:all: --require-hashes -r requirements.txt",
                     "pip install --only-binary=:none: --no-build-isolation --require-hashes -r requirements.txt",
                     "pip install --no-build-isolation --require-hashes -r d/requirements-x.txt",
                     "pip install --no-build-isolation --require-hashes --requirement=d/requirements.in",
                     "pip install --only-binary=:all: --no-deps --require-hashes -r build-requirements.txt"]:
            with self.subTest(text=text):
                self.assertEqual(pins.text_sites(text), 0)

    def test_the_repositorys_credited_installs_still_read_as_credited(self):
        # ci.yml's three hashed installs and vision-real.yml's one each close the build path with
        # `--only-binary` `:all:`, so their counts are only the owed fetches FETCH_NOT_YET lists.
        for f in (".github/workflows/ci.yml", ".github/workflows/vision-real.yml"):
            with self.subTest(f=f):
                text = (ROOT / f).read_text()
                hashed = [x for x in text.splitlines() if "--require-hashes" in x and "pip" in x]
                self.assertTrue(hashed and all(":all:" in x for x in hashed), f)
                n = pins.FETCH_NOT_YET[f][1]
                self.assertEqual(pins.yaml_sites(text), n)
                # Dropping the flag from one install adds that install as a site.
                flag = "--only-binary=:all: " if "--only-binary=:all: " in text else "--only-binary :all: "
                self.assertEqual(pins.yaml_sites(text.replace(flag, "", 1)), n + 1)


class Requirements(unittest.TestCase):
    def test_option_lines_count(self):
        cases = {
            "a==1 " + H + "\n": 0,
            "# c\na==1 \\\n    " + H + " \\\n    " + H + "\n\n": 0,
            "a==1 " + H + "  # pinned\n": 0,
            "--no-binary :all:\na==1 " + H + "\n": 1,
            "--no-binary=:all:\n": 1,
            "-i https://evil.example/simple\n": 1,
            "--find-links https://evil.example/\n": 1,
            "-r other.txt\n": 1,
            "-c c.txt\n": 1,
            "-e git+https://evil.example/x\n": 1,
            "  --no-binary :all:\n": 1,
            # A requirement that carries an option, or a hash pip does not take as sha256, counts.
            "a==1 --no-binary :all: " + H + "\n": 1,
            "a==1 --hash=md5:00\n": 1,
            "a==1 --hash=sha256:" + "ab" * 31 + "\n": 1,
            "a==1\n": 0,  # no fetch: `--require-hashes` refuses a requirement without a hash
            # Lines join as pip joins them: a comment line ending in a backslash does not swallow the next,
            # while a requirement line's trailing comment does, and pip drops it too.
            "# c \\\n--no-binary :all:\n": 1,
            "a==1 " + H + " # c \\\n--no-binary :all:\n": 0,
            "a==1 \\\n--no-binary :all:\n": 1,
            "a==1 " + H + " \\\n": 0,
            "\\--no-binary=:all: \\\n\n": 1,
            # Security fix-list on #6723 at 8ac244db: only a plain hashed pin is allowed. A direct reference
            # is built from source whatever `--only-binary` says; pip expands `${VAR}`; it decodes by BOM or
            # `coding:` declaration, so a UTF-7 file spells an option in ASCII.
            "https://files.example/six-1.0.tar.gz " + H + "\n": 1,
            "./six-1.0.tar.gz " + H + "\n": 1,
            "six @ https://files.example/six-1.0.tar.gz " + H + "\n": 1,
            "six@https://files.example/six-1.0.tar.gz " + H + "\n": 1,
            "${XOPT}\n": 1,
            "six==${V} " + H + "\n": 1,
            "six[x]==1 " + H + "\n": 1,
            "six==1; python_version>'3' " + H + "\n": 1,
            "six>=1 " + H + "\n": 1,
            "\ufeffa==1 " + H + "\n": 2,  # not ASCII, and the BOM glued to the name is no pin
            "# -*- coding: utf-7 -*-\n+AC0ALQ-no-binary=:all:\n": 2,
            "a==1 " + H + "\n# coding: latin-1\n": 1,
            # Security on #6723 at 00f08902: a pin ending in an archive extension is a local file to pip, and a
            # local `+` version can carry UTF-7 text; a `coding` anywhere, or a break other than `\n`, counts.
            "six==1.16.0.tar.gz " + H + "\n": 1,
            "six==1.0+x.zip " + H + "\n": 1,
            "six==1.0.whl " + H + "\n": 1,
            "six==1.0+abc1 " + H + "\n": 1,
            "six==v1 " + H + "\n": 1,
            "six==1.16.0+AC0ALQ-no-binary=:all:- " + H + "\n": 1,
            "#\r#\r# -*- coding: utf-7 -*-\nsix==1.16.0 " + H + "\n": 2,
            "a==1 " + H + "\n\n\n# coding: latin-1\n": 1,
            "a==1 " + H + "\r\n": 1,
            "a==1 " + H + "\x0c\n": 1,
            "a==1.0rc1 " + H + "\nb==2.post1 " + H + "\nc==3.0.dev2 " + H + "\n": 0,
            # A continuation at the end of the file is still read (Security release 4 on #6723).
            "a==1 " + H + "\n--no-binary :all: \\": 1,
        }
        for text, n in cases.items():
            with self.subTest(text=text):
                self.assertEqual(pins.req_sites(text), n)

    def test_scanned_reads_every_name_a_credited_install_may_name(self):
        # L3 on #6723 at 00f08902: the names `_pip_hashed` credits and the names `scanned` reads are one rule.
        names = ["build-requirements.txt", "d/requirements-x.in", "requirements.txt", "x/vendor/requirements.txt",
                 "myrequirements.txt", "requirements.txt.bak", "r.txt"]
        listing = mock.Mock(stdout=b"\0".join(n.encode() for n in names))
        with mock.patch.object(pins.subprocess, "run", return_value=listing), \
                mock.patch("builtins.open", side_effect=OSError):
            kinds = pins.scanned()
        self.assertEqual(sorted(f for f, k in kinds.items() if k == "requirements"),
                         ["build-requirements.txt", "d/requirements-x.in", "requirements.txt"])
        for n in names:
            with self.subTest(n=n):
                self.assertEqual(pins.text_sites("pip install --only-binary=:all: --require-hashes -r " + n),
                                 0 if kinds.get(n) == "requirements" else 1)

    def test_tracked_requirements_files_hold_no_option_line(self):
        # tests/test_pins.py checks pins.scanned() reads these as kind "requirements" (it runs in the
        # records-only step, since scanned() opens every tracked file).
        for f in ("tests/requirements.txt", "tests/requirements-browser.txt"):
            with self.subTest(f=f):
                self.assertEqual(pins.fetch_sites(ROOT / f, "requirements"), 0)
                self.assertGreater(pins.req_sites((ROOT / f).read_text() + "--no-binary :all:\n"), 0)


if __name__ == "__main__":
    unittest.main()
