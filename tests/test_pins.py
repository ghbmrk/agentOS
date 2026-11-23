"""CI-pin-liveness (#6424): tools/pins.py, the one reader for pinned external downloads.

REQ: CI-pin-liveness-1 (one format, fail closed), CI-pin-liveness-2 (the hash is the only authority),
CI-pin-liveness-3 (liveness names each dead source), CI-pin-liveness-4 (every pin and download
site is covered or owed by a release row), CI-pin-liveness-fu (#6524: the owed lists shrink against
main, fetch sites are found structurally and counted per file, `live` opens only a zip that matched).
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


if __name__ == "__main__":
    unittest.main()
