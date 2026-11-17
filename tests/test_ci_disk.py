"""CI-disk-cause (#4422): what filled the runner disk, removed, with a free-disk guard as support.

broker-race (1)'s Go build cache had reached 5.1 GB compressed (5,362,827,158 B restored and
5,376,396,879 B saved on main run 43887011125; shards 0 and 2 held 0.6 and 0.3 GB): each push to
main saved the restored cache plus its own builds, and go drops an entry only after five days
unused. Each job that saves a Go build cache now keeps only the entries its run used before the
save, and a step after the restore prints the runner's cloud, / free and the cache's size, and
stops under a floor. These tests run the test's own copies of the two scripts, each checked
against every job's step byte for byte (the image-disk tests' rule, #4541), never ci.yml's text,
and one runs the keep step's copy against a real go build cache."""
import difflib
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import unittest

from test_workflows import load_steps

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/ci.yml"
GUARD = "Runner disk after the cache restore (CI-disk-cause)"
KEEP = "Build cache keeps only what this run used (CI-disk-cause)"
RESTORE, SAVE = "Go build cache (CI-PATHS)", "Go build cache upload (main only; CI-PATHS)"
MAIN_ONLY = "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
# Each job that saves a Go build cache: its cache path and how it reads it (the machines job's
# root test runs leave root-owned entries).
JOBS = {"broker-race": ("~/.cache/go-build", ""), "broker-checks": ("~/.cache/go-build", ""),
        "machines": ("/tmp/gocache", "sudo")}

GUARD_SCRIPT = r"""vendor=$(cat "${DMI_ID:-/sys/class/dmi/id}/sys_vendor" 2>/dev/null || true)
case "$vendor" in
  "Amazon EC2"*) cloud=AWS;; "Microsoft Corporation"*) cloud=Azure;; *) cloud="unknown-cloud (${vendor:-no DMI vendor})";;
esac
c=${CACHE/#\~/$HOME}
cache_mb=0
[ ! -d "$c" ] || cache_mb=$($AS_ROOT du -sm "$c" | awk '{print $1}')
free_gb=$(( $(df -BM --output=avail / | tail -n 1 | tr -dc 0-9) / 1024 ))
echo "::notice title=runner disk::$cloud runner: / has $free_gb GB free after restoring $cache_mb MB of Go build cache"
# go touches a cache entry it uses only when the entry's mtime is an hour old or more, so an
# entry is this run's if it is newer than an hour (and a minute) before now.
touch -d "@$(( $(date +%s) - 3660 ))" "$RUNNER_TEMP/gocache.mark"
[ "$free_gb" -ge "$DISK_FLOOR_GB" ] || { echo "::error title=runner disk::$cloud runner: / has $free_gb GB free after restoring $cache_mb MB of Go build cache, under the $DISK_FLOOR_GB GB floor; rerun the job, and if the cache is the bulk, see CI-disk-cause in tools/ASSUMPTIONS.md"; exit 1; }
"""

KEEP_SCRIPT = r"""c=${CACHE/#\~/$HOME}
mark="$RUNNER_TEMP/gocache.mark"
[ -e "$mark" ] || { echo "::error title=build cache::no $mark: the runner-disk step did not run, so which entries this run used is unknown"; exit 1; }
[ -d "$c" ] || { echo "no Go build cache at $c"; exit 0; }
entries() { $AS_ROOT find "$c" -mindepth 2 -maxdepth 2 -path "$c/[0-9a-f][0-9a-f]/*" -type f "$@"; }
mb() { entries "$@" -printf '%s\n' | awk '{s += $1} END {printf "%d", s / 1048576}'; }
all=$(mb); used=$(mb -newer "$mark")
echo "::notice title=build cache::$all MB of Go build cache, $used MB of it used by this run, $(( all - used )) MB stale"
if [ "$DROP" = true ]; then
  entries ! -newer "$mark" -delete
  echo "dropped the stale entries; $(mb) MB left to save"
fi
"""

FAKE_DF = """#!/bin/sh
echo Avail
echo "$(cat "$(dirname "$0")/avail")M"
"""

MB = 1 << 20


def job_steps():
    out = {}
    for job, step in load_steps(WORKFLOW.read_text(encoding="utf-8")):
        out.setdefault(job, []).append(step)
    return out


def same(own, step, where):
    if step["run"] != own:
        diff = "".join(difflib.unified_diff(own.splitlines(True), step["run"].splitlines(True), "test copy", where))
        raise AssertionError("%s differs from the test's copy; change the copy in tests/test_ci_disk.py "
                             "to match in the same PR:\n%s" % (where, diff))


class StepsTest(unittest.TestCase):
    def test_every_go_build_cache_save_keeps_only_this_runs_entries(self):
        steps = job_steps()
        saving = sorted(j for j, ss in steps.items() for s in ss
                        if str(s.get("uses", "")).startswith("actions/cache/save@")
                        and any(p in s["with"]["path"] for p in ("go-build", "gocache")))
        self.assertEqual(saving, sorted(JOBS))
        for job, (cache, root) in JOBS.items():
            with self.subTest(job):
                names = [s.get("name") for s in steps[job]]
                self.assertEqual(names.count(GUARD), 1)
                self.assertEqual(names.count(KEEP), 1)
                # The guard follows the restore at once; the keep step comes before the save, so the
                # save uploads what it left.
                self.assertEqual(names.index(GUARD), names.index(RESTORE) + 1)
                self.assertLess(names.index(KEEP), names.index(SAVE))
                guard, keep = steps[job][names.index(GUARD)], steps[job][names.index(KEEP)]
                same(GUARD_SCRIPT, guard, "%s: %s" % (job, GUARD))
                same(KEEP_SCRIPT, keep, "%s: %s" % (job, KEEP))
                self.assertEqual(guard["env"], {"CACHE": cache, "AS_ROOT": root, "DISK_FLOOR_GB": "2"})
                self.assertEqual(keep["env"], {"CACHE": cache, "AS_ROOT": root, "DROP": MAIN_ONLY})
                # Both run on every event the job's tests run on, so a PR's run shows the figures;
                # only main drops anything.
                self.assertEqual(guard.get("if"), keep.get("if"))
                self.assertNotIn("refs/heads/main", str(keep.get("if")))
                self.assertIn(guard.get("if"), (None, "steps.scope.outputs.records != 'true'"))

    def test_the_copy_check_catches_an_edit(self):
        guard = [s for s in job_steps()["machines"] if s.get("name") == GUARD][0]
        same(GUARD_SCRIPT, guard, "machines")
        with self.assertRaises(AssertionError):
            same(GUARD_SCRIPT.replace("-ge", "-gt"), guard, "machines")


class ScriptsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.t = pathlib.Path(self.tmp.name)
        for d in ("bin", "temp", "home", "dmi"):
            (self.t / d).mkdir()
        df = self.t / "bin" / "df"
        df.write_text(FAKE_DF)
        df.chmod(0o755)
        self.cache = self.t / "home" / ".cache" / "go-build"

    def tearDown(self):
        self.tmp.cleanup()

    def run_copy(self, script, **env):
        e = {"PATH": "%s:%s" % (self.t / "bin", os.environ["PATH"]), "HOME": str(self.t / "home"),
             "RUNNER_TEMP": str(self.t / "temp"), "DMI_ID": str(self.t / "dmi"),
             "CACHE": "~/.cache/go-build", "AS_ROOT": "", "DISK_FLOOR_GB": "2", "DROP": "false"}
        e.update(env)
        r = subprocess.run(["bash", "-e", "-c", script], env=e, capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout + r.stderr

    def entry(self, name, size, age):
        p = self.cache / name[:2] / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"\0" * size)
        t = time.time() - age
        os.utime(p, (t, t))
        return p

    def test_guard_names_cloud_free_space_and_cache_size(self):
        (self.t / "bin" / "avail").write_text(str(20 * 1024 + 5))
        (self.t / "dmi" / "sys_vendor").write_text("Microsoft Corporation\n")
        self.entry("ab" + "0" * 62 + "-d", 3 * MB - 64 * 1024, 0)  # du rounds up, directories included
        rc, out = self.run_copy(GUARD_SCRIPT)
        self.assertEqual(rc, 0, out)
        self.assertIn("::notice title=runner disk::Azure runner: / has 20 GB free after restoring 3 MB of Go build cache", out)
        mark = os.stat(self.t / "temp" / "gocache.mark").st_mtime
        self.assertAlmostEqual(mark, time.time() - 3660, delta=30)

    def test_guard_stops_under_the_floor_with_its_figure(self):
        (self.t / "dmi" / "sys_vendor").write_text("Amazon EC2\n")
        for avail, rc_want in ((2 * 1024, 0), (2 * 1024 - 1, 1)):
            with self.subTest(avail):
                (self.t / "bin" / "avail").write_text(str(avail))
                rc, out = self.run_copy(GUARD_SCRIPT)
                self.assertEqual(rc, rc_want, out)
                if rc:
                    self.assertIn("::error title=runner disk::AWS runner: / has 1 GB free after restoring 0 MB of "
                                  "Go build cache, under the 2 GB floor", out)

    def test_guard_names_an_unknown_cloud(self):
        (self.t / "bin" / "avail").write_text("40000")
        rc, out = self.run_copy(GUARD_SCRIPT)
        self.assertEqual(rc, 0, out)
        self.assertIn("unknown-cloud (no DMI vendor) runner: / has 39 GB free after restoring 0 MB", out)

    def mark(self):
        m = self.t / "temp" / "gocache.mark"
        m.touch()
        t = time.time() - 3660
        os.utime(m, (t, t))

    def test_keep_measures_on_every_run_and_drops_only_when_asked(self):
        self.mark()
        used = self.entry("0a" + "1" * 62 + "-a", 2 * MB, 60)
        stale = self.entry("ff" + "2" * 62 + "-d", 5 * MB, 2 * 86400)
        trim = self.cache / "trim.txt"
        trim.write_text("0\n")
        os.utime(trim, (0, 0))
        fuzz = self.cache / "fuzz" / "pkg" / "corpus"
        fuzz.parent.mkdir(parents=True)
        fuzz.write_text("x")
        os.utime(fuzz, (0, 0))
        rc, out = self.run_copy(KEEP_SCRIPT)
        self.assertEqual(rc, 0, out)
        self.assertIn("::notice title=build cache::7 MB of Go build cache, 2 MB of it used by this run, 5 MB stale", out)
        self.assertTrue(stale.exists())
        rc, out = self.run_copy(KEEP_SCRIPT, DROP="true")
        self.assertEqual(rc, 0, out)
        self.assertIn("dropped the stale entries; 2 MB left to save", out)
        self.assertTrue(used.exists())
        self.assertFalse(stale.exists())
        # Only entries go: go's own files and the fuzz corpus (its own step) stay.
        self.assertTrue(trim.exists() and fuzz.exists())

    def test_keep_fails_without_the_mark_and_passes_with_no_cache(self):
        rc, out = self.run_copy(KEEP_SCRIPT, DROP="true")
        self.assertEqual(rc, 1, out)
        self.assertIn("::error title=build cache::no ", out)
        self.mark()
        rc, out = self.run_copy(KEEP_SCRIPT, DROP="true")
        self.assertEqual(rc, 0, out)
        self.assertIn("no Go build cache at %s" % self.cache, out)

    def test_go_keeps_what_it_used_and_rebuilds_only_what_it_did_not(self):
        # The assumption the keep step rests on (CI-disk-cause-1): go marks each cache entry it uses,
        # action and output alike, by its mtime once that is an hour old, so after the drop a package
        # this run built is still a cache hit and one it did not is compiled again.
        go = shutil.which("go")
        self.assertTrue(go, "go is not on PATH")
        mod = self.t / "mod"
        for pkg in ("used", "unused"):
            (mod / pkg).mkdir(parents=True)
            (mod / pkg / "p.go").write_text("package %s\n\nfunc F() int { return %d }\n" % (pkg, len(pkg)))
        (mod / "go.mod").write_text("module m\n\ngo 1.21\n")
        env = dict(os.environ, GOCACHE=str(self.cache), GOPATH=str(self.t / "gopath"), HOME=str(self.t / "home"),
                   GOTOOLCHAIN="local", GOFLAGS="", GOENV="off", GOWORK="off", GO111MODULE="on", GOTELEMETRY="off")

        def build(pkg):
            r = subprocess.run([go, "build", "-x", "./" + pkg], cwd=mod, env=env, capture_output=True, text=True,
                               timeout=300)
            self.assertEqual(r.returncode, 0, r.stderr)
            return "/compile " in r.stderr

        self.assertTrue(build("used") and build("unused"))
        old = time.time() - 2 * 86400
        for p in self.cache.rglob("*"):
            if p.is_file():
                os.utime(p, (old, old))
        self.mark()
        self.assertFalse(build("used"), "a cached package compiled again before the drop")
        rc, out = self.run_copy(KEEP_SCRIPT, DROP="true")
        self.assertEqual(rc, 0, out)
        self.assertFalse(build("used"), "the drop removed an entry this run used")
        self.assertTrue(build("unused"), "the drop kept an entry this run did not use")


if __name__ == "__main__":
    unittest.main()
