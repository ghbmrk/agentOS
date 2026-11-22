"""vision-real.yml fetches ONNX Runtime from its pinned NuGet package and checks both pins (row #6446).

No requirement IDs: CI tooling, not SPEC.md behaviour (VIS-A27). The workflow's download step is
run as written, against a stand-in pin file and a stand-in `curl` that serves local files, so the
test shows the step takes the package, its member path and both hashes from the pin file, and that
a package or library off its pin stops the run with nothing installed.
"""
import hashlib
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "vision-real.yml"
PINS = ROOT / "broker" / "cmd" / "agentos-vision" / "models.pins"
STEP = "- name: Download the pinned runtime and models, check each hash"
LIB = "libonnxruntime.so.1.29.0"
REVIEWED_LIB = "5715f06d8992ca8eeeddcce43df3a7d38f97d537052126f558e912cb312460ca"
NUGET = "https://api.nuget.org/v3-flatcontainer/microsoft.ml.onnxruntime/1.29.0/"
MODELS = ("yolox_tiny.onnx", "face_detection_yunet_2023mar.onnx", "face_recognition_sface_2021dec.onnx",
          "yolo-v9-t-416-license-plates-end2end.onnx", "cct_xs_v2_global.onnx", "yamnet.onnx")

# Stands in for curl: `curl <flags> -o OUT URL` copies $SERVE/<last path part of URL> to OUT.
CURL = """#!/bin/sh
out=; url=
while [ $# -gt 0 ]; do
  case "$1" in -o) out=$2; shift 2;; --retry|--retry-delay) shift 2;; -*) shift;; *) url=$1; shift;; esac
done
cp "$SERVE/${url##*/}" "$out"
"""


def _step():
    """The run script of the workflow's runtime download step, dedented."""
    lines = WORKFLOW.read_text().splitlines()
    start = next(n for n, l in enumerate(lines) if l.strip() == STEP)
    run = start + 1
    assert lines[run].strip() == "run: |", lines[run]
    body = []
    for l in lines[run + 1:]:
        if l.strip() and len(l) - len(l.lstrip()) <= len(lines[run]) - len(lines[run].lstrip()):
            break
        body.append(l)
    col = min(len(l) - len(l.lstrip()) for l in body if l.strip())
    return "\n".join(l[col:] for l in body) + "\n"


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _pins():
    return [l.split() for l in PINS.read_text().splitlines() if l.strip() and not l.startswith("#")]


class ShippedPins(unittest.TestCase):
    def test_library_is_the_reviewed_one_from_the_nuget_package(self):
        rows = {r[1]: r for r in _pins()}
        lib = rows[LIB]
        self.assertEqual(lib[0], REVIEWED_LIB)
        pkg, _, member = lib[2].partition(":")
        self.assertEqual(member, "runtimes/linux-x64/native/libonnxruntime.so")
        self.assertEqual(rows[pkg][2], NUGET + pkg)
        self.assertRegex(rows[pkg][0], r"^[0-9a-f]{64}$")
        self.assertFalse([r for r in rows if r.endswith(".whl") or r.endswith(".tgz")], "one runtime source only")


class DownloadStep(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.serve = self.tmp / "serve"
        bindir = self.tmp / "bin"
        for d in (self.serve, bindir, self.tmp / "runner", self.tmp / "ws" / PINS.parent.relative_to(ROOT)):
            d.mkdir(parents=True)
        (bindir / "curl").write_text(CURL)
        (bindir / "curl").chmod(stat.S_IRWXU)
        self.env = dict(os.environ, PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}", SERVE=str(self.serve),
                        RUNNER_TEMP=str(self.tmp / "runner"), GITHUB_ENV=str(self.tmp / "github_env"))
        # The package name and member path differ from the shipped ones: the step must read them.
        self.member, self.lib = "lib/x/stand-in.so", b"stand-in runtime library"
        with zipfile.ZipFile(self.serve / "stand-in.nupkg", "w") as z:
            z.writestr(self.member, self.lib)
            z.writestr("other/file", b"not taken")
        self.rows = {"stand-in.nupkg": [_sha((self.serve / "stand-in.nupkg").read_bytes()), "https://pkg.invalid/stand-in.nupkg"],
                     LIB: [_sha(self.lib), "stand-in.nupkg:" + self.member]}
        for m in MODELS:
            (self.serve / m).write_bytes(m.encode())
            self.rows[m] = [_sha(m.encode()), "https://models.invalid/" + m]

    def run_step(self):
        pins = self.tmp / "ws" / PINS.relative_to(ROOT)
        pins.write_text("# stand-in\n" + "".join(f"{h}  {f}  {src}\n" for f, (h, src) in self.rows.items()))
        r = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", _step()], cwd=self.tmp / "ws",
                           env=self.env, capture_output=True, text=True, timeout=120)
        return r, self.tmp / "runner" / "vision-models" / LIB

    def test_both_pins_match_installs_the_library(self):
        r, lib = self.run_step()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(lib.read_bytes(), self.lib)

    def test_changed_package_fails_before_extracting(self):
        with zipfile.ZipFile(self.serve / "stand-in.nupkg", "a") as z:
            z.writestr("extra", b"one more file")
        r, lib = self.run_step()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("stand-in.nupkg hashes to", r.stdout)
        self.assertFalse(lib.exists())

    def test_changed_library_pin_fails(self):
        self.rows[LIB][0] = REVIEWED_LIB
        r, lib = self.run_step()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(f"{LIB} hashes to {_sha(self.lib)}, pinned {REVIEWED_LIB}", r.stdout)

    def test_changed_package_pin_fails(self):
        self.rows["stand-in.nupkg"][0] = "0" * 64
        r, lib = self.run_step()
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(lib.exists())

    def test_unpinned_package_fails(self):
        del self.rows["stand-in.nupkg"]
        r, lib = self.run_step()
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(lib.exists())

    def test_library_pin_without_a_member_fails(self):
        self.rows[LIB][1] = "stand-in.nupkg"
        r, lib = self.run_step()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("names no package:member", r.stdout)
        self.assertFalse(lib.exists())


if __name__ == "__main__":
    unittest.main()
