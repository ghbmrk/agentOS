# P1-6 canary harness (spec A5). Tests the harness itself: minting, detection
# power across encodings, the root sweeper, and the target runner. Makes no
# coverage claim for CRED-1–7 / ARC-1: those are claimed by the packages whose
# targets pass this harness (vault P1-3, browser executor P2-6).
import base64
import json
import os
import pathlib
import random
import subprocess
import sys
import tempfile
import unittest
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import canary  # noqa: E402

CONTROLS = [sys.executable, str(ROOT / "tools" / "canary_controls.py")]


def b64_embedded(value, prefix_len, alphabet="std"):
    data = os.urandom(prefix_len) + value.encode() + os.urandom(7)
    enc = base64.b64encode if alphabet == "std" else base64.urlsafe_b64encode
    return enc(data)


class MintTest(unittest.TestCase):
    def test_every_kind_mints_fresh_high_entropy_values(self):
        for kind in canary.KINDS:
            a, b = canary.mint(kind), canary.mint(kind)
            self.assertEqual(a.kind, kind)
            self.assertNotEqual(a.value, b.value)
            self.assertNotEqual(a.fingerprint, b.fingerprint)
            shown = a.value.replace("-", "") if kind == "recovery_code" else a.value
            self.assertIn(a.core, shown)
            self.assertGreaterEqual(a.entropy_bits, 128, kind)

    def test_mint_set_covers_all_kinds(self):
        self.assertEqual(sorted(c.kind for c in canary.mint_set()), sorted(canary.KINDS))

    def test_fingerprint_does_not_reveal_value(self):
        c = canary.mint("api_key")
        self.assertNotIn(c.fingerprint, c.value)
        self.assertNotIn(c.core[:8], c.fingerprint)


class DetectorTest(unittest.TestCase):
    def setUp(self):
        self.canaries = canary.mint_set()
        self.det = canary.Detector(self.canaries)

    def found(self, data):
        return {h.fingerprint for h in self.det.scan_bytes(data, "t")}

    def assert_each_found(self, encode):
        for c in self.canaries:
            data = os.urandom(33) + encode(c) + os.urandom(17)
            self.assertIn(c.fingerprint, self.found(data), (c.kind, encode))

    def test_raw(self):
        self.assert_each_found(lambda c: c.value.encode())

    def test_hex_both_cases(self):
        self.assert_each_found(lambda c: c.value.encode().hex().encode())
        self.assert_each_found(lambda c: c.value.encode().hex().upper().encode())

    def test_url_encoded(self):
        self.assert_each_found(lambda c: urllib.parse.quote(c.value, safe="").encode())

    def test_utf16(self):
        self.assert_each_found(lambda c: c.value.encode("utf-16-le"))
        self.assert_each_found(lambda c: c.value.encode("utf-16-be"))

    def test_base64_inside_larger_blob_at_every_alignment(self):
        for prefix in range(6):
            for alphabet in ("std", "url"):
                self.assert_each_found(lambda c: b64_embedded(c.value, prefix, alphabet))

    def test_partial_leak_of_core(self):
        for c in self.canaries:
            for start in (0, len(c.core) // 3, len(c.core) - canary.WINDOW):
                frag = c.core[start:start + canary.WINDOW].encode()
                self.assertIn(c.fingerprint, self.found(b"..." + frag + b"..."), c.kind)

    def test_hits_report_form_and_offset_without_value(self):
        c = self.canaries[0]
        data = b"x" * 10 + c.value.encode().hex().encode()
        hits = self.det.scan_bytes(data, "f")
        self.assertTrue(any(h.form == "hex" and h.offset == 10 for h in hits))
        self.assertNotIn(c.value, json.dumps([h._asdict() for h in hits]))

    def test_stream_scan_catches_value_split_at_every_boundary(self):
        c = self.canaries[0]
        data = os.urandom(50) + c.value.encode() + os.urandom(50)
        for cut in range(40, 50 + len(c.value) + 10):
            chunks = iter([data[:cut], data[cut:]])
            hits = self.det.scan_stream(chunks, "s")
            self.assertIn(c.fingerprint, {h.fingerprint for h in hits}, cut)

    def test_no_false_positives_on_random_data_or_other_runs(self):
        rnd = random.Random(1).randbytes(1 << 20)
        other = b"".join(c.value.encode() for c in canary.mint_set())
        self.assertEqual(self.det.scan_bytes(rnd + other, "r"), [])


class SweepTest(unittest.TestCase):
    """The root adversary: whatever a model-directed root process could read."""

    def test_memory_only_secret_is_surfaced(self):
        c = canary.mint("bearer_token")
        # The child gets the value on stdin, so it lives only in its memory.
        child = subprocess.Popen(
            [sys.executable, "-c",
             "import sys,time; v=sys.stdin.readline().strip(); held=v*1; "
             "print('ready', flush=True); time.sleep(30)"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            child.stdin.write(c.value + "\n")
            child.stdin.flush()
            self.assertEqual(child.stdout.readline().strip(), "ready")
            det = canary.Detector([c])
            hits = [h for loc, chunks in canary.sweep(pids=[child.pid])
                    for h in det.scan_stream(chunks, loc)]
        finally:
            child.kill()
            child.communicate()
        self.assertTrue(any("/mem" in h.location for h in hits), hits)

    def test_environment_and_files_are_surfaced(self):
        c = canary.mint("api_key")
        with tempfile.TemporaryDirectory() as d:
            pathlib.Path(d, "nested").mkdir()
            pathlib.Path(d, "nested", "cfg.json").write_text(json.dumps({"k": c.value}))
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                                     env={**os.environ, "LEAKED": c.value})
            try:
                det = canary.Detector([c])
                locs = {h.location for loc, chunks in canary.sweep(roots=[d], pids=[child.pid])
                        for h in det.scan_stream(chunks, loc)}
            finally:
                child.kill()
                child.wait()
        self.assertTrue(any(l.endswith("cfg.json") for l in locs), locs)
        self.assertTrue(any(l.endswith("/environ") for l in locs), locs)


class RunnerTest(unittest.TestCase):
    def run_target(self, mode, rounds=2):
        target = {"name": mode, "cmd": CONTROLS + [mode]}
        return canary.run_target(target, rounds=rounds)

    def test_clean_target_has_no_hits(self):
        res = self.run_target("clean")
        self.assertEqual(res["outcome"], "clean")
        self.assertEqual(len(res["rounds"]), 2)

    def test_leaky_target_is_caught_for_every_kind(self):
        res = self.run_target("leaky")
        self.assertEqual(res["outcome"], "leak")
        for rnd in res["rounds"]:
            self.assertEqual(sorted({h["kind"] for h in rnd["hits"]}), sorted(canary.KINDS))

    def test_memory_leak_is_caught_through_the_sweeper(self):
        res = self.run_target("leaky-memory", rounds=1)
        self.assertEqual(res["outcome"], "leak")
        self.assertTrue(any("/mem" in h["location"] for h in res["rounds"][0]["hits"]))

    def test_stderr_is_a_scanned_surface(self):
        res = self.run_target("leaky-log", rounds=1)
        self.assertEqual(res["outcome"], "leak")
        self.assertTrue(all(h["location"] == "<stderr>" for h in res["rounds"][0]["hits"]))

    def test_each_round_uses_fresh_canaries(self):
        res = self.run_target("clean", rounds=3)
        fps = [tuple(r["canaries"]) for r in res["rounds"]]
        self.assertEqual(len(set(fps)), 3)

    def test_crashed_target_is_an_error_not_a_pass(self):
        self.assertEqual(self.run_target("crash", rounds=1)["outcome"], "error")

    def test_report_never_contains_a_canary_value(self):
        with tempfile.TemporaryDirectory() as d:
            reg = pathlib.Path(d, "targets.json")
            reg.write_text(json.dumps({"targets": [
                {"name": "leaky", "cmd": CONTROLS + ["leaky"], "expect": "leak", "control": True}]}))
            out = pathlib.Path(d, "report.json")
            rc = canary.main(["run", "--targets", str(reg), "--rounds", "1", "--report", str(out)])
            self.assertEqual(rc, 0)
            report = json.loads(out.read_text())
            self.assertTrue(report["report_scanned_clean"])

    def test_registry_expectation_mismatch_fails_the_run(self):
        with tempfile.TemporaryDirectory() as d:
            reg = pathlib.Path(d, "targets.json")
            reg.write_text(json.dumps({"targets": [
                {"name": "leaky-real", "cmd": CONTROLS + ["leaky"]}]}))
            self.assertEqual(canary.main(["run", "--targets", str(reg), "--rounds", "1"]), 1)

    def test_shipped_registry_passes(self):
        self.assertEqual(canary.main(["run", "--targets", str(ROOT / "assurance" / "canary-targets.json"),
                                      "--rounds", "1"]), 0)


if __name__ == "__main__":
    unittest.main()
