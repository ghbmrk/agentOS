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
import unittest.mock
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import canary  # noqa: E402

CONTROLS = [sys.executable, str(ROOT / "tools" / "canary_controls.py")]
# A target runs only in the uid sandbox (P3-4b-4c-canary-uid), which needs a
# subordinate id range: the dependency-audit and canary jobs grant one.
needs_sandbox = unittest.skipUnless(canary.confinement_available(), "needs the uid sandbox (tools/ASSUMPTIONS.md D13)")


def shared_dir(d):
    """A test directory a confined target (another uid) can write into."""
    os.chmod(d, 0o777)
    return d


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

    def test_decoded_bytes_and_decoded_fragments(self):
        self.assertEqual(sorted(canary.DECODABLE), ["bearer_token", "private_key", "session_cookie", "totp_seed"])
        for c in self.canaries:
            if c.kind not in canary.DECODABLE:
                self.assertIsNone(c.decoded)
                continue
            self.assertEqual(canary.decode(c.kind, c.value), c.decoded)
            self.assertIn(c.fingerprint, self.found(os.urandom(9) + c.decoded + os.urandom(9)), c.kind)
            self.assertIn(c.fingerprint, self.found(b"=" + c.decoded.hex().encode() + b"="), c.kind)
            self.assertIn(c.fingerprint, self.found(base64.b64encode(os.urandom(2) + c.decoded + os.urandom(3))), c.kind)
            for start in range(len(c.decoded) - canary.DECODED_WINDOW + 1):
                frag = c.decoded[start:start + canary.DECODED_WINDOW]
                self.assertIn(c.fingerprint, self.found(os.urandom(9) + frag + os.urandom(9)), (c.kind, start))
        self.assertLessEqual(canary.DECODED_WINDOW, 10)

    def test_case_variants_of_hex_and_base32(self):
        for c in self.canaries:
            if c.alphabet in (canary.HEX, canary.B32):
                for v in (c.core.upper(), c.core.lower()):
                    self.assertIn(c.fingerprint, self.found(b"<" + v.encode() + b">"), c.kind)
                    frag = v[5:5 + canary.WINDOW].encode()
                    self.assertIn(c.fingerprint, self.found(b"<" + frag + b">"), c.kind)

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

    @needs_sandbox
    def test_clean_target_has_no_hits(self):
        res = self.run_target("clean")
        self.assertEqual(res["outcome"], "clean")
        self.assertEqual(len(res["rounds"]), 2)

    @needs_sandbox
    def test_leaky_target_is_caught_for_every_kind(self):
        res = self.run_target("leaky")
        self.assertEqual(res["outcome"], "leak")
        for rnd in res["rounds"]:
            self.assertEqual(sorted({h["kind"] for h in rnd["hits"]}), sorted(canary.KINDS))

    @needs_sandbox
    def test_memory_leak_is_caught_through_the_sweeper(self):
        res = self.run_target("leaky-memory", rounds=1)
        self.assertEqual(res["outcome"], "leak")
        self.assertTrue(any("/mem" in h["location"] for h in res["rounds"][0]["hits"]))

    @needs_sandbox
    def test_stderr_is_a_scanned_surface(self):
        res = self.run_target("leaky-log", rounds=1)
        self.assertEqual(res["outcome"], "leak")
        self.assertTrue(all(h["location"] == "<stderr>" for h in res["rounds"][0]["hits"]))

    @needs_sandbox
    def test_each_round_uses_fresh_canaries(self):
        res = self.run_target("clean", rounds=3)
        fps = [tuple(r["canaries"]) for r in res["rounds"]]
        self.assertEqual(len(set(fps)), 3)

    @needs_sandbox
    def test_crashed_target_is_an_error_not_a_pass(self):
        self.assertEqual(self.run_target("crash", rounds=1)["outcome"], "error")

    @needs_sandbox
    def test_target_that_never_loads_the_plant_is_an_error(self):
        res = self.run_target("no-ack", rounds=1)
        self.assertEqual(res["outcome"], "error")
        self.assertEqual(res["rounds"][0]["errors"], ["no valid plant ack"])

    @needs_sandbox
    def test_partial_ack_is_an_error(self):
        self.assertEqual(self.run_target("partial-ack", rounds=1)["outcome"], "error")

    @needs_sandbox
    def test_empty_surface_is_an_error(self):
        res = self.run_target("empty-surface", rounds=1)
        self.assertEqual(res["rounds"][0]["errors"], ["empty surface"])

    @needs_sandbox
    def test_exhausted_scan_budget_is_an_error(self):
        target = {"name": "leaky", "cmd": CONTROLS + ["leaky"]}
        res = canary.run_target(target, rounds=1, max_bytes=64)
        self.assertEqual(res["outcome"], "error")
        self.assertTrue(any("budget" in e for e in res["rounds"][0]["errors"]))

    def test_exhausted_sweep_budget_raises(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            pathlib.Path(d, "f").write_bytes(b"x" * 100)
            with self.assertRaises(canary.SweepTruncated):
                canary.dump(pathlib.Path(out, "a"), roots=[d], max_bytes=50)
            self.assertEqual(canary.dump(pathlib.Path(out, "b"), roots=[d], max_bytes=100), 1)

    @needs_sandbox
    def test_decoded_only_leak_is_caught(self):
        res = self.run_target("leaky-decoded", rounds=1)
        self.assertEqual(res["outcome"], "leak")
        self.assertEqual(res["rounds"][0]["kinds_hit"], sorted(canary.DECODABLE))
        self.assertLessEqual(set(res["rounds"][0]["forms_hit"]), {"decoded", "decoded-fragment"})

    def test_controls_are_built_in(self):
        names = {t["name"] for t in canary.control_targets()}
        self.assertLessEqual({"control-clean", "control-leaky-files", "control-leaky-memory",
                              "control-leaky-decoded", "control-no-ack", "control-empty-surface"}, names)

    @needs_sandbox
    def test_report_never_contains_a_canary_value(self):
        with tempfile.TemporaryDirectory() as d:
            reg = pathlib.Path(d, "targets.json")
            reg.write_text(json.dumps({"targets": []}))
            out = pathlib.Path(d, "report.json")
            rc = canary.main(["run", "--targets", str(reg), "--rounds", "1", "--report", str(out)])
            self.assertEqual(rc, 0)
            report = json.loads(out.read_text())
            self.assertTrue(report["report_scanned_clean"])
            self.assertTrue(any(t["outcome"] == "leak" for t in report["targets"]))

    @needs_sandbox
    def test_registry_expectation_mismatch_fails_the_run(self):
        with tempfile.TemporaryDirectory() as d:
            reg = pathlib.Path(d, "targets.json")
            reg.write_text(json.dumps({"targets": [
                {"name": "leaky-real", "cmd": CONTROLS + ["leaky"]}]}))
            self.assertEqual(canary.main(["run", "--targets", str(reg), "--rounds", "1"]), 1)

    def test_registry_cannot_relax_a_product_target_or_add_controls(self):
        with tempfile.TemporaryDirectory() as d:
            reg = pathlib.Path(d, "targets.json")
            for t in ({"name": "x", "cmd": ["true"], "expect": "leak"},
                      {"name": "x", "cmd": ["true"], "expect": "error"},
                      {"name": "x", "cmd": ["true"], "control": True}):
                reg.write_text(json.dumps({"targets": [t]}))
                self.assertEqual(canary.main(["run", "--targets", str(reg), "--rounds", "1"]), 2, t)

    @needs_sandbox
    def test_shipped_registry_passes(self):
        self.assertEqual(canary.main(["run", "--targets", str(ROOT / "assurance" / "canary-targets.json"),
                                      "--rounds", "1"]), 0)


# REQ: LOOP-7, LOOP-9
class TargetEnvTest(unittest.TestCase):
    """P3-4b-4c-canary requirement 1 (#515 Security 2): a target gets PATH,
    a scratch HOME and TMPDIR, the CANARY_* variables, and only the parent
    variables its registry entry names from a fixed allow-list."""

    SECRET = "AGENTOS_TEST_PARENT_SECRET"

    def seen_env(self, target_env=None, parent=None):
        with tempfile.TemporaryDirectory() as d:
            dumped = pathlib.Path(shared_dir(d), "env.json")
            target = {"name": "env-dump", "cmd": CONTROLS + ["env-dump", str(dumped)]}
            if target_env is not None:
                target["env"] = target_env
            synthetic = canary.mint("api_key").value
            extra = {self.SECRET: synthetic, "GOCACHE": "/synthetic/gocache"}
            extra.update(parent or {})
            with unittest.mock.patch.dict(os.environ, extra):
                res = canary.run_target(target, rounds=1)
            self.assertEqual(res["outcome"], "clean", res["rounds"][0]["errors"])
            return json.loads(dumped.read_text()), synthetic

    @needs_sandbox
    def test_a_parent_secret_never_reaches_a_target(self):
        env, synthetic = self.seen_env()
        self.assertNotIn(self.SECRET, env)
        self.assertNotIn(synthetic, json.dumps(env))

    @needs_sandbox
    def test_a_target_sees_only_the_minimal_environment(self):
        env, _ = self.seen_env()
        # A Python target may add LC_CTYPE itself when it starts in the C
        # locale (PEP 538); the harness never passes it.
        env.pop("LC_CTYPE", None)
        self.assertEqual(set(env), {"PATH", "HOME", "TMPDIR", "GOTOOLCHAIN", "CANARY_PLANT", "CANARY_ACK",
                                    "CANARY_SURFACE_DIR"})
        self.assertEqual(env["PATH"], os.environ["PATH"])
        self.assertEqual(env["HOME"], env["TMPDIR"])
        self.assertNotEqual(env["HOME"], os.environ.get("HOME"))
        self.assertTrue(pathlib.Path(env["HOME"]).name.startswith("canary-home-"))
        self.assertFalse(pathlib.Path(env["HOME"]).exists(), "scratch home outlives the round")

    @needs_sandbox
    def test_each_round_gets_a_fresh_scratch_home(self):
        homes = []
        with tempfile.TemporaryDirectory() as d:
            shared_dir(d)
            for i in range(2):
                dumped = pathlib.Path(d, "env%d.json" % i)
                canary.run_target({"name": "env-dump", "cmd": CONTROLS + ["env-dump", str(dumped)]}, rounds=1)
                homes.append(json.loads(dumped.read_text())["HOME"])
        self.assertNotEqual(homes[0], homes[1])

    @needs_sandbox
    def test_a_named_variable_comes_from_the_parent(self):
        env, _ = self.seen_env(target_env=["GOFLAGS"], parent={"GOFLAGS": "-mod=vendor"})
        self.assertEqual(env["GOFLAGS"], "-mod=vendor")
        # The parent's GOCACHE (seen_env sets one) is not passed: it is not named, and no entry may name it.
        self.assertNotIn("GOCACHE", env)
        self.assertNotIn(self.SECRET, env)
        with unittest.mock.patch.dict(os.environ):
            os.environ.pop("GOFLAGS", None)
            env, _ = self.seen_env(target_env=["GOFLAGS"])
        self.assertNotIn("GOFLAGS", env, "a name the parent does not set stays unset")

    def test_an_entry_naming_gotoolchain_or_gocache_is_refused(self):
        # canary-env-r1 (#583 Security re-sign): GOTOOLCHAIN from the parent can be
        # auto (a toolchain download), and GOCACHE=off breaks every round.
        self.assertEqual(canary.TARGET_ENV_ALLOWED, frozenset({"GOFLAGS"}))
        with tempfile.TemporaryDirectory() as d:
            reg = pathlib.Path(d, "targets.json")
            for env in (["GOTOOLCHAIN"], ["GOCACHE"], ["GOFLAGS", "GOTOOLCHAIN"]):
                reg.write_text(json.dumps({"targets": [{"name": "t", "cmd": CONTROLS + ["clean"], "env": env}]}))
                with self.assertRaises(ValueError, msg=env):
                    canary.load_registry(reg)

    def test_gotoolchain_stays_local_past_the_allow_list(self):
        # The second layer: GOTOOLCHAIN=local is set after the parent's values, so
        # even an allow-list that let the name through could not undo it.
        target = {"name": "t", "env": ["GOTOOLCHAIN", "GOFLAGS"]}
        with unittest.mock.patch.object(canary, "TARGET_ENV_ALLOWED", frozenset({"GOTOOLCHAIN", "GOFLAGS"})), \
                unittest.mock.patch.dict(os.environ, {"GOTOOLCHAIN": "auto", "GOFLAGS": "-mod=vendor"}):
            env = canary.target_env(target, "/scratch")
        self.assertEqual(env["GOTOOLCHAIN"], "local")
        self.assertEqual(env["GOFLAGS"], "-mod=vendor", "the bypass did apply the parent's values")

    def test_a_name_outside_the_allow_list_is_refused_at_load(self):
        with tempfile.TemporaryDirectory() as d:
            reg = pathlib.Path(d, "targets.json")
            for env in ([self.SECRET], ["HOME"], ["PATH"], ["CANARY_PLANT"], ["LD_PRELOAD"],
                        "GOFLAGS", [["GOFLAGS"]], [{"GOFLAGS": "/x"}], ["GOFLAGS=/x"]):
                reg.write_text(json.dumps({"targets": [{"name": "t", "cmd": CONTROLS + ["clean"], "env": env}]}))
                with self.assertRaises(ValueError, msg=env):
                    canary.load_registry(reg)
                self.assertEqual(canary.main(["run", "--targets", str(reg), "--rounds", "1"]), 2, env)

    def test_the_shipped_registry_names_only_allowed_variables(self):
        for t in canary.load_registry(ROOT / "assurance" / "canary-targets.json"):
            self.assertLessEqual(set(t.get("env", [])), canary.TARGET_ENV_ALLOWED)

    @needs_sandbox
    def test_shipped_targets_never_get_a_cache_go_refuses(self):
        # Security 4a on #583, point 1: probecmd starts the harness with
        # GOCACHE=off, under which `go test` refuses to build, so a shipped
        # target must not take GOCACHE from the parent.
        for t in canary.load_registry(ROOT / "assurance" / "canary-targets.json"):
            env, _ = self.seen_env(target_env=t.get("env", []), parent={"GOCACHE": "off"})
            self.assertNotIn("GOCACHE", env, t["name"])

    @needs_sandbox
    def test_a_target_never_fetches_a_go_toolchain(self):
        # Security 4a on #583, point 2: GOTOOLCHAIN=local, so a round never
        # downloads the toolchain go.mod names into its scratch home.
        with unittest.mock.patch.dict(os.environ, {"GOTOOLCHAIN": "auto"}):
            env, _ = self.seen_env()
        self.assertEqual(env["GOTOOLCHAIN"], "local")

    @needs_sandbox
    def test_controls_get_the_minimal_environment_too(self):
        with unittest.mock.patch.dict(os.environ, {self.SECRET: canary.mint("api_key").value}):
            self.assertEqual(canary.run_target(canary.control_targets()[0], rounds=1)["outcome"], "clean")


# REQ: LOOP-7
class ConfinementTest(unittest.TestCase):
    """P3-4b-4c-canary-uid requirement 3 (#583 L3 point 2): a target runs as a
    subordinate uid in its own user and PID namespace, so it cannot read the
    harness's /proc entries or its HOME, and a sandbox that cannot start never
    runs the target."""

    SECRET = "AGENTOS_TEST_HARNESS_SECRET"

    def probe(self, *args):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(shared_dir(d), "probe.json")
            target = {"name": "probe", "cmd": CONTROLS + [args[0], str(out)] + list(args[1:])}
            synthetic = canary.mint("api_key").value
            with unittest.mock.patch.dict(os.environ, {self.SECRET: synthetic}):
                res = canary.run_target(target, rounds=1)
            self.assertEqual(res["outcome"], "clean", res["rounds"][0]["errors"])
            text = out.read_text()
        self.assertNotIn(synthetic, text)
        return json.loads(text)

    @needs_sandbox
    def test_a_target_cannot_read_the_harness_environ(self):
        seen = self.probe("parent-environ")
        self.assertIn(seen["result"], ("EACCES", "empty"), seen)
        self.assertNotEqual(seen["uid"], os.getuid(), "the target ran as the harness's uid")

    @needs_sandbox
    def test_a_target_cannot_read_a_private_file_in_the_harness_home(self):
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as open_home:
            os.chmod(open_home, 0o755)  # only the file's own 0600 stands in the way
            for d in (home, open_home):
                planted = pathlib.Path(d, ".netrc")
                fd = os.open(planted, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(canary.mint("password").value)
                with unittest.mock.patch.dict(os.environ, {"HOME": d}):
                    seen = self.probe("read-file", str(planted))
                self.assertEqual(seen["result"], "EACCES", (d, seen))

    @needs_sandbox
    def test_the_confinement_control_is_built_in(self):
        [t] = [t for t in canary.control_targets() if t["name"] == "control-confined"]
        res = canary.run_target(t, rounds=1)
        self.assertEqual(res["outcome"], "clean", res["rounds"][0]["errors"])

    @needs_sandbox
    def test_a_round_runs_when_the_harness_tmpdir_is_private(self):
        # probecmd starts the harness with TMPDIR in a Go test's 0700 t.TempDir,
        # which the target's uid cannot search: round directories go to ROUND_DIR.
        with tempfile.TemporaryDirectory() as private, unittest.mock.patch.object(tempfile, "tempdir", private):
            os.chmod(private, 0o700)
            res = canary.run_target(canary.control_targets()[0], rounds=1)
        self.assertEqual(res["outcome"], "clean", res["rounds"][0]["errors"])

    @needs_sandbox
    def test_a_target_that_outlives_its_timeout_is_an_error(self):
        res = canary.run_target({"name": "hang", "cmd": ["sleep", "30"]}, rounds=1, timeout=2)
        self.assertEqual(res["outcome"], "error")
        self.assertIn("exit timeout", res["rounds"][0]["errors"])

    def test_a_sandbox_that_cannot_start_never_runs_the_target(self):
        for broken in (unittest.mock.patch.object(canary.depaudit, "_unshare_flags",
                                                  side_effect=OSError("no subordinate range")),
                       unittest.mock.patch.object(canary.depaudit, "_unshare_flags",
                                                  return_value=["--no-such-unshare-flag"])):
            with tempfile.TemporaryDirectory() as d, broken:
                dumped = pathlib.Path(shared_dir(d), "env.json")
                res = canary.run_target({"name": "env-dump", "cmd": CONTROLS + ["env-dump", str(dumped)]}, rounds=1)
                self.assertFalse(dumped.exists(), "the target ran outside the sandbox")
            self.assertEqual(res["outcome"], "error")
            self.assertTrue(any("sandbox" in e for e in res["rounds"][0]["errors"]), res["rounds"][0]["errors"])


# REQ: LOOP-7
class RoundTest(unittest.TestCase):
    """P3-4b-4a: the scheduled round Loop 2's canary probe runs. One round
    per target with fresh canaries; a leak is a High finding, a failed
    control makes the whole round an error, and no canary value is output."""

    def round(self, targets, controls=None):
        minted = []
        real_mint = canary.mint

        def mint(kind):
            c = real_mint(kind)
            minted.append(c.value)
            return c
        with tempfile.TemporaryDirectory() as d, \
                unittest.mock.patch.object(canary, "mint", mint), \
                unittest.mock.patch.object(canary, "control_targets",
                                           controls or canary.control_targets):
            reg = pathlib.Path(d, "targets.json")
            reg.write_text(json.dumps({"targets": targets}))
            out = pathlib.Path(d, "round.json")
            rc = canary.main(["round", "--targets", str(reg), "--out", str(out)])
            text = out.read_text() if out.exists() else ""
        for v in minted:
            self.assertNotIn(v, text)
        return rc, json.loads(text) if text else None

    @needs_sandbox
    def test_a_leaking_target_is_a_high_finding(self):
        contain = {"kind": "grant", "name": "G4", "label": "pre-allowance G4"}
        rc, out = self.round([{"name": "planted-leak", "cmd": CONTROLS + ["leaky"], "contain": contain}])
        self.assertEqual(rc, 0)
        self.assertEqual(out["check"], "canary")
        self.assertEqual(out["checked"], ["planted-leak"])
        self.assertEqual(out["errors"], [])
        [f] = out["findings"]
        self.assertEqual((f["check"], f["subject"], f["severity"], f["contain"]),
                         ("canary", "planted-leak", "high", contain))
        self.assertIn("api_key", f["detail"])

    @needs_sandbox
    def test_a_clean_round_reports_nothing(self):
        rc, out = self.round([{"name": "quiet", "cmd": CONTROLS + ["clean"]}])
        self.assertEqual(rc, 0)
        self.assertEqual((out["findings"], out["checked"], out["errors"]), ([], ["quiet"], []))

    @needs_sandbox
    def test_a_target_error_is_not_checked(self):
        rc, out = self.round([{"name": "broken", "cmd": CONTROLS + ["crash"]},
                              {"name": "quiet", "cmd": CONTROLS + ["clean"]}])
        self.assertEqual(rc, 1)
        self.assertEqual(out["checked"], ["quiet"])
        self.assertEqual(out["findings"], [])
        self.assertEqual(len(out["errors"]), 1)
        self.assertTrue(out["errors"][0].startswith("broken: "))

    @needs_sandbox
    def test_a_leak_from_a_target_that_also_errored_is_kept(self):
        # P3-4b-4c-canary requirement 2 (#515 Security 5): a crash after a
        # leak does not hide it; the round still closes nothing for it.
        contain = {"kind": "executor", "name": "browser", "label": "the browser"}
        rc, out = self.round([{"name": "leak-then-crash", "cmd": CONTROLS + ["leaky-crash"], "contain": contain},
                              {"name": "quiet", "cmd": CONTROLS + ["clean"]}])
        self.assertEqual(rc, 1)
        self.assertEqual(out["checked"], ["quiet"])
        [f] = out["findings"]
        self.assertEqual((f["check"], f["subject"], f["severity"], f["contain"]),
                         ("canary", "leak-then-crash", "high", contain))
        self.assertEqual(f["detail"], "kinds: " + ", ".join(sorted(canary.KINDS)))
        [e] = out["errors"]
        self.assertTrue(e.startswith("leak-then-crash: "), e)
        self.assertIn("exit 3", e)

    @needs_sandbox
    def test_an_errored_target_without_hits_has_no_finding(self):
        rc, out = self.round([{"name": "broken", "cmd": CONTROLS + ["crash"]}])
        self.assertEqual((rc, out["findings"], out["checked"]), (1, [], []))

    @needs_sandbox
    def test_a_failed_control_makes_the_round_an_error(self):
        blind = [{"name": "control-blind", "cmd": CONTROLS + ["clean"], "expect": "leak",
                  "kinds": list(canary.KINDS), "forms": None, "why": None, "control": True}]
        rc, out = self.round([{"name": "planted-leak", "cmd": CONTROLS + ["leaky"]}], controls=lambda: blind)
        self.assertEqual(rc, 1)
        self.assertEqual((out["findings"], out["checked"]), ([], []))
        self.assertTrue(out["errors"][0].startswith("control control-blind: "))

    def test_registry_contain_must_be_well_formed(self):
        for contain in ({"kind": "machine", "name": "x"}, {"kind": "grant"}, {"kind": "grant", "name": "G1", "x": 1}):
            rc, out = self.round([{"name": "t", "cmd": CONTROLS + ["clean"], "contain": contain}])
            self.assertEqual(rc, 2, contain)
            self.assertIsNone(out)


if __name__ == "__main__":
    unittest.main()
