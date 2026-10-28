"""Tests for tools/root_tests.py: every root-gated Go test runs in a root CI step (CI-root-go, #3539),
one whose skip or failure fails CI (CI-root-go-2, #3541).

No SPEC requirement IDs: CI tooling (issues #3539, #3541). All data is synthetic.
"""
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import root_tests  # noqa: E402

M = root_tests.MODULE
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text()

HELPERS = """package p

func needRoot(t *testing.T) {
\tt.Helper()
\tif os.Geteuid() != 0 {
\t\tt.Skip("needs root")
\t}
}

func rig(t *testing.T) *r {
\tneedRoot(t)
\treturn &r{}
}

func TestMain(m *testing.M) {
\trig(nil)
}

func TestThroughTwoHelpers(t *testing.T) {
\tr := rig(t)
\t_ = r
}

func TestDirect(t *testing.T) {
\tif bin == "" || os.Geteuid() != 0 {
\t\tt.Skipf("needs root and %s", "runsc")
\t}
}

func TestReturnsEarly(t *testing.T) {
\tcheck(t)
\tif os.Geteuid() != 0 {
\t\tt.Log("not root: the rest needs root")
\t\treturn
\t}
}

func TestInASubtest(t *testing.T) {
\tt.Run("x", func(t *testing.T) {
\t\tif os.Geteuid() != 0 {
\t\t\tt.Skip("needs root")
\t\t}
\t})
}

func TestBranchesOnly(t *testing.T) {
\tif os.Geteuid() != 0 {
\t\tcases["EACCES"] = func() {}
\t}
}

func TestSkipsAsRoot(t *testing.T) {
\tif os.Geteuid() == 0 {
\t\tt.Skip("root bypasses permissions")
\t}
}

func TestGetuidSkips(t *testing.T) {
\tif os.Getuid() != 0 {
\t\tt.Skip("mounting needs root")
\t}
}

func TestBranchesThenSkipsAsRoot(t *testing.T) {
\tif os.Geteuid() != 0 && err != nil {
\t\tt.Fatal(err)
\t}
\tplainOnly(t)
}

func plainOnly(t *testing.T) {
\tif os.Geteuid() == 0 {
\t\tt.Skip("the kernel never runs as root")
\t}
}

func TestComparesUIDsOnly(t *testing.T) {
\tif k, err := read(os.Geteuid()); err != nil || uid != os.Geteuid() {
\t\tt.Fatal(k)
\t}
}

func TestPlain(t *testing.T) {
\tcheck(t)
}
"""


def tree(files):
    d = tempfile.TemporaryDirectory()
    for rel, text in files.items():
        p = pathlib.Path(d.name) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return d


K = f"{M}/owner/kernelsock"
STEPS = f"""      - name: Machine tests as root
        run: |
          rc=0
          sudo setpriv --no-new-privs env "PATH=$PATH" \\
            go test -count=1 -json ./cgroup ./vm/... ./recovery > /tmp/m.json || rc=$?
          python3 -I ../tools/require_ran.py --named-skips-only --gated ./vm/... ./recovery < /tmp/m.json || exit 1
          [ "$rc" -eq 0 ]
          sudo env "PATH=$PATH" go test -count=1 -json -run '^(TestA|TestB)$' \\
            ./owner/kernelsock > /tmp/k.json || rc=$?
          python3 -I ../tools/require_ran.py < /tmp/k.json \\
            {K}.TestA {K}.TestB
      - name: Not root
        run: go test -count=1 ./clerk/run
      - name: Root-gated Go tests no other step runs (CI-root-go, #3539)
        run: |
          python3 -I ../tools/root_tests.py --plan > "$RUNNER_TEMP/root-plan"
          sudo env go test -json -run "$pat" "$pkg" > out.json
          python3 -I ../tools/require_ran.py $names < out.json
      - name: After
        run: true
"""


def runs_of(*lines, keys=""):
    body = "".join(f"          {line}\n" for line in lines)
    return root_tests.root_runs("      - name: x\n" + keys + "        run: |\n" + body)


GO = "sudo env go test -count=1 -json ./owner/kernelsock > /tmp/x.json || rc=$?"
NAMED = f"python3 -I ../tools/require_ran.py < /tmp/x.json {K}.TestA"
COVERS = [(["./owner/kernelsock"], None, frozenset({f"{K}.TestA"}), ())]


class GatedTest(unittest.TestCase):
    def test_finds_skips_and_returns_through_helpers(self):
        with tree({"p/p_test.go": HELPERS, "p/p.go": "package p\n"}) as d:
            found = root_tests.gated(d)
        # #3541 (L3 on #3540): a test that branches on the uid has root-only checks and counts too;
        # one that also skips as root, or only passes the uid along, does not.
        self.assertEqual(found, {f"{M}/p": ["TestBranchesOnly", "TestDirect", "TestGetuidSkips", "TestInASubtest",
                                            "TestReturnsEarly", "TestThroughTwoHelpers"]})

    def test_vendor_testdata_and_root_package(self):
        gate = "package x\n\nfunc TestR(t *testing.T) {\n\tif os.Geteuid() != 0 {\n\t\tt.SkipNow()\n\t}\n}\n"
        with tree({"x_test.go": gate, "vendor/v/v_test.go": gate, "a/testdata/t_test.go": gate}) as d:
            self.assertEqual(root_tests.gated(d), {M: ["TestR"]})

    def test_helpers_across_files_of_a_package(self):
        with tree({"q/a_test.go": "package q\n\nfunc TestX(t *testing.T) {\n\tneedRoot(t)\n}\n",
                   "q/b_test.go": HELPERS.replace("package p", "package q")}) as d:
            self.assertIn("TestX", root_tests.gated(d)[f"{M}/q"])


class RunsTest(unittest.TestCase):
    def test_reads_root_go_test_lines(self):
        self.assertEqual(root_tests.root_runs(STEPS), [
            (["./cgroup", "./vm/...", "./recovery"], None, frozenset(), ("./vm/...", "./recovery")),
            (["./owner/kernelsock"], "^(TestA|TestB)$", frozenset({f"{K}.TestA", f"{K}.TestB"}), ()),
        ])

    def test_a_named_root_run_covers(self):
        self.assertEqual(runs_of(GO, NAMED), COVERS)
        self.assertEqual(runs_of(GO, NAMED + " || exit 1", '[ "$rc" -eq 0 ]'), COVERS)

    def test_a_run_whose_skip_cannot_fail_ci_covers_nothing(self):
        # #3541: each of these lets a root-gated test skip or fail while the step stays green.
        cases = {
            "-v, no require_ran": [GO.replace(" > /tmp/x.json || rc=$?", "")],
            "no require_ran": [GO],
            "|| true on require_ran": [GO, NAMED + " || true"],
            "|| fail=1, never checked": [GO, NAMED + " || fail=1"],
            "&& after require_ran": [GO, NAMED + " && echo ok"],
            "require_ran in a pipe": [GO, NAMED + " | tee log"],
            "require_ran reads another file": [GO, NAMED.replace("/tmp/x.json", "/tmp/y.json")],
            "the file is rewritten first": [GO, "sudo env go test ./clerk > /tmp/x.json", NAMED],
            "require_ran not run as a command": [GO, "true " + NAMED],
            "another script reads the file": [GO, NAMED.replace("require_ran.py", "summary.py")],
            "require_ran reads another file, named as an argument":
                [GO, NAMED.replace("< /tmp/x.json", "< /tmp/y.json /tmp/x.json")],
            "under an if": ["if [ -n \"$X\" ]; then", GO, NAMED, "fi"],
            "exit 0 earlier": ["[ -n \"$X\" ] || exit 0", GO, NAMED],
            "set +e": ["set +e", GO, NAMED],
            "in the background": [GO + " &", NAMED],
            "commented out": ["# " + GO, NAMED],
            "the test is not named": [GO, NAMED.replace(".TestA", ".TestOther")],
        }
        for why, lines in cases.items():
            runs = runs_of(*lines)
            self.assertFalse(root_tests.covered(K, "TestA", runs), why)

    def test_a_step_that_can_skip_or_pass_on_failure_covers_nothing(self):
        for keys in ("        if: github.event_name == 'push'\n", "        continue-on-error: true\n",
                     "        shell: bash {0}\n"):
            self.assertEqual(runs_of(GO, NAMED, keys=keys), [], keys)
        self.assertEqual(runs_of(GO, NAMED, keys="        working-directory: broker\n"), COVERS)

    def test_comments_cover_nothing(self):
        # #3540 Security review: a commented-out root step must not count as running its package.
        for line in ("# " + GO, "true # " + GO):
            self.assertEqual(runs_of(line, NAMED), [], line)
        self.assertEqual(runs_of(GO + " # b", NAMED + " # c"), COVERS)
        yaml_comment = "      - name: x\n        # " + GO + "\n        run: |\n          " + NAMED + "\n"
        self.assertEqual(root_tests.root_runs(yaml_comment), [])

    def test_covered(self):
        runs = root_tests.root_runs(STEPS)
        self.assertTrue(root_tests.covered(f"{M}/vm/gvisor", "TestAny", runs))
        self.assertTrue(root_tests.covered(f"{M}/vm", "TestAny", runs))
        self.assertTrue(root_tests.covered(f"{M}/recovery", "TestAny", runs))
        self.assertFalse(root_tests.covered(f"{M}/cgroup", "TestAny", runs), "run, but require_ran does not name it")
        self.assertFalse(root_tests.covered(f"{M}/vmx", "TestAny", runs))
        self.assertTrue(root_tests.covered(K, "TestB", runs))
        self.assertFalse(root_tests.covered(K, "TestBackups", runs))
        self.assertFalse(root_tests.covered(f"{M}/clerk/run", "TestAny", runs))
        self.assertFalse(root_tests.covered(f"{M}/recovery/sub", "TestAny", runs))

    def test_generated_step(self):
        self.assertTrue(root_tests.generated_step(STEPS))
        self.assertFalse(root_tests.generated_step(STEPS.replace("require_ran.py $names", "cat")))
        self.assertFalse(root_tests.generated_step(STEPS.replace("sudo env go", "env go")))
        self.assertFalse(root_tests.generated_step(STEPS.replace("Root-gated Go tests", "Other")))


class CheckTest(unittest.TestCase):
    FOUND = {K: ["TestA", "TestEdgeEnroll"], f"{M}/vm/gvisor": ["TestG"]}

    def test_a_gated_test_no_step_names_fails_without_the_generated_step(self):
        runs = root_tests.root_runs(STEPS)
        self.assertEqual(root_tests.problems(self.FOUND, runs, False, {}),
                         [f"{M}/owner/kernelsock.TestEdgeEnroll: root-gated, and no root step in ci.yml runs it"])
        self.assertEqual(root_tests.problems(self.FOUND, runs, False, {f"{M}/owner/kernelsock.TestEdgeEnroll": "no TPM"}), [])

    def test_the_generated_step_runs_what_no_step_names(self):
        runs = root_tests.root_runs(STEPS)
        self.assertEqual(root_tests.plan(self.FOUND, runs, {}),
                         [(f"{M}/owner/kernelsock", "^(TestEdgeEnroll)$", ["TestEdgeEnroll"])])
        self.assertEqual(root_tests.plan(self.FOUND, runs, {f"{M}/owner/kernelsock.TestEdgeEnroll": "x"}), [])
        self.assertEqual(root_tests.problems(self.FOUND, runs, True, {}), [])

    def test_stale_or_unexplained_exemptions_fail(self):
        runs = root_tests.root_runs(STEPS)
        self.assertEqual(root_tests.problems(self.FOUND, runs, True, {f"{M}/gone.TestX": "why"}),
                         [f"{M}/gone.TestX: EXEMPT names no root-gated test"])
        self.assertEqual(root_tests.problems(self.FOUND, runs, True, {f"{M}/vm/gvisor.TestG": " "}),
                         [f"{M}/vm/gvisor.TestG: EXEMPT gives no reason"])


class RepoTest(unittest.TestCase):
    """The real tree and ci.yml: the #3536 gap stays closed."""

    def test_repo_passes(self):
        self.assertEqual(root_tests.main([]), 0)
        self.assertTrue(root_tests.generated_step(CI))

    def test_kernelsock_root_tests_run_as_root(self):
        # #3536: owner/kernelsock's wire tests skip off root; every one of them must be in a root step.
        found, runs = root_tests.gated(), root_tests.root_runs(CI)
        ks = found.get(f"{M}/owner/kernelsock", [])
        self.assertIn("TestCertifyReachesTheKernel", ks)
        planned = {t for _, _, ts in root_tests.plan(found, runs) for t in ts}
        for t in ks:
            self.assertTrue(t in planned or root_tests.covered(f"{M}/owner/kernelsock", t, runs), t)

    def test_without_the_generated_step_the_check_fails(self):
        cut = CI.replace("Root-gated Go tests", "Some other step")
        found, runs = root_tests.gated(), root_tests.root_runs(cut)
        probs = root_tests.problems(found, runs, root_tests.generated_step(cut))
        self.assertIn(f"{M}/owner/kernelsock.TestCertifyReachesTheKernel: root-gated, and no root step in ci.yml runs it", probs)

    def test_every_root_step_names_what_it_covers(self):
        # #3541: each root run ci.yml counts is read back through require_ran.py, so a skip there fails.
        runs = root_tests.root_runs(CI)
        pkgs = {p for ps, _, _, _ in runs for p in ps}
        self.assertTrue({"./vm/...", "./recovery", "./floor", "./infer/...", "./e2e"} <= pkgs, pkgs)
        found = root_tests.gated()
        for p, ts in found.items():
            for t in ts:
                if root_tests.covered(p, t, runs):
                    continue
                self.assertIn((p, t), {(q, u) for q, _, us in root_tests.plan(found, runs) for u in us}, t)

    def test_unlock_capability_check_runs_as_root(self):
        # L3 on #3540: TestNoCapsSeesCapabilities branches on Geteuid() and checks root's capabilities.
        found = root_tests.gated()
        self.assertIn("TestNoCapsSeesCapabilities", found[f"{M}/cmd/agentos-unlock"])
        self.assertIn("TestTheDropRefusesRootAndChecksItTook", found[f"{M}/cmd/agentos-unlock"])
        self.assertIn("TestUnreadableOwnedMarkerCountsAsOwned", found[f"{M}/cmd/agentos-ap"])

    def test_root_skipping_tests_are_left_to_the_non_root_jobs(self):
        # The reverse gap: a test that skips as root must not be pulled into the root step.
        planned = {t for _, _, ts in root_tests.plan(root_tests.gated(), root_tests.root_runs(CI)) for t in ts}
        self.assertNotIn("TestAnOwnerUIDThatCannotBeTakenSendsNothing", planned)
        self.assertFalse(any(t == "TestMain" for t in planned))


if __name__ == "__main__":
    unittest.main()
