"""Tests for tools/root_tests.py: every root-gated Go test runs in a root CI step (CI-root-go, #3539),
one whose skip or failure fails CI (CI-root-go-2, #3541), and every go command of the generated step
under no_new_privs (CI-root-go-4, #3571).

No SPEC requirement IDs: CI tooling (issues #3539, #3541, #3549, #3571, #3572). All data is synthetic.
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
            {K}.TestA {K}.TestB || exit 1
      - name: Not root
        run: go test -count=1 ./clerk/run
      - name: Root-gated Go tests no other step runs (CI-root-go, #3539)
        run: |
          python3 -I ../tools/root_tests.py --plan > "$RUNNER_TEMP/root-plan"
          sudo setpriv --no-new-privs env go test -json -run "$pat" "$pkg" \\
            > out.json
          python3 -I ../tools/require_ran.py $names < out.json
      - name: After
        run: true
"""


def runs_of(*lines, keys=""):
    body = "".join(f"          {line}\n" for line in lines)
    return root_tests.root_runs("      - name: x\n" + keys + "        run: |\n" + body)


GO = "sudo env go test -count=1 -json ./owner/kernelsock > /tmp/x.json || rc=$?"
NAMED = f"python3 -I ../tools/require_ran.py < /tmp/x.json {K}.TestA || exit 1"
BARE = NAMED.replace(" || exit 1", "")
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

    def test_a_test_both_gated_and_root_skipping_is_reported(self):
        # #3549: calls match by bare name, so a method named like a root-gated helper that skips as
        # root drops the test from both kinds of job; it is reported, not dropped.
        collide = ("package c\n\nfunc setup(t *testing.T) {\n\tneedRoot(t)\n}\n\n"
                   "func (h *h) setup() {\n\tif os.Geteuid() == 0 {\n\t\th.t.Skip(\"as root\")\n\t}\n}\n\n"
                   "func TestCollides(t *testing.T) {\n\tsetup(t)\n}\n")
        mixed = {}
        with tree({"c/c_test.go": collide + HELPERS.replace("package p", "")}) as d:
            found = root_tests.gated(d, mixed)
        self.assertNotIn("TestCollides", found[f"{M}/c"])
        self.assertEqual(mixed, {f"{M}/c": ["TestBranchesThenSkipsAsRoot", "TestCollides"]})
        self.assertEqual(root_tests.problems(found, [], True, {}, mixed), [
            f"{M}/c.TestBranchesThenSkipsAsRoot: root-gated, and skips as root, so no CI job runs all of it",
            f"{M}/c.TestCollides: root-gated, and skips as root, so no CI job runs all of it"])
        why = {f"{M}/c.TestCollides": "x", f"{M}/c.TestBranchesThenSkipsAsRoot": "y"}
        self.assertEqual(root_tests.problems(found, [], True, why, mixed), [])


class RunsTest(unittest.TestCase):
    def test_reads_root_go_test_lines(self):
        self.assertEqual(root_tests.root_runs(STEPS), [
            (["./cgroup", "./vm/...", "./recovery"], None, frozenset(), ("./vm/...", "./recovery")),
            (["./owner/kernelsock"], "^(TestA|TestB)$", frozenset({f"{K}.TestA", f"{K}.TestB"}), ()),
        ])

    def test_a_named_root_run_covers(self):
        self.assertEqual(runs_of(GO, NAMED), COVERS)
        self.assertEqual(runs_of(GO, NAMED, '[ "$rc" -eq 0 ]'), COVERS)
        # `|| exit 1` ends the step whatever errexit's state, so turning it off loses nothing.
        self.assertEqual(runs_of("set +o errexit", GO, NAMED, "true"), COVERS)

    def test_a_run_whose_skip_cannot_fail_ci_covers_nothing(self):
        # #3541: each of these lets a root-gated test skip or fail while the step stays green.
        cases = {
            "-v, no require_ran": [GO.replace(" > /tmp/x.json || rc=$?", "")],
            "no require_ran": [GO],
            "|| true on require_ran": [GO, BARE + " || true"],
            "|| fail=1, never checked": [GO, BARE + " || fail=1"],
            "&& after require_ran": [GO, BARE + " && echo ok"],
            "require_ran in a pipe": [GO, BARE + " | tee log"],
            # #3546 L3: without `|| exit 1`, errexit decides, and it can be turned off many ways.
            "no || exit 1": [GO, BARE],
            "no || exit 1, set +e": ["set +e", GO, BARE, "true"],
            "no || exit 1, set +eu": ["set +eu", GO, BARE, "true"],
            "no || exit 1, set -u +e": ["set -u +e", GO, BARE, "true"],
            "no || exit 1, set +o errexit": ["set +o errexit", GO, BARE, "true"],
            "no || exit 1, shopt": ["shopt -u -o errexit", GO, BARE, "true"],
            "|| exit 0": [GO, BARE + " || exit 0"],
            "|| exit 1 in a subshell": [GO, "( " + NAMED + " )"],
            "a trap": ["trap 'exit 0' EXIT", GO, NAMED],
            "a trap later": [GO, NAMED, "trap 'exit 0' EXIT"],
            "exit 00": [GO, NAMED, "exit 00"],
            "return 0 in a function": ["f() {", GO, NAMED, "return 0", "}", "f"],
            "a function keyword": ["function f {", GO, NAMED, "}", "f"],
            "a function called with || true": ["f() {", GO, NAMED, "}", "f || true"],
            "require_ran reads another file": [GO, NAMED.replace("/tmp/x.json", "/tmp/y.json")],
            "the file is rewritten first": [GO, "sudo env go test ./clerk > /tmp/x.json", NAMED],
            "require_ran not run as a command": [GO, "true " + NAMED],
            "another script reads the file": [GO, NAMED.replace("require_ran.py", "summary.py")],
            "a name after || exit 1": [GO, NAMED + " x"],
            "require_ran reads another file, named as an argument":
                [GO, NAMED.replace("< /tmp/x.json", "< /tmp/y.json /tmp/x.json")],
            "under an if": ["if [ -n \"$X\" ]; then", GO, NAMED, "fi"],
            "exit 0 earlier": ["[ -n \"$X\" ] || exit 0", GO, NAMED],
            "&& after || exit 1": [GO, NAMED + " && false"],
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
        self.assertEqual(root_tests.step_faults(STEPS), [])
        self.assertIsNone(root_tests.step_faults(STEPS.replace("Root-gated Go tests", "Other")))
        self.assertFalse(root_tests.generated_step(STEPS.replace("require_ran.py $names", "cat")))
        self.assertFalse(root_tests.generated_step(STEPS.replace("sudo setpriv --no-new-privs env go", "env go")))
        # #3542: as agentosd.service runs (NoNewPrivileges=yes; L7-6), so a uid change that works
        # only as plain root fails CI.
        self.assertFalse(root_tests.generated_step(STEPS.replace("setpriv --no-new-privs ", "")))
        self.assertFalse(root_tests.generated_step(STEPS.replace("--no-new-privs", "--reuid=0")))
        self.assertFalse(root_tests.generated_step(STEPS.replace(
            "          python3 -I ../tools/require_ran.py $names",
            "          sudo env go test -run x ./y > o.json\n          python3 -I ../tools/require_ran.py $names")))
        self.assertFalse(root_tests.generated_step(STEPS.replace("Root-gated Go tests", "Other")))
        # Comments never run, and a guarded line may keep its tail across a continuation.
        self.assertTrue(root_tests.generated_step(STEPS.replace(
            "          python3 -I ../tools/require_ran.py $names", "          # sudo env go test ./y\n"
            "          python3 -I ../tools/require_ran.py $names")))

    GUARDED = "sudo setpriv --no-new-privs env go"

    def test_each_simple_command_of_the_generated_step_runs_go_with_no_new_privs(self):
        # #3571: the guard reads each simple command, not the line's first words.
        for op in (";", "&&", "||", "|", "&", ";;", "|&", "\\\n            ;"):
            with self.subTest(op=op):
                self.assertFalse(root_tests.generated_step(STEPS.replace(
                    self.GUARDED, f"sudo setpriv --no-new-privs true {op} sudo env go")))
        self.assertFalse(root_tests.generated_step(STEPS.replace(
            "\n          python3 -I ../tools/require_ran.py $names",
            "\n          sudo setpriv --no-new-privs true#; sudo env go test ./y > o.json"
            "\n          python3 -I ../tools/require_ran.py $names")), "# inside a word starts no comment")
        self.assertFalse(root_tests.generated_step(STEPS.replace(
            self.GUARDED, "sudo setpriv --no-new-privs true; (sudo env go")))

    def test_a_respelled_go_needs_no_new_privs_too(self):
        # #3571: a go test without the literal `go test` is still a go command.
        plain = "\n          sudo env {} -run x ./y > o.json\n"
        for go in ("go  test", "\"go\" test", "g\\o test", "/usr/local/go/bin/go test", "$GO test",
                   '"${GO}" test', "sh -c 'go test'", "eval \"$CMD\"", "x=$(sudo env go test ./y)",
                   "x=`go test ./y`", "cat <(go test ./y)"):
            with self.subTest(go=go):
                cut = STEPS.replace("\n          python3 -I ../tools/require_ran.py $names", plain.format(go)
                                    + "          python3 -I ../tools/require_ran.py $names")
                self.assertFalse(root_tests.generated_step(cut), cut)
        # An expansion is in command position after a keyword, an assignment or a redirection.
        for go in ("! $GO test ./y", "do $GO test ./y", "GOFLAGS=x $GO test ./y", "2> e.log $GO test ./y"):
            with self.subTest(go=go):
                cut = STEPS.replace("\n          python3 -I ../tools/require_ran.py $names", f"\n          {go}\n"
                                    + "          python3 -I ../tools/require_ran.py $names")
                self.assertFalse(root_tests.generated_step(cut), cut)
        self.assertFalse(root_tests.generated_step(STEPS.replace(
            "-run \"$pat\"", "-run \"$pat")), "a line the check cannot read fails")

    def test_a_lost_wrapper_is_named(self):
        # #3572: the problem names the missing prefix, not every generated-step test as unrun.
        cut = STEPS.replace(self.GUARDED, "sudo env go")
        found = {K: ["TestEdgeEnroll"]}
        probs = root_tests.check(found, root_tests.root_runs(cut), cut, {})
        self.assertEqual(len(probs), 1, probs)
        self.assertIn("`sudo env go test -json", probs[0])
        self.assertIn("without `sudo setpriv --no-new-privs`", probs[0])
        cut = STEPS.replace("Root-gated Go tests", "Other")
        self.assertEqual(root_tests.check(found, root_tests.root_runs(cut), cut, {}),
                         [f"{K}.TestEdgeEnroll: root-gated, and no root step in ci.yml runs it"])


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
        self.assertEqual(root_tests.step_faults(CI), [])
        mixed = {}
        root_tests.gated(mixed=mixed)
        self.assertEqual(mixed, {})

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

    def test_root_skipping_tests_are_left_to_the_non_root_jobs(self):
        # The reverse gap: a test that skips as root must not be pulled into the root step.
        planned = {t for _, _, ts in root_tests.plan(root_tests.gated(), root_tests.root_runs(CI)) for t in ts}
        self.assertNotIn("TestAnOwnerUIDThatCannotBeTakenSendsNothing", planned)
        self.assertFalse(any(t == "TestMain" for t in planned))


if __name__ == "__main__":
    unittest.main()
