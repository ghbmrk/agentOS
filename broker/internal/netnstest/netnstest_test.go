package netnstest

import (
	"errors"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func combined(env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = env
	return cmd.CombinedOutput()
}

func TestJudge(t *testing.T) {
	const name = "TestX"
	pass := "=== RUN   TestX\n--- PASS: TestX (0.01s)\nPASS\n"
	skip := "=== RUN   TestX\n    x_test.go:9: no netlink socket here\n--- SKIP: TestX (0.00s)\nPASS\n"
	subSkip := "=== RUN   TestX\n=== RUN   TestX/a\n--- PASS: TestX (0.00s)\n    --- SKIP: TestX/a (0.00s)\nPASS\n"
	for _, c := range []struct {
		what     string
		name     string
		out      string
		err      error
		required bool
		skipped  bool
		fails    string
	}{
		{what: "a pass", out: pass},
		{what: "a pass, required", out: pass, required: true},
		{what: "a skip, required", out: skip, required: true, fails: "--- SKIP: TestX (0.00s)"},
		{what: "a subtest's skip, required", out: subSkip, required: true, fails: "--- SKIP: TestX/a"},
		{what: "a skip", out: skip, skipped: true},
		{what: "a subtest's skip", out: subSkip, skipped: true},
		{what: "no test ran", out: "testing: warning: no tests to run\nPASS\n", fails: "did not report TestX as passing"},
		{what: "another test passed", out: "--- PASS: TestXY (0.00s)\nPASS\n", fails: "did not report TestX as passing"},
		{what: "a subtest's pass, by its name", name: "TestX/a", out: "=== RUN   TestX/a\n    --- PASS: TestX/a (0.00s)\n--- PASS: TestX (0.00s)\nPASS\n"},
		{what: "a failed run", out: "--- FAIL: TestX (0.00s)\n", err: errors.New("exit status 1"), fails: "netns run failed"},
	} {
		n := name
		if c.name != "" {
			n = c.name
		}
		skipped, err := judge(n, []byte(c.out), c.err, c.required)
		switch {
		case c.fails != "":
			if err == nil || !strings.Contains(err.Error(), c.fails) {
				t.Errorf("%s: got %v, want an error naming %q", c.what, err, c.fails)
			}
		case err != nil:
			t.Errorf("%s: %v", c.what, err)
		case (skipped != "") != c.skipped:
			t.Errorf("%s: skipped %q, want a skip: %v", c.what, skipped, c.skipped)
		}
	}
}

const (
	childEnv   = "AGENTOS_NETNSTEST_NETNS"
	fixtureEnv = "AGENTOS_NETNSTEST_FIXTURE"
)

// TestFixture is run only by TestChildSkipFailsParent, as a separate test
// binary process; it then passes or skips inside the namespace.
func TestFixture(t *testing.T) {
	mode := os.Getenv(fixtureEnv)
	if mode == "" {
		return
	}
	var tools []string
	if mode == "missing" {
		tools = []string{"agentos-no-such-tool"}
	}
	if !Run(t, childEnv, combined, tools...) {
		return
	}
	if mode == "skip" {
		t.Skip("no netlink socket here")
	}
}

// TestChildSkipFailsParent (#5112): a skip inside the namespaced run
// fails the parent test under CI=1 and skips it elsewhere, so the forged
// netlink tests cannot pass with their assertions not run.
func TestChildSkipFailsParent(t *testing.T) {
	if os.Getenv(fixtureEnv) != "" {
		return
	}
	if err := exec.Command("unshare", "-rn", "true").Run(); err != nil {
		missing(t, "no unprivileged user namespaces: %v", err)
	}
	var base []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CI=") && !strings.HasPrefix(kv, "AGENTOS_REQUIRE_NETNS=") && !strings.HasPrefix(kv, childEnv+"=") {
			base = append(base, kv)
		}
	}
	for _, c := range []struct {
		mode, ci string
		fails    bool
		want     string
		at       string // what the failure or skip says, named at the fixture's own line
	}{
		{"skip", "CI=1", true, "--- FAIL: TestFixture", "the namespaced run skipped"},
		{"skip", "", false, "--- SKIP: TestFixture", "skipped in the namespace"},
		{"pass", "CI=1", false, "--- PASS: TestFixture", ""},
		{"missing", "", false, "--- SKIP: TestFixture", "agentos-no-such-tool missing"},
	} {
		env := append(append([]string{}, base...), fixtureEnv+"="+c.mode)
		if c.ci != "" {
			env = append(env, c.ci)
		}
		out, err := combined(env, os.Args[0], "-test.run", "^TestFixture$", "-test.count=1", "-test.v")
		var exit *exec.ExitError
		if failed := errors.As(err, &exit); failed != c.fails || (err != nil && !failed) {
			t.Errorf("%s %q: exit %v, want failure %v\n%s", c.mode, c.ci, err, c.fails, out)
		}
		if !strings.Contains(string(out), c.want) {
			t.Errorf("%s %q: output lacks %q\n%s", c.mode, c.ci, c.want, out)
		}
		// The parent logs the namespaced run's own output, and a failure or
		// skip names the calling test's line, not the helper's (#5152).
		if c.mode != "missing" && !strings.Contains(string(out), "in a fresh namespace (unshare -rn):") {
			t.Errorf("%s %q: the namespaced run's output is not logged\n%s", c.mode, c.ci, out)
		}
		if c.at != "" && !regexp.MustCompile(`netnstest_test\.go:\d+: `+regexp.QuoteMeta(c.at)).Match(out) {
			t.Errorf("%s %q: %q is not named at the fixture's line\n%s", c.mode, c.ci, c.at, out)
		}
		if c.fails && !strings.Contains(string(out), "CI requires them") {
			t.Errorf("%s %q: the failure does not say why\n%s", c.mode, c.ci, out)
		}
	}
}

// TestOnPathSkipsEmptyEntries (#5152): an empty PATH entry, at either end
// or doubled (::), is not read as the working directory, so a tool there
// does not count; a listed directory's executable file does, and a file
// without an execute bit, a directory or a missing name does not.
func TestOnPathSkipsEmptyEntries(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "tool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "plain"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(bin, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	t.Chdir(bin)
	for _, c := range []struct {
		path, name string
		want       bool
	}{
		{bin, "tool", true},
		{other + ":" + bin, "tool", true},
		{bin, "plain", false},
		{bin, "dir", false},
		{bin, "absent", false},
		{"", "tool", false},
		{":" + other, "tool", false},
		{other + ":", "tool", false},
		{other + "::" + other, "tool", false},
	} {
		t.Setenv("PATH", c.path)
		if got := onPath(c.name); got != c.want {
			t.Errorf("PATH %q, cwd holding it: onPath(%q) = %v, want %v", c.path, c.name, got, c.want)
		}
	}
}

// TestRunAsArgs: Ready probes unshare with the caller's flags, RunAs runs
// the test again under the same flags with childEnv=1, and Run's flags are
// -rn; in the child both return true at once. A missing tool or a refused
// probe skips the test outside CI.
func TestRunAsArgs(t *testing.T) {
	const env = "AGENTOS_NETNSTEST_ARGS"
	bin := t.TempDir()
	for _, n := range []string{"unshare", "nft"} {
		if err := os.WriteFile(filepath.Join(bin, n), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	t.Setenv("CI", "")
	t.Setenv("AGENTOS_REQUIRE_NETNS", "")
	t.Setenv(env, "")
	var calls [][]string
	fake := func(probe error) Exec {
		return func(e []string, name string, args ...string) ([]byte, error) {
			calls = append(calls, append([]string{name}, args...))
			if args[len(args)-1] == "true" {
				return []byte("probe output"), probe
			}
			if !slices.Contains(e, env+"=1") {
				t.Errorf("the child's environment lacks %s=1", env)
			}
			return []byte("--- PASS: " + strings.TrimSuffix(strings.TrimPrefix(args[slices.Index(args, "-test.run")+1], "^"), "$") + " (0.00s)\n"), nil
		}
	}
	sub := func(name string, f func(t *testing.T)) (skipped bool) {
		t.Run(name, func(t *testing.T) {
			defer func() { skipped = t.Skipped() }()
			f(t)
		})
		return skipped
	}
	if sub("flags", func(t *testing.T) {
		calls = nil
		if RunAs(t, env, fake(nil), []string{"--map-root-user", "--map-auto"}, "nft") {
			t.Error("the parent reported itself the child")
		}
		want := [][]string{
			{"unshare", "--map-root-user", "--map-auto", "true"},
			{"unshare", "--map-root-user", "--map-auto", "--", os.Args[0], "-test.run", "^" + t.Name() + "$", "-test.count=1", "-test.v"},
		}
		if !slices.EqualFunc(calls, want, slices.Equal) {
			t.Errorf("calls %q, want %q", calls, want)
		}
	}) {
		t.Error("RunAs skipped with every tool there")
	}
	if sub("rn", func(t *testing.T) {
		calls = nil
		if Run(t, env, fake(nil)) {
			t.Error("the parent reported itself the child")
		}
		if len(calls) != 2 || !slices.Equal(calls[0], []string{"unshare", "-rn", "true"}) || !slices.Equal(calls[1][:3], []string{"unshare", "-rn", "--"}) {
			t.Errorf("calls %q, want unshare -rn", calls)
		}
	}) {
		t.Error("Run skipped with every tool there")
	}
	if !sub("tool missing", func(t *testing.T) { Ready(t, fake(nil), []string{"-rn"}, "nft", "ip") }) {
		t.Error("Ready did not skip with ip missing")
	}
	if !sub("probe refused", func(t *testing.T) { Ready(t, fake(errors.New("exit status 1")), []string{"-rn"}) }) {
		t.Error("Ready did not skip with the probe refused")
	}
	t.Setenv(env, "1")
	calls = nil
	if !Run(t, env, fake(nil)) || !RunAs(t, env, fake(nil), []string{"-r"}) || len(calls) != 0 {
		t.Errorf("in the child: calls %q, want none and true", calls)
	}
}

// TestOnlyTestsImportTheHelper (#5152): netnstest is written for tests, so
// no non-test Go file under broker/ imports it, under any build tag; a
// production importer would link test machinery into a binary.
func TestOnlyTestsImportTheHelper(t *testing.T) {
	const self = "github.com/ghbmrk/agentos/broker/internal/netnstest"
	importers, err := nonTestImporters("../..", self)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range importers {
		t.Errorf("%s imports %s; import it only from _test.go files", f, self)
	}
	// The scan sees a tagged non-test importer and a raw-string import, and
	// not a test one or one under testdata.
	dir := t.TempDir()
	for name, text := range map[string]string{
		"a/a.go":          "//go:build agentos_x\n\npackage a\n\nimport _ \"example.test/m/netnstest\"\n",
		"c/c.go":          "package c\n\nimport _ `example.test/m/netnstest`\n",
		"b/b_test.go":     "package b\n\nimport _ \"example.test/m/netnstest\"\n",
		"d/testdata/d.go": "package d\n\nimport _ \"example.test/m/netnstest\"\n",
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := nonTestImporters(dir, "example.test/m/netnstest")
	if err != nil || len(got) != 2 || !strings.HasSuffix(got[0], "a/a.go") || !strings.HasSuffix(got[1], "c/c.go") {
		t.Fatalf("synthetic: got %q, %v, want a/a.go and the raw-string c/c.go", got, err)
	}
}

// nonTestImporters lists the non-test Go files under root, vendor,
// testdata and dot directories aside, that import self.
func nonTestImporters(root, self string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "vendor" || n == "testdata" || strings.HasPrefix(n, ".") && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, im := range f.Imports {
			if path, err := strconv.Unquote(im.Path.Value); err != nil || path == self {
				found = append(found, p)
			}
		}
		return nil
	})
	return found, err
}
