package netnstest

import (
	"errors"
	"os"
	"os/exec"
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
	if !Run(t, childEnv, combined) {
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
	}{
		{"skip", "CI=1", true, "--- FAIL: TestFixture"},
		{"skip", "", false, "--- SKIP: TestFixture"},
		{"pass", "CI=1", false, "--- PASS: TestFixture"},
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
		if c.fails && !strings.Contains(string(out), "CI requires them") {
			t.Errorf("%s %q: the failure does not say why\n%s", c.mode, c.ci, out)
		}
	}
}
