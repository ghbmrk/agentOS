// Package netnstest runs a test again as root of a fresh user and network
// namespace (unshare -rn) and judges that run, for the enforcer's tests
// that need the kernel's network as the enforcer has it (ENF-netns-skip-fu,
// #5112). In CI (Required) a missing tool or namespace fails the test, and
// so does a skip inside the namespaced run: its exit status alone would
// read as a pass with the assertions not run. Only test code imports it.
//
// It launches nothing itself: the caller passes an Exec, so the package
// reaches neither os/exec nor a launcher (childproc's gate) and adds no
// import to the enforcer's packages (broker/daemon/arc2_test.go).
package netnstest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Exec runs name with args and the environment env and returns its
// combined output, as exec.Cmd.CombinedOutput does.
type Exec func(env []string, name string, args ...string) ([]byte, error)

// Required is true in CI, where a missing tool or kernel feature fails a
// test instead of skipping it.
func Required() bool {
	return os.Getenv("CI") != "" || os.Getenv("AGENTOS_REQUIRE_NETNS") == "1"
}

// Run reports whether this is the namespaced run of the calling test. If
// it is not, Run checks that unshare and tools are on the path and that a
// user namespace can be made, runs the test again under unshare -rn with
// childEnv=1 set, and returns false once that run passed. A failed run
// fails t, and so does a skip in it when Required; otherwise a skip there
// skips t.
func Run(t *testing.T, childEnv string, run Exec, tools ...string) bool {
	t.Helper()
	return RunAs(t, childEnv, run, []string{"-rn"}, tools...)
}

// RunAs is Run with unshare's namespace flags given, for a test that needs
// another namespace than a fresh user and network one (radio/ble's maps
// the runner's subordinate ids and keeps the network).
func RunAs(t *testing.T, childEnv string, run Exec, flags []string, tools ...string) bool {
	t.Helper()
	if os.Getenv(childEnv) == "1" {
		return true
	}
	Ready(t, run, flags, tools...)
	args := append(append(append([]string{}, flags...), "--", os.Args[0]), "-test.run", "^"+t.Name()+"$", "-test.count=1", "-test.v")
	out, err := run(append(os.Environ(), childEnv+"=1"), "unshare", args...)
	t.Logf("in a fresh namespace (unshare %s):\n%s", strings.Join(flags, " "), out)
	skipped, err := judge(t.Name(), out, err, Required())
	switch {
	case err != nil:
		t.Fatal(err)
	case skipped != "":
		t.Skipf("skipped in the namespace: %s", skipped)
	}
	return false
}

// Ready checks that unshare and tools are on the path and that unshare
// with flags can make its namespaces. If not, it fails t when Required
// and skips it otherwise; it returns only when all are there.
func Ready(t *testing.T, run Exec, flags []string, tools ...string) {
	t.Helper()
	for _, tool := range append([]string{"unshare"}, tools...) {
		if !onPath(tool) {
			missing(t, "%s missing", tool)
		}
	}
	if out, err := run(os.Environ(), "unshare", append(append([]string{}, flags...), "true")...); err != nil {
		missing(t, "unshare %s cannot make its namespaces: %v\n%s", strings.Join(flags, " "), err, out)
	}
}

// judge reads the namespaced run of test name. It returns an error when
// the run failed, did not report name as passing, or (when required)
// skipped anything; otherwise the skip lines, if the run skipped.
func judge(name string, out []byte, runErr error, required bool) (string, error) {
	if runErr != nil {
		return "", fmt.Errorf("netns run failed: %v", runErr)
	}
	var skips []string
	passed := false
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "--- SKIP: ") {
			skips = append(skips, trimmed)
		}
		if strings.HasPrefix(trimmed, "--- PASS: "+name+" (") {
			passed = true
		}
	}
	switch {
	case len(skips) > 0 && required:
		return "", fmt.Errorf("the namespaced run skipped, so its assertions did not run, and CI requires them: %s", strings.Join(skips, "; "))
	case len(skips) > 0:
		return strings.Join(skips, "; "), nil
	case !passed:
		return "", fmt.Errorf("the namespaced run did not report %s as passing", name)
	}
	return "", nil
}

func missing(t *testing.T, format string, args ...any) {
	t.Helper()
	if Required() {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// onPath reports whether name is an executable file in a directory of
// PATH. Unlike exec.LookPath it skips an empty entry, which POSIX reads as
// the current directory: a test's working directory is not where its
// tools come from.
func onPath(name string) bool {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		if fi, err := os.Stat(filepath.Join(dir, name)); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return true
		}
	}
	return false
}
