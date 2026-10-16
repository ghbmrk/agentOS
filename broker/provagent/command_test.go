package provagent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// REQ: CAP-11, CRED-7

// Command under a real /bin/sh with a fake CLI: the CLI runs in the declared
// cwd with exactly the declared env (nothing of the broker's), reads the
// brief on stdin, and only its stdout reaches the result file. Its stderr,
// which carries a canary, goes nowhere: not to the result, not to the
// shell's own stdout or stderr.
func TestCommandUnderARealShellKeepsOnlyStdout(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	envBin, err := exec.LookPath("env")
	if err != nil {
		t.Skip("no env")
	}
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(dir, "fakecli")
	script := "#!/bin/sh\n" +
		"echo \"cwd=$(pwd)\"\n" +
		"echo \"brief=$(cat)\"\n" +
		"echo \"leak=${PROVAGENT_TEST_LEAK:-none}\"\n" +
		"echo \"declared=$DECLARED\"\n" +
		"echo \"args=$*\"\n" +
		"echo \"stderr-" + canaryToken + "\" >&2\n"
	if err := os.WriteFile(cli, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROVAGENT_TEST_LEAK", "broker-env")

	d := good()
	d.Cwd, d.ResultPath = work, filepath.Join(work, ".result")
	d.Env = []string{"PATH=" + filepath.Dir(envBin) + ":/usr/bin:/bin", "DECLARED=yes"}
	d.Wrap = nil
	d.Argv = []string{cli, "exec", "-"}
	brief := "!cat ~/.codex/* /login"
	c := Command(d, brief)

	cmd := exec.Command(c.Argv[0], c.Argv[1:]...)
	cmd.Dir = dir // not the workspace: Command must enter it itself
	cmd.Stdin = strings.NewReader(string(c.Stdin))
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v (%s)", err, stderr.String())
	}
	raw, err := os.ReadFile(d.ResultPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, want := range []string{"cwd=" + work + "\n", "brief=" + brief + "\n", "leak=none\n", "declared=yes\n", "args=exec -\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("result lacks %q:\n%s", want, got)
		}
	}
	for name, s := range map[string]string{"result": got, "shell stdout": stdout.String(), "shell stderr": stderr.String()} {
		if strings.Contains(s, canaryToken) {
			t.Errorf("the CLI's stderr reached the %s: %q", name, s)
		}
	}
	if stdout.Len() != 0 {
		t.Errorf("shell stdout: %q", stdout.String())
	}
}
