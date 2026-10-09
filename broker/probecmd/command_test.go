package probecmd

// REQ: LOOP-7, LOOP-9, ARC-2

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/loops"
)

// canaryRound is CommandProbe running the repository's canary harness in
// round mode over registry targets.
func canaryRound(t *testing.T, targets []map[string]any) *CommandProbe {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	reg := filepath.Join(t.TempDir(), "targets.json")
	b, _ := json.Marshal(map[string]any{"targets": targets})
	if err := os.WriteFile(reg, b, 0o600); err != nil {
		t.Fatal(err)
	}
	// The harness runs from a release-listed wrapper, as in the image.
	release := t.TempDir()
	wrapper := filepath.Join(release, "canary")
	body := "#!/bin/sh\nexec " + py + " " + filepath.Join(root, "tools", "canary.py") + ` "$@"` + "\n"
	if err := os.WriteFile(wrapper, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return &CommandProbe{For: loops.CheckCanary, Interval: time.Hour, Timeout: 5 * time.Minute, Release: release,
		Cmd: []string{wrapper, "round", "--targets", reg}}
}

func controlCmd(t *testing.T, mode string) []string {
	root, _ := filepath.Abs("../..")
	return []string{"python3", filepath.Join(root, "tools", "canary_controls.py"), mode}
}

// LOOP-7: a clean round reports nothing.
func TestACleanCanaryRoundReportsNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the canary harness")
	}
	p := canaryRound(t, []map[string]any{{"name": "quiet", "cmd": controlCmd(t, "clean")}})
	res, err := p.Run(context.Background())
	if err != nil || len(res.Found) != 0 || strings.Join(res.Checked, ",") != "quiet" {
		t.Fatalf("%+v %v", res, err)
	}
}

// script writes body as a probe command into a release directory and
// returns a probe that runs it.
func script(t *testing.T, timeout time.Duration, body string) *CommandProbe {
	t.Helper()
	release := t.TempDir()
	p := filepath.Join(release, "probe")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return &CommandProbe{For: loops.CheckCanary, Interval: time.Hour, Timeout: timeout, Release: release, Cmd: []string{p}}
}

// LOOP-7: a round the command could not complete is an error, never
// clean: an error line, a missing or oversized or malformed output, a
// nonzero exit, a timeout. Errors keep what was found and checked.
func TestACommandProbeFailsClosed(t *testing.T) {
	ok := `{"check":"canary","checked":["a"],"findings":[{"check":"canary","subject":"a","detail":"kinds: pin","severity":"high"}],"errors":[]}`
	cases := map[string]string{
		"errors":    `printf '%s' '{"check":"canary","checked":["b"],"findings":[],"errors":["a: exit 1"]}' > "$2"; exit 1`,
		"no output": `exit 0`,
		"malformed": `printf 'not json' > "$2"`,
		"exit":      `printf '%s' '` + ok + `' > "$2"; exit 3`,
		"too big":   `head -c 2000000 /dev/zero | tr '\0' ' ' > "$2"`,
		"check":     `printf '%s' '{"check":"corpus","checked":[],"findings":[],"errors":[]}' > "$2"`,
		"timeout":   `sleep 30`,
	}
	for name, body := range cases {
		p := script(t, time.Second, body)
		start := time.Now()
		res, err := p.Run(context.Background())
		if err == nil {
			t.Errorf("%s: no error", name)
		}
		if name == "errors" && strings.Join(res.Checked, ",") != "b" {
			t.Errorf("errors: lost what was checked: %+v", res)
		}
		if time.Since(start) > 10*time.Second {
			t.Errorf("%s: ran past its timeout", name)
		}
	}
	p := script(t, time.Second, `printf '%s' '`+ok+`' > "$2"`)
	res, err := p.Run(context.Background())
	if err != nil || len(res.Found) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if f := res.Found[0]; f.ID != loops.FindingID(loops.CheckCanary, "a", "") || f.Severity != loops.High {
		t.Fatalf("finding %+v", f)
	}
}

// LOOP-1: a preempted round is stopped at once.
func TestACommandProbeStopsWhenPreempted(t *testing.T) {
	p := script(t, time.Minute, `sleep 30`)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	start := time.Now()
	if _, err := p.Run(ctx); err == nil {
		t.Fatal("no error")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("not stopped")
	}
}

// ARC-2: a command that is not a file directly in the release directory,
// or is a link there, is refused before it runs.
func TestACommandOutsideTheReleaseIsRefused(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	p := script(t, time.Second, "touch "+marker)
	outside := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(p.Release, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]func(q *CommandProbe){
		"shell":      func(q *CommandProbe) { q.Cmd = []string{"/bin/sh", q.Cmd[0]} },
		"outside":    func(q *CommandProbe) { q.Cmd = []string{outside} },
		"relative":   func(q *CommandProbe) { q.Cmd = []string{"probe"} },
		"dotdot":     func(q *CommandProbe) { q.Cmd = []string{q.Release + "/../" + filepath.Base(q.Release) + "/probe"} },
		"link":       func(q *CommandProbe) { q.Cmd = []string{link} },
		"no release": func(q *CommandProbe) { q.Release = "" },
		"rel. dir":   func(q *CommandProbe) { q.Release = "release" },
	} {
		q := *p
		c(&q)
		if _, err := q.Run(context.Background()); err == nil {
			t.Errorf("%s: ran %v", name, q.Cmd)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("%s: executed", name)
		}
	}
}

// ARC-2: a probe command does not see the daemon's environment
// (#515 Security 2).
func TestACommandGetsAMinimalEnvironment(t *testing.T) {
	t.Setenv("AGENTOS_TEST_CANARY", "synthetic-canary-7f3a")
	out := filepath.Join(t.TempDir(), "env")
	p := script(t, 5*time.Second, "env > "+out+`; printf '%s' '{"check":"canary","checked":[],"findings":[],"errors":[]}' > "$2"`)
	if _, err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil || strings.Contains(string(b), "synthetic-canary") {
		t.Fatalf("environment %q %v", b, err)
	}
	allowed := map[string]bool{"PATH": true, "HOME": true, "TMPDIR": true, "GOCACHE": true, "GOFLAGS": true, "PWD": true, "SHLVL": true, "_": true}
	home := ""
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		k, v, _ := strings.Cut(l, "=")
		if !allowed[k] {
			t.Errorf("the command saw %s", k)
		}
		if k == "HOME" {
			home = v
		}
	}
	if h, _ := os.UserHomeDir(); home == "" || home == h {
		t.Fatalf("HOME %q is not the probe's scratch", home)
	}
}

// LOOP-1 (#515 Security 1): a timeout kills the command's whole process
// group, so a backgrounded grandchild does not outlive the round.
func TestATimeoutKillsTheGrandchildToo(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "pid")
	p := script(t, 500*time.Millisecond, "sleep 300 &\necho $! > "+pidfile+"\nsleep 300")
	if _, err := p.Run(context.Background()); err == nil {
		t.Fatal("a timed-out round is not an error")
	}
	b, err := os.ReadFile(pidfile)
	if err != nil {
		t.Fatal(err)
	}
	pid := strings.TrimSpace(string(b))
	deadline := time.Now().Add(waitDelay)
	for {
		st, err := os.ReadFile("/proc/" + pid + "/stat")
		if err != nil || strings.Fields(string(st[strings.LastIndexByte(string(st), ')')+1:]))[0] == "Z" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("grandchild %s outlived the round", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
