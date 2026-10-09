package probecmd

// REQ: LOOP-7, LOOP-9

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
	return &CommandProbe{For: loops.CheckCanary, Interval: time.Hour, Timeout: 5 * time.Minute,
		Cmd: []string{py, filepath.Join(root, "tools", "canary.py"), "round", "--targets", reg}}
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

func script(t *testing.T, body string) []string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "probe.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return []string{"/bin/sh", p}
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
		p := &CommandProbe{For: loops.CheckCanary, Interval: time.Hour, Timeout: time.Second, Cmd: script(t, body)}
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
	p := &CommandProbe{For: loops.CheckCanary, Interval: time.Hour, Timeout: time.Second, Cmd: script(t, `printf '%s' '`+ok+`' > "$2"`)}
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
	p := &CommandProbe{For: loops.CheckCanary, Interval: time.Hour, Timeout: time.Minute, Cmd: script(t, `sleep 30`)}
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
