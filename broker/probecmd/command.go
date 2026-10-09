// Package probecmd runs an off-the-shelf harness as a LOOP-7 probe. It is
// apart from loops because it starts a child process, which the learning
// plane may not (ARC-2, daemon TestARC2ControlPathCannotReachInference).
// Its one exec is reviewed (daemon escapeOK, P3-4b-3a): only a file
// directly in the release directory, with a minimal environment, in a
// process group a timeout kills whole. Wiring it into agentosd is
// P3-4b-4c.
package probecmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/loops"
)

// maxProbeOutput caps what a probe command may write (P3-4b-4a).
const maxProbeOutput = 1 << 20

// CommandProbe runs an off-the-shelf harness as a LOOP-7 probe, such as
// tools/canary.py in round mode. The command gets "--out <file>" appended
// and writes one JSON object there: {"check", "checked", "findings",
// "errors"}. Its stdout and stderr are discarded, since a harness's chatter
// is not evidence and may echo what it tested. Anything short of a whole,
// parseable output of the probe's own check, written by a command that
// exited zero, is an error, never a clean run.
type CommandProbe struct {
	For      loops.Check
	Interval time.Duration
	// Timeout bounds one run; the command's process group is killed past
	// it.
	Timeout time.Duration
	// Release is the directory of release-listed harnesses: Cmd[0] must be
	// a regular file directly in it, never a link (ARC-2). The wiring sets
	// it from a constant, never from configuration or state.
	Release string
	Cmd     []string
}

// waitDelay bounds the wait for a killed command's pipes.
const waitDelay = time.Second

func (p *CommandProbe) Check() loops.Check   { return p.For }
func (p *CommandProbe) Every() time.Duration { return p.Interval }

type commandOutput struct {
	Check    loops.Check `json:"check"`
	Checked  []string    `json:"checked"`
	Findings []struct {
		Check    loops.Check    `json:"check"`
		Subject  string         `json:"subject"`
		Detail   string         `json:"detail"`
		Severity loops.Severity `json:"severity"`
		Contain  *loops.Target  `json:"contain,omitempty"`
	} `json:"findings"`
	Errors []string `json:"errors"`
}

// Run runs the command once. A finding's ID is its check and subject, so
// a target that leaks a different mix of kinds stays one finding.
func (p *CommandProbe) Run(ctx context.Context) (loops.ProbeResult, error) {
	if len(p.Cmd) == 0 || p.Timeout <= 0 {
		return loops.ProbeResult{}, errors.New("command probe: no command or timeout")
	}
	if err := p.released(); err != nil {
		return loops.ProbeResult{}, err
	}
	dir, err := os.MkdirTemp("", "agentos-probe-")
	if err != nil {
		return loops.ProbeResult{}, err
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "out.json")
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.Cmd[0], append(append([]string{}, p.Cmd[1:]...), "--out", out)...)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	// Never the daemon's environment (#515 Security 2): HOME and TMPDIR
	// are the run's own directory.
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + dir, "TMPDIR=" + dir, "GOCACHE=off", "GOFLAGS="}
	// The whole group dies on timeout, grandchildren too (#515 Security 1).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = waitDelay
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return loops.ProbeResult{}, fmt.Errorf("command probe %s: %w", p.For, ctx.Err())
	}
	res, err := p.read(out)
	if runErr != nil {
		err = errors.Join(err, fmt.Errorf("command probe %s: %w", p.For, runErr))
	}
	return res, err
}

// released checks Cmd[0] is a regular file directly in Release, which
// must be absolute and clean.
func (p *CommandProbe) released() error {
	r, bin := p.Release, p.Cmd[0]
	if r == "" || !filepath.IsAbs(r) || filepath.Clean(r) != r {
		return fmt.Errorf("command probe %s: release directory %q is not an absolute clean path", p.For, r)
	}
	if !filepath.IsAbs(bin) || filepath.Dir(bin) != r || filepath.Join(r, filepath.Base(bin)) != bin {
		return fmt.Errorf("command probe %s: %q is not a harness the release lists", p.For, bin)
	}
	fi, err := os.Lstat(bin)
	if err != nil {
		return fmt.Errorf("command probe %s: %w", p.For, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("command probe %s: %s is not a regular file", p.For, bin)
	}
	return nil
}

func (p *CommandProbe) read(path string) (loops.ProbeResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return loops.ProbeResult{}, fmt.Errorf("command probe %s: no output: %w", p.For, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxProbeOutput+1))
	if err != nil {
		return loops.ProbeResult{}, err
	}
	if len(b) > maxProbeOutput {
		return loops.ProbeResult{}, fmt.Errorf("command probe %s: output over %d bytes", p.For, maxProbeOutput)
	}
	var o commandOutput
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&o); err != nil {
		return loops.ProbeResult{}, fmt.Errorf("command probe %s: malformed output: %w", p.For, err)
	}
	if o.Check != p.For {
		return loops.ProbeResult{}, fmt.Errorf("command probe %s: output is for %q", p.For, o.Check)
	}
	res := loops.ProbeResult{Checked: o.Checked}
	for _, x := range o.Findings {
		res.Found = append(res.Found, loops.Finding{ID: loops.FindingID(x.Check, x.Subject, ""), Check: x.Check,
			Subject: x.Subject, Detail: x.Detail, Severity: x.Severity, Contain: x.Contain})
	}
	if len(o.Errors) > 0 {
		return res, fmt.Errorf("command probe %s: %s", p.For, strings.Join(o.Errors, "; "))
	}
	return res, nil
}
