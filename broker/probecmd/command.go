// Package probecmd runs an off-the-shelf harness as a LOOP-7 probe. It is
// apart from loops because it starts a child process, which the learning
// plane may not (ARC-2, daemon TestARC2ControlPathCannotReachInference);
// whatever wires it into a process takes that up by review (P3-4b-4c).
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
	// Timeout bounds one run; the command is killed past it.
	Timeout time.Duration
	Cmd     []string
}

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
	cmd.WaitDelay = time.Second
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
