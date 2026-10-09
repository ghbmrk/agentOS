// Package loop7 is a Loop 2 source for LOOP-7's off-the-shelf checks
// (P3-4b-3): bounded rounds of the broker's Go native fuzz targets, and
// rounds of the in-guest socket probe (broker/sockprobe), run in spare
// capacity (LOOP-1). A crash or a probe failure enters LOOP-9's chain as a
// finding through Report; the crashing input stays in the target's corpus
// as evidence and as a regression replayed every round, and the finding
// is resolved once the regression passes.
//
// Nothing here writes or chooses test input (D-067): the fuzz engine is
// Go's own, the targets and seeds are the repository's, and the probe's
// frames are fixed.
package loop7

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/sockets"
	"github.com/ghbmrk/agentos/broker/sockprobe"
)

// Reporter is Loop 2's in-process entry point (*loops.Guard).
type Reporter interface {
	Report(ctx context.Context, f loops.Finding) (loops.Record, error)
	Resolve(id string, r loops.Replay) error
	OpenReported(c loops.Check) []loops.Finding
}

// Target is one fuzz target, built as a test binary (`go test -c`).
type Target struct {
	Pkg    string // the package's short name, as in "sockets"
	Name   string // the fuzz function, as in "FuzzRequest"
	Binary string // the compiled test binary
	// Dir is the binary's working directory. Its testdata/fuzz/<Name>
	// holds the seed corpus; a crashing input is written there, kept,
	// and replayed every round.
	Dir string
}

func (t Target) subject() string { return t.Pkg + "." + t.Name }

// ProbeRun runs the socket probe in an agent machine with guest
// authority, and returns the machine and the probe's result.
type ProbeRun func(ctx context.Context) (machine string, res sockprobe.Result, err error)

// Config wires the source.
type Config struct {
	// Inner is Loop 2's passive checks (*loops.Guard). There is one
	// source per loop, so this source offers Inner's work first.
	Inner   loops.Source
	Report  Reporter
	Targets []Target
	// FuzzTime bounds one fuzz job. Default 30 s.
	FuzzTime time.Duration
	// Every is the gap between two LOOP-7 jobs. Default 1 h.
	Every time.Duration
	// CacheDir holds the fuzz engine's generated corpus.
	CacheDir string
	// Probe and Trail run the socket probe and read the journal; both or
	// neither.
	Probe ProbeRun
	Trail func() []journal.Record
	// Window is the journal's coalescing window for refusals. Default 1 m.
	Window time.Duration
	Now    func() time.Time
}

// Source is Loop 2's source with LOOP-7 rounds added.
type Source struct {
	cfg Config

	mu   sync.Mutex
	next time.Time
	turn int // which LOOP-7 job comes next: the probe, then each target
}

// New checks cfg and returns the source.
func New(cfg Config) (*Source, error) {
	if cfg.Inner == nil || cfg.Report == nil {
		return nil, errors.New("loop7: Inner and Report are required")
	}
	if (cfg.Probe == nil) != (cfg.Trail == nil) {
		return nil, errors.New("loop7: Probe and Trail go together")
	}
	if cfg.Inner.Loop() != loops.Secure {
		return nil, errors.New("loop7: Inner must be Loop 2's source")
	}
	for _, t := range cfg.Targets {
		if t.Pkg == "" || !fuzzName.MatchString(t.Name) || t.Binary == "" || t.Dir == "" {
			return nil, fmt.Errorf("loop7: bad target %+v", t)
		}
	}
	if len(cfg.Targets) > 0 && cfg.CacheDir == "" {
		return nil, errors.New("loop7: fuzz targets need a CacheDir")
	}
	if cfg.FuzzTime <= 0 {
		cfg.FuzzTime = 30 * time.Second
	}
	if cfg.Every <= 0 {
		cfg.Every = time.Hour
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Source{cfg: cfg}, nil
}

var fuzzName = regexp.MustCompile(`^Fuzz[A-Za-z0-9_]*$`)

// Loop is Loop 2.
func (s *Source) Loop() loops.Loop { return loops.Secure }

// Urgent is Inner's: a LOOP-7 round is never urgent.
func (s *Source) Urgent() bool {
	u, ok := s.cfg.Inner.(loops.Urgent)
	return ok && u.Urgent()
}

// Next offers Inner's work first, then one LOOP-7 job per Every. Neither
// makes model calls. A job that is preempted is offered again at once.
func (s *Source) Next(ctx context.Context, modelOK bool) (loops.Job, bool) {
	if j, ok := s.cfg.Inner.Next(ctx, modelOK); ok {
		return j, true
	}
	jobs := len(s.cfg.Targets)
	if s.cfg.Probe != nil {
		jobs++
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	if jobs == 0 || now.Before(s.next) {
		return loops.Job{}, false
	}
	at := s.turn % jobs
	s.turn++
	s.next = now.Add(s.cfg.Every)
	// A preempted job is offered again at once.
	retry := func(ctx context.Context) {
		if ctx.Err() != nil {
			s.mu.Lock()
			s.turn, s.next = at, time.Time{}
			s.mu.Unlock()
		}
	}
	i := at
	if s.cfg.Probe != nil {
		if i == 0 {
			return loops.Job{Name: "probe", Run: func(ctx context.Context) loops.Result {
				n, err := s.probe(ctx)
				retry(ctx)
				return loops.Result{Value: float64(n), Err: err}
			}}, true
		}
		i--
	}
	t := s.cfg.Targets[i]
	return loops.Job{Name: "fuzz", Run: func(ctx context.Context) loops.Result {
		n, err := s.Fuzz(ctx, t)
		retry(ctx)
		return loops.Result{Value: float64(n), Err: err}
	}}, true
}

// Fuzz is one round for t: replay its corpus, fuzz it for FuzzTime, and
// replay again if the fuzzing failed. Each failing corpus input is
// reported; each open finding for t whose input passes is resolved. It
// returns the number of failing inputs, and returns soon after ctx ends.
func (s *Source) Fuzz(ctx context.Context, t Target) (int, error) {
	n, err := s.replay(ctx, t)
	if err != nil || ctx.Err() != nil {
		return n, err
	}
	cmd := s.command(ctx, t, "-test.run=^$", "-test.fuzz=^"+t.Name+"$",
		"-test.fuzztime="+s.cfg.FuzzTime.String(), "-test.parallel=1",
		"-test.fuzzcachedir="+s.cfg.CacheDir)
	if out, err := cmd.CombinedOutput(); err == nil || ctx.Err() != nil {
		return n, nil
	} else if !bytes.Contains(out, []byte("Failing input written to")) {
		return n, fmt.Errorf("loop7: fuzzing %s did not run: %v", t.subject(), err)
	}
	return s.replay(ctx, t)
}

// failLine and passLine are a seed subtest failing or passing under
// -test.v.
var (
	failLine = regexp.MustCompile(`^\s*--- FAIL: (Fuzz[A-Za-z0-9_]*)/([^\s/]+) `)
	passLine = regexp.MustCompile(`^\s*--- PASS: (Fuzz[A-Za-z0-9_]*)/([^\s/]+) `)
)

// replay runs t's corpus files, reports each failing one and resolves
// t's open findings whose stored input it replayed and passed.
func (s *Source) replay(ctx context.Context, t Target) (int, error) {
	out, runErr := s.command(ctx, t, "-test.run=^"+t.Name+"$", "-test.v").CombinedOutput()
	if ctx.Err() != nil {
		return 0, nil
	}
	failing, ran := map[string]bool{}, map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if m := failLine.FindStringSubmatch(sc.Text()); m != nil && m[1] == t.Name {
			failing[m[2]] = true
		} else if m := passLine.FindStringSubmatch(sc.Text()); m != nil && m[1] == t.Name {
			ran[m[2]] = true
		}
	}
	if runErr != nil && len(failing) == 0 {
		return 0, fmt.Errorf("loop7: replaying %s: %v", t.subject(), runErr)
	}
	var errs []error
	// Each stored input whose own subtest passed in this run: only such a
	// replay closes a finding. An input that never ran (a panic stops the
	// binary before later seeds) or was removed keeps its finding open.
	passed := map[string]bool{}
	for _, file := range sortedKeys(ran) {
		if data, err := os.ReadFile(filepath.Join(t.Dir, "testdata", "fuzz", t.Name, file)); err == nil {
			passed[crashDetail(data)] = true
		}
	}
	for _, file := range sortedKeys(failing) {
		data, err := os.ReadFile(filepath.Join(t.Dir, "testdata", "fuzz", t.Name, file))
		if err != nil {
			// A failing f.Add seed, not a file: report it by name.
			data = []byte(file)
		}
		f := loops.Finding{Check: loops.CheckFuzz, Subject: t.subject(), Severity: loops.High, Detail: crashDetail(data)}
		if _, err := s.cfg.Report.Report(ctx, f); err != nil {
			errs = append(errs, err)
		}
	}
	for _, f := range s.cfg.Report.OpenReported(loops.CheckFuzz) {
		if f.Subject == t.subject() && passed[f.Detail] {
			r := loops.Replay{Evidence: f.Detail, Passed: true, At: s.cfg.Now()}
			errs = append(errs, s.cfg.Report.Resolve(f.ID, r))
		}
	}
	return len(failing), errors.Join(errs...)
}

// crashDetail names a crashing input by its digest; the input itself
// stays in the corpus.
func crashDetail(data []byte) string {
	h := sha256.Sum256(data)
	return "crash input sha256:" + hex.EncodeToString(h[:])
}

func (s *Source) command(ctx context.Context, t Target, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, t.Binary, args...)
	cmd.Dir = t.Dir
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	// The fuzz engine runs workers as children: the whole group stops on
	// cancel, so the job yields within the preemption target (LOOP-1).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 200 * time.Millisecond
	return cmd
}

// probe is one probe round: run it in a guest, check the journal against
// what it sent, report a failure, or resolve the machine's open probe
// findings on a clean round.
func (s *Source) probe(ctx context.Context) (int, error) {
	start := s.cfg.Now()
	machine, res, err := s.cfg.Probe(ctx)
	if ctx.Err() != nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("loop7: probe: %w", err)
	}
	fails := append(res.Failures, Journaled(machine, s.cfg.Trail(), start, s.cfg.Now(), s.cfg.Window)...)
	subject := "socket." + machine
	var errs []error
	detail := ""
	if len(fails) > 0 {
		detail = probeDetail(fails)
		f := loops.Finding{Check: loops.CheckProbe, Subject: subject, Severity: loops.High, Detail: detail}
		if _, err := s.cfg.Report.Report(ctx, f); err != nil {
			errs = append(errs, err)
		}
	}
	for _, f := range s.cfg.Report.OpenReported(loops.CheckProbe) {
		// A clean round replays the probe's frames: the only pass that
		// closes a probe finding.
		if f.Subject == subject && len(fails) == 0 {
			r := loops.Replay{Evidence: f.Detail, Passed: true, At: s.cfg.Now()}
			errs = append(errs, s.cfg.Report.Resolve(f.ID, r))
		}
	}
	return len(fails), errors.Join(errs...)
}

// maxDetail bounds a probe finding's evidence text.
const maxDetail = 1024

func probeDetail(fails []string) string {
	d := "probe failures: " + strings.Join(fails, "; ")
	if len(d) > maxDetail {
		d = d[:maxDetail]
	}
	return d
}

// Journaled is the broker side of a probe round on machine between start
// and end: each refusal in the probe set is journaled (a socket-refusal note
// for the machine and code, at most window before start, since notes are
// coalesced per window), and no frame had an effect (no intent from the
// machine in the round). It returns the failures in plain words.
func Journaled(machine string, trail []journal.Record, start, end time.Time, window time.Duration) []string {
	// The codes come from the broker's own probe set, never from what the
	// guest says it sent: an empty Result must not pass the round.
	want := map[sockets.Code]bool{}
	for _, f := range sockprobe.Frames {
		want[f.Want] = true
	}
	var fails []string
	for _, r := range trail {
		if r.At.Before(start.Add(-window)) || r.At.After(end) {
			continue
		}
		if r.Type == journal.RecEgress && r.Egress != nil && r.Egress.Adapter == sockets.RefusalNote && r.Egress.Machine == machine {
			for c := range want {
				if r.Egress.Operation == c.Token() {
					delete(want, c)
				}
			}
		}
		if r.Intent != nil && r.Intent.Machine == machine && !r.At.Before(start) {
			fails = append(fails, fmt.Sprintf("a probe round on %s journaled intent %s", machine, r.Intent.Action))
		}
	}
	for _, c := range sortedKeys(want) {
		fails = append(fails, fmt.Sprintf("refusal %q on %s was not journaled", c, machine))
	}
	return fails
}

func sortedKeys[K ~string, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
