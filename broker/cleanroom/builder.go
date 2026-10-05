// Package cleanroom is the public side of the open-source bridge: the
// clean-room builder (SPEC v0.12 OSS-2).
//
// The private side may tell it only a hint, a choice among the values of
// the public schema (package hint, OSS-1). For each hint the builder creates
// a fresh agent machine from the clean-room image, which holds only the
// public repository, a toolchain, and synthetic fixtures. The machine is
// labelled public and is never forked from another machine, and its broker
// socket serves only three things: the hint, a place to submit the result,
// and the metered model route. It has no tools that reach an executor, no
// owner channel, no vault, journal, recall index, or workspace, and no
// network but that socket. It builds the generalized skill, adapter, or
// regression from public information, tests it on the synthetic fixtures,
// and submits it. The builder stores the result as an Artifact with its
// provenance and destroys the machine. Artifacts are the only thing a
// publisher can take (OSS-2, OSS-3). Artifacts rebuilt from an embargo kind
// (vuln) are held for the private-report path until it clears (OSS-5).
package cleanroom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/hint"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/vm"
)

// Prefix starts every clean-room machine's ID, and no other machine's: the
// services mux never hands a machine with this prefix to the guest plane.
const Prefix = "cr-"

// Machines is the part of vm.Manager the builder uses.
type Machines interface {
	Create(ctx context.Context, id string, s vm.Spec) (vm.Machine, error)
	Get(id string) (vm.Machine, error)
	Resume(ctx context.Context, id string) error
	Destroy(ctx context.Context, id string) error
	Machines() []string
}

// Config sets up a Builder.
type Config struct {
	Dir      string // broker-held state (queue, artifacts, log); created 0700
	Machines Machines
	// Image names the clean-room image registered with the vm manager. It
	// must be built from the public repository and synthetic fixtures only
	// (P2-1).
	Image string
	MemMB int64 // 0 means 1024
	Argv  []string
	Env   []string // static; never owner data
	// Model serves a machine's model route; with it, Meter is required and
	// every call is metered (OP-8). Nil answers 503.
	Model func(machine string) http.Handler
	Meter *meter.Meter
	// Schema is the public hint schema; nil means hint.Default().
	Schema *hint.Schema
	// Timeout bounds one job's wall time (0 means 2 h). Attempts bounds how
	// many machines one job may use (0 means 2). Retry is the wait after a
	// machine could not be created, e.g. no spare capacity (0 means 1 min).
	Timeout  time.Duration
	Attempts int
	Retry    time.Duration
	Poll     time.Duration // machine state checks; 0 means 5 s
	MaxQueue int           // jobs waiting; 0 means 64
	Logf     func(format string, args ...any)
	Now      func() time.Time
}

// Builder runs clean rooms. It implements hint.Outbox.
type Builder struct {
	cfg   Config
	store *Store
	wake  chan struct{}

	qmu sync.Mutex

	mu       sync.Mutex
	sessions map[string]*session
	lmu      sync.Mutex
}

var _ hint.Outbox = (*Builder)(nil)

// New checks cfg and opens the builder's state directory.
func New(cfg Config) (*Builder, error) {
	if cfg.Dir == "" || cfg.Machines == nil || cfg.Image == "" {
		return nil, errors.New("cleanroom: Dir, Machines, and Image are required")
	}
	if cfg.Model != nil && cfg.Meter == nil {
		return nil, errors.New("cleanroom: model egress needs the OP-8 meter")
	}
	if cfg.Schema == nil {
		cfg.Schema = hint.Default()
	}
	if cfg.MemMB <= 0 {
		cfg.MemMB = 1024
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Hour
	}
	if cfg.Attempts <= 0 {
		cfg.Attempts = 2
	}
	if cfg.Retry <= 0 {
		cfg.Retry = time.Minute
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 5 * time.Second
	}
	if cfg.MaxQueue <= 0 {
		cfg.MaxQueue = 64
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	for _, d := range []string{cfg.Dir, filepath.Join(cfg.Dir, "queue"), filepath.Join(cfg.Dir, "sockets"), filepath.Join(cfg.Dir, "days")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return nil, err
		}
	}
	// A batch a crash caught before its rename was never taken.
	if old, err := filepath.Glob(filepath.Join(cfg.Dir, "incoming-*")); err == nil {
		for _, d := range old {
			os.RemoveAll(d)
		}
	}
	st, err := openStore(filepath.Join(cfg.Dir, "artifacts"))
	if err != nil {
		return nil, err
	}
	return &Builder{cfg: cfg, store: st, wake: make(chan struct{}, 1), sessions: map[string]*session{}}, nil
}

// Store is where artifacts are kept.
func (b *Builder) Store() *Store { return b.store }

// Outcome is one finished job, as logged.
type Outcome struct {
	Job      string `json:"job"`
	Day      string `json:"day"`
	Kind     string `json:"kind"`
	Result   string `json:"result"` // built, failed
	Artifact string `json:"artifact,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// Outcomes lists finished jobs, oldest first.
func (b *Builder) Outcomes() ([]Outcome, error) {
	b.lmu.Lock()
	defer b.lmu.Unlock()
	data, err := os.ReadFile(filepath.Join(b.cfg.Dir, "outcomes.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Outcome
	for _, line := range strings.Split(string(data), "\n") {
		var o Outcome
		if json.Unmarshal([]byte(line), &o) == nil && o.Job != "" {
			out = append(out, o)
		}
	}
	return out, nil
}

func (b *Builder) logOutcome(o Outcome) error {
	b.lmu.Lock()
	defer b.lmu.Unlock()
	line, _ := json.Marshal(o)
	f, err := os.OpenFile(filepath.Join(b.cfg.Dir, "outcomes.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Run builds queued hints one at a time until ctx ends. It first destroys
// any clean-room machine a previous run left behind; its job, if still
// queued, starts again on a fresh machine.
func (b *Builder) Run(ctx context.Context) error {
	for _, id := range b.cfg.Machines.Machines() {
		if strings.HasPrefix(id, Prefix) {
			if err := b.cfg.Machines.Destroy(context.Background(), id); err != nil {
				b.cfg.Logf("cleanroom: destroying leftover %s: %v", id, err)
			}
		}
	}
	for {
		b.qmu.Lock()
		jobs, err := b.queued()
		b.qmu.Unlock()
		if err != nil {
			// Keep running: a queue that cannot be read now may be
			// readable later, and nothing else builds hints.
			b.cfg.Logf("cleanroom: reading the queue: %v", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(b.cfg.Retry):
			}
			continue
		}
		if len(jobs) == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-b.wake:
				continue
			}
		}
		if err := b.runJob(ctx, jobs[0]); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			b.cfg.Logf("cleanroom: job %s: %v", jobs[0].ID, err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(b.cfg.Retry):
			}
		}
	}
}

// runJob runs one job on a fresh machine. It returns an error only when the
// job should be tried again later (no machine could be created, or ctx
// ended); a job that ran is finished, built or failed, and leaves the queue.
func (b *Builder) runJob(ctx context.Context, j *job) error {
	h, embargo, err := parseCanonical(b.cfg.Schema, []byte(j.Hint))
	if err != nil {
		return b.finish(j, "", Outcome{Result: "failed", Reason: "hint no longer matches the schema"})
	}
	if _, err := b.store.Get(artifactID(j)); err == nil {
		// Stored before a crash took the queue entry with it.
		return b.finish(j, h.Kind, Outcome{Result: "built", Artifact: artifactID(j)})
	}
	if j.Attempts >= b.cfg.Attempts {
		return b.finish(j, h.Kind, Outcome{Result: "failed", Reason: "no result within the allowed attempts"})
	}
	id := Prefix + j.ID
	s := &session{b: b, id: id, job: j, kind: h.Kind, embargo: embargo, done: make(chan struct{})}
	b.mu.Lock()
	b.sessions[id] = s
	b.mu.Unlock()
	defer b.endSession(id)

	m, err := b.cfg.Machines.Create(ctx, id, vm.Spec{
		Image: b.cfg.Image, Class: admission.Experiment, MemMB: b.cfg.MemMB,
		Argv: b.cfg.Argv, Env: b.cfg.Env, Label: vm.Public,
	})
	if err != nil {
		if !capacity(err) {
			// Not a matter of waiting for room: spend an attempt, so a
			// job that can never start leaves the queue.
			j.Attempts++
			if werr := writeJSON(j.path, j); werr != nil {
				return werr
			}
		}
		return fmt.Errorf("creating clean room: %w", err)
	}
	defer b.destroy(id)
	// A job's outcome is logged once its machine is gone. Ending the
	// session first means no result can commit after a failure is logged;
	// one that already committed makes the job built.
	done := func(o Outcome) error {
		if a := s.end(); a != "" {
			o = Outcome{Result: "built", Artifact: a}
		}
		b.destroy(id)
		return b.finish(j, h.Kind, o)
	}
	j.Attempts++
	if err := writeJSON(j.path, j); err != nil {
		return err
	}
	if err := b.isClean(m); err != nil {
		return done(Outcome{Result: "failed", Reason: err.Error()})
	}
	deadline := time.NewTimer(b.cfg.Timeout)
	defer deadline.Stop()
	tick := time.NewTicker(b.cfg.Poll)
	defer tick.Stop()
	for {
		select {
		case <-s.done:
			s.mu.Lock()
			a, failure, parked := s.artifact, s.failure, s.parked
			s.mu.Unlock()
			if parked {
				b.destroy(id)
				return b.park(j, h.Kind, failure)
			}
			if failure != "" {
				return done(Outcome{Result: "failed", Reason: failure})
			}
			return done(Outcome{Result: "built", Artifact: a})
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			if j.Attempts >= b.cfg.Attempts {
				return done(Outcome{Result: "failed", Reason: "timed out"})
			}
			if s.end() != "" {
				// Committed at the deadline: the job is built.
				return done(Outcome{})
			}
			return errors.New("timed out; trying again on a fresh machine")
		case <-tick.C:
			m, err := b.cfg.Machines.Get(id)
			if err != nil {
				return done(Outcome{Result: "failed", Reason: "machine is gone"})
			}
			if err := b.isClean(m); err != nil {
				s.fail(err.Error())
				continue
			}
			if m.State != vm.Running {
				// Preempted for higher-class work (RES-1): continue when
				// capacity allows.
				if err := b.cfg.Machines.Resume(ctx, id); err != nil {
					b.cfg.Logf("cleanroom: resuming %s: %v", id, err)
				}
			}
		}
	}
}

// isClean checks the machine is what a clean room must be: the clean-room
// image, labelled public, not forked from anything.
func (b *Builder) isClean(m vm.Machine) error {
	switch {
	case m.Spec.Image != b.cfg.Image:
		return errors.New("clean room is not on the clean-room image")
	case m.Label != vm.Public:
		return errors.New("clean room received private data")
	case m.ForkBase != "":
		return errors.New("clean room was forked from another machine")
	}
	return nil
}

func (b *Builder) destroy(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := b.cfg.Machines.Destroy(ctx, id); err != nil && !errors.Is(err, vm.ErrUnknown) {
		b.cfg.Logf("cleanroom: destroying %s: %v", id, err)
	}
}

// finish logs a job's outcome and takes it off the queue.
func (b *Builder) finish(j *job, kind string, o Outcome) error {
	o.Job, o.Day, o.Kind = j.ID, j.Day, kind
	if err := b.logOutcome(o); err != nil {
		return err
	}
	b.qmu.Lock()
	defer b.qmu.Unlock()
	if err := os.Remove(j.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	syncDir(filepath.Dir(j.path))
	return nil
}

// capacity reports whether a Create error means only that there is no
// spare capacity now.
func capacity(err error) bool {
	return errors.Is(err, admission.ErrNoRoom) || errors.Is(err, admission.ErrPressure) || errors.Is(err, vm.ErrRevoked)
}

func (b *Builder) parkDir() string { return filepath.Join(b.cfg.Dir, "parked") }

// park logs a job that needs public material as failed and keeps it aside
// for Requeue (potency PR2).
func (b *Builder) park(j *job, kind, reason string) error {
	// Move first, then log: the log never says parked for a job still
	// queued, and a crash between the two cannot log it twice.
	b.qmu.Lock()
	err := os.MkdirAll(b.parkDir(), 0o700)
	if err == nil {
		err = os.Rename(j.path, filepath.Join(b.parkDir(), filepath.Base(j.path)))
	}
	if err == nil {
		syncDir(filepath.Dir(j.path))
		err = syncDir(b.parkDir())
	}
	b.qmu.Unlock()
	if err != nil {
		return err
	}
	return b.logOutcome(Outcome{Job: j.ID, Day: j.Day, Kind: kind, Result: "parked", Reason: reason})
}

// parked lists parked jobs.
func (b *Builder) parked() []*job {
	ents, _ := os.ReadDir(b.parkDir())
	var out []*job
	for _, e := range ents {
		j := &job{}
		p := filepath.Join(b.parkDir(), e.Name())
		if readJSON(p, j) == nil {
			j.path = p
			out = append(out, j)
		}
	}
	return out
}

// Requeue puts parked jobs back in the queue with fresh attempts, for when
// clean rooms can reach the public material they lacked (ARC-6 (d)). Jobs
// from embargo kinds (vuln) stay parked: their clean rooms stay offline
// (PS1). A parked hint now queued or built is coalesced into it.
func (b *Builder) Requeue() (int, error) {
	b.qmu.Lock()
	defer b.qmu.Unlock()
	jobs, err := b.queued()
	if err != nil {
		return 0, err
	}
	have := map[string]into{}
	for _, j := range jobs {
		have[j.Hint] = into{desc: "job " + j.ID}
	}
	built, err := b.store.list(func(Manifest) bool { return true })
	if err != nil {
		return 0, err
	}
	for _, a := range built {
		have[string(a.m.Hint)] = into{desc: a.m.ID, artifact: a.m.ID}
	}
	dir := filepath.Join(b.queueDir(), "requeue-"+newID())
	n := 0
	for _, j := range b.parked() {
		h, embargo, err := parseCanonical(b.cfg.Schema, []byte(j.Hint))
		if err != nil || embargo {
			continue
		}
		if in, ok := have[j.Hint]; ok {
			// Removed first, so a job that stays parked is not logged
			// coalesced again on the next Requeue.
			if err := os.Remove(j.path); err != nil {
				b.cfg.Logf("cleanroom: removing coalesced parked job %s: %v", j.ID, err)
				continue
			}
			o := Outcome{Job: j.ID, Day: j.Day, Kind: h.Kind, Result: "coalesced", Reason: "same hint as " + in.desc, Artifact: in.artifact}
			if err := b.logOutcome(o); err != nil {
				return n, err
			}
			continue
		}
		have[j.Hint] = into{desc: "job " + j.ID}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return n, err
		}
		p := j.path
		j.Attempts = 0
		if err := writeJSON(filepath.Join(dir, filepath.Base(p)), j); err != nil {
			return n, err
		}
		if err := os.Remove(p); err != nil {
			return n, err
		}
		n++
	}
	select {
	case b.wake <- struct{}{}:
	default:
	}
	return n, nil
}
