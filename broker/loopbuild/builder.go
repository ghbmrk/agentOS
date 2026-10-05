// Package loopbuild is Loop 1's model-backed builder (BOARD W3-builder,
// W3 step 3c): for each hypothesis it runs a fresh private experiment
// machine whose only reach is its own broker socket, which serves the
// brief, a place to submit one candidate, and the metered model route.
//
// The builder is treated as compromised (security C-3c-4): what it submits
// is clipped to MaxFiles text files of MaxFileBytes, MaxCandidateBytes in
// all, written only in the hypothesis class's namespace; Loop 1 stamps the
// source and origin and the change pipeline decides the rest (held-out
// evaluation, CHG-1, LOOP-6). The machine is never forked from another,
// never handed to the guest plane (so no executor, owner channel, vault,
// recall, workspace or managed_tree), and destroyed after its job.
package loopbuild

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/vm"
)

// Prefix starts every builder machine's ID, and no other machine's: its
// services are this package's socket, never the guest plane's. It is
// modelroute.BuilderPrefix, by which the vault process knows them
// (agentosd TestBuilderMachinesReachOnlyTheBuilder).
const Prefix = "lb-"

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
	Dir      string // sockets; created 0700
	Machines Machines
	// Image is the minimal builder image (toolchain and brief client;
	// C-3c-3), never the agent's.
	Image string
	MemMB int64 // 0 means DefaultMemMB
	Argv  []string
	Env   []string // static; never owner data
	// Model serves a machine's model route, which forwards with the
	// machine's private label (C-3c-6); Meter is then required, and every
	// call is metered against the builder's share (C-3c-5). Nil answers
	// 503.
	Model func(machine string) http.Handler
	Meter *meter.Meter
	// JobTokens caps one job's model tokens (0 means DefaultJobTokens);
	// Timeout bounds its wall time (0 means DefaultTimeout).
	JobTokens int64
	Timeout   time.Duration
	Poll      time.Duration // machine state checks; 0 means 5 s
	Logf      func(format string, args ...any)
}

// Defaults (C-3c-5; the N95 lens note on memory).
const (
	DefaultMemMB     = 768
	DefaultJobTokens = 200_000
	DefaultTimeout   = 30 * time.Minute
)

// Builder runs Loop 1's builder machines, one job at a time (C-3c-1).
type Builder struct {
	cfg  Config
	slot chan struct{}

	mu       sync.Mutex
	sessions map[string]*session
}

var (
	_ loops.Builder = (*Builder)(nil)
	_ loops.Private = (*Builder)(nil)
)

// Errors a job ends with. Loop 1 measures a failed job like any other.
var (
	ErrClass     = errors.New("loopbuild: no builder for this class")
	ErrNoResult  = errors.New("loopbuild: the builder submitted no candidate")
	ErrNotClean  = errors.New("loopbuild: builder machine is not what it must be")
	ErrMachineUp = errors.New("loopbuild: builder machine could not start")
)

// New checks cfg and prepares the socket directory.
func New(cfg Config) (*Builder, error) {
	if cfg.Dir == "" || cfg.Machines == nil || cfg.Image == "" {
		return nil, errors.New("loopbuild: Dir, Machines, and Image are required")
	}
	if cfg.Model != nil && cfg.Meter == nil {
		return nil, errors.New("loopbuild: model egress needs the OP-8 meter")
	}
	if cfg.MemMB <= 0 {
		cfg.MemMB = DefaultMemMB
	}
	if cfg.JobTokens <= 0 {
		cfg.JobTokens = DefaultJobTokens
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 5 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	return &Builder{cfg: cfg, slot: make(chan struct{}, 1), sessions: map[string]*session{}}, nil
}

// Private: a builder's candidate is never public, whatever its inputs'
// labels, since it was made in a private machine (C-3c-4, C-3c-6).
func (b *Builder) Private(loops.Brief) bool { return true }

// Cleanup destroys builder machines a previous run left behind.
func (b *Builder) Cleanup() {
	for _, id := range b.cfg.Machines.Machines() {
		if strings.HasPrefix(id, Prefix) {
			b.destroy(id)
		}
	}
}

// Build runs one job: a fresh private machine reads the brief and submits
// one candidate, or the job ends with an error when the time, the token
// cap or ctx runs out first. The machine is destroyed either way.
func (b *Builder) Build(ctx context.Context, br loops.Brief) (change.Candidate, error) {
	ns, ok := ClassNS[br.Hypothesis.Class]
	if !ok {
		return change.Candidate{}, fmt.Errorf("%w: %s", ErrClass, br.Hypothesis.Class)
	}
	select {
	case b.slot <- struct{}{}:
		defer func() { <-b.slot }()
	case <-ctx.Done():
		return change.Candidate{}, ctx.Err()
	}
	brief, err := json.Marshal(newBrief(br, ns))
	if err != nil {
		return change.Candidate{}, err
	}
	id := Prefix + newID()
	s := &session{b: b, id: id, ns: ns, brief: brief, done: make(chan struct{})}
	b.mu.Lock()
	b.sessions[id] = s
	b.mu.Unlock()
	defer b.endSession(id)

	ctx, cancel := context.WithTimeout(ctx, b.cfg.Timeout)
	defer cancel()
	m, err := b.cfg.Machines.Create(ctx, id, vm.Spec{
		Image: b.cfg.Image, Class: admission.Experiment, MemMB: b.cfg.MemMB,
		Argv: b.cfg.Argv, Env: b.cfg.Env, Label: vm.Private,
	})
	if err != nil {
		return change.Candidate{}, fmt.Errorf("%w: %v", ErrMachineUp, err)
	}
	defer b.destroy(id)
	if err := b.isClean(m); err != nil {
		return change.Candidate{}, err
	}
	tick := time.NewTicker(b.cfg.Poll)
	defer tick.Stop()
	for {
		select {
		case <-s.done:
			files := s.end()
			if files == nil {
				return change.Candidate{}, ErrNoResult
			}
			return change.Candidate{Source: change.Local, Origin: "loop1", Files: files}, nil
		case <-ctx.Done():
			if files := s.end(); files != nil {
				return change.Candidate{Source: change.Local, Origin: "loop1", Files: files}, nil
			}
			return change.Candidate{}, ctx.Err()
		case <-tick.C:
			m, err := b.cfg.Machines.Get(id)
			if err != nil {
				s.end()
				return change.Candidate{}, ErrNoResult
			}
			if err := b.isClean(m); err != nil {
				s.end()
				return change.Candidate{}, err
			}
			if m.State != vm.Running {
				// Preempted for higher-class work (RES-1): continue when
				// capacity allows, within the job's time.
				if err := b.cfg.Machines.Resume(ctx, id); err != nil && ctx.Err() == nil {
					b.cfg.Logf("loopbuild: resuming %s: %v", id, err)
				}
			}
		}
	}
}

// isClean checks the machine is what a builder machine must be: the
// builder image, not forked from anything, and labelled private.
func (b *Builder) isClean(m vm.Machine) error {
	switch {
	case m.Spec.Image != b.cfg.Image:
		return fmt.Errorf("%w: not on the builder image", ErrNotClean)
	case m.ForkBase != "":
		return fmt.Errorf("%w: forked from another machine", ErrNotClean)
	case m.Label != vm.Private:
		return fmt.Errorf("%w: not labelled private", ErrNotClean)
	}
	return nil
}

func (b *Builder) destroy(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := b.cfg.Machines.Destroy(ctx, id); err != nil && !errors.Is(err, vm.ErrUnknown) {
		b.cfg.Logf("loopbuild: destroying %s: %v", id, err)
	}
}

func (b *Builder) socketDir(id string) string { return filepath.Join(b.cfg.Dir, id) }

func newID() string {
	var r [8]byte
	rand.Read(r[:])
	return hex.EncodeToString(r[:])
}
