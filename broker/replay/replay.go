// Package replay is the change pipeline's Evaluator (SPEC LOOP-5, CHG-1):
// counterfactual replay of a past task inside a fresh agent machine.
//
// Each Run creates an experiment-class machine from the guest image, seeds
// its layer with the tree under evaluation (the guest-facing namespaces),
// hands the guest the case's input as an owner message, and returns the
// guest's reply. The machine's socket is served by a guest plane of its own
// (package guest, unchanged) whose services are replay versions:
//
//   - broker tools: an effect request is answered from the journaled
//     outcome of the same effect in the task the case came from. Nothing
//     reaches the journal or an executor. An effect the task did not record
//     fails the run (fails closed).
//   - owner messages: the case input goes in; the reply is the output and
//     never reaches the owner.
//   - model access: Config.Model, metered by Config.Meter, built for the
//     tree under evaluation (its routing rule). Without Model, model calls
//     answer 503, and replay is fully offline (ASSUMPTIONS R2).
//
// The machine has no network (vm), so these are all the guest can reach.
// It is destroyed when the run ends, whatever the outcome.
//
// Assumptions are listed in ASSUMPTIONS.md next to this file.
package replay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/vm"
)

// Prefix starts every replay machine's ID. Services routes on it, and the
// machine manager keeps it for replay (vm.EvalPrefix).
const Prefix = vm.EvalPrefix

// TreeDir is where the guest finds the tree under evaluation.
const TreeDir = "etc/agentos/tree"

// untested are the namespaces a replay cannot exercise: it boots the
// configured image and guest configuration, not the tree's. A tree that
// changes them is not evaluated (ErrNotEvaluated).
var untested = []string{"config", "guest-image", "host-image"}

// guestNamespaces are the tree namespaces a guest reads. Routing is applied
// on the broker side (Config.Model); the authority and governance
// namespaces are the broker's and never reach a guest.
var guestNamespaces = map[string]bool{"procedures": true, "skills": true, "context": true}

// Machines is the part of the machine manager (vm.Manager) replay uses.
type Machines interface {
	CreateSeeded(ctx context.Context, id string, s vm.Spec, seed map[string][]byte) (vm.Machine, error)
	Destroy(ctx context.Context, id string) error
	Machines() []string
}

// Recordings supplies the effects recorded for a probe: the journaled
// intents of the real task its case came from. The probe ID is opaque to
// the evaluator; the lookup is the broker's (the change pipeline's case
// store). A probe with no task, such as a security fixture, has none.
type Recordings interface {
	Effects(probeID string) ([]journal.Status, error)
}

// Config configures New.
type Config struct {
	Machines   Machines
	Recordings Recordings
	// Active returns the active tree's files in namespace ns (the change
	// pipeline's Files). A tree that differs from it under the untested
	// namespaces is not evaluated.
	Active func(ns string) change.Tree
	// Spec is the replay machine: Image, MemMB, Argv, Env. Class is always
	// Experiment and Label private (owner task data, REV-5).
	Spec vm.Spec
	// Dir holds the replay machines' socket directories (0700).
	Dir string
	// Model returns model access for a run on tree t. Nil serves no model
	// access. Meter is required with it: model calls are never unmetered.
	Model func(t change.Tree) http.Handler
	Meter *meter.Meter
	// Timeout bounds one run, from creating the machine to its reply.
	// Default 10 minutes.
	Timeout time.Duration
	// Logf reports broker-side faults. Nil is silent.
	Logf func(format string, args ...any)
}

var (
	// ErrUnrecorded: the guest asked for an effect the task did not record.
	ErrUnrecorded = errors.New("replay: unrecorded effect; replay fails closed")
	// ErrNoReply: the guest did not answer within the run's time.
	ErrNoReply = errors.New("replay: no reply from the guest")
	// ErrNotEvaluated: the tree changes what a replay cannot run (the
	// image or the guest configuration), so it was not tested on this box.
	// It is never a pass.
	ErrNotEvaluated = errors.New("replay: not tested on this box (changes the image or configuration)")
)

// destroyTimeout bounds destroying a replay machine after its run.
const destroyTimeout = 2 * time.Minute

// Evaluator implements change.Evaluator. It is also the vm.Services for
// replay machines (see Services).
type Evaluator struct {
	cfg   Config
	plane *guest.Plane
	mu    sync.Mutex
	runs  map[string]*run
}

// New checks cfg and starts the replay plane.
func New(cfg Config) (*Evaluator, error) {
	if cfg.Machines == nil || cfg.Recordings == nil || cfg.Active == nil || cfg.Dir == "" || cfg.Spec.Image == "" {
		return nil, errors.New("replay: Machines, Recordings, Active, Dir, and Spec.Image are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Minute
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	cfg.Spec.Class = admission.Experiment
	cfg.Spec.Label = vm.Private
	e := &Evaluator{cfg: cfg, runs: map[string]*run{}}
	pc := guest.Config{
		Dir:        cfg.Dir,
		Machines:   planeMachines{},
		Effects:    effects{e},
		Route:      func(string) (string, bool) { return "replay", true },
		OwnerReply: e.reply,
		Logf:       cfg.Logf,
	}
	if cfg.Model != nil {
		pc.Meter = cfg.Meter
		pc.Model = func(id string) http.Handler {
			if r := e.get(id); r != nil && r.model != nil {
				return r.model
			}
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "no replay run", http.StatusServiceUnavailable)
			})
		}
	}
	p, err := guest.New(pc)
	if err != nil {
		return nil, fmt.Errorf("replay: %w", err)
	}
	e.plane = p
	// Replay machines left by an earlier broker run belong to no run.
	for _, id := range cfg.Machines.Machines() {
		if strings.HasPrefix(id, Prefix) {
			ctx, cancel := context.WithTimeout(context.Background(), destroyTimeout)
			if err := cfg.Machines.Destroy(ctx, id); err != nil {
				cfg.Logf("replay: destroy leftover %s: %v", id, err)
			}
			cancel()
		}
	}
	return e, nil
}

// run is one replay in progress.
type run struct {
	id    string
	model http.Handler
	fx    *recorded
	mu    sync.Mutex
	msg   string // the owner message the case input went in as
	out   chan []byte
	fail  chan error
	once  sync.Once
}

func (r *run) failed(err error) {
	r.once.Do(func() { r.fail <- err })
}

// Run replays probe c on tree t and returns the guest's reply.
func (e *Evaluator) Run(ctx context.Context, t change.Tree, c change.Probe) ([]byte, error) {
	for _, ns := range untested {
		if !sameFiles(inNamespace(t, ns), e.cfg.Active(ns)) {
			return nil, fmt.Errorf("%w: %s", ErrNotEvaluated, ns)
		}
	}
	recs, err := e.cfg.Recordings.Effects(c.ID)
	if err != nil {
		return nil, fmt.Errorf("replay: recordings for %s: %w", c.ID, err)
	}
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	r := &run{id: Prefix + hex.EncodeToString(b[:]), fx: newRecorded(recs), out: make(chan []byte, 1), fail: make(chan error, 1)}
	r.fx.onMiss = r.failed
	if e.cfg.Model != nil {
		r.model = e.cfg.Model(t)
	}
	e.mu.Lock()
	e.runs[r.id] = r
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.runs, r.id)
		e.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()
	if _, err := e.cfg.Machines.CreateSeeded(ctx, r.id, e.cfg.Spec, seed(t)); err != nil {
		return nil, fmt.Errorf("replay: start %s: %w", c.ID, err)
	}
	defer func() {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), destroyTimeout)
		defer cancel()
		if err := e.cfg.Machines.Destroy(dctx, r.id); err != nil {
			e.cfg.Logf("replay: destroy %s: %v", r.id, err)
		}
	}()
	r.mu.Lock()
	msg, err := e.plane.DeliverOwner(r.id, string(c.Input), false)
	r.msg = msg
	r.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("replay: deliver %s: %w", c.ID, err)
	}
	select {
	case out := <-r.out:
		return out, nil
	case err := <-r.fail:
		return nil, fmt.Errorf("replay %s: %w", c.ID, err)
	case <-ctx.Done():
		return nil, fmt.Errorf("replay %s: %w: %v", c.ID, ErrNoReply, ctx.Err())
	}
}

func inNamespace(t change.Tree, ns string) change.Tree {
	out := change.Tree{}
	for p, b := range t {
		if first, _, _ := strings.Cut(p, "/"); first == ns {
			out[p] = b
		}
	}
	return out
}

func sameFiles(a, b change.Tree) bool {
	if len(a) != len(b) {
		return false
	}
	for p, x := range a {
		y, ok := b[p]
		if !ok || !bytes.Equal(x, y) {
			return false
		}
	}
	return true
}

// seed lays the guest-facing part of t out under TreeDir. Tree paths are
// already clean (change.cleanPath); anything else is skipped.
func seed(t change.Tree) map[string][]byte {
	out := map[string][]byte{}
	for p, b := range t {
		ns, _, _ := strings.Cut(p, "/")
		if !guestNamespaces[ns] || path.Clean(p) != p || strings.HasPrefix(p, "../") {
			continue
		}
		out[path.Join(TreeDir, p)] = b
	}
	return out
}

func (e *Evaluator) get(id string) *run {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.runs[id]
}

// reply receives the guest's answer. Only the answer to the case's own
// message is the output.
func (e *Evaluator) reply(machine, msgID, text string) {
	r := e.get(machine)
	if r == nil {
		return
	}
	r.mu.Lock()
	ok := msgID == r.msg
	r.mu.Unlock()
	if ok {
		select {
		case r.out <- []byte(text):
		default:
		}
	}
}

// Open and Close make the Evaluator the vm.Services of replay machines.
func (e *Evaluator) Open(id string) (string, error) { return e.plane.Open(id) }
func (e *Evaluator) Close(id string)                { e.plane.Close(id) }

// Shutdown stops the replay plane.
func (e *Evaluator) Shutdown() { e.plane.Shutdown() }

// Services routes each machine to its guest services: replay machines (ID
// starting with Prefix) to the evaluator, every other machine to Live. A
// replay machine never reaches the live plane, so it never reaches the
// journal, an executor, or the owner. Live may be nil.
type Services struct {
	Live   vm.Services
	Replay *Evaluator
}

func (s Services) Open(id string) (string, error) {
	if strings.HasPrefix(id, Prefix) {
		return s.Replay.Open(id)
	}
	if s.Live == nil {
		return "", nil
	}
	return s.Live.Open(id)
}

func (s Services) Close(id string) {
	if strings.HasPrefix(id, Prefix) {
		s.Replay.Close(id)
		return
	}
	if s.Live != nil {
		s.Live.Close(id)
	}
}

// planeMachines is the replay plane's view of its machines: a replay
// machine is its own lineage, is already private, and takes no per-step
// snapshots (it is thrown away, and must not fill the snapshot store).
type planeMachines struct{}

func (planeMachines) Step(context.Context, string) error { return nil }
func (planeMachines) RaisePrivate(string) error          { return nil }
func (planeMachines) Lineage(id string) (string, error)  { return id, nil }

// effects routes the plane's effect calls to the run whose machine made
// them, by the origin the plane sets ("guest:<machine>").
type effects struct{ e *Evaluator }

func (f effects) fx(in string) (*recorded, error) {
	id, _, _ := strings.Cut(in, "/")
	if r := f.e.get(id); r != nil {
		return r.fx, nil
	}
	return nil, errors.New("replay: no run for this machine")
}

func (f effects) Submit(in journal.Intent) (journal.Status, error) {
	fx, err := f.fx(in.ID)
	if err != nil {
		return journal.Status{}, err
	}
	return fx.Submit(in)
}

func (f effects) Authorize(_ context.Context, id string) (journal.Status, error) {
	fx, err := f.fx(id)
	if err != nil {
		return journal.Status{}, err
	}
	return fx.Authorize(id)
}

func (f effects) Dispatch(_ context.Context, id string) (journal.Status, error) {
	fx, err := f.fx(id)
	if err != nil {
		return journal.Status{}, err
	}
	return fx.Dispatch(id)
}

func (f effects) Get(id string) (journal.Status, error) {
	fx, err := f.fx(id)
	if err != nil {
		return journal.Status{}, err
	}
	return fx.Get(id)
}
