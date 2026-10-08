package dailyhost

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/dailypolicy"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/question"
)

func provisionedConfig(r *rig) Config {
	cfg := r.cfg
	cfg.Daily.Gate = nil
	cfg.Daily.Recheck = nil
	return cfg
}
func provisionedPolicy(r *rig, g *grants.Gate) dailypolicy.Config {
	return dailypolicy.Config{Budget: g, Clock: func(context.Context) (time.Time, error) { return r.now, nil }, Quiet: func(time.Time) bool { return false }, Eligible: func(context.Context, dq.Batch) error { return nil }, AgedAfter: time.Minute}
}
func provisionedGate(t *testing.T, r *rig, limit int) (*grants.Gate, grants.Config) {
	t.Helper()
	cfg := grants.Config{Now: func() time.Time { return r.now }, RequestsPerHour: limit, PacingStore: &change.FileStore{Path: filepath.Join(t.TempDir(), "pacing.json")}, PacingMaxStoreLatency: time.Second}
	first := grants.New(cfg)
	if first.PacingHealth() != nil {
		t.Fatal("trusted fixture provisioning")
	}
	cfg.PacingRequireExisting = true
	return grants.New(cfg), cfg
}

// REQ: CH-15
func TestProvisionedHostRejectsIncompleteAccountingConfiguration(t *testing.T) {
	r := setup(t)
	for _, cfg := range []grants.Config{{}, {PacingRequireExisting: true}, {PacingStore: &change.MemStore{}, PacingMaxStoreLatency: time.Second}, {PacingStore: &change.MemStore{}, PacingRequireExisting: true}, {PacingStore: &change.MemStore{}, PacingRequireExisting: true, PacingMaxStoreLatency: -time.Second}, {PacingStore: &change.MemStore{}, PacingRequireExisting: true, PacingMaxStoreLatency: 6 * time.Minute}} {
		g := grants.New(cfg)
		if h, err := NewProvisioned(provisionedConfig(r), provisionedPolicy(r, g)); h != nil || err != ErrConfig {
			t.Fatal("unsafe configuration accepted", err)
		}
	}
	if h, err := NewProvisioned(provisionedConfig(r), provisionedPolicy(r, nil)); h != nil || err != ErrConfig {
		t.Fatal("nil shared gate accepted")
	}
}

// REQ: CH-15
func TestProvisionedHostRejectsAmbiguousPolicyBindings(t *testing.T) {
	r := setup(t)
	g, _ := provisionedGate(t, r, 3)
	for _, kind := range []string{"reserve", "recheck", "health", "engine", "clock"} {
		t.Run(kind, func(t *testing.T) {
			cfg := provisionedConfig(r)
			pc := provisionedPolicy(r, g)
			switch kind {
			case "reserve":
				cfg.Daily.Gate = func(context.Context, dq.Batch) error { return nil }
			case "recheck":
				cfg.Daily.Recheck = func(context.Context, dq.Batch) error { return nil }
			case "health":
				cfg.PolicyHealth = func() error { return nil }
			case "engine":
				pc.Engine = &engine{}
			case "clock":
				pc.Clock = nil
			}
			if h, err := NewProvisioned(cfg, pc); h != nil || err != ErrConfig {
				t.Fatal("ambiguous/incomplete policy accepted", err)
			}
		})
	}
}

// REQ: CH-15, CH-11, CH-2
func TestProvisionedHostMissingLedgerPreservesHeldRecoveryControls(t *testing.T) {
	r := setup(t)
	path := filepath.Join(t.TempDir(), "absent.json")
	g := grants.New(grants.Config{Now: func() time.Time { return r.now }, PacingStore: &change.FileStore{Path: path}, PacingRequireExisting: true, PacingMaxStoreLatency: time.Second})
	h, err := NewProvisioned(provisionedConfig(r), provisionedPolicy(r, g))
	if err != nil {
		t.Fatal(err)
	}
	if h.Status().Code != Recovery || !h.Status().Held || h.Health() != ErrPolicyRecovery || h.Activate() != ErrPolicyRecovery {
		t.Fatal("missing ledger did not hold host")
	}
	if _, err = h.Step(t.Context()); err != ErrPolicyRecovery || r.m.count() != 0 {
		t.Fatal("recovery host dispatched", err)
	}
	if err = h.Channel().LocalStop(t.Context()); err != nil || !r.e.Stopped() {
		t.Fatal("recovery host lost STOP", err)
	}
	b, err := (&change.FileStore{Path: path}).Load()
	if err != nil || b != nil {
		t.Fatal("assembly initialized missing ledger")
	}
}

// REQ: CH-15, CH-2
func TestProvisionedHostUsesCommonDebtAndExactlyOneReservation(t *testing.T) {
	r := setup(t)
	g, cfg := provisionedGate(t, r, 2)
	book, err := question.New(question.Config{Reserve: g.Reserve, Now: func(context.Context) (time.Time, error) { return r.now, nil }, Send: func(string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	q, err := book.Ask(t.Context(), "synthetic-agent", "synthetic-choice", question.Spec{Text: "Which color?", Default: "blue", Wait: 10 * time.Minute})
	if err != nil || q.State != question.Waiting {
		t.Fatal("fixture question reservation", err)
	}
	h, err := NewProvisioned(provisionedConfig(r), provisionedPolicy(r, g))
	if err != nil {
		t.Fatal(err)
	}
	if !h.Status().Held || r.m.count() != 0 {
		t.Fatal("construction activated notifications")
	}
	if err = h.Activate(); err != nil {
		t.Fatal(err)
	}
	id, err := h.Step(t.Context())
	if err != nil || id == 0 || r.m.count() != 1 {
		t.Fatal(id, err)
	}
	if g.Reserve(false) {
		t.Fatal("digest did not consume shared allowance")
	}
	reopened := grants.New(cfg)
	if reopened.PacingHealth() != nil || reopened.Reserve(false) {
		t.Fatal("strict reopen lost shared debt")
	}
	if err = h.Channel().LocalStop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = r.e.Resume(); err != nil {
		t.Fatal(err)
	}
	if !h.Status().Held {
		t.Fatal("RESUME activated host")
	}
}

// REQ: CH-15, CH-11
func TestProvisionedHostCannotOmitRecoveryBinding(t *testing.T) {
	r := setup(t)
	s := &change.MemStore{}
	cfg := grants.Config{Now: func() time.Time { return r.now }, PacingStore: s, PacingMaxStoreLatency: time.Second}
	g := grants.New(cfg)
	cfg.PacingRequireExisting = true
	g = grants.New(cfg)
	h, err := NewProvisioned(provisionedConfig(r), provisionedPolicy(r, g))
	if err != nil {
		t.Fatal(err)
	}
	if err = h.Activate(); err != nil {
		t.Fatal(err)
	}
	s.Fail = errors.New("synthetic private custody canary")
	if g.Reserve(false) {
		t.Fatal("failed ledger reservation accepted")
	}
	if _, err = h.Step(t.Context()); err != ErrPolicyRecovery || h.Status().Code != Recovery || r.m.count() != 0 {
		t.Fatal("unbound recovery", err)
	}
	if strings.Contains(h.Status().Line(), "canary") {
		t.Fatal("private error disclosed")
	}
}

type hostAccountingBlock struct {
	file             *change.FileStore
	block            bool
	entered, release chan struct{}
}

func (s *hostAccountingBlock) Load() ([]byte, error) { return s.file.Load() }
func (s *hostAccountingBlock) Save(b []byte) error {
	if s.block {
		close(s.entered)
		<-s.release
	}
	return s.file.Save(b)
}

// REQ: CH-15, CH-11, CH-2
func TestProvisionedHostReportsStalledLedgerAndKeepsStop(t *testing.T) {
	r := setup(t)
	s := &hostAccountingBlock{file: &change.FileStore{Path: filepath.Join(t.TempDir(), "pacing.json")}, entered: make(chan struct{}), release: make(chan struct{})}
	gc := grants.Config{Now: func() time.Time { return r.now }, PacingStore: s, PacingMaxStoreLatency: 200 * time.Millisecond}
	g := grants.New(gc)
	if g.PacingHealth() != nil {
		t.Fatal("fixture provisioning")
	}
	gc.PacingRequireExisting = true
	g = grants.New(gc)
	h, err := NewProvisioned(provisionedConfig(r), provisionedPolicy(r, g))
	if err != nil {
		t.Fatal(err)
	}
	s.block = true
	result := make(chan bool, 1)
	go func() { result <- g.Reserve(false) }()
	<-s.entered
	t.Cleanup(func() {
		select {
		case <-s.release:
		default:
			close(s.release)
		}
	})
	timer := time.NewTimer(250 * time.Millisecond)
	<-timer.C
	health := make(chan error, 1)
	go func() { health <- h.Health() }()
	select {
	case err := <-health:
		if err != ErrPolicyRecovery {
			t.Fatal("overdue health not bound", err)
		}
	case <-time.After(time.Second):
		t.Fatal("host health waited for ledger save")
	}
	if _, err = h.Step(t.Context()); err != ErrPolicyRecovery || h.Status().Code != Recovery || r.m.count() != 0 {
		t.Fatal("overdue host dispatched", err)
	}
	if err = h.Channel().LocalStop(t.Context()); err != nil || !r.e.Stopped() {
		t.Fatal("overdue host lost STOP", err)
	}
	close(s.release)
	if <-result {
		t.Fatal("overdue reservation returned permission")
	}
}
