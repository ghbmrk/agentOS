package dailyhost

import (
	"context"
	"errors"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestqueue/dailypolicy"
	"github.com/ghbmrk/agentos/broker/grants"
)

// REQ: CH-15
func TestHostPolicyRecoveryRefusesActivationAndProducesFixedStatus(t *testing.T) {
	r := setup(t)
	fail := false
	r.cfg.PolicyHealth = func() error {
		if fail {
			return errors.New("synthetic private policy canary")
		}
		return nil
	}
	h, err := New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.Activate(); err != nil {
		t.Fatal(err)
	}
	fail = true
	before, err := r.cfg.Daily.Queue.List()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Step(t.Context()); err != ErrPolicyRecovery {
		t.Fatal("policy failure escaped host", err)
	}
	after, err := r.cfg.Daily.Queue.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) || r.m.count() != 0 {
		t.Fatal("health refusal mutated queue or sent")
	}
	if h.Status().Code != Recovery || strings.Contains(h.Status().Line(), "canary") {
		t.Fatal(h.Status())
	}
	h.Hold()
	if err = h.Activate(); err != ErrPolicyRecovery || !h.Status().Held {
		t.Fatal("reactivated unhealthy policy", err)
	}
}

// REQ: CH-15
func TestHostBindsActualDurablePolicyHealth(t *testing.T) {
	r := setup(t)
	s := &change.MemStore{}
	g := grants.New(grants.Config{Now: func() time.Time { return r.now }, PacingStore: s})
	p, err := dailypolicy.New(dailypolicy.Config{Budget: g, Engine: r.e, Clock: func(_ context.Context) (time.Time, error) { return r.now, nil }, Quiet: func(time.Time) bool { return false }, Eligible: func(context.Context, dq.Batch) error { return nil }, AgedAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	r.cfg.PolicyHealth = p.Health
	r.cfg.Daily.Gate = p.Check
	r.cfg.Daily.Recheck = p.Recheck
	h, err := New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.Activate(); err != nil {
		t.Fatal(err)
	}
	s.Fail = errors.New("synthetic accounting canary")
	if g.Reserve(false) {
		t.Fatal("failed accounting admitted")
	}
	if _, err = h.Step(t.Context()); err != ErrPolicyRecovery || r.m.count() != 0 || h.Status().Code != Recovery {
		t.Fatal(err, h.Status(), r.m.count())
	}
	// A new ledger cannot clear a quarantined gate. Reopening the same file
	// is covered in policy tests; replacing a live object's store is not recovery.
}

// REQ: CH-11, CH-15
func TestBlockedPolicyHealthDoesNotDelayStopOrAllowStaleActivation(t *testing.T) {
	r := setup(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	block := false
	r.cfg.PolicyHealth = func() error {
		if block {
			close(entered)
			<-release
		}
		return nil
	}
	h, err := New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	block = true
	activate := make(chan error, 1)
	go func() { activate <- h.Activate() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("health callback not entered")
	}
	stop := make(chan error, 1)
	go func() { stop <- h.Channel().LocalStop(t.Context()) }()
	select {
	case err := <-stop:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("STOP waited for policy health")
	}
	if err = r.e.Resume(); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err = <-activate; err == nil || !h.Status().Held || r.m.count() != 0 {
		t.Fatal("stale activation survived STOP/RESUME", err)
	}
}
