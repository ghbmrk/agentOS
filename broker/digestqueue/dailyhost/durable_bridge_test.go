package dailyhost

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/change"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/daily"
	"github.com/ghbmrk/agentos/broker/digestqueue/dailypolicy"
	"github.com/ghbmrk/agentos/broker/digestqueue/heartbeat"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/question"
)

func newDurableBridgeFixture(t *testing.T) *bridgeFixture {
	t.Helper()
	f := &bridgeFixture{dir: t.TempDir(), now: time.Date(2026, 10, 8, 11, 59, 0, 0, time.UTC), eng: &engine{}}
	f.pacing = &change.FileStore{Path: filepath.Join(f.dir, "pacing")}
	f.open(t, nil, true)
	if f.h.cfg.PolicyHealth == nil || f.budget.PacingHealth() != nil {
		t.Fatal("durable health not bound")
	}
	return f
}

// Retire the previous host's whole dispatch scope before replacing all writers.
// The same protected paths are reused, never an empty replacement ledger.
func reopenDurableBridge(t *testing.T, f *bridgeFixture) {
	t.Helper()
	oldHost, oldQueue, oldNotes, oldBudget, oldBeat := f.h, f.q, f.n, f.budget, f.h.cfg.Daily.Heartbeat
	if err := oldHost.Quiesce(t.Context(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	f.pacing = &change.FileStore{Path: filepath.Join(f.dir, "pacing")}
	f.open(t, nil, false)
	if f.h == oldHost || f.q == oldQueue || f.n == oldNotes || f.budget == oldBudget || f.h.cfg.Daily.Heartbeat == oldBeat {
		t.Fatal("reopen reused live state")
	}
	if !f.h.Status().Held {
		t.Fatal("reopen activated notifications")
	}
}

func durableQuestionBook(t *testing.T, f *bridgeFixture) *question.Book {
	t.Helper()
	b, err := question.New(question.Config{Send: f.h.Channel().Notify, Now: func(context.Context) (time.Time, error) { return f.now, nil }, Reserve: f.budget.Reserve, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func askThroughActualBridge(t *testing.T, f *bridgeFixture, b *question.Book, key string) {
	t.Helper()
	type result struct {
		status question.Status
		err    error
	}
	done := make(chan result, 1)
	go func() {
		s, err := b.Ask(t.Context(), "synthetic-agent", key, question.Spec{Text: "Which tray?", Default: "left", Wait: 10 * time.Minute})
		done <- result{s, err}
	}()
	item := bridgePoll(t, f.link)
	if item.To != "+15550000999" || !strings.Contains(item.Text, "Which tray?") {
		t.Fatal(item)
	}
	bridgeOp(t, f.link, bridgeproto.OpSent, bridgeproto.Sent{ID: item.ID, Code: bridgeproto.CodeOK}, nil)
	select {
	case r := <-done:
		if r.err != nil || r.status.State != question.Waiting {
			t.Fatal(r)
		}
	case <-time.After(time.Second):
		t.Fatal("question did not return")
	}
}
func acceptDurableDigest(t *testing.T, f *bridgeFixture, wantID uint64) uint64 {
	t.Helper()
	done := bridgeStep(t, f.h)
	item := bridgePoll(t, f.link)
	if item.To != "+15550000999" || !strings.Contains(item.Text, heartbeat.Line) {
		t.Fatal(item)
	}
	bridgeOp(t, f.link, bridgeproto.OpSent, bridgeproto.Sent{ID: item.ID, Code: bridgeproto.CodeOK}, nil)
	r := bridgeAwaitStep(t, done)
	if r.err != nil || r.id == 0 || wantID != 0 && r.id != wantID {
		t.Fatal(r)
	}
	return r.id
}
func requireQuestionHeld(t *testing.T, f *bridgeFixture, b *question.Book, key string) {
	t.Helper()
	s, err := b.Ask(t.Context(), "synthetic-agent", key, question.Spec{Text: "Which tray?", Default: "left", Wait: 10 * time.Minute})
	if err != nil || s.State != question.Held {
		t.Fatal(s, err)
	}
	bridgeEmpty(t, f.link)
}

// REQ: CH-15, CH-18, OP-1, OP-2
func TestFiveStoreAcceptedReopenPreservesSharedQuestionDebt(t *testing.T) {
	f := newDurableBridgeFixture(t)
	book := durableQuestionBook(t, f)
	askThroughActualBridge(t, f, book, "first")
	askThroughActualBridge(t, f, book, "second")
	f.now = f.now.Add(time.Minute)
	if err := f.h.Activate(); err != nil {
		t.Fatal(err)
	}
	id := acceptDurableDigest(t, f, 0)
	oldBudget := f.budget
	reopenDurableBridge(t, f)
	if f.budget == oldBudget || f.budget.Reserve(false) {
		t.Fatal("five-store reopen reset shared debt")
	}
	if err := f.h.Activate(); err != nil {
		t.Fatal(err)
	}
	again, err := f.h.Step(t.Context())
	if err != nil || again != id {
		t.Fatal(again, err)
	}
	b, err := f.q.Get(id)
	if err != nil || b.State != dq.Accepted || b.Attempts != 1 {
		t.Fatal(b, err)
	}
	requireQuestionHeld(t, f, durableQuestionBook(t, f), "after-restart")
	// Ordinary time advancement frees the pacing allowance; it does not create
	// a second daily identity or resurrect acknowledged owner notes.
	f.now = f.now.Add(time.Hour)
	bridgeOp(t, f.link, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	askThroughActualBridge(t, f, durableQuestionBook(t, f), "next-hour")
	if got, err := f.h.Step(t.Context()); err != nil || got != id {
		t.Fatal(got, err)
	}
	bridgeEmpty(t, f.link)
	if note, err := f.n.Peek(t.Context()); err != nil || note != nil {
		t.Fatal(note, err)
	}
}

// REQ: CH-15, OP-1, OP-2
func TestFiveStorePacedReadyReopenSendsSameBatchWhenBudgetExpires(t *testing.T) {
	f := newDurableBridgeFixture(t)
	book := durableQuestionBook(t, f)
	for i := range 3 {
		askThroughActualBridge(t, f, book, fmt.Sprint(i))
	}
	f.now = f.now.Add(time.Minute)
	if err := f.h.Activate(); err != nil {
		t.Fatal(err)
	}
	id, err := f.h.Step(t.Context())
	if id == 0 || !errors.Is(err, dailypolicy.ErrPaced) {
		t.Fatal(id, err)
	}
	b, err := f.q.Get(id)
	if err != nil || b.State != dq.Ready || b.Attempts != 0 {
		t.Fatal(b, err)
	}
	bridgeEmpty(t, f.link)
	reopenDurableBridge(t, f)
	if err = f.h.Activate(); err != nil {
		t.Fatal(err)
	}
	again, err := f.h.Step(t.Context())
	if again != id || !errors.Is(err, dailypolicy.ErrPaced) {
		t.Fatal(again, err)
	}
	bridgeEmpty(t, f.link)
	f.now = f.now.Add(59 * time.Minute) // initial question debt expires before digest TTL
	bridgeOp(t, f.link, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	acceptDurableDigest(t, f, id)
	b, err = f.q.Get(id)
	if err != nil || b.State != dq.Accepted || b.Attempts != 1 {
		t.Fatal(b, err)
	}
	reopenDurableBridge(t, f)
	available := 0
	for f.budget.Reserve(false) {
		available++
	}
	if available != 2 {
		t.Fatal("retry double-counted or lost debt", available)
	}
}

type durableBridgeLedgerCut struct {
	file        *change.FileStore
	fail, after bool
}

func (s *durableBridgeLedgerCut) Load() ([]byte, error) { return s.file.Load() }
func (s *durableBridgeLedgerCut) Save(b []byte) error {
	if !s.fail {
		return s.file.Save(b)
	}
	if s.after {
		if err := s.file.Save(b); err != nil {
			return err
		}
	}
	return errors.New("synthetic private ledger canary")
}

// REQ: CH-15, OP-1, OP-2
func TestFiveStoreLedgerCutRecoversExactDebtBeforeBridgeRetry(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprint(after), func(t *testing.T) {
			f := newDurableBridgeFixture(t)
			// Install the fault wrapper while all previous dispatch/store writers are
			// quiescent, and fail only the dispatch reservation after construction.
			if err := f.h.Quiesce(t.Context(), func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			cut := &durableBridgeLedgerCut{file: &change.FileStore{Path: filepath.Join(f.dir, "pacing")}, after: after}
			f.pacing = cut
			f.open(t, nil, false)
			f.now = f.now.Add(time.Minute)
			if err := f.h.Activate(); err != nil {
				t.Fatal(err)
			}
			cut.fail = true
			id, err := f.h.Step(t.Context())
			if id == 0 || !errors.Is(err, dailypolicy.ErrRecovery) {
				t.Fatal(id, err)
			}
			bridgeEmpty(t, f.link)
			if _, err = f.h.Step(t.Context()); err != ErrPolicyRecovery || f.h.Status().Code != Recovery || strings.Contains(f.h.Status().Line(), "canary") {
				t.Fatal(err, f.h.Status())
			}
			if err = f.h.Activate(); err != ErrPolicyRecovery {
				t.Fatal("broken budget activated", err)
			}
			b, err := f.q.Get(id)
			if err != nil || b.State != dq.Ready || b.Attempts != 0 {
				t.Fatal(b, err)
			}
			// Clearing the store wrapper alone cannot repair the quarantined Gate.
			cut.fail = false
			if f.budget.Reserve(false) || f.budget.PacingHealth() != grants.ErrPacingRecovery {
				t.Fatal("live repair bypass")
			}
			reopenDurableBridge(t, f)
			if err = f.h.Activate(); err != nil {
				t.Fatal(err)
			}
			acceptDurableDigest(t, f, id)
			reopenDurableBridge(t, f)
			available := 0
			for f.budget.Reserve(false) {
				available++
			}
			want := 2
			if after {
				want = 1
			}
			if available != want {
				t.Fatal("recovery refunded or lost an uncertain reservation", available, want)
			}
		})
	}
}

type durableBridgeLedgerBlock struct {
	file             *change.FileStore
	block            bool
	entered, release chan struct{}
}

func (s *durableBridgeLedgerBlock) Load() ([]byte, error) { return s.file.Load() }
func (s *durableBridgeLedgerBlock) Save(b []byte) error {
	if s.block {
		close(s.entered)
		<-s.release
	}
	return s.file.Save(b)
}

// REQ: CH-11, CH-15, OP-1, OP-2
func TestFiveStoreStopDuringLedgerSaveSpendsButNeverHandsOff(t *testing.T) {
	f := newDurableBridgeFixture(t)
	if err := f.h.Quiesce(t.Context(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	block := &durableBridgeLedgerBlock{file: &change.FileStore{Path: filepath.Join(f.dir, "pacing")}, entered: make(chan struct{}), release: make(chan struct{})}
	released := false
	t.Cleanup(func() {
		if !released {
			close(block.release)
		}
	})
	f.pacing = block
	f.open(t, nil, false)
	f.now = f.now.Add(time.Minute)
	if err := f.h.Activate(); err != nil {
		t.Fatal(err)
	}
	block.block = true
	done := bridgeStep(t, f.h)
	select {
	case <-block.entered:
	case <-time.After(time.Second):
		t.Fatal("ledger did not block")
	}
	bridgeStop(t, f.h, true)
	close(block.release)
	released = true
	r := bridgeAwaitStep(t, done)
	if !errors.Is(r.err, context.Canceled) {
		t.Fatal(r)
	}
	bridgeEmpty(t, f.link)
	b, err := f.q.Get(r.id)
	if err != nil || b.State != dq.Ready || b.Attempts != 0 {
		t.Fatal(b, err)
	}
	if err = f.eng.Resume(); err != nil {
		t.Fatal(err)
	}
	reopenDurableBridge(t, f)
	if _, err = f.h.Step(t.Context()); !errors.Is(err, daily.ErrHeld) {
		t.Fatal(err)
	}
	if err = f.h.Activate(); err != nil {
		t.Fatal(err)
	}
	acceptDurableDigest(t, f, r.id)
	reopenDurableBridge(t, f)
	if !f.budget.Reserve(false) || f.budget.Reserve(false) {
		t.Fatal("cancelled durable reservation was refunded")
	}
}

// REQ: CH-11, CH-15, OP-1, OP-2
func TestFiveStoreUnknownReopenKeepsDebtAndRejectsLateBridgeAcceptance(t *testing.T) {
	f := newDurableBridgeFixture(t)
	book := durableQuestionBook(t, f)
	askThroughActualBridge(t, f, book, "one")
	askThroughActualBridge(t, f, book, "two")
	f.now = f.now.Add(time.Minute)
	if err := f.h.Activate(); err != nil {
		t.Fatal(err)
	}
	done := bridgeStep(t, f.h)
	item := bridgePoll(t, f.link)
	bridgeStop(t, f.h, true)
	r := bridgeAwaitStep(t, done)
	if !errors.Is(r.err, context.Canceled) {
		t.Fatal(r)
	}
	bridgeOp(t, f.link, bridgeproto.OpSent, bridgeproto.Sent{ID: item.ID, Code: bridgeproto.CodeOK}, nil)
	if f.link.Stray() != 1 {
		t.Fatal("late acceptance not stray")
	}
	if err := f.eng.Resume(); err != nil {
		t.Fatal(err)
	}
	reopenDurableBridge(t, f)
	if err := f.h.Activate(); err != nil {
		t.Fatal(err)
	}
	id, err := f.h.Step(t.Context())
	if id != r.id || !errors.Is(err, daily.ErrUncertain) {
		t.Fatal(id, err)
	}
	b, err := f.q.Get(id)
	if err != nil || b.State != dq.Unknown || b.Attempts != 1 {
		t.Fatal(b, err)
	}
	requireQuestionHeld(t, f, durableQuestionBook(t, f), "unknown-restart")
}
