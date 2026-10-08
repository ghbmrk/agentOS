package dailyhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestnotes"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/daily"
	"github.com/ghbmrk/agentos/broker/digestqueue/dailypolicy"
	"github.com/ghbmrk/agentos/broker/digestqueue/heartbeat"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/sockets"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type bridgeFixture struct {
	dir    string
	now    time.Time
	h      *Host
	q      *dq.Queue
	n      *digestnotes.Source
	link   *modemlink.Link
	eng    *engine
	budget *grants.Gate
}

var bridgeLimits = dq.Limits{MaxBatches: 8, MaxSources: 4, MaxAttempts: 3, MaxBytes: 65536}

func bridgeOp(t *testing.T, l *modemlink.Link, op string, args, out any) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	res, err := l.Ops()[op](t.Context(), sockets.Peer{Kind: "owner"}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		raw, err = json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
}
func bridgePoll(t *testing.T, l *modemlink.Link) *bridgeproto.Item {
	t.Helper()
	var out struct{ Item *bridgeproto.Item }
	deadline := time.Now().Add(time.Second)
	for out.Item == nil && time.Now().Before(deadline) {
		bridgeOp(t, l, bridgeproto.OpOutbox, struct{}{}, &out)
	}
	if out.Item == nil {
		t.Fatal("real bridge handoff never arrived")
	}
	return out.Item
}
func bridgeEmpty(t *testing.T, l *modemlink.Link) {
	t.Helper()
	var out struct{ Item *bridgeproto.Item }
	bridgeOp(t, l, bridgeproto.OpOutbox, struct{}{}, &out)
	if out.Item != nil {
		t.Fatal("unexpected bridge item", out.Item)
	}
}
func newBridgeFixture(t *testing.T, st dq.Store) *bridgeFixture {
	t.Helper()
	f := &bridgeFixture{dir: t.TempDir(), now: time.Date(2026, 10, 8, 11, 59, 0, 0, time.UTC), eng: &engine{}}
	f.open(t, st, true)
	return f
}
func (f *bridgeFixture) open(t *testing.T, st dq.Store, seed bool) {
	t.Helper()
	var err error
	f.n, err = digestnotes.New(digestnotes.Config{Store: &change.FileStore{Path: filepath.Join(f.dir, "notes")}, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	oc := owner.Config{Owner: "+15550000999", Store: owner.FileStore{Path: filepath.Join(f.dir, "owner")}, Engine: f.eng, Now: func() time.Time { return f.now }, Location: time.UTC}
	if seed {
		producer, err := owner.NewTransactional(oc, f.n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := producer.LocalSignIn("100000"); !errors.Is(err, owner.ErrWrongCode) {
			t.Fatal(err)
		}
	} // quiescent producer before installing transport; no unrelated urgent alert
	if st == nil {
		st = &change.FileStore{Path: filepath.Join(f.dir, "queue")}
	}
	f.q, err = dq.New(st, bridgeLimits)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() (time.Time, error) { return f.now, nil }
	hb, err := heartbeat.New(heartbeat.Config{Store: &change.FileStore{Path: filepath.Join(f.dir, "heartbeat")}, Clock: clock, Zone: "UTC", Minute: 720})
	if err != nil {
		t.Fatal(err)
	}
	if f.link == nil {
		f.link = modemlink.New(modemlink.Config{Owner: oc.Owner, Now: oc.Now, Location: time.UTC, SendWait: time.Second, PollWait: 5 * time.Millisecond})
	}
	bridgeOp(t, f.link, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	if f.budget == nil {
		f.budget = grants.New(grants.Config{Now: oc.Now, RequestsPerHour: 3})
	}
	policy, err := dailypolicy.New(dailypolicy.Config{Budget: f.budget, Engine: f.eng, Clock: func(context.Context) (time.Time, error) { return f.now, nil }, Quiet: func(time.Time) bool { return false }, Eligible: func(context.Context, dq.Batch) error { return nil }, AgedAfter: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	oc.Modem = f.link
	f.h, err = New(Config{Owner: oc, Notes: f.n, Daily: daily.Config{Queue: f.q, Heartbeat: hb, Clock: clock, TTL: time.Hour, Gate: policy.Check, Recheck: policy.Recheck}, OwnerNotesEligible: func(context.Context, dq.Snapshot) error { return nil }, RetentionDays: 1, PollInterval: time.Minute, StepTimeout: time.Second})
	if err != nil || f.h.Health() != nil {
		t.Fatal(err, f.h.Status())
	}
}
func bridgeStop(t *testing.T, h *Host, local bool) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		if local {
			done <- h.Channel().LocalStop(t.Context())
		} else {
			h.Channel().Handle(t.Context(), "+15550000999", "STOP")
			done <- nil
		}
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("actual owner STOP waited for daily I/O")
	}
}

type bridgeStepResult struct {
	id  uint64
	err error
}

func bridgeStep(t *testing.T, h *Host) <-chan bridgeStepResult {
	t.Helper()
	done := make(chan bridgeStepResult, 1)
	go func() { id, err := h.Step(t.Context()); done <- bridgeStepResult{id, err} }()
	return done
}
func bridgeAwaitStep(t *testing.T, done <-chan bridgeStepResult) bridgeStepResult {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(time.Second):
		t.Fatal("daily step did not finish")
		return bridgeStepResult{}
	}
}

// REQ: CH-15, CH-18, TIM-1, OP-1, OP-2
func TestActualHostRunnerBridgeCadenceAndFourFileReopen(t *testing.T) {
	f := newBridgeFixture(t, nil)
	if err := f.h.Activate(); err != nil {
		t.Fatal(err)
	}
	ticks, stopped := fakeTicks(f.h)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.h.Run(ctx) }()
	await(t, f.h, func(s Status) bool { return s.Steps == 1 && s.Code == Idle })
	if batches, err := f.q.List(); err != nil || len(batches) != 0 {
		t.Fatal(batches, err)
	}
	bridgeEmpty(t, f.link)
	f.now = f.now.Add(time.Minute)
	ticks <- f.now
	item := bridgePoll(t, f.link)
	if item.To != "+15550000999" || !strings.Contains(item.Text, heartbeat.Line) || !strings.Contains(item.Text, "wrong codes") || strings.Contains(item.Text, "receipt") || strings.Contains(item.Text, "mac") {
		t.Fatal(item)
	}
	bridgeOp(t, f.link, bridgeproto.OpSent, bridgeproto.Sent{ID: item.ID, Code: bridgeproto.CodeOK}, nil)
	await(t, f.h, func(s Status) bool { return s.Steps == 2 && s.Code == Accepted })
	id := f.h.Status().LastBatch
	ticks <- f.now
	await(t, f.h, func(s Status) bool { return s.Steps == 3 })
	bridgeEmpty(t, f.link)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || !*stopped {
		t.Fatal(err)
	}
	f.open(t, nil, false)
	f.h.Activate()
	again, err := f.h.Step(t.Context())
	if err != nil || again != id {
		t.Fatal("restart replaced accepted identity", again, err)
	}
	bridgeEmpty(t, f.link)
	st, err := (owner.FileStore{Path: filepath.Join(f.dir, "owner")}).Load()
	if err != nil || st.DigestOutbox.Produced != 1 || st.DigestOutbox.Acked != 1 || len(st.DigestOutbox.Pending) != 0 {
		t.Fatal(st, err)
	}
	if pending, err := f.n.Peek(t.Context()); err != nil || pending != nil {
		t.Fatal("restart resurrected guard notice", pending, err)
	}
	f.now = f.now.Add(24 * time.Hour)
	bridgeOp(t, f.link, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	next := bridgeStep(t, f.h)
	item = bridgePoll(t, f.link)
	bridgeOp(t, f.link, bridgeproto.OpSent, bridgeproto.Sent{ID: item.ID, Code: bridgeproto.CodeOK}, nil)
	result := bridgeAwaitStep(t, next)
	if result.err != nil || result.id <= id {
		t.Fatal(result)
	}
	batches, err := f.q.List()
	if err != nil || len(batches) != 1 || batches[0].ID != result.id {
		t.Fatal(batches, err)
	}
}

type bridgeSaveBlock struct {
	dq.Store
	target           dq.State
	entered, release chan struct{}
	once             sync.Once
	unblock          sync.Once
}

func (s *bridgeSaveBlock) Save(raw []byte) error {
	var st struct {
		Batches []dq.Batch `json:"batches"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	for _, b := range st.Batches {
		if b.State == s.target {
			s.once.Do(func() { close(s.entered); <-s.release })
			break
		}
	}
	return s.Store.Save(raw)
}
func (s *bridgeSaveBlock) releaseSave() { s.unblock.Do(func() { close(s.release) }) }
func blockedBridgeFixture(t *testing.T, state dq.State) (*bridgeFixture, *bridgeSaveBlock) {
	t.Helper()
	f := newBridgeFixture(t, nil)
	f.now = f.now.Add(time.Minute)
	block := &bridgeSaveBlock{Store: &change.FileStore{Path: filepath.Join(f.dir, "queue")}, target: state, entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(block.releaseSave)
	f.h.Hold()
	f.open(t, block, false)
	f.h.Activate()
	return f, block
}

// REQ: CH-2, CH-15, OP-1, OP-2
func TestActualHostTextAndLocalStopDuringBeginNeverReachBridge(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(fmt.Sprint(local), func(t *testing.T) {
			f, block := blockedBridgeFixture(t, dq.Sending)
			done := bridgeStep(t, f.h)
			select {
			case <-block.entered:
			case <-time.After(time.Second):
				t.Fatal("Begin did not block")
			}
			bridgeStop(t, f.h, local)
			block.releaseSave()
			result := bridgeAwaitStep(t, done)
			if !errors.Is(result.err, context.Canceled) {
				t.Fatal(result)
			}
			b, err := f.q.Get(result.id)
			if err != nil || b.State != dq.Ready || b.Attempts != 1 {
				t.Fatal(b, err)
			}
			bridgeEmpty(t, f.link)
			f.eng.Resume()
			if _, err := f.h.Step(t.Context()); !errors.Is(err, daily.ErrHeld) {
				t.Fatal(err)
			}
			if err := f.h.Activate(); err != nil {
				t.Fatal(err)
			}
			retry := bridgeStep(t, f.h)
			item := bridgePoll(t, f.link)
			bridgeOp(t, f.link, bridgeproto.OpSent, bridgeproto.Sent{ID: item.ID, Code: bridgeproto.CodeOK}, nil)
			retried := bridgeAwaitStep(t, retry)
			b, err = f.q.Get(retried.id)
			if retried.err != nil || retried.id != result.id || err != nil || b.Attempts != 2 || b.State != dq.Accepted {
				t.Fatal(retried, b, err)
			}
		})
	}
}
func TestActualHostStopAfterHandoffPersistsUnknownAndRejectsLateReceipt(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(fmt.Sprint(local), func(t *testing.T) {
			f := newBridgeFixture(t, nil)
			f.now = f.now.Add(time.Minute)
			f.h.Activate()
			done := bridgeStep(t, f.h)
			item := bridgePoll(t, f.link)
			bridgeStop(t, f.h, local)
			result := bridgeAwaitStep(t, done)
			if !errors.Is(result.err, context.Canceled) {
				t.Fatal(result)
			}
			bridgeOp(t, f.link, bridgeproto.OpSent, bridgeproto.Sent{ID: item.ID, Code: bridgeproto.CodeOK}, nil)
			if f.link.Stray() != 1 {
				t.Fatal("late result not isolated")
			}
			f.eng.Resume()
			f.open(t, nil, false)
			f.h.Activate()
			if id, err := f.h.Step(t.Context()); id != result.id || !errors.Is(err, daily.ErrUncertain) {
				t.Fatal(id, err)
			}
			b, err := f.q.Get(result.id)
			if err != nil || b.State != dq.Unknown || b.Attempts != 1 {
				t.Fatal(b, err)
			}
			bridgeEmpty(t, f.link)
		})
	}
}
func TestActualHostFinishPersistenceExcludesQuiescenceButNotStop(t *testing.T) {
	f, block := blockedBridgeFixture(t, dq.Accepted)
	done := bridgeStep(t, f.h)
	item := bridgePoll(t, f.link)
	bridgeOp(t, f.link, bridgeproto.OpSent, bridgeproto.Sent{ID: item.ID, Code: bridgeproto.CodeOK}, nil)
	select {
	case <-block.entered:
	case <-time.After(time.Second):
		t.Fatal("Finish did not block")
	}
	bridgeStop(t, f.h, true)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	called := false
	if err := f.h.Quiesce(ctx, func(context.Context) error { called = true; return nil }); !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatal(err, called)
	}
	block.releaseSave()
	result := bridgeAwaitStep(t, done)
	if result.err != nil {
		t.Fatal(result)
	}
	if err := f.h.Quiesce(t.Context(), func(context.Context) error {
		b, err := f.q.Get(result.id)
		if err != nil || b.State != dq.Accepted {
			t.Fatal(b, err)
		}
		called = true
		return nil
	}); err != nil || !called || !f.h.Status().Held {
		t.Fatal(err, called, f.h.Status())
	}
}
