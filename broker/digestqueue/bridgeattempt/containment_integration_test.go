package bridgeattempt

import (
	"bytes"
	"context"
	"errors"
	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestnotes"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/ownersource"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/owner"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type initialOwner struct{ channel *owner.Channel }

func (o *initialOwner) InformContext(ctx context.Context, text string) error {
	return o.channel.InformContext(ctx, text)
}

type containmentFileBlock struct {
	change.FileStore
	unblockOnce      sync.Once
	mu               sync.Mutex
	saves, blockAt   int
	entered, release chan struct{}
}

func (s *containmentFileBlock) unblock() { s.unblockOnce.Do(func() { close(s.release) }) }

func (s *containmentFileBlock) Save(raw []byte) error {
	s.mu.Lock()
	s.saves++
	block := s.saves == s.blockAt
	s.mu.Unlock()
	if block {
		close(s.entered)
		<-s.release
	}
	return s.FileStore.Save(raw)
}
func containmentFixture(t *testing.T, blockAt int) (*Controller, *owner.Channel, *modemlink.Link, *digestqueue.Queue, *containmentFileBlock, digestqueue.Batch) {
	t.Helper()
	dir := t.TempDir()
	auth := owner.FileStore{Path: filepath.Join(dir, "owner.json")}
	n, err := digestnotes.New(digestnotes.Config{Store: &change.FileStore{Path: filepath.Join(dir, "notes.json")}, Location: time.UTC, Rand: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	rawEngine := &containmentEngine{}
	cfg := owner.Config{Owner: "+15550000999", Engine: rawEngine, Store: auth, Now: func() time.Time { return now }, Location: time.UTC}
	// Capture the real event before installing a modem, so its urgent alert
	// cannot introduce an unrelated send into the fixture.
	producer, err := owner.NewTransactional(cfg, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := producer.LocalSignIn("100000"); !errors.Is(err, owner.ErrWrongCode) {
		t.Fatal(err)
	}
	if err := producer.FlushDigestNotes(t.Context()); err != nil {
		t.Fatal(err)
	}
	source, err := ownersource.New(n)
	if err != nil {
		t.Fatal(err)
	}
	store := &containmentFileBlock{FileStore: change.FileStore{Path: filepath.Join(dir, "queue.json")}, blockAt: blockAt, entered: make(chan struct{}), release: make(chan struct{})}
	limits := digestqueue.Limits{MaxBatches: 8, MaxSources: 8, MaxAttempts: 2, MaxBytes: 1 << 20}
	t.Cleanup(store.unblock)
	q, err := digestqueue.New(store, limits)
	if err != nil {
		t.Fatal(err)
	}
	collect, err := digestqueue.NewCollector(q, map[string]digestqueue.Source{ownersource.ID: source})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := collect.Collect(t.Context(), now, now.Add(time.Hour))
	if err != nil || batch == nil {
		t.Fatal(batch, err)
	}
	link := modemlink.New(modemlink.Config{Owner: cfg.Owner, Now: cfg.Now, SendWait: time.Second, PollWait: 5 * time.Millisecond})
	bridgeCall(t, link, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	recipient := &initialOwner{}
	controller, err := NewController(Config{Queue: q, Owner: recipient, Now: cfg.Now, Sources: map[string]Validator{ownersource.ID: source.Validate}, Gate: func(context.Context, digestqueue.Batch) error {
		if rawEngine.Stopped() {
			return ErrHeld
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := controller.WrapEngine(rawEngine)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Engine, cfg.Modem = wrapped, link
	channel, err := owner.NewTransactional(cfg, n)
	if err != nil || channel.OwnerStateHealth() != nil {
		t.Fatal(err)
	}
	recipient.channel = channel // construction only; controller is still held
	if err := controller.Release(); err != nil {
		t.Fatal(err)
	}
	return controller, channel, link, q, store, *batch
}
func containmentStop(t *testing.T, c *owner.Channel, local bool) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		if local {
			done <- c.LocalStop(t.Context())
		} else {
			c.Handle(t.Context(), "+15550000999", "STOP")
			done <- nil
		}
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("actual owner STOP waited for dispatch")
	}
}
func containmentPoll(t *testing.T, l *modemlink.Link) *bridgeproto.Item {
	t.Helper()
	var out struct{ Item *bridgeproto.Item }
	for i := 0; i < 100 && out.Item == nil; i++ {
		bridgeCall(t, l, bridgeproto.OpOutbox, struct{}{}, &out)
	}
	if out.Item == nil {
		t.Fatal("no real bridge handoff")
	}
	return out.Item
}
func containmentReopen(t *testing.T, s *containmentFileBlock) *digestqueue.Queue {
	t.Helper()
	q, err := digestqueue.New(&change.FileStore{Path: s.Path}, digestqueue.Limits{MaxBatches: 8, MaxSources: 8, MaxAttempts: 2, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// REQ: CH-2, CH-15, OP-1, OP-2
func TestActualOwnerStopDuringBeginPreventsBridgeCall(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(map[bool]string{false: "text", true: "local"}[local], func(t *testing.T) {
			controller, channel, link, _, store, b := containmentFixture(t, 4)
			done := make(chan error, 1)
			go func() { done <- controller.Send(t.Context(), b.ID) }()
			select {
			case <-store.entered:
			case <-time.After(time.Second):
				t.Fatal("Begin not blocked")
			}
			containmentStop(t, channel, local)
			store.unblock()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			q := containmentReopen(t, store)
			got := state(t, q, b.ID)
			if got.State != digestqueue.Ready || got.Attempts != 1 {
				t.Fatal(got)
			}
			var out struct{ Item *bridgeproto.Item }
			bridgeCall(t, link, bridgeproto.OpOutbox, struct{}{}, &out)
			if out.Item != nil {
				t.Fatal("STOP reached bridge", out.Item)
			}
			if !errors.Is(controller.Send(t.Context(), b.ID), ErrHeld) {
				t.Fatal("STOP admitted another dispatch")
			}
		})
	}
}
func TestActualOwnerStopAfterBridgeHandoffPersistsUnknownAndIgnoresLateReceipt(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(map[bool]string{false: "text", true: "local"}[local], func(t *testing.T) {
			controller, channel, link, _, store, b := containmentFixture(t, 0)
			done := make(chan error, 1)
			go func() { done <- controller.Send(t.Context(), b.ID) }()
			item := containmentPoll(t, link)
			if item.To != "+15550000999" || bytes.Contains([]byte(item.Text), []byte("receipt")) {
				t.Fatal("wrong disclosure", item)
			}
			containmentStop(t, channel, local)
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			q := containmentReopen(t, store)
			if got := state(t, q, b.ID); got.State != digestqueue.Unknown || got.Attempts != 1 {
				t.Fatal(got)
			}
			bridgeCall(t, link, bridgeproto.OpSent, bridgeproto.Sent{ID: item.ID, Code: bridgeproto.CodeOK}, nil)
			if link.Stray() != 1 || state(t, q, b.ID).State != digestqueue.Unknown {
				t.Fatal("late receipt settled old attempt")
			}
			if err := controller.Release(); err != nil {
				t.Fatal(err)
			}
			if err := controller.Send(t.Context(), b.ID); !errors.Is(err, digestqueue.ErrState) {
				t.Fatal("unknown batch retried", err)
			}
		})
	}
}
func TestActualQueueFinishBlocksInvalidationButNotOwnerStop(t *testing.T) {
	controller, channel, link, q, store, b := containmentFixture(t, 5)
	done := make(chan error, 1)
	go func() { done <- controller.Send(t.Context(), b.ID) }()
	item := containmentPoll(t, link)
	bridgeCall(t, link, bridgeproto.OpSent, bridgeproto.Sent{ID: item.ID, Code: bridgeproto.CodeOK}, nil)
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("Finish not blocked")
	}
	containmentStop(t, channel, true)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	called := false
	if err := controller.Quiesce(ctx, func(context.Context) error { called = true; return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if called || !controller.Held() {
		t.Fatal("unfinished dispatch allowed invalidation")
	}
	store.unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := controller.Quiesce(t.Context(), func(context.Context) error {
		got := state(t, q, b.ID)
		if got.State != digestqueue.Accepted || got.Attempts != 1 {
			t.Fatal("mutation overtook durable finish", got)
		}
		called = true
		return nil
	}); err != nil || !called || !controller.Held() {
		t.Fatal(err)
	}
	if got := state(t, containmentReopen(t, store), b.ID); got.State != digestqueue.Accepted {
		t.Fatal(got)
	}
}
