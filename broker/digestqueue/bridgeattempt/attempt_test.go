package bridgeattempt

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modemlink"
)

type notice struct {
	calls int
	text  string
	err   error
	hook  func()
}

func (n *notice) InformContext(_ context.Context, text string) error {
	n.calls++
	n.text = text
	if n.hook != nil {
		n.hook()
	}
	return n.err
}

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func rig(t *testing.T, lines ...string) (*digestqueue.Queue, *change.MemStore, digestqueue.Batch, *notice, Config) {
	t.Helper()
	st := &change.MemStore{}
	q, err := digestqueue.New(st, digestqueue.Limits{MaxBatches: 8, MaxSources: 8, MaxAttempts: 2, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	s, err := digestqueue.NewSnapshotWithReceipt("change", 1, lines, []string{"owner:g1"}, "private-synthetic-receipt")
	if err != nil {
		t.Fatal(err)
	}
	b, err := q.Enqueue([]digestqueue.Snapshot{s}, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Acknowledge(b.ID, s.Source, s.Generation, s.Hash); err != nil {
		t.Fatal(err)
	}
	n := &notice{}
	cfg := Config{Queue: q, Owner: n, Now: func() time.Time { return now }, Gate: func(context.Context, digestqueue.Batch) error { return nil }, Sources: map[string]Validator{"change": func(context.Context, digestqueue.Snapshot) error { return nil }}}
	return q, st, b, n, cfg
}
func attempt(t *testing.T, cfg Config, id uint64) error {
	t.Helper()
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a.Send(context.Background(), id)
}
func state(t *testing.T, q *digestqueue.Queue, id uint64) digestqueue.Batch {
	t.Helper()
	b, err := q.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// REQ: CH-12, CH-19, OP-1, OP-2, OP-3
func TestAcceptedIsDurableTransportOnlyAndReceiptIsPrivate(t *testing.T) {
	q, _, b, n, c := rig(t, "A fixed notice.", "Another fixed notice.")
	n.hook = func() {
		if got := state(t, q, b.ID); got.State != digestqueue.Sending || got.Attempts != 1 {
			t.Fatal("transport called before durable begin", got)
		}
	}
	if err := attempt(t, c, b.ID); err != nil {
		t.Fatal(err)
	}
	if got := state(t, q, b.ID); got.State != digestqueue.Accepted || got.Evidence == "" {
		t.Fatal(got)
	}
	if n.text != "Daily update: A fixed notice. Another fixed notice." || strings.Contains(n.text, "receipt") || strings.Contains(n.text, "owner:g1") {
		t.Fatal(n.text)
	}
}
func TestAmbiguousTransportErrorsCannotRetry(t *testing.T) {
	for _, err := range []error{modem.ErrDown, context.DeadlineExceeded, &modemlink.SendCanceledError{Cause: context.Canceled, ItemID: "synthetic-id", Handed: true}} {
		t.Run(err.Error(), func(t *testing.T) {
			q, _, b, n, c := rig(t, "Fixed notice.")
			n.err = err
			if got := attempt(t, c, b.ID); !errors.Is(got, err) {
				t.Fatal(got)
			}
			if state(t, q, b.ID).State != digestqueue.Unknown {
				t.Fatal("ambiguous send eligible")
			}
			if got := attempt(t, c, b.ID); got == nil || n.calls != 1 {
				t.Fatal("unknown retried", got, n.calls)
			}
		})
	}
}
func TestOnlyAffirmativeBeforeHandoffCancellationPermitsRetry(t *testing.T) {
	q, _, b, n, c := rig(t, "Fixed notice.")
	n.err = &modemlink.SendCanceledError{Cause: context.Canceled, Handed: false}
	if err := attempt(t, c, b.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if state(t, q, b.ID).State != digestqueue.Ready {
		t.Fatal("not-sent not retained")
	}
	if err := attempt(t, c, b.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if state(t, q, b.ID).State != digestqueue.Failed {
		t.Fatal("unbounded attempts")
	}
}
func TestUnsafeOrOversizePayloadNeverBegins(t *testing.T) {
	for _, s := range []string{"Use verification code 123456.", strings.Repeat("a", control.MaxText), "Newline\ncontrol", "Unicode 🐈 notice"} {
		t.Run(s[:min(len(s), 20)], func(t *testing.T) {
			q, _, b, n, c := rig(t, s)
			if err := attempt(t, c, b.ID); !errors.Is(err, ErrRendering) {
				t.Fatal(err)
			}
			if n.calls != 0 || state(t, q, b.ID).Attempts != 0 {
				t.Fatal("unsafe payload began")
			}
		})
	}
}
func TestMissingGateOrSourceValidatorRefused(t *testing.T) {
	_, _, _, _, c := rig(t, "Fixed notice.")
	c.Gate = nil
	if _, err := New(c); err == nil {
		t.Fatal("no dispatch gate")
	}
	c.Gate = func(context.Context, digestqueue.Batch) error { return nil }
	c.Sources = map[string]Validator{"change": nil}
	if _, err := New(c); err == nil {
		t.Fatal("nil source validator")
	}
}
func TestGateAndSourceRefusalLeaveReady(t *testing.T) {
	for _, source := range []bool{false, true} {
		q, _, b, n, c := rig(t, "Fixed notice.")
		denied := errors.New("fresh check refused")
		if source {
			c.Sources["change"] = func(context.Context, digestqueue.Snapshot) error { return denied }
		} else {
			c.Gate = func(context.Context, digestqueue.Batch) error { return denied }
		}
		if err := attempt(t, c, b.ID); !errors.Is(err, denied) {
			t.Fatal(err)
		}
		if n.calls != 0 || state(t, q, b.ID).Attempts != 0 {
			t.Fatal("denied send began")
		}
	}
}
func TestBeginSaveFailureDoesNotCallTransport(t *testing.T) {
	q, st, b, n, c := rig(t, "Fixed notice.")
	st.Fail = errors.New("disk full")
	if err := attempt(t, c, b.ID); err == nil {
		t.Fatal("save succeeded")
	}
	if n.calls != 0 {
		t.Fatal("failed begin sent")
	}
	if _, err := q.Get(b.ID); !errors.Is(err, digestqueue.ErrRecovery) {
		t.Fatal(err)
	}
}
func TestAcceptedButFinishSaveFailureStaysQuarantined(t *testing.T) {
	q, st, b, n, c := rig(t, "Fixed notice.")
	n.hook = func() { st.Fail = errors.New("finish failed") }
	if err := attempt(t, c, b.ID); err == nil {
		t.Fatal("finish failure hidden")
	}
	if n.calls != 1 {
		t.Fatal(n.calls)
	}
	st.Fail = nil
	reopened, err := digestqueue.New(st, digestqueue.Limits{MaxBatches: 8, MaxSources: 8, MaxAttempts: 2, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if state(t, reopened, b.ID).State != digestqueue.Unknown {
		t.Fatal("restart replayed ambiguous accepted send")
	}
	if _, err = q.Get(b.ID); !errors.Is(err, digestqueue.ErrRecovery) {
		t.Fatal(err)
	}
}
func TestExpiredOrUnacknowledgedDoesNotInvokeTransport(t *testing.T) {
	q, _, b, n, c := rig(t, "Fixed notice.")
	c.Now = func() time.Time { return b.Expires }
	if err := attempt(t, c, b.ID); !errors.Is(err, digestqueue.ErrExpired) {
		t.Fatal(err)
	}
	if n.calls != 0 || state(t, q, b.ID).Attempts != 0 {
		t.Fatal("expired send")
	}
}
func TestCancelledAndNilContextsDoNotBegin(t *testing.T) {
	q, _, b, n, c := rig(t, "Fixed notice.")
	a, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = a.Send(ctx, b.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = a.Send(nil, b.ID); err == nil {
		t.Fatal("nil context")
	}
	if n.calls != 0 || state(t, q, b.ID).Attempts != 0 {
		t.Fatal("cancelled admission")
	}
}

type enteredContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *enteredContext) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { close(c.entered) })
	return err
}

// REQ: OP-6
func TestCancelledWaitForAnotherAttemptReturnsWithoutWaitingForTransport(t *testing.T) {
	_, _, b, n, c := rig(t, "Fixed notice.")
	entered, release := make(chan struct{}), make(chan struct{})
	n.hook = func() { close(entered); <-release }
	a, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() { first <- a.Send(context.Background(), b.ID) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first send did not enter")
	}
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	checked := make(chan struct{})
	go func() { done <- a.Send(&enteredContext{Context: ctx, entered: checked}, b.ID) }()
	<-checked
	cancel()
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cancelled waiter blocked behind transport")
	}
}
func TestCallbacksCannotMutateTransportPayloadOrPrivateQueueState(t *testing.T) {
	q, _, b, n, c := rig(t, "Original fixed notice.")
	c.Sources["change"] = func(_ context.Context, s digestqueue.Snapshot) error {
		s.Lines[0] = "Mutated source."
		s.References[0] = "mutated-ref"
		return nil
	}
	c.Gate = func(_ context.Context, b digestqueue.Batch) error {
		b.Snapshots[0].Lines[0] = "Mutated gate."
		b.Acknowledged[0] = false
		return nil
	}
	if err := attempt(t, c, b.ID); err != nil {
		t.Fatal(err)
	}
	if n.text != "Daily update: Original fixed notice." || state(t, q, b.ID).Snapshots[0].References[0] != "owner:g1" {
		t.Fatal("callback alias changed persisted/rendered payload")
	}
}
func TestGateCancellationPreventsDurableBegin(t *testing.T) {
	q, _, b, n, c := rig(t, "Fixed notice.")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Gate = func(context.Context, digestqueue.Batch) error { cancel(); return nil }
	a, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Send(ctx, b.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if n.calls != 0 || state(t, q, b.ID).Attempts != 0 {
		t.Fatal("gate cancellation sent")
	}
}
func TestSourceAllowlistIsCopiedAndUnknownSourcesRefuse(t *testing.T) {
	q, _, b, n, c := rig(t, "Fixed notice.")
	a, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	delete(c.Sources, "change")
	if err = a.Send(context.Background(), b.ID); err != nil {
		t.Fatal("caller map mutation changed live allowlist", err)
	}
	if n.calls != 1 || state(t, q, b.ID).State != digestqueue.Accepted {
		t.Fatal("not accepted")
	}
	q, _, b, n, c = rig(t, "Fixed notice.")
	c.Sources = map[string]Validator{"other": func(context.Context, digestqueue.Snapshot) error { return nil }}
	if err = attempt(t, c, b.ID); !errors.Is(err, ErrConfig) {
		t.Fatal(err)
	}
	if n.calls != 0 || state(t, q, b.ID).Attempts != 0 {
		t.Fatal("unknown source began")
	}
}
func TestUnacknowledgedSourceCannotDispatch(t *testing.T) {
	q, _, _, n, c := rig(t, "First notice.")
	s, err := digestqueue.NewSnapshot("other", 1, []string{"Another fixed notice."}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := q.Enqueue([]digestqueue.Snapshot{s}, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	c.Sources["other"] = func(context.Context, digestqueue.Snapshot) error { return nil }
	if err = attempt(t, c, b.ID); !errors.Is(err, digestqueue.ErrUnacknowledged) {
		t.Fatal(err)
	}
	if n.calls != 0 || state(t, q, b.ID).Attempts != 0 {
		t.Fatal("unacknowledged send")
	}
}

func TestWrappedOrMalformedCancellationDoesNotEstablishNonDelivery(t *testing.T) {
	for _, sendErr := range []error{errors.Join(errors.New("another transport error"), &modemlink.SendCanceledError{Cause: context.Canceled, Handed: false}), &modemlink.SendCanceledError{Cause: errors.New("unspecified cause"), Handed: false}} {
		q, _, b, n, c := rig(t, "Fixed notice.")
		n.err = sendErr
		if err := attempt(t, c, b.ID); !errors.Is(err, sendErr) {
			t.Fatal(err)
		}
		if state(t, q, b.ID).State != digestqueue.Unknown {
			t.Fatal("unqualified cancellation manufactured retry permission")
		}
	}
}
