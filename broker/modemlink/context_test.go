package modemlink

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
)

func waitQueued(t *testing.T, l *Link) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		l.mu.Lock()
		queued := len(l.queue) > 0
		l.mu.Unlock()
		if queued {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("send did not queue")
		case <-tick.C:
		}
	}
}
func awaitContextSend(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("send ignored cancellation")
		return nil
	}
}

// REQ: OP-2, OP-6
func TestCancelledBeforeAdmissionDoesNotQueueOrClaimHandoff(t *testing.T) {
	l, _ := rig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := l.SendContext(ctx, ownerNum, "Fixed notice.")
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var canceled *SendCanceledError
	if !errors.As(err, &canceled) || canceled.Handed {
		t.Fatal("claimed handoff", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.queue)+len(l.out) != 0 {
		t.Fatal("canceled text admitted")
	}
}
func TestCancellationDropsQueuedTextBeforeHandoff(t *testing.T) {
	l, _ := rig(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.SendContext(ctx, ownerNum, "Fixed notice.") }()
	waitQueued(t, l)
	cancel()
	err := awaitContextSend(t, done)
	var canceled *SendCanceledError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &canceled) || canceled.Handed {
		t.Fatal(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.queue)+len(l.out) != 0 {
		t.Fatal("canceled item retained")
	}
}
func TestCancellationAfterHandoffStaysPossiblySentAndLateReceiptIsStray(t *testing.T) {
	l, _ := rig(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.SendContext(ctx, ownerNum, "Fixed notice.") }()
	it := poll(t, l)
	cancel()
	err := awaitContextSend(t, done)
	var canceled *SendCanceledError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &canceled) || !canceled.Handed || canceled.ItemID != it.ID {
		t.Fatal("lost permanent handoff evidence", err)
	}
	if err = call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}, nil); err != nil {
		t.Fatal(err)
	}
	if l.Stray() != 1 {
		t.Fatal("late receipt treated as current", l.Stray())
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.queue)+len(l.out) != 0 {
		t.Fatal("canceled text replayed")
	}
}
func TestContextDeadlineDoesNotWaitForLongBridgeTimeout(t *testing.T) {
	l, _ := rig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.SendContext(ctx, ownerNum, "Fixed notice.") }()
	err := awaitContextSend(t, done)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
func TestContextSendStillReturnsBridgeSuccess(t *testing.T) {
	l, _ := rig(t)
	done := make(chan error, 1)
	go func() { done <- l.SendContext(context.Background(), ownerNum, "Fixed notice.") }()
	it := poll(t, l)
	if err := call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}, nil); err != nil {
		t.Fatal(err)
	}
	if err := awaitContextSend(t, done); err != nil {
		t.Fatal(err)
	}
}
func TestRequestContextCancellationKeepsRecipientRestriction(t *testing.T) {
	l, _ := rig(t)
	if err := l.SendRequestContext(context.Background(), "+15550000888", "Fixed request."); !errors.Is(err, ErrRecipient) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.SendRequestContext(ctx, ownerNum, "Fixed request."); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestNilSendContextRefused(t *testing.T) {
	l, _ := rig(t)
	if err := l.SendContext(nil, ownerNum, "Fixed notice."); !errors.Is(err, ErrSendContext) {
		t.Fatal(err)
	}
}
