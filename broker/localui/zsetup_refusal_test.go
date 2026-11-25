package localui

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// refusingOwner refuses OpSetupProgress with code for its first n calls,
// then answers with then: "" is an answer, anything else that refusal.
type refusingOwner struct {
	code, then string
	n          int32
	calls      atomic.Int32
}

func (o *refusingOwner) Call(_ context.Context, op string, _, _ any) error {
	if op != localapi.OpSetupProgress {
		return Refused(sockets.ErrUnknownOp)
	}
	if o.calls.Add(1) <= o.n {
		return Refused(o.code)
	}
	if o.then != "" {
		return Refused(o.then)
	}
	return nil
}

// #1617: only setup closed and unknown op decide that setup is closed. A
// socket-level refusal (too many connections, internal error, request
// failed) is no decision: Open asks again, so one stray refusal at start
// does not leave an open setup closed until reboot.
// REQ: HW-10
func TestOpenClosesOnlyOnSetupClosedOrUnknownOp(t *testing.T) {
	ctx := context.Background()
	for _, code := range []sockets.Code{sockets.ErrTooMany, sockets.ErrInternal, sockets.ErrFailed} {
		o := &refusingOwner{code: string(code), n: 3}
		open, err := AgentosdSetup{Owner: o}.Open(ctx, time.Millisecond)
		if err != nil || !open || o.calls.Load() != 4 {
			t.Fatalf("%s then an answer: open %v, err %v, calls %d", code, open, err, o.calls.Load())
		}
		o = &refusingOwner{code: string(code), n: 2, then: localapi.ErrSetupClosed}
		if open, err := (AgentosdSetup{Owner: o}).Open(ctx, time.Millisecond); err != nil || open {
			t.Fatalf("%s then setup closed: open %v, err %v", code, open, err)
		}
	}
	for _, code := range []string{localapi.ErrSetupClosed, string(sockets.ErrUnknownOp)} {
		o := &refusingOwner{then: code}
		if open, err := (AgentosdSetup{Owner: o}).Open(ctx, time.Millisecond); err != nil || open || o.calls.Load() != 1 {
			t.Fatalf("%s: open %v, err %v, calls %d", code, open, err, o.calls.Load())
		}
	}
	tctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	o := &refusingOwner{code: string(sockets.ErrTooMany), n: 1 << 30}
	if open, err := (AgentosdSetup{Owner: o}).Open(tctx, time.Millisecond); open || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("refused until the bound: open %v, err %v", open, err)
	}
}

// #1617 (L3 l3): Wait shares Open's rule, so a stray refusal is not taken
// for agentosd's answer.
// REQ: HW-10
func TestWaitRetriesAStrayRefusal(t *testing.T) {
	o := &refusingOwner{code: string(sockets.ErrTooMany), n: 2}
	if err := (AgentosdSetup{Owner: o}).Wait(context.Background(), time.Millisecond); err != nil || o.calls.Load() != 3 {
		t.Fatalf("err %v, calls %d", err, o.calls.Load())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	o = &refusingOwner{code: string(sockets.ErrInternal), n: 1 << 30}
	if err := (AgentosdSetup{Owner: o}).Wait(ctx, time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait %v", err)
	}
}
