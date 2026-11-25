package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localui"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// strayRefusal refuses OpSetupProgress with code for its first n calls,
// then answers with then: "" is an answer (setup open).
type strayRefusal struct {
	code, then string
	n          int32
	calls      atomic.Int32
}

func (o *strayRefusal) Call(context.Context, string, any, any) error {
	if o.calls.Add(1) <= o.n {
		return localui.Refused(o.code)
	}
	if o.then != "" {
		return localui.Refused(o.then)
	}
	return nil
}

// #1617: a non-closed refusal from setup_progress (too many connections,
// internal error) is retried, and setupOpen still answers open once
// agentosd answers; setup closed and unknown op still answer closed.
// REQ: HW-10
func TestSetupOpenRetriesAStrayRefusal(t *testing.T) {
	ctx := context.Background()
	for _, code := range []sockets.Code{sockets.ErrTooMany, sockets.ErrInternal} {
		o := &strayRefusal{code: string(code), n: 2}
		open, err := setupOpen(ctx, localui.AgentosdSetup{Owner: o}, 5*time.Second)
		if err != nil || !open || o.calls.Load() != 3 {
			t.Fatalf("%s then open: open %v, err %v, calls %d", code, open, err, o.calls.Load())
		}
	}
	for _, code := range []string{localapi.ErrSetupClosed, string(sockets.ErrUnknownOp)} {
		o := &strayRefusal{code: string(sockets.ErrTooMany), n: 1, then: code}
		open, err := setupOpen(ctx, localui.AgentosdSetup{Owner: o}, 5*time.Second)
		if err != nil || open {
			t.Fatalf("%s: open %v, err %v", code, open, err)
		}
	}
	o := &strayRefusal{code: string(sockets.ErrTooMany), n: 1 << 30}
	if open, err := setupOpen(ctx, localui.AgentosdSetup{Owner: o}, 300*time.Millisecond); err == nil || open {
		t.Fatalf("refused past the bound: open %v, err %v", open, err)
	}
}
