package main

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localui"
)

// otherHooks is a Hooks that is not agentosd's: only AlreadySetUp is used.
type otherHooks struct {
	localui.Hooks
	set bool
}

func (h otherHooks) AlreadySetUp() bool { return h.set }

// foreignDone is a context whose Done channel is its own, so a child
// context made from it holds a watcher goroutine until the child is
// cancelled.
type foreignDone struct{ ch chan struct{} }

func (foreignDone) Deadline() (time.Time, bool) { return time.Time{}, false }
func (f foreignDone) Done() <-chan struct{}     { return f.ch }
func (foreignDone) Err() error                  { return nil }
func (foreignDone) Value(any) any               { return nil }

type answers struct{}

func (answers) Call(context.Context, string, any, any) error { return nil }

// #1617: hooks other than agentosd's answer through AlreadySetUp, never
// through agentosd's socket; and setupOpen's own bound is released on return.
// REQ: HW-10
func TestSetupOpenOtherHooksAndReleasesItsBound(t *testing.T) {
	if open, err := setupOpen(context.Background(), otherHooks{set: false}, time.Second); err != nil || !open {
		t.Fatalf("not set up: open %v, err %v", open, err)
	}
	if open, err := setupOpen(context.Background(), otherHooks{set: true}, time.Second); err != nil || open {
		t.Fatalf("set up: open %v, err %v", open, err)
	}
	if open, err := setupOpen(context.Background(), nil, time.Second); err != nil || open {
		t.Fatalf("nil hooks: open %v, err %v", open, err)
	}
	before := runtime.NumGoroutine()
	f := foreignDone{ch: make(chan struct{})}
	if open, err := setupOpen(f, localui.AgentosdSetup{Owner: answers{}}, time.Minute); err != nil || !open {
		t.Fatalf("answer: open %v, err %v", open, err)
	}
	for i := 0; i < 100 && runtime.NumGoroutine() > before; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		t.Fatalf("setupOpen left its bound running: %d goroutines, was %d", n, before)
	}
}
