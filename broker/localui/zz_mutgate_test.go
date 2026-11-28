package localui

import (
	"runtime"
	"testing"
	"time"
)

type foreignDone struct{ ch chan struct{} }

func (foreignDone) Deadline() (time.Time, bool) { return time.Time{}, false }
func (f foreignDone) Done() <-chan struct{}     { return f.ch }
func (foreignDone) Err() error                  { return nil }
func (foreignDone) Value(any) any               { return nil }

// #1617: each of Open's asks releases its own callTimeout bound when it
// returns, rather than holding it until callTimeout passes.
// REQ: HW-10
func TestOpenReleasesEachAsk(t *testing.T) {
	before := runtime.NumGoroutine()
	f := foreignDone{ch: make(chan struct{})}
	o := &refusingOwner{code: "internal error", n: 1}
	if open, err := (AgentosdSetup{Owner: o}).Open(f, time.Millisecond); err != nil || !open {
		t.Fatalf("open %v, err %v", open, err)
	}
	for i := 0; i < 100 && runtime.NumGoroutine() > before; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		t.Fatalf("Open left an ask's bound running: %d goroutines, was %d", n, before)
	}
	localui4Kills(t) // MUT-kill-localui-4 (#6768): subtests, so mutgate's targets stay theirs
}
