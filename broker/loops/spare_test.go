package loops

import (
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/loops/loopstest"
)

// The spare envelope on the kernel (MIG-4-spend-m): a lower cap is a
// derivation of the envelope the kernel enforces, a higher one a fresh
// envelope from the owner's passkey, and the day's spend counts across every
// envelope the loop held.

func TestLoweringTheSpareCapDerivesAKeyTheKernelEnforces(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)}
	sp, k := newSpare(t, clk.now)
	one := SpareCap(1, loopstest.OutPerM)
	must(t, sp.SetCap(3*one))
	if len(sp.Key().Links) != len(sp.Envelope.Links)+1 || k.Widened != 0 {
		t.Fatalf("a lower cap is not one derivation of the envelope: %d links, widened %d", len(sp.Key().Links), k.Widened)
	}
	for i := 0; i < 3; i++ {
		if rf := k.Call(sp.Key(), one); rf != nil {
			t.Fatal(rf)
		}
	}
	if sp.Room(clk.now().UnixMilli()) {
		t.Fatal("room left past the cap")
	}
	if rf := k.Call(sp.Key(), 1); rf == nil || rf.Code != key.RSpendDay {
		t.Fatalf("kernel admitted a call past the spare cap: %v", rf)
	}
	if got := sp.Calls(sp.Used(clk.now().UnixMilli())); got != 3 {
		t.Fatalf("used %d calls, want 3", got)
	}
	// The day's spend leaves the window after a day.
	clk.add(time.Duration(key.DayMS) * time.Millisecond)
	if !sp.Room(clk.now().UnixMilli()) {
		t.Fatal("no room a day later")
	}
}

func TestRaisingTheSpareCapNeedsTheOwnersPasskey(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)}
	sp, k := newSpare(t, clk.now)
	must(t, sp.SetCap(loopstest.EnvelopeCap))
	if rf := k.Call(sp.Key(), 100); rf != nil {
		t.Fatal(rf)
	}
	widen := sp.Widen
	sp.Widen = nil
	if err := sp.SetCap(loopstest.EnvelopeCap + 1); !errors.Is(err, ErrNoWiden) || sp.Cap() != loopstest.EnvelopeCap {
		t.Fatalf("raise with no passkey: %v, cap %d", err, sp.Cap())
	}
	sp.Widen = widen
	old := sp.Key()
	must(t, sp.SetCap(2*loopstest.EnvelopeCap))
	if k.Widened != 1 || sp.Key().Tip() == old.Tip() || sp.Cap() != 2*loopstest.EnvelopeCap {
		t.Fatalf("raise did not take a fresh envelope: widened %d, cap %d", k.Widened, sp.Cap())
	}
	// Spend under the old envelope still counts toward the day.
	if used := sp.Used(clk.now().UnixMilli()); used != 100 {
		t.Fatalf("used %d after the raise, want the 100 spent before it", used)
	}
	// Like any grant, the new envelope is live after the hold.
	if rf := k.Call(sp.Key(), 100); rf == nil {
		t.Fatal("a widened envelope was live before its hold")
	}
	clk.add(time.Duration(kernel.GrantHold) * time.Millisecond)
	if rf := k.Call(sp.Key(), 100); rf != nil {
		t.Fatal(rf)
	}
	// Lowering again narrows the widened envelope; nothing more is asked.
	must(t, sp.SetCap(10))
	if k.Widened != 1 || sp.Cap() != 10 {
		t.Fatalf("lowering after a raise: widened %d, cap %d", k.Widened, sp.Cap())
	}
}

func TestAWidenedEnvelopeMustHoldTheCapAsked(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)}
	sp, k := newSpare(t, clk.now)
	must(t, sp.SetCap(10))
	sp.Widen = func(n int64) (key.Key, error) { return k.Widen(n - 1) }
	if err := sp.SetCap(2 * loopstest.EnvelopeCap); err == nil || sp.Cap() != 10 {
		t.Fatalf("an envelope short of the cap asked was taken: %v", err)
	}
}

func TestEvalKeyNeedsACap(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)}
	sp, _ := newSpare(t, clk.now)
	if _, err := sp.EvalKey(); err == nil {
		t.Fatal("evaluation key before any cap")
	}
}

func TestSpareCapRoundsUpAndClamps(t *testing.T) {
	if got := SpareCap(1, 1); got != 1 {
		t.Fatalf("one call at 1 per million: %d, want it rounded up to 1", got)
	}
	if got := SpareCap(3, 15_000_000); got != 3*TokensPerCall*15 {
		t.Fatalf("three calls: %d", got)
	}
	if got := SpareCap(1<<40, 1<<40); got != 1<<63-1 {
		t.Fatalf("overflow not clamped: %d", got)
	}
}
