package loops

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/loops/loopstest"
)

// REQ: KEY-6, RES-5
//
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

// A lowering holds every key handed out before it to the new cap: the kernel
// refuses a call under a plan citing an older Key or EvalKey, one already
// running included, so none stays live at its old cap (L3 on #2837).
func TestLoweringTheSpareCapRevokesKeysHandedOutBefore(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)}
	sp, k := newSpare(t, clk.now)
	one := SpareCap(1, loopstest.OutPerM)
	lower := func(n int64, stale map[string]key.Key) {
		t.Helper()
		running := map[string]string{}
		for name, ck := range stale {
			running[name] = k.Plan(ck)
			if rf := k.Spend(running[name], one); rf != nil {
				t.Fatalf("%s: %v", name, rf)
			}
		}
		must(t, sp.SetCap(n))
		for name, ck := range stale {
			if rf := k.Spend(running[name], one); rf == nil || rf.Code != key.RRevoked {
				t.Fatalf("a running plan citing the %s spent after the cap was lowered to %d: %v", name, n, rf)
			}
			if rf := k.Call(ck, one); rf == nil {
				t.Fatalf("a new plan citing the %s spent after the cap was lowered to %d", name, n)
			}
		}
	}
	must(t, sp.SetCap(loopstest.EnvelopeCap))
	if sp.Key().Tip() == sp.Envelope.Tip() {
		t.Fatal("the envelope itself was handed out")
	}
	lower(10*one, map[string]key.Key{"envelope-cap key": sp.Key()})
	ek, err := sp.EvalKey()
	must(t, err)
	lower(0, map[string]key.Key{"earlier key": sp.Key(), "evaluation key": ek})
	// The day's spend is already past a zero cap, so the kernel rejects
	// the plan itself (#2838).
	if rf := k.Call(sp.Key(), one); rf == nil || rf.Code != kernel.CPlan {
		t.Fatalf("current key past a zero cap: %v", rf)
	}
	// A raise takes nothing back, and a cap set again derives a fresh key,
	// never the one revoked.
	must(t, sp.SetCap(10*one))
	if rf := k.Call(sp.Key(), one); rf != nil {
		t.Fatal(rf)
	}
}

func TestLoweringTheSpareCapNeedsTheOwnersRevocation(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)}
	sp, k := newSpare(t, clk.now)
	must(t, sp.SetCap(10))
	old := sp.Key()
	id := k.Plan(old)
	sp.Revoke = nil
	if err := sp.SetCap(5); !errors.Is(err, ErrNoRevoke) || sp.Cap() != 10 || sp.Key().Tip() != old.Tip() {
		t.Fatalf("lowered with no revocation: %v, cap %d", err, sp.Cap())
	}
	fail := errors.New("revocation not anchored")
	sp.Revoke = func(key.ID) error { return fail }
	if err := sp.SetCap(5); !errors.Is(err, fail) || sp.Cap() != 10 {
		t.Fatalf("lowered past a failed revocation: %v, cap %d", err, sp.Cap())
	}
	sp.Revoke = k.Revoke
	must(t, sp.SetCap(5))
	if rf := k.Spend(id, 1); rf == nil || rf.Code != key.RRevoked {
		t.Fatalf("earlier key live after the retried lowering: %v", rf)
	}
}

// The kernel holds a new cap to the day's earlier spend (#2838): after a
// lowering, the spend made before it counts toward the new cap, and a cap
// set twice gives no second key room past it.
func TestTheSpareCapCountsTheDaysEarlierSpend(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)}
	sp, k := newSpare(t, clk.now)
	one := SpareCap(1, loopstest.OutPerM)
	must(t, sp.SetCap(3*one))
	for i := 0; i < 2; i++ {
		if rf := k.Call(sp.Key(), one); rf != nil {
			t.Fatal(rf)
		}
	}
	must(t, sp.SetCap(2*one))
	if rf := k.Call(sp.Key(), one); rf == nil || rf.Code != key.RSpendDay {
		t.Fatalf("a call past the lowered cap, counting the day's earlier spend: %v", rf)
	}
	clk.add(time.Duration(key.DayMS) * time.Millisecond)
	first := sp.Key()
	must(t, sp.SetCap(2*one))
	calls := 0
	for _, ck := range []key.Key{first, sp.Key(), first, sp.Key()} {
		if k.Call(ck, one) == nil {
			calls++
		}
	}
	if calls != 2 {
		t.Fatalf("%d calls under a 2-call cap set twice", calls)
	}
}

// While Widen waits on the owner's passkey, Spare holds no lock: Cap, Key,
// Used and a lowering return. The raise's Commit then finds the cap moved
// and refuses with ErrMoved, and the lowering stands (KEY-6). A re-raise
// after a lowering needs the passkey even under the envelope's own cap.
func TestWidenRunsOutsideTheSpareLock(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)}
	sp, k := newSpare(t, clk.now)
	one := SpareCap(1, loopstest.OutPerM)
	must(t, sp.SetCap(10*one))
	entered, release := make(chan struct{}), make(chan struct{})
	sp.Widen = func(n int64) (key.Key, error) {
		close(entered)
		<-release
		return k.Widen(n)
	}
	prepared := make(chan error, 1)
	go func() {
		p, err := sp.Prepare(2 * loopstest.EnvelopeCap)
		if err == nil {
			err = sp.Commit(p)
		}
		prepared <- err
	}()
	<-entered
	done := make(chan error, 1)
	go func() {
		_, _ = sp.Cap(), sp.Key()
		_ = sp.Used(clk.now().UnixMilli())
		done <- sp.SetCap(5 * one)
	}()
	select {
	case err := <-done:
		must(t, err)
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the spare lock was held across the passkey wait")
	}
	close(release)
	if err := <-prepared; !errors.Is(err, ErrMoved) {
		t.Fatalf("a raise prepared before a lowering committed: %v", err)
	}
	if sp.Cap() != 5*one || capOf(t, sp.Key()) != 5*one {
		t.Fatalf("the lowering did not stand: cap %d", sp.Cap())
	}
	sp.Widen = nil
	if err := sp.SetCap(8 * one); !errors.Is(err, ErrNoWiden) || sp.Cap() != 5*one {
		t.Fatalf("a re-raise under the envelope's cap without the passkey: %v, cap %d", err, sp.Cap())
	}
}

// Prepare refuses a widened envelope that sits under one already held (its
// spend would count twice in Used) or that does not hold exactly the cap
// asked, and Commit refuses when the envelope moved even though the cap is
// back where Prepare saw it (KEY-6).
func TestAWidenedEnvelopeIsFreshAndExact(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)}
	sp, k := newSpare(t, clk.now)
	one := SpareCap(1, loopstest.OutPerM)
	must(t, sp.SetCap(10*one))
	env := sp.Envelope
	sp.Widen = func(n int64) (key.Key, error) {
		return key.Derive(env, sp.Holder, sp.Holder.Public().(ed25519.PublicKey), key.LowerSpendDay(n))
	}
	if err := sp.SetCap(20 * one); err == nil || sp.Cap() != 10*one {
		t.Fatalf("a derivation of the held envelope was taken as a widening: %v, cap %d", err, sp.Cap())
	}
	sp.Widen = func(n int64) (key.Key, error) { return k.Widen(n + 1) }
	if err := sp.SetCap(20 * one); err == nil || sp.Cap() != 10*one {
		t.Fatalf("an envelope over the cap asked was taken: %v, cap %d", err, sp.Cap())
	}
	sp.Widen = k.Widen
	p, err := sp.Prepare(10 * one)
	must(t, err)
	clk.add(time.Millisecond)
	must(t, sp.SetCap(20*one))
	must(t, sp.SetCap(10*one))
	if err := sp.Commit(p); !errors.Is(err, ErrMoved) {
		t.Fatalf("a commit after the envelope moved, at the same cap: %v", err)
	}
}

// The rest of Prepare's and Commit's refusals, one case each.
func TestPrepareAndCommitRefuse(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)}
	sp, k := newSpare(t, clk.now)
	one := SpareCap(1, loopstest.OutPerM)
	// Commit refuses when the first cap was set after Prepare, even at
	// the same cap and envelope.
	p, err := sp.Prepare(5 * one)
	must(t, err)
	must(t, sp.SetCap(0))
	if err := sp.Commit(p); !errors.Is(err, ErrMoved) || sp.Cap() != 0 {
		t.Fatalf("a commit prepared before the first cap: %v, cap %d", err, sp.Cap())
	}
	if err := sp.SetCap(-1); err == nil {
		t.Fatal("a negative cap")
	}
	// Without widen, a cap above the current one is refused and the
	// passkey is never asked.
	asked := 0
	sp.Widen = func(n int64) (key.Key, error) { asked++; return k.Widen(n) }
	if _, err := sp.prepare(5*one, false); !errors.Is(err, ErrNoWiden) || asked != 0 {
		t.Fatalf("prepare without widening: %v, asked %d", err, asked)
	}
	// A passkey that fails is the refusal.
	fail := errors.New("passkey dismissed")
	sp.Widen = func(int64) (key.Key, error) { return key.Key{}, fail }
	if err := sp.SetCap(5 * one); !errors.Is(err, fail) {
		t.Fatalf("a failed passkey: %v", err)
	}
	// An envelope swapped in outside Commit is refused.
	held := sp.Envelope
	other, err := key.Derive(held, sp.Holder, sp.Holder.Public().(ed25519.PublicKey), key.LowerSpendDay(loopstest.EnvelopeCap-1))
	must(t, err)
	sp.Envelope = other
	if err := sp.SetCap(0); err == nil {
		t.Fatal("an envelope changed outside Commit was used")
	}
	sp.Envelope = held
}

// A passkey that hands back an envelope already held is that envelope, not
// a second one: its spend counts once in Used.
func TestAWidenedEnvelopeAlreadyHeldCountsOnce(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)}
	sp, k := newSpare(t, clk.now)
	must(t, sp.SetCap(loopstest.EnvelopeCap))
	if rf := k.Call(sp.Key(), 100); rf != nil {
		t.Fatal(rf)
	}
	must(t, sp.SetCap(10))
	env := sp.Envelope
	sp.Widen = func(int64) (key.Key, error) { return env, nil }
	must(t, sp.SetCap(loopstest.EnvelopeCap))
	if used := sp.Used(clk.now().UnixMilli()); used != 100 {
		t.Fatalf("used %d, want the 100 spent counted once", used)
	}
}
