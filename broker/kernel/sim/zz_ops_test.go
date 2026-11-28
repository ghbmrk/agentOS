package sim

// REQ: EVL-1, KRN-7, TIM-1, D-146

import (
	"errors"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// scriptedSim is seed 0's machine, set up, with every draw from here on
// the script's.
func scriptedSim(t *testing.T, picks ...[2]uint64) (*sim, *script) {
	t.Helper()
	s, err := newSim(Config{Seed: 0})
	if err != nil {
		t.Fatal(err)
	}
	sc := scripted(t, s.w, picks...)
	s.rng, s.disk.rng = s.w.rng, s.w.rng
	return s, sc
}

// rescript replaces what is left of the script.
func rescript(s *sim, sc *script, picks ...[2]uint64) { sc.picks = picks }

// draws is a gen's 32 seed bytes, each drawn as IntN(256).
func draws(b byte) [][2]uint64 {
	var p [][2]uint64
	for range 32 {
		p = append(p, [2]uint64{256, uint64(b)})
	}
	return p
}

// A root the planner drew no verb for gets trash, so every root grants one.
func TestARootWithNoVerbDrawnGetsTrash(t *testing.T) {
	no := [2]uint64{2, 1}
	s, sc := scriptedSim(t, no, no, no, no, no, no)
	r := s.newRoot()
	sc.done()
	if !slices.Equal(r.Root.Verbs, []key.Verb{key.Trash}) {
		t.Fatalf("verbs %v", r.Root.Verbs)
	}
}

// The owner's action racing the kernel's decision is a revoke of a key the
// sim granted half the time, and a STOP the other half; each is traced.
func TestTheRaceRevokesOrStops(t *testing.T) {
	s, sc := scriptedSim(t, [2]uint64{2, 0}, [2]uint64{8, 3})
	s.w.race()
	sc.done()
	if s.trace[len(s.trace)-1] != "0 race: revoke" || !s.k.State().Changes.Revoked[s.ids[3]] || s.k.State().Stopped {
		t.Fatalf("trace %q, revoked %v", s.trace, s.k.State().Changes.Revoked)
	}
	s, sc = scriptedSim(t, [2]uint64{2, 1})
	s.w.race()
	sc.done()
	if s.trace[len(s.trace)-1] != "0 race: stop" || !s.k.State().Stopped || len(s.k.State().Changes.Revoked) != 0 {
		t.Fatalf("trace %q, stopped %v", s.trace, s.k.State().Stopped)
	}
}

// A clock jump back counts only when it lands behind the log's last entry:
// one that lands on its time does not (TIM-1).
func TestAClockJumpBackCountsOnlyBehindTheLog(t *testing.T) {
	for _, c := range []struct {
		past  int64 // how far the clock is past the last entry before the jump
		count int
	}{{hour, 0}, {hour - 1, 1}} {
		s, sc := scriptedSim(t, [2]uint64{16, 14}, [2]uint64{8, 1}, [2]uint64{48, 0})
		s.now = 5 * hour
		if err := s.k.Stop(s.kt()); err != nil {
			t.Fatal(err)
		}
		es := s.k.Log().Entries()
		s.now = es[len(es)-1].At + c.past
		if err := s.op(); err != nil {
			t.Fatal(err)
		}
		sc.done()
		if s.clockBack != c.count {
			t.Errorf("%dms past the log, jumped back an hour: %d counted, want %d", c.past, s.clockBack, c.count)
		}
	}
}

// A widening that failed to anchor is left unconfirmed for the world to
// judge, and counted.
func TestAnUnanchoredWideningIsUnconfirmed(t *testing.T) {
	s, _ := scriptedSim(t)
	if err := s.widened(errAnchor); !errors.Is(err, errAnchor) || !s.w.unconfirmed || s.widenUnproven != 1 {
		t.Fatalf("%v, unconfirmed %v, counted %d", err, s.w.unconfirmed, s.widenUnproven)
	}
}

// The hostile jump reads held steps only: a step accepted but not yet held,
// under a key whose hold is longer than the base jump, sets none.
func TestTheHostileJumpReadsHeldStepsOnly(t *testing.T) {
	s, sc := scriptedSim(t, [2]uint64{6, 0})
	i := slices.IndexFunc(s.roots, func(r key.Key) bool {
		return slices.ContainsFunc(r.Root.Verbs, func(v key.Verb) bool { c, _ := key.ClassOf(v); return c.Irreversible() })
	})
	if i < 0 {
		t.Fatal("seed 0 grants no irreversible verb")
	}
	v := s.roots[i].Root.Verbs[slices.IndexFunc(s.roots[i].Root.Verbs, func(v key.Verb) bool { c, _ := key.ClassOf(v); return c.Irreversible() })]
	lk, err := key.Derive(s.pool[2*i], s.holder.priv, s.holder.pub, key.LimitHold(5*hour, 10*hour))
	if err != nil {
		t.Fatal(err)
	}
	st := kernel.PlanStep{Verb: v, Clerk: "mail", Args: map[string]string{}}
	for _, n := range key.ArgNames(v) {
		st.Args[n] = "alice"
	}
	s.now = kernel.GrantHold + 1 // the roots are past their hold
	if err := s.k.Submit(s.kt(), kernel.SignPlan(kernel.Plan{ID: "unheld", Key: lk, Steps: []kernel.PlanStep{st}}, s.holder.priv)); err != nil {
		t.Fatal(err)
	}
	if p := s.k.State().Plans["unheld"]; p.Status != kernel.SActive && p.Status != kernel.SPending || len(p.Steps) != 1 || p.Steps[0].Phase == kernel.PHeld {
		t.Fatalf("plan %+v", p)
	}
	s.now = 0 // the step's window, were it held at 0, runs past the base hour
	if got := s.pastHolds(); got != hour {
		t.Fatalf("jump %dms, want the base hour", got)
	}
	sc.done()
}

// The owner cuts a phone off: the phone's own cut-off is refused, the
// owner's taken, and the phone is cut in the world's books and the sim's.
func TestACutOffPhoneIsCutInTheWorldsBooks(t *testing.T) {
	s, sc := scriptedSim(t, draws(7)...)
	if err := s.phoneOp(); err != nil {
		t.Fatal(err)
	}
	phone := s.phone.pk
	if !phone.Valid() {
		t.Fatal("no phone enrolled")
	}
	rescript(s, sc, [2]uint64{4, 0}, [2]uint64{2, 1})
	if err := s.phoneOp(); err != nil {
		t.Fatal(err)
	}
	sc.done()
	if s.phone.pk.Valid() || !key.In(s.w.cut, phone) || len(s.cutPhones) != 1 || len(s.w.bad) != 0 {
		t.Fatalf("phone still %v, world cut %v, judged %q", s.phone.pk.Valid(), s.w.cut, s.w.bad)
	}
}

// A phone's renewal the owner co-signed alone is refused whole and counted,
// and its key never reaches the home clerk's pool.
func TestARefusedPhoneRenewalIsNotPooled(t *testing.T) {
	s, sc := scriptedSim(t, draws(7)...)
	if err := s.phoneOp(); err != nil {
		t.Fatal(err)
	}
	pool := len(s.pool)
	rescript(s, sc, [2]uint64{4, 3}, [2]uint64{4, 0}, [2]uint64{8, 0})
	if err := s.phoneOp(); err != nil {
		t.Fatal(err)
	}
	sc.done()
	if s.bigRefused != 1 || len(s.pool) != pool || len(s.phoneKeys) != 0 {
		t.Fatalf("%d refused, pool %d (was %d), phone keys %d", s.bigRefused, len(s.pool), pool, len(s.phoneKeys))
	}
}

// grant's co-signers: none, the owner and the home clerk, the owner alone,
// or both hardware keys; only the last is taken for a clerk key, and a
// batch refused without the second hardware key is no finding.
func TestGrantsCosignersAreDrawn(t *testing.T) {
	for n, want := range []bool{false, false, false, true, true} {
		s, sc := scriptedSim(t, [2]uint64{8, uint64(n)})
		s.now = hour // a renewal, not the key set up at 0
		k := s.clerkKey(s.owner.pass, s.roots[0])
		err := s.grant(k)
		sc.done()
		if _, taken := s.k.State().Grants[k.Tip()]; taken != want || taken != (err == nil) || len(s.w.bad) != 0 {
			t.Errorf("draw %d: taken %v, %v, judged %q", n, taken, err, s.w.bad)
		}
	}
}

// Truncating to nothing is a prefix too: a log torn in its first frame
// starts again empty (LOG-2).
func TestTheDiskTruncatesToEmpty(t *testing.T) {
	d := &Disk{}
	if err := d.Append([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := d.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if b, err := d.ReadAll(); err != nil || len(b) != 0 {
		t.Fatalf("%q, %v", b, err)
	}
}

// A cut-off the log took but the sim never recorded, as when a crash ends
// the op right after it, is read back from the log: the phone is cut in
// the world's books, not merely forgotten.
func TestACutOffOnlyTheLogHasIsReadBack(t *testing.T) {
	s, sc := scriptedSim(t, draws(7)...)
	if err := s.phoneOp(); err != nil {
		t.Fatal(err)
	}
	sc.done()
	phone := s.phone.pk
	if err := s.k.Unenroll(s.kt(), key.Unenroll(s.owner.pass, phone)); err != nil {
		t.Fatal(err)
	}
	s.syncPhone()
	if s.phone.pk.Valid() || !key.In(s.w.cut, phone) {
		t.Fatalf("phone still %v, world cut %v", s.phone.pk.Valid(), s.w.cut)
	}
}
