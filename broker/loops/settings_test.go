package loops

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/loops/loopstest"
)

// REQ: HLD-4, RES-5, KEY-6, CH-14
//
// Loop settings: on by default and changed by the owner's text, applied
// directly with no journal (HLD-4). A raise of the spare budget needs the
// owner's passkey (KEY-6); a lowering revokes the keys at the old cap and
// never waits on the passkey.

func TestLoopsAreOnByDefaultAndSaidInOneLine(t *testing.T) {
	r := newRig(t)
	set := r.s.Settings()
	for _, l := range All {
		if !set.On(l) {
			t.Fatalf("loop %s is off by default", l)
		}
	}
	if set.SpareCalls != NoSpareBudget {
		t.Fatalf("default spare budget %d, want no fixed budget", set.SpareCalls)
	}
	if c := r.spare.Cap(); c != SpareCap(NoSpareBudget, loopstest.OutPerM) {
		t.Fatalf("spare cap %d, want no fixed budget", c)
	}
	line := DefaultsLine(set.SpareCalls)
	if strings.Count(line, ".") != 1 || !strings.Contains(line, "LOOPS OFF") || !strings.Contains(line, "spare plan quota") || !strings.Contains(line, "at most 1500 AI calls a day while a pay-per-token key") || !strings.Contains(line, "and check for updates") {
		t.Fatalf("defaults line %q", line)
	}
}

// LOOP-0 (#2291) and OP-8: the default has no fixed call budget, but loop
// calls can reach pay-per-token routes, which keep a money cap, so the
// spare key holds the OP-8 default of 1500 calls a day, in minor units.
// Security's repro on #2319: 2000 replay calls of 10 000 tokens (20M) were
// all admitted; past the cap they are refused. A budget at or under the cap
// applies on text; above it is a raise.
func TestNoFixedBudgetKeepsThePaidRouteMoneyCap(t *testing.T) {
	one := SpareCap(1, loopstest.OutPerM)
	if c := SpareCap(NoSpareBudget, loopstest.OutPerM); c != PaidRouteCalls*one || c != loopstest.EnvelopeCap {
		t.Fatalf("no-budget cap %d, want the OP-8 default of %d calls", c, PaidRouteCalls)
	}
	if SpareCap(0, loopstest.OutPerM) != 0 {
		t.Fatalf("a zero budget must fit no call: %d", SpareCap(0, loopstest.OutPerM))
	}
	r := newRig(t)
	admitted := 0
	for i := 0; i < 2000; i++ {
		rf := r.call(one)
		if rf != nil {
			if rf.Code != key.RSpendDay {
				t.Fatal(rf)
			}
			break
		}
		admitted++
	}
	if admitted != int(PaidRouteCalls) {
		t.Fatalf("%d loop calls admitted with no fixed budget, want the paid-route cap %d", admitted, PaidRouteCalls)
	}
	if used := r.spare.Used(r.clk.now().UnixMilli()); used > SpareCap(NoSpareBudget, loopstest.OutPerM) {
		t.Fatalf("%d spent, over the paid-route cap", used)
	}
	// A budget at the cap is a lower and applies; above it is a raise,
	// which needs the owner's passkey.
	ctx := context.Background()
	r.spare.Widen = nil
	if got, ok := r.s.Text(ctx, "SPARE BUDGET 2000", true); !ok || r.s.Settings().SpareCalls == 2000 || !strings.Contains(got, "passkey") {
		t.Fatalf("a budget above the paid-route cap applied without the passkey: %q", got)
	}
	if got, ok := r.s.Text(ctx, "SPARE BUDGET 1500", true); !ok || r.s.Settings().SpareCalls != 1500 {
		t.Fatalf("a budget at the cap is narrowing and applies on text: %q %v", got, ok)
	}
	if c := r.spare.Cap(); c != SpareCap(1500, loopstest.OutPerM) || r.kern.Widened != 0 {
		t.Fatalf("set budget not applied to the spare key: %d (widened %d)", c, r.kern.Widened)
	}
}

func TestParseTextTakesWholeMessagesOnly(t *testing.T) {
	cases := []struct {
		msg  string
		ok   bool
		want Request
	}{
		{"loops off", true, Request{Kind: KindLoops}},
		{"Loops on!", true, Request{Kind: KindLoops, On: true}},
		{"LOOP 2 OFF", true, Request{Kind: KindLoops, Loop: Secure}},
		{"loop 3 on.", true, Request{Kind: KindLoops, Loop: Maintain, On: true}},
		{"spare budget 40", true, Request{Kind: KindBudget, Calls: 40}},
		{"stop sharing", true, Request{Kind: KindSharing}},
		{"START SHARING", true, Request{Kind: KindSharing, On: true}},
		{"learning off", true, Request{Kind: KindLoops, Loop: Improve}},
		{"Security tests on", true, Request{Kind: KindLoops, Loop: Secure, On: true}},
		{"UPDATE CHECKS OFF.", true, Request{Kind: KindLoops, Loop: Maintain}},
		{"help loops", true, Request{Kind: KindHelp}},
		{"learning off now", false, Request{}},
		{"loop 4 off", false, Request{}},
		{"loop 02 off", false, Request{}},
		{"spare budget 999999", true, Request{Kind: KindBudget, Calls: MaxSpareCalls + 1}}, // answered with the limit (UX-57-2)
		{"spare budget -3", true, Request{Kind: KindBudget, Calls: 3}},                     // punctuation is ignored (CH-11)
		{"turn the loops off please", false, Request{}},
		{"loops off and book a table", false, Request{}},
	}
	for _, c := range cases {
		got, ok := ParseText(c.msg)
		if ok != c.ok || got != c.want {
			t.Errorf("ParseText(%q) = %+v, %v; want %+v, %v", c.msg, got, ok, c.want, c.ok)
		}
	}
}

// With no journal anywhere in the rig, each owner text applies on Text and
// survives a restart over the same store (HLD-4, UPD-4, UPD-5).
func TestOwnerTextAppliesSettingsWithoutAJournal(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	for _, msg := range []string{"LOOPS OFF", "LOOPS ON", "LOOP 2 OFF", "LEARNING OFF", "UPDATES FAST", "UPDATE SOAK 14", "SECURITY UPDATES ASK"} {
		if got, ok := r.s.Text(ctx, msg, true); !ok || strings.Contains(got, "could not") || strings.Contains(got, "Not allowed") {
			t.Fatalf("%s: %q %v", msg, got, ok)
		}
	}
	check := func(when string) {
		t.Helper()
		set := r.s.Settings()
		if set.Off || set.On(Secure) || set.On(Improve) || !set.On(Maintain) {
			t.Fatalf("%s: loops %+v", when, set)
		}
		if u := set.Updates; u.ChannelName() != ChannelFast || u.Soak() != 14 || !u.SecurityAsk {
			t.Fatalf("%s: updates %+v", when, u)
		}
	}
	check("applied")
	r.restart()
	check("after a restart")
	if !strings.Contains(strings.Join(r.s.Digest(), "\n"), "Learning is off. Reply LEARNING ON to restart it.") {
		t.Fatalf("digest does not say loop 1 is off: %q", r.s.Digest())
	}
}

// While STOP is in force only narrowings apply: LOOPS OFF, a lower and
// slower updates; LOOPS ON, a raise and faster updates are refused, and the
// passkey is never asked (HLD-4, KEY-6).
func TestOnlyNarrowingsApplyDuringStop(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.stopped.Store(true)
	for _, msg := range []string{"LOOPS OFF", "SPARE BUDGET 100", "UPDATE SOAK 14", "UPDATES PINNED"} {
		if got, ok := r.s.Text(ctx, msg, true); !ok || strings.Contains(got, "stopped") {
			t.Fatalf("%s during STOP: %q %v", msg, got, ok)
		}
	}
	for _, msg := range []string{"LOOPS ON", "LEARNING ON", "SPARE BUDGET 400", "UPDATES FAST", "UPDATE SOAK 7", "SECURITY UPDATES AUTO"} {
		if got, _ := r.s.Text(ctx, msg, true); got != "Everything is stopped, so only pauses and lower limits apply now." {
			t.Fatalf("%s during STOP: %q", msg, got)
		}
	}
	set := r.s.Settings()
	if !set.Off || set.SpareCalls != 100 || set.Updates.ChannelName() != ChannelPinned || set.Updates.Soak() != 14 {
		t.Fatalf("%+v", set)
	}
	if r.kern.Widened != 0 || r.spare.Cap() != SpareCap(100, loopstest.OutPerM) {
		t.Fatalf("a raise during STOP asked the passkey or moved the cap: widened %d, cap %d", r.kern.Widened, r.spare.Cap())
	}
}

// STOP SHARING and START SHARING go to the pipeline's setting (Sharing);
// a locked session takes only STOP SHARING.
func TestStopSharingGoesToThePipeline(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	for _, msg := range []string{"START SHARING", "STOP SHARING"} {
		req, _ := ParseText(msg)
		must(t, r.s.Set(ctx, req, true))
	}
	req, _ := ParseText("START SHARING")
	if err := r.s.Set(ctx, req, false); err == nil {
		t.Fatal("START SHARING applied in a locked session")
	}
	if got := r.sharing.calls(); len(got) != 2 || !got[0] || got[1] {
		t.Fatalf("sharing calls %v", got)
	}
}

func TestOneLoopOnAfterAllOffTurnsOnOnlyThatLoop(t *testing.T) {
	r := newRig(t)
	for _, msg := range []string{"LOOPS OFF", "LOOP 2 ON"} {
		req, _ := ParseText(msg)
		must(t, r.s.Set(context.Background(), req, true))
	}
	set := r.s.Settings()
	if !set.On(Secure) || set.On(Improve) || set.On(Maintain) {
		t.Fatalf("after LOOPS OFF, LOOP 2 ON: %+v", set)
	}
}

func TestZeroSpareBudgetAllowsNoModelCall(t *testing.T) {
	r := newRig(t)
	req, _ := ParseText("SPARE BUDGET 0")
	must(t, r.s.Set(context.Background(), req, true))
	// The clerk admits every call at its worst case (Clerk.Call), so the
	// smallest real call costs at least one minor unit.
	if rf := r.call(1); rf == nil || rf.Code != key.RSpendDay {
		t.Fatalf("a model call fit under a zero spare budget: %v", rf)
	}
}

func TestRepliesSayWhatChanged(t *testing.T) {
	set := Settings{SpareCalls: 40}
	cases := map[string]string{
		"LOOPS OFF":          "Spare-time work is off: no learning, security tests or update checks until you reply LOOPS ON.",
		"LOOPS ON":           "Spare-time work is back on. Reply LOOPS OFF if this wasn't you.",
		"SECURITY TESTS OFF": "Security tests are off until you reply SECURITY TESTS ON.",
		"UPDATE CHECKS ON":   "Update checks are back on. Reply UPDATE CHECKS OFF if this wasn't you.",
		"LEARNING ON":        "Learning is back on. Reply LEARNING OFF if this wasn't you.",
		"SPARE BUDGET 40":    "Spare-time work may now use up to 40 AI calls a day.",
		"HELP LOOPS":         HelpText,
	}
	for msg, want := range cases {
		r, ok := ParseText(msg)
		if got := Confirm(r, set); !ok || got != want {
			t.Errorf("%s: %q", msg, got)
		}
	}
	if len(HelpText) > 153 {
		t.Fatalf("HELP LOOPS is %d characters; keep it to one SMS segment", len(HelpText))
	}
}

// capOf is the day cap k's chain holds.
func capOf(t *testing.T, k key.Key) int64 {
	t.Helper()
	n, ok := dayCap(k)
	if !ok {
		t.Fatal("no day cap")
	}
	return n
}

// Every raise of the spare budget is a widening (KEY-6): with no passkey,
// or one that fails, nothing changes; with one, both the setting and the
// spare key's day cap rise. A raise back up after a lowering, still under
// the envelope's own cap, needs the passkey too (RES-5).
func TestRaisingTheSpareBudgetNeedsThePasskey(t *testing.T) {
	ctx := context.Background()
	unchanged := func(t *testing.T, r *rig, calls int64) {
		t.Helper()
		want := SpareCap(calls, loopstest.OutPerM)
		if got := r.s.Settings().SpareCalls; got != calls {
			t.Fatalf("budget %d, want %d", got, calls)
		}
		if r.spare.Cap() != want || capOf(t, r.spare.Key()) != want {
			t.Fatalf("spare cap %d, key cap %d, want %d", r.spare.Cap(), capOf(t, r.spare.Key()), want)
		}
	}
	t.Run("no passkey", func(t *testing.T) {
		r := newRig(t)
		r.spare.Widen = nil
		if got, ok := r.s.Text(ctx, "SPARE BUDGET 2000", true); !ok || got != "Raising spare-time AI use needs your passkey. Nothing changed." {
			t.Fatalf("%q %v", got, ok)
		}
		unchanged(t, r, NoSpareBudget)
	})
	t.Run("passkey fails", func(t *testing.T) {
		r := newRig(t)
		r.spare.Widen = func(int64) (key.Key, error) { return key.Key{}, errors.New("passkey dismissed") }
		if got, _ := r.s.Text(ctx, "SPARE BUDGET 2000", true); !strings.Contains(got, "passkey") {
			t.Fatalf("%q", got)
		}
		unchanged(t, r, NoSpareBudget)
	})
	t.Run("passkey", func(t *testing.T) {
		r := newRig(t)
		if got, ok := r.s.Text(ctx, "SPARE BUDGET 2000", true); !ok || got != "Spare-time work may now use up to 2000 AI calls a day." {
			t.Fatalf("%q %v", got, ok)
		}
		unchanged(t, r, 2000)
		if r.widened() != 1 {
			t.Fatalf("widened %d", r.widened())
		}
	})
	t.Run("re-raise under the envelope's cap", func(t *testing.T) {
		r := newRig(t)
		if _, ok := r.s.Text(ctx, "SPARE BUDGET 100", true); !ok {
			t.Fatal("lower")
		}
		r.spare.Widen = nil
		if got, _ := r.s.Text(ctx, "SPARE BUDGET 400", true); !strings.Contains(got, "passkey") {
			t.Fatalf("a re-raise below the envelope's cap applied without the passkey: %q", got)
		}
		unchanged(t, r, 100)
	})
}

// A lower from a locked session applies, and the kernel refuses a key that
// Spare.Key() handed out before it, a plan already running on it included
// (KEY-6, RES-5).
func TestLoweringTheBudgetRevokesKeysAtTheOldCap(t *testing.T) {
	r := newRig(t)
	one := SpareCap(1, loopstest.OutPerM)
	old := r.spare.Key()
	running := r.kern.Plan(old)
	if rf := r.kern.Spend(running, one); rf != nil {
		t.Fatal(rf)
	}
	if got, ok := r.s.Text(context.Background(), "SPARE BUDGET 10", false); !ok || r.s.Settings().SpareCalls != 10 {
		t.Fatalf("a locked lower: %q %v", got, ok)
	}
	if rf := r.kern.Spend(running, one); rf == nil || rf.Code != key.RRevoked {
		t.Fatalf("a running plan on the old key spent after the lower: %v", rf)
	}
	if rf := r.kern.Call(old, one); rf == nil {
		t.Fatal("a new plan on the old key spent after the lower")
	}
	if rf := r.kern.Call(r.spare.Key(), one); rf != nil {
		t.Fatalf("the lowered key: %v", rf)
	}
}

// While a raise waits inside Widen, narrowings and the scheduler's reads
// all return: LOOPS OFF from a locked session, a lower, Settings, Narrows,
// Spare.Cap and a Tick. The raise then finds the cap moved and is refused,
// and the lower stands (HLD-4, KEY-6).
func TestNarrowingsNeverWaitOnThePasskey(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	entered, release := r.gateWiden()
	raised := make(chan string, 1)
	go func() {
		got, _ := r.s.Text(ctx, "SPARE BUDGET 2000", true)
		raised <- got
	}()
	<-entered
	done := make(chan error, 1)
	go func() {
		done <- func() error {
			if got, ok := r.s.Text(ctx, "LOOPS OFF", false); !ok || strings.Contains(got, "could not") {
				return fmt.Errorf("LOOPS OFF: %q %v", got, ok)
			}
			if got, ok := r.s.Text(ctx, "SPARE BUDGET 50", false); !ok || strings.Contains(got, "could not") {
				return fmt.Errorf("lower: %q %v", got, ok)
			}
			_ = r.s.Settings()
			_ = r.s.Narrows("LOOPS OFF")
			_ = r.spare.Cap()
			r.s.Tick(ctx)
			return nil
		}()
	}()
	select {
	case err := <-done:
		must(t, err)
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("a narrowing waited on the passkey")
	}
	close(release)
	if got := <-raised; got != "The spare budget changed while I waited for your passkey. Nothing changed; send it again." {
		t.Fatalf("the raise after a lower: %q", got)
	}
	if set := r.s.Settings(); !set.Off || set.SpareCalls != 50 || r.spare.Cap() != SpareCap(50, loopstest.OutPerM) {
		t.Fatalf("the lower did not stand: %+v, cap %d", set, r.spare.Cap())
	}
}

// Raises and lowers race, some of them waiting inside Widen. At the end
// the saved budget maps to the cap the spare key holds (RES-5).
func TestConcurrentBudgetChangesEndConsistent(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.spare.Widen = func(n int64) (key.Key, error) {
		runtime.Gosched()
		return r.widen(n)
	}
	var wg sync.WaitGroup
	for i := range 16 {
		calls := 1600 + i
		if i%2 == 1 {
			calls = 10 + i
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.s.Text(ctx, fmt.Sprintf("SPARE BUDGET %d", calls), true)
		}()
	}
	wg.Wait()
	want := SpareCap(r.s.Settings().SpareCalls, loopstest.OutPerM)
	if r.spare.Cap() != want || capOf(t, r.spare.Key()) != want {
		t.Fatalf("budget %d calls (cap %d), spare cap %d, key cap %d", r.s.Settings().SpareCalls, want, r.spare.Cap(), capOf(t, r.spare.Key()))
	}
	r.restart()
	if r.spare.Cap() != want {
		t.Fatalf("after a restart the cap is %d, want %d", r.spare.Cap(), want)
	}
}

// A locked "SPARE BUDGET 400" is a lower against 1500, but it is judged
// against the budget current under budgetMu: when a lower to 100 lands
// first, it is a raise and is refused (CH-14, KEY-6).
func TestALockedLowerCannotBecomeARaise(t *testing.T) {
	r := newRig(t)
	r.spare.Widen = nil
	r.s.budgetMu.Lock()
	type answer struct {
		reply string
		ok    bool
	}
	got := make(chan answer, 1)
	go func() {
		reply, ok := r.s.Text(context.Background(), "SPARE BUDGET 400", false)
		got <- answer{reply, ok}
	}()
	// Let the text pass Text's own check and wait on budgetMu, then land
	// the lower to 100 as setBudget would.
	time.Sleep(100 * time.Millisecond)
	must(t, r.spare.SetCap(SpareCap(100, loopstest.OutPerM)))
	r.s.mu.Lock()
	r.s.st.Settings.SpareCalls = 100
	r.s.mu.Unlock()
	r.s.budgetMu.Unlock()
	if a := <-got; a.ok {
		t.Fatalf("a locked raise applied: %q", a.reply)
	}
	if r.s.Settings().SpareCalls != 100 || r.spare.Cap() != SpareCap(100, loopstest.OutPerM) {
		t.Fatalf("budget %d, cap %d", r.s.Settings().SpareCalls, r.spare.Cap())
	}
}
