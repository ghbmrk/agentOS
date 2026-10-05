package owner

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// REQ: CH-2, CH-4, CH-18, CRED-8

// fakeVerifier stands in for the vault process: it holds the seed, spends
// each matched step, and keeps its own last step, which an unlock of the
// vault also advances (egress K7). fail, when set, decides an error per
// call; block, when set, holds every call until it yields an error.
type fakeVerifier struct {
	mu      sync.Mutex
	seed    []byte
	now     func() time.Time
	fail    func(counted bool) error
	block   chan error
	last    int64
	afters  []int64
	counted []bool
}

func (f *fakeVerifier) VerifyTOTP(code string, after int64, counted bool) (int64, bool, error) {
	f.mu.Lock()
	f.afters = append(f.afters, after)
	f.counted = append(f.counted, counted)
	block := f.block
	f.mu.Unlock()
	if block != nil {
		return 0, false, <-block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		if err := f.fail(counted); err != nil {
			return 0, false, err
		}
	}
	step, ok := MatchTOTP(f.seed, code, f.now(), max(after, f.last))
	if ok {
		f.last = step
	}
	return step, ok, nil
}

func (f *fakeVerifier) calls() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.afters) }

func newVerifierRig(t *testing.T) (*rig, *fakeVerifier) {
	t.Helper()
	r := newRig(t, nil)
	f := &fakeVerifier{seed: testSecrets.TOTPSeed, now: r.clock}
	r.verifier = f
	r.ch = r.open()
	return r, f
}

func failWith(kind VerifyFailure, until time.Time) func(bool) error {
	return func(bool) error { return &VerifyError{Kind: kind, Until: until} }
}

// CH-4, CRED-8: with the seed held only by the vault process, the channel
// accepts code-generator codes through it, tells it the last step the
// channel accepted, and still refuses a replayed code.
func TestHighTierCodesAreCheckedWhereTheSeedIs(t *testing.T) {
	r, f := newVerifierRig(t)
	if len(r.ch.codes.sec.TOTPSeed) != 0 {
		t.Fatal("the channel holds a seed")
	}
	r.unlock()
	step := r.ch.codes.st.LastStep
	if step == 0 || f.afters[len(f.afters)-1] != 0 || !f.counted[len(f.counted)-1] {
		t.Fatalf("first unlock: step %d, afters %v, counted %v", step, f.afters, f.counted)
	}
	code := totpAt(testSecrets.TOTPSeed, r.clock().Unix())
	r.ch.RequireUnlock()
	if got := r.say(code); !strings.HasPrefix(got, "Wrong code") {
		t.Fatalf("replayed code: %q", got)
	}
	if f.afters[len(f.afters)-1] != step {
		t.Fatalf("channel did not pass its last step: %v", f.afters)
	}
	r.unlock()
	if r.ch.codes.st.LastStep <= step {
		t.Fatalf("step not recorded: %d", r.ch.codes.st.LastStep)
	}
}

// A code the vault process already spent (say, on a vault unlock) is
// refused by the channel, even though the channel never saw it (K7).
func TestCodeSpentByTheVaultIsRefused(t *testing.T) {
	r, f := newVerifierRig(t)
	r.advance(30 * time.Second)
	code := totpAt(testSecrets.TOTPSeed, r.clock().Unix())
	f.last = r.clock().Unix() / totpStep
	if got := r.say(code); !strings.HasPrefix(got, "Wrong code") {
		t.Fatalf("spent code accepted: %q", got)
	}
}

// CH-18: when no check can run, nothing is counted and nothing unlocks,
// and the owner is told which case it is, since retrying helps only in
// some of them.
func TestVerifierFailureCountsNothingAndSaysWhy(t *testing.T) {
	r, f := newVerifierRig(t)
	until := r.clock().Add(7 * time.Minute)
	want := map[VerifyFailure]string{
		VaultLocked:  "The vault is locked",
		VaultDown:    "The vault is not answering",
		VerifyPaused: "paused until " + until.Format("15:04"),
		VerifyLost:   "Try again with the next code",
	}
	seen := map[string]bool{}
	for kind, frag := range want {
		f.fail = failWith(kind, until)
		r.ch.codes.verifyOffUntil = time.Time{}
		got := r.say(r.totp())
		if !strings.Contains(got, frag) || !strings.Contains(got, "did not count") || seen[got] {
			t.Fatalf("%v: %q", kind, got)
		}
		seen[got] = true
	}
	if n := len(r.ch.codes.st.Wrong); n != 0 || r.ch.codes.st.LowLocked {
		t.Fatalf("counted %d wrong codes while no check ran", n)
	}
	if r.ch.SessionUnlocked(r.clock()) {
		t.Fatal("unlocked without a check")
	}
	f.fail = nil
	r.ch.codes.verifyOffUntil = time.Time{}
	r.unlock()
}

// O5 checks are marked silent for the vault's separate bound. When that
// bound is full the chat passes on unstripped, the owner is alerted once,
// and a counted code still works.
func TestFullSilentBoundPassesChatOnAndCountedCodesStillWork(t *testing.T) {
	r, f := newVerifierRig(t)
	r.unlock()
	r.say("plan my week 000000")
	if f.counted[len(f.counted)-1] {
		t.Fatal("chat code sent as a counted check")
	}
	until := r.clock().Add(10 * time.Minute)
	f.fail = func(counted bool) error {
		if counted {
			return nil
		}
		return &VerifyError{Kind: VerifyPaused, Until: until}
	}
	first := r.say("plan my week 123456")
	if !strings.Contains(first, "Many texts ending in a code") {
		t.Fatalf("no flood alert: %q", first)
	}
	if got := r.agent.got(); got[len(got)-1] != "plan my week 123456" {
		t.Fatalf("chat not passed on unstripped: %q", got)
	}
	if again := r.say("plan my week 654321"); strings.Contains(again, "Many texts") {
		t.Fatalf("alerted twice within AlertEvery: %q", again)
	}
	r.ch.RequireUnlock()
	r.unlock()
}

var tokenRe = regexp.MustCompile(`UNLOCK ([A-Z2-9]{4})`)

// O4: a challenge attempt the vault never checked is refunded: the owner
// keeps the token and the attempt.
func TestChallengeAttemptIsRefundedWhenTheVaultCannotCheck(t *testing.T) {
	r, f := newVerifierRig(t)
	r.ch.codes.st.Challenged = true
	m := tokenRe.FindStringSubmatch(r.say("UNLOCK"))
	if m == nil {
		t.Fatal("no challenge token")
	}
	f.fail = failWith(VaultLocked, time.Time{})
	if got := r.say("UNLOCK " + m[1] + " " + r.totp()); !strings.Contains(got, "vault is locked") {
		t.Fatalf("locked vault: %q", got)
	}
	if r.ch.codes.st.BoundUsed != 0 || !r.ch.codes.challengeOK(m[1], r.clock()) {
		t.Fatalf("attempt or token spent: bound %d", r.ch.codes.st.BoundUsed)
	}
	f.fail = nil
	if got := r.say("UNLOCK " + m[1] + " " + r.totp()); !strings.HasPrefix(got, "Unlocked until") {
		t.Fatalf("kept token: %q", got)
	}
}

// CH-2: STOP is applied at once, even with a hung vault process and a
// backlog of coded texts; after the first check gets no answer the rest
// fail fast (VerifyBreaker) instead of each waiting.
func TestStopIsNotQueuedBehindAHungVerifier(t *testing.T) {
	r, f := newVerifierRig(t)
	f.block = make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.ch.Run(ctx)
	for i := 0; i < 20; i++ {
		_ = r.phone.Send(boxNum, "plan my week 123456")
	}
	for f.calls() == 0 {
		time.Sleep(time.Millisecond)
	}
	_ = r.phone.Send(boxNum, "STOP")
	if got := r.inbox(); !strings.HasPrefix(got, "Stopped.") || !r.eng.Stopped() {
		t.Fatalf("STOP behind a hung check: %q", got)
	}
	f.block <- &VerifyError{Kind: VerifyLost}
	for i := 0; i < 20; i++ {
		r.inbox()
	}
	if n := f.calls(); n != 1 {
		t.Fatalf("%d checks reached a hung vault process, want 1", n)
	}

	// Handle (the owner socket) takes the same fast path.
	f.mu.Lock()
	f.block = make(chan error)
	f.mu.Unlock()
	r.ch.codes.verifyOffUntil = time.Time{}
	go r.ch.Handle(ctx, ownerNum, "plan my week 123456")
	for f.calls() == 1 {
		time.Sleep(time.Millisecond)
	}
	done := make(chan []string)
	go func() { done <- r.ch.Handle(ctx, ownerNum, "STOP") }()
	select {
	case out := <-done:
		if len(out) == 0 || !strings.HasPrefix(out[0], "Stopped.") {
			t.Fatalf("STOP: %q", out)
		}
	case <-time.After(time.Second):
		t.Fatal("STOP waited on a code check")
	}
	f.block <- &VerifyError{Kind: VerifyLost}
}

// The grid cell is checked locally before the vault process is asked, so
// a right grid answer does not count as a wrong code there; a wrong one
// is still checked as a code-generator code.
func TestGridAnswerDoesNotReachTheVerifier(t *testing.T) {
	r, f := newVerifierRig(t)
	cell := gridRe.FindStringSubmatch(r.say("status"))
	if cell == nil {
		t.Fatal("no grid challenge")
	}
	n := f.calls()
	if got := r.say("000000"); !strings.HasPrefix(got, "Wrong code") || f.calls() != n+1 {
		t.Fatalf("wrong grid answer: %q, %d calls", got, f.calls()-n)
	}
	n = f.calls()
	if got := r.say(GridCell(testSecrets.GridSeed, cell[1])); !strings.HasPrefix(got, "Unlocked") {
		t.Fatalf("grid unlock: %q", got)
	}
	if f.calls() != n {
		t.Fatal("grid answer sent to the verifier")
	}
}
