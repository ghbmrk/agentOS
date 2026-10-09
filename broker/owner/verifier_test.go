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
	// proof, when set, is a vault unlock's ticket whose sign-in proof
	// (UnlockProofPrefix+proof) matches once (P2-4f).
	proof string
}

func (f *fakeVerifier) VerifyTOTP(code string, after int64, counted bool) (int64, bool, error) {
	f.mu.Lock()
	f.afters = append(f.afters, after)
	f.counted = append(f.counted, counted)
	block := f.block
	f.mu.Unlock()
	if block != nil {
		if err := <-block; err != nil {
			return 0, false, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		if err := f.fail(counted); err != nil {
			return 0, false, err
		}
	}
	if f.proof != "" && code == UnlockProofPrefix+f.proof {
		f.proof = ""
		f.last = max(after, f.last) + 1
		return f.last, true, nil
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
// bound is full the chat passes on unstripped and a counted code still
// works. The owner gets one flood alert per FloodAlertEvery, whether a
// bucket fills or challenge mode trips, and every event is in the digest.
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
	if !strings.Contains(first, "Many wrong codes have come from your number") ||
		!strings.Contains(first, "unchecked until "+until.Format("15:04")) {
		t.Fatalf("no flood alert: %q", first)
	}
	if got := r.agent.got(); got[len(got)-1] != "plan my week 123456" {
		t.Fatalf("chat not passed on unstripped: %q", got)
	}
	r.advance(12 * time.Hour)
	if again := r.say("plan my week 654321"); strings.Contains(again, "Many wrong codes") {
		t.Fatalf("alerted twice within FloodAlertEvery: %q", again)
	}
	r.ch.RequireUnlock()
	r.unlock()

	// The counted bucket full is a flood sign too; after a day it alerts
	// again.
	r.ch.RequireUnlock()
	f.fail = failWith(VerifyPaused, r.clock().Add(5*time.Minute))
	r.advance(12 * time.Hour)
	if got := r.say(r.totp()); !strings.Contains(got, "paused until") || !strings.Contains(got, "Many wrong codes") {
		t.Fatalf("counted bucket full: %q", got)
	}
	notes := r.ch.TakeDigestNotes()
	if len(notes) != 1 || notes[0] != "Possible code flood: 2 texts with a code passed on unchecked, 1 codes refused at the vault's limit." {
		t.Fatalf("digest %q", notes)
	}
}

// Arbitrator condition (P2-4c): codes are checked only for texts from the
// owner's number. Agent or guest text (Notify, the guest's owner reply)
// and texts from any other number never reach the verifier, so a code
// passed on unchecked in chat gives the agent nothing to test.
func TestOnlyOwnerTextsReachTheVerifier(t *testing.T) {
	r, f := newVerifierRig(t)
	code := totpAt(testSecrets.TOTPSeed, r.clock().Unix())
	r.ch.Notify("Your code is " + code)
	r.ch.Notify(code)
	r.sayFrom("+15559999999", code)
	r.sayFrom("+15559999999", "plan my week "+code)
	if n := f.calls(); n != 0 {
		t.Fatalf("%d checks from text that was not the owner's", n)
	}
	r.unlock()
	if f.calls() != 1 {
		t.Fatal("owner code not checked")
	}
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

// CH-2: a STOP sent while a RESUME code is being checked is never lifted
// by that RESUME, on the RESUME-code path or the challenge path.
func TestStopDuringAResumeCheckIsNotLifted(t *testing.T) {
	for _, challenge := range []bool{false, true} {
		r, f := newVerifierRig(t)
		ctx := context.Background()
		r.ch.codes.st.LowLocked = true // RESUME then needs a code-generator code
		r.say("STOP")
		var resume string
		if challenge {
			r.ch.codes.st.Challenged = true
			m := tokenRe.FindStringSubmatch(r.say("UNLOCK"))
			resume = "RESUME " + m[1] + " "
		} else {
			r.say("RESUME")
			resume = "RESUME "
		}
		f.mu.Lock()
		f.block = make(chan error)
		f.mu.Unlock()
		n := f.calls()
		done := make(chan string)
		code := r.totp()
		go func() { done <- strings.Join(r.ch.Handle(ctx, ownerNum, resume+code), " | ") }()
		for f.calls() == n {
			time.Sleep(time.Millisecond)
		}
		r.ch.Handle(ctx, ownerNum, "STOP") // mid-check
		f.block <- nil                     // the code is right
		if got := <-done; !strings.Contains(got, "A STOP arrived while the code was checked") || !r.eng.Stopped() {
			t.Fatalf("challenge=%v: %q, stopped %v", challenge, got, r.eng.Stopped())
		}
	}
}

// #65 security C1: the vault unlock's sign-in proof signs in on the local
// page only. Every other strong-code path (approvals, RESUME, chat codes)
// refuses it before the vault process sees it, without counting it, so it
// cannot be spent on an approval within its minute.
func TestUnlockProofOnlySignsIn(t *testing.T) {
	r, f := newVerifierRig(t)
	f.proof = "0123456789abcdef0123456789abcdef"
	proof := UnlockProofPrefix + f.proof
	for _, o := range []strongOpts{
		{unlock: time.Hour, count: true}, // texted approval, unlock by text
		{unlock: time.Hour},              // high-tier RESUME / YES
		{silent: true},                   // O5 code in chat
	} {
		r.ch.mu.Lock()
		res, _, err := r.ch.codes.checkStrong(proof, r.clock(), o)
		wrong := len(r.ch.codes.st.Wrong)
		r.ch.mu.Unlock()
		if res != strongWrong || err != nil || wrong != 0 {
			t.Fatalf("%+v: res %v err %v wrong %d", o, res, err, wrong)
		}
	}
	if f.calls() != 0 {
		t.Fatalf("the vault process was asked %d times", f.calls())
	}
	if _, _, err := r.ch.LocalSignIn(proof); err != nil {
		t.Fatalf("sign-in with the proof: %v", err)
	}
}

// A refused unlock proof is not a wrong code: the vault process refuses
// one it has no match for (a late redirect) and counts a wrong one itself
// (#65 L3 follow-up 1).
func TestRefusedUnlockProofIsNotCounted(t *testing.T) {
	r, f := newVerifierRig(t)
	if _, _, err := r.ch.LocalSignIn(UnlockProofPrefix + "0123456789abcdef0123456789abcdef"); err != ErrWrongCode {
		t.Fatalf("refused proof: %v", err)
	}
	r.ch.mu.Lock()
	wrong := len(r.ch.codes.st.Wrong)
	r.ch.mu.Unlock()
	if wrong != 0 {
		t.Fatalf("refused proof counted: %d", wrong)
	}
	// The vault process counts it in its own bucket instead.
	if f.calls() != 1 || !f.counted[0] {
		t.Fatalf("vault process not asked to count it: %v", f.counted)
	}
	// And the owner, who just unlocked, gets no wrong-code text (#75 L3).
	select {
	case m := <-r.phone.Inbox():
		t.Fatalf("owner texted: %q", m.Text)
	case <-time.After(100 * time.Millisecond):
	}
}
