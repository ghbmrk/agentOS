package owner

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// REQ: CH-4, CH-18, CRED-8

// fakeVerifier stands in for the vault process: it holds the seed, spends
// each matched step, and keeps its own last step, which an unlock of the
// vault also advances (egress K7).
type fakeVerifier struct {
	mu     sync.Mutex
	seed   []byte
	now    func() time.Time
	err    error
	last   int64
	afters []int64
}

func (f *fakeVerifier) VerifyTOTP(code string, after int64) (int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.afters = append(f.afters, after)
	if f.err != nil {
		return 0, false, f.err
	}
	step, ok := MatchTOTP(f.seed, code, f.now(), max(after, f.last))
	if ok {
		f.last = step
	}
	return step, ok, nil
}

func newVerifierRig(t *testing.T) (*rig, *fakeVerifier) {
	t.Helper()
	r := newRig(t, nil)
	f := &fakeVerifier{seed: testSecrets.TOTPSeed, now: r.clock}
	r.verifier = f
	r.ch = r.open()
	return r, f
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
	if step == 0 || f.afters[len(f.afters)-1] != 0 {
		t.Fatalf("first unlock: step %d, afters %v", step, f.afters)
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

// When no check can run (vault locked, process down, or it refuses for
// too many wrong codes), nothing is counted and nothing unlocks.
func TestVerifierFailureCountsNothing(t *testing.T) {
	r, f := newVerifierRig(t)
	f.err = errors.New("vault locked")
	for i := 0; i < WrongToLock+1; i++ {
		if got := r.say(r.totp()); got != stateErr {
			t.Fatalf("verifier down: %q", got)
		}
	}
	if n := len(r.ch.codes.st.Wrong); n != 0 || r.ch.codes.st.LowLocked {
		t.Fatalf("counted %d wrong codes while no check ran", n)
	}
	if r.ch.SessionUnlocked(r.clock()) {
		t.Fatal("unlocked without a check")
	}
	f.err = nil
	r.unlock()
}

// The grid cell is checked locally before the vault process is asked, so
// a grid answer does not count as a wrong code there.
func TestGridAnswerDoesNotReachTheVerifier(t *testing.T) {
	r, f := newVerifierRig(t)
	cell := gridRe.FindStringSubmatch(r.say("status"))
	if cell == nil {
		t.Fatal("no grid challenge")
	}
	n := len(f.afters)
	if got := r.say(GridCell(testSecrets.GridSeed, cell[1])); !strings.HasPrefix(got, "Unlocked") {
		t.Fatalf("grid unlock: %q", got)
	}
	if len(f.afters) != n {
		t.Fatal("grid answer sent to the verifier")
	}
}
