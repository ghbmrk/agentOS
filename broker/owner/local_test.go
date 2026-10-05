package owner

import (
	"context"
	"strings"
	"testing"
	"time"
)

// REQ: CH-7, CH-11, CH-18

// The local UI (P2-2) signs in with a code-generator code. Per O4's
// carry-forward, that sign-in is also a local unlock: it clears challenge
// mode and the low-tier lock, as a texted UNLOCK with the challenge would,
// without needing the texted challenge, because joining the box's Wi-Fi
// already proves the card.
func TestLocalSignInClearsChallengeModeAndUnlocks(t *testing.T) {
	r := newRig(t, nil)
	enterChallenge(t, r)
	if !r.ch.codes.st.LowLocked || r.ch.SessionUnlocked(r.clock()) {
		t.Fatal("setup: expected low tier locked and session locked")
	}
	until, err := r.ch.LocalSignIn(r.totp())
	if err != nil {
		t.Fatal(err)
	}
	st := r.ch.LocalStatus()
	if st.Challenged || st.LowLocked || !st.Unlocked || !until.Equal(r.clock().Add(DefaultUnlockFor)) {
		t.Fatalf("after local sign-in: %+v until %v", st, until)
	}
	// Text codes work normally again: a bare code no longer drops.
	if got := r.say("hello " + r.totp()); strings.Contains(got, "ignored") {
		t.Fatalf("still challenged by text: %q", got)
	}
}

func TestLocalSignInAcceptsTheAskedGridCellOnly(t *testing.T) {
	r := newRig(t, nil)
	cell := r.ch.LocalGridCell()
	if cell == "" {
		t.Fatal("no grid cell asked")
	}
	other := "A1"
	if cell == other {
		other = "B1"
	}
	if _, err := r.ch.LocalSignIn(GridCell(testSecrets.GridSeed, other)); err != ErrWrongCode {
		t.Fatalf("unasked cell: %v", err)
	}
	cell = r.ch.LocalGridCell()
	if _, err := r.ch.LocalSignIn(GridCell(testSecrets.GridSeed, cell)); err != nil {
		t.Fatalf("asked cell: %v", err)
	}
	// Single use (CH-18).
	r.ch.codes.challenge = cell
	if _, err := r.ch.LocalSignIn(GridCell(testSecrets.GridSeed, cell)); err != ErrWrongCode {
		t.Fatalf("spent cell reused: %v", err)
	}
}

// Wrong local codes count like any wrong code (CH-18): five lock the low
// tier and the owner is texted, so guessing on the Wi-Fi is visible.
func TestLocalWrongCodesCountAndAlertTheOwner(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	r.advance(time.Second)
	for i := 0; i < WrongToLock; i++ {
		if _, err := r.ch.LocalSignIn(wrongCode(i)); err != ErrWrongCode {
			t.Fatalf("wrong %d: %v", i, err)
		}
	}
	if !r.ch.codes.st.LowLocked || r.ch.SessionUnlocked(r.clock()) {
		t.Fatal("five wrong local codes did not lock")
	}
	if got := r.inbox(); !strings.Contains(got, "box's Wi-Fi") {
		t.Fatalf("owner alert: %q", got)
	}
}

// Local attempts have their own fixed 24-hour bound, so the Wi-Fi is not
// an unmetered guessing path even in challenge mode, where wrong codes no
// longer escalate anything.
func TestLocalAttemptsAreBounded(t *testing.T) {
	r := newRig(t, nil)
	enterChallenge(t, r)
	for i := 0; i < LocalBound; i++ {
		if _, err := r.ch.LocalSignIn(wrongCode(i)); err != ErrWrongCode {
			t.Fatalf("attempt %d: %v", i, err)
		}
		r.advance(time.Minute)
	}
	if _, err := r.ch.LocalSignIn(r.totp()); err != ErrTooMany {
		t.Fatalf("over the bound, even a right code: %v", err)
	}
	// The bound survives a restart.
	r.ch = r.open()
	if _, err := r.ch.LocalSignIn(r.totp()); err != ErrTooMany {
		t.Fatalf("bound forgotten on restart: %v", err)
	}
	r.advance(WrongWindow)
	if _, err := r.ch.LocalSignIn(r.totp()); err != nil {
		t.Fatalf("next window: %v", err)
	}
}

// RESUME on the local UI: the caller has a signed-in device, which is a
// stronger proof than CH-11's texted code, so no further code is asked.
func TestLocalStopAndResume(t *testing.T) {
	r := newRig(t, nil)
	if msg, err := r.ch.LocalResume(); err != nil || msg != "Not stopped. Nothing to resume." {
		t.Fatalf("resume while running: %q %v", msg, err)
	}
	if err := r.ch.LocalStop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !r.ch.LocalStatus().Stopped {
		t.Fatal("not stopped")
	}
	// A texted RESUME code issued before is void after a local resume.
	r.say("RESUME")
	msg, err := r.ch.LocalResume()
	if err != nil || !strings.HasPrefix(msg, "Resumed.") || r.eng.Stopped() {
		t.Fatalf("local resume: %q %v", msg, err)
	}
	if r.ch.resume != nil {
		t.Fatal("texted RESUME code still live")
	}
}

func TestTOTPMatchesTheChannelsCheck(t *testing.T) {
	r := newRig(t, nil)
	r.advance(30 * time.Second)
	if _, err := r.ch.LocalSignIn(TOTP(testSecrets.TOTPSeed, r.clock())); err != nil {
		t.Fatal(err)
	}
}

// Every local sign-in is texted to the owner, coalesced to one text an
// hour that lists each (CH-15). Wrong local codes are texted on the first
// of a bound window and when the bound runs out, and listed in the digest.
func TestLocalSignInAlertsAreCoalesced(t *testing.T) {
	r := newRig(t, nil)
	if _, err := r.ch.LocalSignIn(r.totp()); err != nil {
		t.Fatal(err)
	}
	first := r.clock().Format("15:04")
	if got := r.inbox(); got != "A phone signed in on the box's Wi-Fi at "+first+". Not you? Text STOP." {
		t.Fatalf("sign-in alert: %q", got)
	}
	r.advance(10 * time.Minute)
	r.ch.LocalSignIn(r.totp())
	second := r.clock().Format("15:04")
	r.advance(10 * time.Minute)
	r.ch.LocalSignIn(r.totp())
	third := r.clock().Format("15:04")
	r.ch.Tick()
	select {
	case m := <-r.phone.Inbox():
		t.Fatalf("second sign-in text inside the hour: %q", m.Text)
	default:
	}
	r.advance(SignInAlertEvery)
	r.ch.Tick()
	if got := r.inbox(); got != "Phones signed in on the box's Wi-Fi at "+second+", "+third+". Not you? Text STOP." {
		t.Fatalf("coalesced alert: %q", got)
	}

	r = newRig(t, nil)
	r.ch.LocalSignIn(wrongCode(1))
	if got := r.inbox(); !strings.HasPrefix(got, "A wrong code was entered on the box's Wi-Fi") {
		t.Fatalf("first wrong-code alert: %q", got)
	}
	r.advance(time.Minute)
	r.ch.LocalSignIn(wrongCode(2))
	select {
	case m := <-r.phone.Inbox():
		t.Fatalf("second wrong code texted: %q", m.Text)
	default:
	}
	notes := strings.Join(r.ch.TakeDigestNotes(), " ")
	if !strings.Contains(notes, "2 wrong codes entered on the box's Wi-Fi") {
		t.Fatalf("digest: %q", notes)
	}
	if r.ch.UnlockPeriod() != DefaultUnlockFor {
		t.Fatal("unlock period")
	}
}

// Held-back sign-ins survive a restart, and a failed send keeps them for
// the next Tick (second re-review on #32).
func TestLocalSignInAlertsSurviveRestartAndFailedSend(t *testing.T) {
	r := newRig(t, nil)
	r.ch.LocalSignIn(r.totp())
	r.inbox()
	r.advance(10 * time.Minute)
	r.ch.LocalSignIn(r.totp())
	held := r.clock().Format("15:04")
	r.ch = r.open()
	r.advance(SignInAlertEvery)
	r.box.SetDown(true)
	r.ch.Tick()
	r.box.SetDown(false)
	select {
	case m := <-r.phone.Inbox():
		t.Fatalf("text while the modem was down: %q", m.Text)
	default:
	}
	r.ch = r.open()
	r.ch.Tick()
	if got := r.inbox(); got != "A phone signed in on the box's Wi-Fi at "+held+". Not you? Text STOP." {
		t.Fatalf("held sign-in after restart and failed send: %q", got)
	}
	// Sent once only.
	r.advance(SignInAlertEvery)
	r.ch.Tick()
	select {
	case m := <-r.phone.Inbox():
		t.Fatalf("sign-in texted twice: %q", m.Text)
	default:
	}
}

// A sign-in recorded while a sign-in text is out stays for the next text,
// even at the maxSignIns cap (third re-review on #32).
func TestSignInDuringSendIsKept(t *testing.T) {
	r := newRig(t, nil)
	now := r.clock()
	r.ch.mu.Lock()
	r.ch.codes.commit(func(s *State) {
		for i := 0; i < maxSignIns; i++ {
			s.LocalSignIns = append(s.LocalSignIns, now.Add(time.Duration(i-maxSignIns)*time.Minute))
		}
	})
	text, n, m := r.ch.signInTextLocked(now)
	r.ch.mu.Unlock()
	// One more signs in mid-send; the cap pushes out the oldest.
	if _, err := r.ch.LocalSignIn(r.totp()); err != nil {
		t.Fatal(err)
	}
	r.ch.sendSignIns(text, n, m, now)
	if got := r.ch.codes.st.LocalSignIns; len(got) != 1 {
		t.Fatalf("left after send: %v", got)
	}
}

// When the local bound runs out the owner is told until when.
func TestLocalBoundExhaustionIsTexted(t *testing.T) {
	r := newRig(t, nil)
	enterChallenge(t, r)
	for i := 0; i < LocalBound; i++ {
		r.ch.LocalSignIn(wrongCode(i))
	}
	var last string
	for {
		select {
		case m := <-r.phone.Inbox():
			last = m.Text
			continue
		default:
		}
		break
	}
	if !strings.HasPrefix(last, "Sign-in on the box's Wi-Fi is paused until") {
		t.Fatalf("bound alert: %q", last)
	}
}
