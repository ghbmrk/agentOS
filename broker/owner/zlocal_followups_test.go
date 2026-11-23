package owner

import (
	"strings"
	"testing"
	"time"
)

// REQ: CH-18 (#1793)
// A LocalStart after now, left by a clock set back, counts as elapsed
// (O35): the local sign-in bound is whole again, a pause it held is over,
// the next try starts a fresh window at now, and "paused until" then
// names a time 24 hours from now, not 24 hours from the future start.
func TestAFutureLocalStartCountsAsElapsed(t *testing.T) {
	for _, skew := range []time.Duration{24 * time.Hour, time.Minute} {
		t.Run(skew.String(), func(t *testing.T) {
			r := newRig(t, nil)
			enterChallenge(t, r)
			now := r.clock()
			r.ch.codes.commit(func(s *State) { s.LocalStart, s.LocalUsed = now.Add(skew), LocalBound })
			if st := r.ch.LocalStatus(); st.LocalLeft != LocalBound || st.LocalReset != "" {
				t.Fatalf("future start %v ahead: %+v, want the whole bound and no reset", skew, st)
			}
			for i := 0; i < LocalBound; i++ {
				r.ch.LocalSignIn(wrongCode(i))
				if i == 0 {
					if got := r.ch.codes.st.LocalStart; !got.Equal(now) {
						t.Fatalf("window starts %v, want now %v", got, now)
					}
				}
			}
			r.ch.WaitSends()
			want := "Sign-in on my Wi-Fi is paused until " + now.Add(WrongWindow).In(time.UTC).Format("15:04")
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
			if !strings.HasPrefix(last, want) {
				t.Fatalf("bound alert %q, want prefix %q", last, want)
			}
			if st := r.ch.LocalStatus(); st.LocalLeft != 0 || st.LocalReset != now.Add(WrongWindow).In(time.UTC).Format("15:04") {
				t.Fatalf("after the bound: %+v", st)
			}
		})
	}
}

// REQ: CH-15, UX-2wb-1 (#1752 item 1)
// The texts a local page call sends after its reply go out in call order:
// a later call's alert waits behind an earlier call's sign-in text still
// in the modem (afterReply's sendTail chain), and follows it once sent.
func TestTextsAfterTheReplyGoInCallOrder(t *testing.T) {
	r, g, open := raceRig(t, 10)
	defer func() { open(); r.ch.WaitSends() }()
	if _, _, err := r.ch.LocalSignIn(r.totp()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the sign-in text never reached the modem")
	}
	if _, _, err := r.ch.LocalSignIn("000000"); err == nil {
		t.Fatal("wrong code accepted")
	}
	// A broken chain would send the alert at once, past the held text.
	time.Sleep(100 * time.Millisecond)
	if got, _ := g.tried(); len(got) != 1 {
		t.Fatalf("texts in the modem with the first still held: %q, want only the sign-in text", got)
	}
	open()
	r.ch.WaitSends()
	got, _ := g.tried()
	if len(got) != 2 || strings.HasPrefix(got[0], "A wrong code") || !strings.HasPrefix(got[1], "A wrong code") {
		t.Fatalf("texts %q, want the sign-in text, then the wrong-code alert", got)
	}
}

// REQ: CH-7, UX-2wb-1 (#1802, Security N1 on #1686)
// Once DrainSends has begun, a text after a reply is not started on a
// goroutine the drain might miss (a WaitGroup Add racing its Wait): it is
// sent in the caller, before the call returns, so it is neither lost nor
// raced.
func TestATextAfterTheDrainBeganIsSentInTheCaller(t *testing.T) {
	r, g, open := raceRig(t, 10)
	open()
	r.ch.DrainSends(time.Second, nil)
	if _, _, err := r.ch.LocalSignIn("000000"); err == nil {
		t.Fatal("wrong code accepted")
	}
	if got, _ := g.tried(); len(got) != 1 || !strings.HasPrefix(got[0], "A wrong code") {
		t.Fatalf("texts when the call returned %q, want the wrong-code alert", got)
	}
}
