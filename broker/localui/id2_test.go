package localui

import (
	"strings"
	"testing"
	"time"
)

// REQ: ID-2

// ID-2: there is no first-caller enrollment. Before pairing, a stranger who
// texts the box first, with no code or a wrong one, does not become the
// owner; only a code from this box's setup page or card pairs. Guesses are
// capped per hour, so the card's setup code cannot be found by trying.
func TestFirstCallerIsNotEnrolled(t *testing.T) {
	r := newRig(t)
	r.hooks.progress.Online = true
	r.get("/setup")
	const stranger = "+15550004242"
	for _, text := range []string{"HELLO", "SETUP", "PAIR", "OWNER", "START", "PAIR ABCDEFGH"} {
		r.srv.OfferText(stranger, text)
		if r.srv.setup.st.Owner != "" {
			t.Fatalf("first caller enrolled by %q", text)
		}
	}
	for i := 0; i < PairTriesPerHour+5; i++ {
		r.srv.OfferText(stranger, "PAIR ZZZZ-ZZZZ")
	}
	// The cap holds even for the right code: guessing cannot reach it.
	if _, handled := r.srv.OfferText(stranger, "PAIR "+r.card.SetupCode); !handled || r.srv.setup.st.Owner != "" {
		t.Fatal("pairing still open after the hour's wrong guesses")
	}
	if len(r.hooks.sent) != 0 {
		t.Fatalf("the box texted a stranger: %+v", r.hooks.sent)
	}
	// The card holder pairs once the hour has passed.
	r.advance(61 * time.Minute)
	reply, _ := r.srv.OfferText(ownerNum, "PAIR "+r.card.SetupCode)
	if r.srv.setup.st.Owner != ownerNum || !strings.Contains(reply, "Page code") {
		t.Fatalf("card holder not paired: %q", reply)
	}
}
