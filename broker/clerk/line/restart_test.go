package line

// REQ: KRN-8, CLK-2

import (
	"context"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// Security fix-list on #3881 (6503740548): a clerk restart forgets a
// may-have-been-sent text; the kernel's probe must then read unknown, not
// notdone, so the text is not sent again (KRN-8).
func TestRestartNeverResendsAMaybeSentText(t *testing.T) {
	r := newRig(t, true)
	r.line.answer = func() error { return context.DeadlineExceeded }
	if res := r.text(t, "lost", shopNum, "on my way"); res.Detail != RMaybeSent {
		t.Fatalf("lost: %+v", res)
	}
	r.line.answer = nil
	// The clerk process restarts: same line, its sealed account reopened.
	r.c, r.signer = newClerk(t, &r.now, r.line, &r.logged)
	setUp(t, r.c, r.signer)
	for i := 0; i < 3; i++ {
		r.now += kernel.ProbeEvery + 1
		if err := r.k.Tick(r.now); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(r.line.texts()); n != 1 {
		t.Fatalf("a may-have-been-sent text was handed %d times: %v", n, r.line.texts())
	}
}
