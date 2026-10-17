package maintain

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/update"
)

// REQ: UPD-5, CH-12, P2-2a-f4b, P2-2a-f4c, P2-2a-f4d, P2-2a-f4f

// askedFast has release 2 on the fast channel waiting for the owner as c1.
func askedFast(t *testing.T) *rig {
	t.Helper()
	r := newRig(t)
	r.settings.Updates.Channel = update.ChannelFast
	r.release(2, func(m *update.Manifest) { m.Channel = update.ChannelFast })
	r.tick()
	if n := len(r.p.proposed()); n != 1 {
		t.Fatalf("proposed %d times", n)
	}
	return r
}

// askedSecurity has security release 2 waiting for the owner as c1: no
// attestor is listed, so the owner approves it.
func askedSecurity(t *testing.T) *rig {
	t.Helper()
	r := newRig(t)
	r.allow = nil
	r.release(2, func(m *update.Manifest) { m.Security = true })
	r.tick()
	if n := len(r.p.proposed()); n != 1 {
		t.Fatalf("proposed %d times", n)
	}
	return r
}

func day(r *rig) string { return r.clk.now().Format("Mon 2 Jan") }

// wantLine checks STATUS and the digest say want, and never that the
// release is waiting for the owner's approval.
func wantLine(t *testing.T, r *rig, want string) {
	t.Helper()
	if st := r.l.Status(); st.Line != want {
		t.Fatalf("status %q, want %q", st.Line, want)
	}
	if d := r.digest(); !strings.Contains(d, want) || strings.Contains(d, "waiting for your approval") {
		t.Fatalf("digest %q, want %q", d, want)
	}
}

// P2-2a-f4b: after the owner's NO, STATUS says so with the day and that
// the next update will be offered; the release is not asked again, and a
// newer one is.
func TestDeclinedReleaseLine(t *testing.T) {
	for name, c := range map[string]struct {
		rig    func(*testing.T) *rig
		prefix string
	}{
		"ordinary": {askedFast, "Update 2"},
		"security": {askedSecurity, "Security update 2"},
	} {
		t.Run(name, func(t *testing.T) {
			r := c.rig(t)
			r.p.close("c1", change.ClosedDeclined)
			wantLine(t, r, c.prefix+": you said no on "+day(r)+". I will offer the next update when it is out.")
			r.nextCheck()
			if n := len(r.p.proposed()); n != 1 {
				t.Fatalf("a declined release asked again: proposed %d times", n)
			}
			if st := r.l.Status(); !strings.Contains(st.Line, "you said no") {
				t.Fatalf("status after the next check %q", st.Line)
			}
		})
	}

	r := askedFast(t)
	r.p.close("c1", change.ClosedDeclined)
	r.release(3, func(m *update.Manifest) { m.Channel = update.ChannelFast })
	r.nextCheck()
	if got := r.p.proposed(); len(got) != 2 {
		t.Fatalf("a newer release after a NO: proposed %d times", len(got))
	}
	if st := r.l.Status(); !strings.Contains(st.Line, "Update 3 has been waiting for your approval") {
		t.Fatalf("status %q", st.Line)
	}
}

func TestLeftOutReleaseLine(t *testing.T) {
	r := askedFast(t)
	r.p.close("c1", change.ClosedLeftOut)
	wantLine(t, r, "Update 2: you left it out on "+day(r)+". I will offer the next update when it is out.")
	r.nextCheck()
	if n := len(r.p.proposed()); n != 1 {
		t.Fatalf("a release left out asked again: proposed %d times", n)
	}
}

// After a lapse no request is open, and STATUS says when it is asked
// again.
func TestLapsedReleaseLine(t *testing.T) {
	r := askedFast(t)
	r.p.lapse("c1")
	wantLine(t, r, "Update 2: your approval request closed on "+day(r)+" without an answer. I will ask again at the next daily check.")
	r.nextCheck()
	if n := len(r.p.proposed()); n != 2 {
		t.Fatalf("lapsed release proposed %d times", n)
	}
	if st := r.l.Status(); !strings.Contains(st.Line, "Update 2 has been waiting for your approval since "+day(r)) {
		t.Fatalf("status after the new request %q", st.Line)
	}
}

// P2-2a-f4c, P2-2a-f4f: an approved release that was not installed is
// offered again at the next daily check, not before; from the third
// failure STATUS counts them.
func TestFailedInstallReofferedAtNextCheck(t *testing.T) {
	r := askedFast(t)
	r.p.close("c1", change.ClosedFailed)
	wantLine(t, r, "Update 2 was approved but could not be installed. I will try again at the next daily check.")
	r.clk.add(time.Hour)
	if _, ok := r.l.Next(context.Background(), true); ok {
		t.Fatal("a check before the daily one")
	}
	r.nextCheck()
	if n := len(r.p.proposed()); n != 2 {
		t.Fatalf("failed install proposed %d times", n)
	}
	if st := r.l.Status(); !strings.Contains(st.Line, "Update 2 has been waiting for your approval since "+day(r)) {
		t.Fatalf("status after the new request %q", st.Line)
	}
	r.p.close("c2", change.ClosedFailed)
	r.nextCheck()
	r.p.close("c3", change.ClosedFailed)
	wantLine(t, r, "Update 2 has failed to install 3 times. I will try again at the next daily check.")
}

// P2-2a-f4d: a NO Loop 3 has read survives a restart: the release is not
// asked again.
func TestDeclinedReleaseNotAskedAfterRestart(t *testing.T) {
	for _, kind := range []string{change.ClosedDeclined, change.ClosedLeftOut} {
		r := askedFast(t)
		r.p.close("c1", kind)
		r.l.Next(context.Background(), true) // the scheduler's next look reads it
		r.l = r.newLoop()
		r.tick()
		r.nextCheck()
		if n := len(r.p.proposed()); n != 1 {
			t.Fatalf("%s: asked again after a restart: proposed %d times", kind, n)
		}
		if st := r.l.Status(); !strings.Contains(st.Line, "you ") {
			t.Fatalf("%s: status %q", kind, st.Line)
		}
	}
}
