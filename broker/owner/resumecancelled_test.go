package owner

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/control"
)

// REQ: KRN-7, CH-11, CH-12

// A STOP's own fold cancels every unsent kernel step, so RESUME never
// brings one back (#5138). A RESUME reply after a STOP that cancelled
// some says how many, after any count of held actions and any fresh undo
// windows, so an owner who expected a pause does not wait for a send that
// will never come (#5151 R1); after one that cancelled none it says
// nothing of it, since that would imply a loss the owner did not have
// (#5665). Catches a RESUME path that drops the note, says it with
// nothing cancelled, or reads the count after the lift.
func TestResumeSaysWhatStopCancelled(t *testing.T) {
	two := " STOP cancelled 2 actions; they stay cancelled, so ask again for any you still want."
	for _, c := range []struct {
		held, cancelled int
		err             error
		want            string
	}{
		{0, 0, nil, "Resumed."},
		{1, 0, nil, "Resumed. 1 stopped action may now run."},
		{0, 1, nil, "Resumed. STOP cancelled 1 action; it stays cancelled, so ask again if you still want it."},
		{0, 2, nil, "Resumed." + two},
		{2, 2, nil, "Resumed. 2 stopped actions may now run." + two},
		{0, 0, errors.New("kernel unreachable"), "Resumed. " + control.StopCancelledNote},
	} {
		r := newRig(t, nil)
		for range c.held {
			r.eng.list = append(r.eng.list, control.Status{Phase: control.Held})
		}
		r.eng.cancelled, r.eng.cancelErr = c.cancelled, c.err
		r.say("STOP")
		code := regexp.MustCompile(`RESUME ([0-9]{6})`).FindStringSubmatch(r.say("resume"))[1]
		if got := r.say("RESUME " + code); got != c.want {
			t.Errorf("%d held, %d cancelled, %v: %q, want %q", c.held, c.cancelled, c.err, got, c.want)
		}
	}

	// With a queued item re-windowed: the window sentence, then the note.
	r := newRig(t, nil)
	r.eng.cancelled = 2
	res, _ := r.ch.QueueAutoReply(AutoReply{Ref: "r1", Recipients: []string{"sam@example.com"}, Body: "Thanks."})
	r.inbox()
	r.say("STOP")
	r.advance(time.Hour)
	code := regexp.MustCompile(`RESUME ([0-9]{6})`).FindStringSubmatch(r.say("resume"))[1]
	id := res.Queued.ID
	if got, want := r.say("RESUME "+code), "Resumed. "+id+" runs at 13:02 unless you reply UNDO "+id+"."+two; got != want {
		t.Errorf("queued: %q, want %q", got, want)
	}

	// The owner page's RESUME, with and without a cancel.
	for n, want := range map[int]string{0: "Resumed. Stopped actions may now run.", 2: "Resumed. Stopped actions may now run." + two} {
		r = newRig(t, nil)
		r.eng.cancelled = n
		r.say("STOP")
		msg, err := r.ch.LocalResume(r.ch.LocalStatus().Locks, r.ch.StopGen())
		if err != nil || msg != want {
			t.Errorf("local, %d cancelled: %q %v, want %q", n, msg, err, want)
		}
	}

	// RESUME after a lockout's challenge.
	r = newRig(t, nil)
	r.eng.cancelled = 2
	r.say("STOP")
	tok := enterChallenge(t, r)
	if got := r.say("RESUME " + tok + " " + r.totp()); !strings.HasSuffix(got, " Resumed."+two) || r.eng.Stopped() {
		t.Errorf("challenge: %q", got)
	}
}

// The RESUME reply stays inside the text budget with the longest note: every
// head a RESUME reply starts with, and up to 999 re-windowed IDs, which
// fall back to the count form, fit (#5151, #5665). Catches a note that pushes
// the worst case past MaxSegments or out of GSM-7.
func TestResumeNoteFitsTheTextBudget(t *testing.T) {
	heads := []string{"Resumed.", "Resumed. 999 stopped actions may now run.",
		"Resumed. Stopped actions may now run.", "Codes work normally again. Resumed."}
	var notes []string
	for _, c := range []struct {
		n   int
		err error
	}{{1, nil}, {999999, nil}, {0, errors.New("unread")}} {
		f := &fakeEngine{stopped: true, cancelled: c.n, cancelErr: c.err}
		notes = append(notes, control.CancelledNote(f))
	}
	for _, note := range notes {
		for _, n := range []int{0, 1, 2, 10, 999} {
			ids := make([]string, n)
			for i := range ids {
				ids[i] = fmt.Sprintf("K%05d", i)
			}
			tail := resumeTail(ids, "13:02", note)
			if !strings.HasSuffix(tail, note) {
				t.Fatalf("%d ids: %q lacks the note", n, tail)
			}
			for _, h := range heads {
				if !fits(h + tail) {
					t.Errorf("%d ids, head %q: %q does not fit", n, h, h+tail)
				}
			}
		}
	}
}
