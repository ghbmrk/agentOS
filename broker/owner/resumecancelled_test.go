package owner

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/control"
)

// REQ: KRN-7, CH-11

// A STOP's own fold cancels every unsent kernel step, so RESUME never
// brings one back (#5138). Every RESUME reply says so, after any count of
// held actions and any fresh undo windows, so an owner who expected a
// pause does not wait for a send that will never come (#5151 R1). Catches
// a RESUME path that drops the sentence.
func TestResumeSaysStopCancelsStayCancelled(t *testing.T) {
	tail := " " + control.StopCancelledNote
	for n, want := range map[int]string{
		0: "Resumed." + tail,
		1: "Resumed. 1 stopped action may now run." + tail,
		2: "Resumed. 2 stopped actions may now run." + tail,
	} {
		r := newRig(t, nil)
		for range n {
			r.eng.list = append(r.eng.list, control.Status{Phase: control.Held})
		}
		r.say("STOP")
		code := regexp.MustCompile(`RESUME ([0-9]{6})`).FindStringSubmatch(r.say("resume"))[1]
		if got := r.say("RESUME " + code); got != want {
			t.Errorf("%d held: %q, want %q", n, got, want)
		}
	}

	// With a queued item re-windowed: the window sentence, then the note.
	r := newRig(t, nil)
	res, _ := r.ch.QueueAutoReply(AutoReply{Ref: "r1", Recipients: []string{"sam@example.com"}, Body: "Thanks."})
	r.inbox()
	r.say("STOP")
	r.advance(time.Hour)
	code := regexp.MustCompile(`RESUME ([0-9]{6})`).FindStringSubmatch(r.say("resume"))[1]
	id := res.Queued.ID
	if got, want := r.say("RESUME "+code), "Resumed. "+id+" runs at 13:02 unless you reply UNDO "+id+"."+tail; got != want {
		t.Errorf("queued: %q, want %q", got, want)
	}

	// The owner page's RESUME.
	r = newRig(t, nil)
	r.say("STOP")
	msg, err := r.ch.LocalResume(r.ch.LocalStatus().Locks, r.ch.StopGen())
	if want := "Resumed. Stopped actions may now run." + tail; err != nil || msg != want {
		t.Errorf("local: %q %v, want %q", msg, err, want)
	}

	// RESUME after a lockout's challenge.
	r = newRig(t, nil)
	r.say("STOP")
	tok := enterChallenge(t, r)
	if got := r.say("RESUME " + tok + " " + r.totp()); !strings.HasSuffix(got, " Resumed."+tail) || r.eng.Stopped() {
		t.Errorf("challenge: %q", got)
	}
}

// The RESUME reply stays inside the text budget with the note added: every
// head a RESUME reply starts with, and up to 999 re-windowed IDs, which
// fall back to the count form, fit (#5151). Catches a note that pushes
// the worst case past MaxSegments or out of GSM-7.
func TestResumeNoteFitsTheTextBudget(t *testing.T) {
	heads := []string{"Resumed.", "Resumed. 999 stopped actions may now run.",
		"Resumed. Stopped actions may now run.", "Codes work normally again. Resumed."}
	for _, n := range []int{0, 1, 2, 10, 999} {
		ids := make([]string, n)
		for i := range ids {
			ids[i] = fmt.Sprintf("K%05d", i)
		}
		tail := resumeTail(ids, "13:02")
		if !strings.HasSuffix(tail, " "+control.StopCancelledNote) {
			t.Fatalf("%d ids: %q lacks the note", n, tail)
		}
		for _, h := range heads {
			if !fits(h + tail) {
				t.Errorf("%d ids, head %q: %q does not fit", n, h, h+tail)
			}
		}
	}
}
