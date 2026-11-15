package control

// REQ: KRN-7, CH-12

import (
	"context"
	"errors"
	"testing"
)

// cancelEngine is an Engine whose STOP cancels steps, as daemon's
// bothStops over the kernel: the count reads only while stopped.
type cancelEngine struct {
	*fakeEngine
	cancelled int
	err       error
}

func (c cancelEngine) StopCancelled() (int, error) {
	if !c.Stopped() {
		return 0, c.err
	}
	return c.cancelled, c.err
}

// RESUME's note names what the STOP cancelled, read before the lift, and
// only when it cancelled something (#5665): a STOP that cancelled nothing
// implies no loss, and a count that cannot be read keeps the general
// note, since silence could hide one (KRN-7). An Engine whose STOP only
// holds gets no note. Catches a note said with nothing cancelled, dropped
// with a cancel, or read after the RESUME.
func TestResumeNoteNamesOnlyWhatStopCancelled(t *testing.T) {
	head := "Resumed. Held actions may now run."
	for _, c := range []struct {
		name string
		eng  Engine
		want string
	}{
		{"holds only", &fakeEngine{stopped: true}, head},
		{"none cancelled", cancelEngine{fakeEngine: &fakeEngine{stopped: true}}, head},
		{"one", cancelEngine{fakeEngine: &fakeEngine{stopped: true}, cancelled: 1},
			head + " STOP cancelled 1 action; it stays cancelled, so ask again if you still want it."},
		{"two", cancelEngine{fakeEngine: &fakeEngine{stopped: true}, cancelled: 2},
			head + " STOP cancelled 2 actions; they stay cancelled, so ask again for any you still want."},
		{"unread", cancelEngine{fakeEngine: &fakeEngine{stopped: true}, err: errors.New("unreachable")},
			head + " " + StopCancelledNote},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, _ := newHandler(t, &fakeEngine{}, fakeAuth{}, forbiddenAgent{t})
			h.Engine = c.eng
			one(t, h.Handle(context.Background(), owner, "RESUME"))
			if got := one(t, h.Handle(context.Background(), owner, "RESUME 111111")); got != c.want {
				t.Fatalf("%q, want %q", got, c.want)
			}
		})
	}
}

// failingResume is a cancelEngine whose RESUME fails to record.
type failingResume struct{ cancelEngine }

func (failingResume) Resume() error { return errors.New("the journal's write failed") }

// A RESUME that fails names the count it read before the attempt, so the
// owner hears it before a re-STOP can restart the count (Security on
// #5734), and asks again only once RESUME works, since planning is
// stopped (L3 on #5734). Catches a failure reply that drops what the STOP
// cancelled, or one that tells the owner to ask now.
func TestAFailedResumeNamesWhatStopCancelled(t *testing.T) {
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{}, forbiddenAgent{t})
	h.Engine = failingResume{cancelEngine{fakeEngine: &fakeEngine{stopped: true}, cancelled: 3}}
	one(t, h.Handle(context.Background(), owner, "RESUME"))
	want := "RESUME failed to record. Still stopped. STOP cancelled 3 actions; they stay cancelled; once RESUME works, ask again for any you still want."
	if got := one(t, h.Handle(context.Background(), owner, "RESUME 111111")); got != want {
		t.Fatalf("%q, want %q", got, want)
	}
}

// The notes' words, pinned as text (mutgate on #5734): StopCancelledNote
// is built from the unknown form, so a test that compares against it
// alone cannot tell the unknown form from the count's.
func TestTheNotesWording(t *testing.T) {
	for _, c := range []struct {
		got, want string
	}{
		{Cancels{}.Resumed(), " STOP may have cancelled some actions; any it cancelled stay cancelled, so ask again for any you still want."},
		{Cancels{}.Failed(), " STOP may have cancelled some actions; any it cancelled stay cancelled; once RESUME works, ask again for any you still want."},
		{Cancels{known: true}.Resumed(), ""},
		{Cancels{n: 1, known: true}.Failed(), " STOP cancelled 1 action; it stays cancelled; once RESUME works, ask again if you still want it."},
	} {
		if c.got != c.want {
			t.Errorf("%q, want %q", c.got, c.want)
		}
	}
}
