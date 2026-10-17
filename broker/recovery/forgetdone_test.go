package recovery

// REQ: CAP-3, R2C

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// W3-forget-b2c-f1-r2 (UX 2 on #610): agentosd logs a done marker once a
// forget's done text has sent, so a restore can tell a forget told done
// from one still owed. The marker is an entry like any other.

// R2C: a marker is chained, MAC'd and anchored with the forget before it,
// and a log with no marker writes no done field at all.
func TestForgetLogDoneMarkerIsAnAuthenticatedEntry(t *testing.T) {
	x := newBox(t)
	pc := newPCCounter("host-a")
	plain, err := AppendForget(x.b, pc, ForgetEntry{Goal: "goal-1", At: t0})
	must(t, err)
	if bytes.Contains(plain, []byte(`"done"`)) {
		t.Fatalf("a log with no marker writes a done field: %s", plain)
	}
	cp, err := AppendForget(x.b, pc, ForgetEntry{Goal: "goal-1", At: t0.Add(time.Hour), Done: true})
	must(t, err)
	l, err := openForgetLog(forgetKey(x.rk), cp)
	must(t, err)
	if len(l.Entries) != 2 || l.Entries[0].Done || !l.Entries[1].Done || l.Entries[1].Goal != "goal-1" {
		t.Fatalf("entries: %+v", l.Entries)
	}
	if l.head() != pc.max {
		t.Fatalf("marker not anchored: head %d, counter %d", l.head(), pc.max)
	}
	// Flipping done either way is an entry the key did not make.
	for i := range l.Entries {
		var m forgetLog
		must(t, json.Unmarshal(cp, &m))
		m.Entries[i].Done = !m.Entries[i].Done
		raw, _ := json.Marshal(m)
		if _, err := openForgetLog(forgetKey(x.rk), raw); !errors.Is(err, errForgedLog) {
			t.Fatalf("entry %d with done flipped: %v", i, err)
		}
	}
}

// R2C: the confirmation question asks for the last forget's day; a done
// marker told days later is not a forget.
func TestTheQuestionDatesTheLastForgetNotItsMarker(t *testing.T) {
	now := t0
	forgot := now.Add(-200 * 24 * time.Hour)
	l := forgetLog{Entries: []ForgetEntry{
		{Seq: 1, Goal: "goal-1", At: forgot},
		{Seq: 2, Goal: "goal-1", At: forgot.Add(3 * 24 * time.Hour), Done: true},
	}}
	f, err := newQuestion(PendingUnanchored, l, true, now, nil, now, bytes.NewReader(bytes.Repeat([]byte{7}, 512)))
	must(t, err)
	q, err := f.question()
	must(t, err)
	if f.Answer < 0 || f.Answer >= len(q.Dates) || !q.Dates[f.Answer].Equal(civil(forgot)) {
		t.Fatalf("answer %d of %v, want %v", f.Answer, q.Dates, civil(forgot))
	}
}
