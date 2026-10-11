package grants

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: ADP-9, CH-12, CAP-3, A12, A4

// reasonVerifier is the rig's verifier with an adapter guard that gives
// every effect the same fixed reason.
type reasonVerifier struct {
	*fakeVerifier
	reason string
}

func (v reasonVerifier) Escalate(context.Context, journal.Intent) (Escalation, error) {
	return Escalation{Reason: v.reason}, nil
}

// dayRig is a rig with one invoice rule allowing two sends a day and ten
// per record; reason, if set, is the adapter guard's reason.
func dayRig(t *testing.T, reason string) (*rig, func(id, rec string) journal.Status) {
	return ruleRig(t, reason, "invoice.send", 10, 2)
}

// ruleRig is a rig with one rule on action, which the mail adapter
// declares as a send, bounded perRec per record and perDay a day.
func ruleRig(t *testing.T, reason, action string, perRec, perDay int) (*rig, func(id, rec string) journal.Status) {
	r := newRig(t, func(c *Config) {
		c.Declared["mail"][action] = "send"
		if reason != "" {
			c.Verifiers["mail"] = reasonVerifier{c.Verifiers["mail"].(*fakeVerifier), reason}
		}
	})
	g := mailGrant()
	g.Ops[action] = "send"
	r.grant(g)
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: action, Params: map[string]string{"template": "invoice"},
		AmountCap: 15000, PerRecord: perRec, PerDay: perDay}})
	send := func(id, rec string) journal.Status {
		r.t.Helper()
		x := sam()
		x.Record = rec
		r.ver.set(rec, x)
		return r.effect(id, action, map[string]any{"template": "invoice", "record": rec}, "sam@example.com")
	}
	return r, send
}

// askedDetail submits id past the bound and returns its owner item's Detail.
func askedDetail(t *testing.T, r *rig, send func(id, rec string) journal.Status, id string) string {
	t.Helper()
	return askedDetailOn(t, r, send, id, "inv-"+id)
}

// askedDetailOn is askedDetail with id on record rec.
func askedDetailOn(t *testing.T, r *rig, send func(id, rec string) journal.Status, id, rec string) string {
	t.Helper()
	if st := send(id, rec); st.State != journal.Pending {
		t.Fatalf("%s past the bound: %s %q", id, st.State, st.Permission.Reason)
	}
	r.g.Flush()
	_, items := r.own.last(t)
	if len(items) != 1 || items[0].Ref != id {
		t.Fatalf("%s: asked %+v", id, items)
	}
	return items[0].Detail
}

// TestBoundAskNamesQueuedSends (SR3-2-f2): an ask made only because the
// day's places are taken says how many of them are sends still queued, so
// the owner can see why a send the rule covers is asked. It names a count
// and a verb only, never a queued send's recipient or record.
func TestBoundAskNamesQueuedSends(t *testing.T) {
	for _, c := range []struct {
		name    string
		started int // sends that run before STOP
		want    string
	}{
		{"both queued", 0, "2 earlier sends still queued"},
		{"one queued", 1, "1 earlier send still queued"},
		{"both started", 2, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, send := dayRig(t, "")
			for i, id := range []string{"agent/q1", "agent/q2"} {
				if i == c.started {
					if _, err := r.eng.Stop(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				want := journal.Succeeded
				if i >= c.started {
					want = journal.Authorized
				}
				if st := send(id, "inv-"+id); st.State != want {
					t.Fatalf("%s: %s %q, want %s", id, st.State, st.Permission.Reason, want)
				}
			}
			got := askedDetail(t, r, send, "agent/q3")
			if got != c.want {
				t.Fatalf("Detail %q, want %q", got, c.want)
			}
			if strings.Contains(got, "inv-") || strings.Contains(got, "sam") {
				t.Fatalf("Detail carries a queued send's parameter: %q", got)
			}
			// The decision is unchanged: asked, nothing ran past the bound.
			if r.exec.runs("agent/q3") != 0 {
				t.Fatal("the asked send ran")
			}
		})
	}
}

// TestBoundAskNamesQueuedActions (SR3-2-f2 noun): when the rule's action
// is not a send, the note counts earlier actions, not sends.
func TestBoundAskNamesQueuedActions(t *testing.T) {
	for _, c := range []struct {
		started int
		want    string
	}{
		{0, "2 earlier actions still queued"},
		{1, "1 earlier action still queued"},
	} {
		r, send := ruleRig(t, "", "invoice.remind", 10, 2)
		for i, id := range []string{"agent/q1", "agent/q2"} {
			if i == c.started {
				if _, err := r.eng.Stop(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			want := journal.Succeeded
			if i >= c.started {
				want = journal.Authorized
			}
			if st := send(id, "inv-"+id); st.State != want {
				t.Fatalf("%s: %s %q, want %s", id, st.State, st.Permission.Reason, want)
			}
		}
		if got := askedDetail(t, r, send, "agent/q3"); got != c.want {
			t.Fatalf("Detail %q, want %q", got, c.want)
		}
	}
}

// TestBoundAskNamesQueuedPerRecord (SR3-2-f2 per record): an ask made
// because the record's places are taken, with the day still open, counts
// the sends queued on that record only, not those queued on another.
func TestBoundAskNamesQueuedPerRecord(t *testing.T) {
	for _, c := range []struct {
		name    string
		started int // sends on the record that run before STOP
		want    string
	}{
		{"both queued", 0, "2 earlier sends still queued"},
		{"one queued", 1, "1 earlier send still queued"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, send := ruleRig(t, "", "invoice.send", 2, 10)
			for i, id := range []string{"agent/r1", "agent/r2"} {
				if i == c.started {
					if _, err := r.eng.Stop(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				want := journal.Succeeded
				if i >= c.started {
					want = journal.Authorized
				}
				if st := send(id, "inv-r"); st.State != want {
					t.Fatalf("%s: %s %q, want %s", id, st.State, st.Permission.Reason, want)
				}
			}
			// Queued on another record: within the day, not this record.
			if st := send("agent/o1", "inv-o"); st.State != journal.Authorized {
				t.Fatalf("o1: %s %q", st.State, st.Permission.Reason)
			}
			if got := askedDetailOn(t, r, send, "agent/r3", "inv-r"); got != c.want {
				t.Fatalf("Detail %q, want %q", got, c.want)
			}
		})
	}
}

// TestBoundAskKeepsGuardReason (SR3-2-f2 fit): an adapter guard's reason
// stays the Detail; the queued count is appended only if both fit the
// 40-character field.
func TestBoundAskKeepsGuardReason(t *testing.T) {
	for _, c := range []struct{ reason, want string }{
		{"flagged", "flagged; 2 earlier sends still queued"},
		{"past today's 200", "past today's 200"},
		{"sent from a newly linked address book", "sent from a newly linked address book"},
	} {
		r, send := dayRig(t, c.reason)
		if _, err := r.eng.Stop(context.Background()); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"agent/q1", "agent/q2"} {
			if st := send(id, "inv-"+id); st.State != journal.Authorized {
				t.Fatalf("%s: %s %q", id, st.State, st.Permission.Reason)
			}
		}
		got := askedDetail(t, r, send, "agent/q3")
		if got != c.want || len(got) > 40 {
			t.Fatalf("reason %q: Detail %q, want %q", c.reason, got, c.want)
		}
	}
}

// TestErasedSendStillBoundPerRecord (SR3-2-f3, CAP-3): a send erased
// under CAP-3 loses its record key but keeps its place per record, so a
// second send on the same record within the day is asked, not passed.
func TestErasedSendStillBoundPerRecord(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", Params: map[string]string{"template": "invoice"},
		AmountCap: 15000, PerRecord: 1, PerDay: 10}})
	r.ver.set("inv-1042", sam())
	send := func(id string) journal.Status {
		return r.effect(id, "invoice.send", map[string]any{"template": "invoice", "record": "inv-1042"}, "sam@example.com")
	}
	if st := send("agent/e1"); st.State != journal.Succeeded {
		t.Fatalf("e1: %s %q", st.State, st.Permission.Reason)
	}
	if erased, _, err := r.eng.Erase([]string{"agent/e1"}); err != nil || len(erased) != 1 {
		t.Fatalf("erase: %v %v", erased, err)
	}
	if st := send("agent/e2"); st.State != journal.Pending || r.exec.runs("agent/e2") != 0 {
		t.Fatalf("second send on the record after erasure: %s %q", st.State, st.Permission.Reason)
	}
}

// TestQueuedNoteIsNotWhatIsApproved (SR3-2-f2, decision unchanged): the
// queued count is shown, not approved. An owner's YES to a send asked
// with the note still covers it once the queued sends have started and
// the count reads differently, and a restart re-issues the ask the owner
// was sent.
func TestQueuedNoteIsNotWhatIsApproved(t *testing.T) {
	queue := func(t *testing.T) (*rig, func(id, rec string) journal.Status) {
		r, send := dayRig(t, "")
		if _, err := r.eng.Stop(context.Background()); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"agent/q1", "agent/q2"} {
			send(id, "inv-"+id)
		}
		if d := askedDetail(t, r, send, "agent/q3"); d != "2 earlier sends still queued" {
			t.Fatalf("Detail %q", d)
		}
		return r, send
	}
	t.Run("approved", func(t *testing.T) {
		r, _ := queue(t)
		r.decide(true, "owner")
		if err := r.eng.Resume(); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"agent/q1", "agent/q2", "agent/q3"} {
			st, err := r.g.Dispatch(context.Background(), id)
			if err != nil || st.State != journal.Succeeded {
				t.Fatalf("%s: %s %v", id, st.State, err)
			}
		}
	})
	t.Run("restart", func(t *testing.T) {
		r, _ := queue(t)
		req, items := r.own.last(t)
		asked := r.now()
		r.boot = []owner.Carried{{Ref: items[0].Ref, Request: req, Asked: asked, Expires: asked.Add(15 * time.Minute), Sum: owner.ItemSum(items[0])}}
		if err := r.eng.Resume(); err != nil {
			t.Fatal(err)
		}
		if st, err := r.g.Dispatch(context.Background(), "agent/q1"); err != nil || st.State != journal.Succeeded {
			t.Fatalf("q1: %s %v", st.State, err)
		}
		r.advance(time.Minute)
		r.open()
		r.g.Tick()
		r.g.Flush()
		if st := r.state("agent/q3"); st.State != journal.Pending {
			t.Fatalf("q3 after restart: %s %q", st.State, st.Permission.Reason)
		}
		if len(r.own.each) != 1 {
			t.Fatalf("re-issued %v", r.own.each)
		}
		again := r.own.reqs[r.own.each[0]]
		if len(again) != 1 || again[0].Detail != "2 earlier sends still queued" {
			t.Fatalf("re-issued %+v, want what the owner was sent", again)
		}
	})
}
