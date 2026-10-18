package mail_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/verb"
)

// REQ: CH-19, ADP-2 (SR3-5-f4)

// The fixed words, one per cause of an organize refusal or unknown.
const (
	wChanged    = "mail: changed since approval"
	wNoCheck    = "mail: no check ran for this message; ask again"
	wDiffer     = "mail: the message changed between checks; ask again"
	wCheckGone  = "mail: the earlier check is gone, so this cannot be confirmed"
	wNotMoved   = "mail: the message is not where the move put it"
	wStillThere = "mail: the message is still where it was"
)

// ghost reports a message at the pinned INBOX place once on is set, as
// if the move left the original behind.
type ghost struct {
	mail.Store
	on bool
}

func (g *ghost) Fetch(ctx context.Context, folder string, validity uint32, uids []uint32) ([]mail.Message, error) {
	if g.on && folder == "INBOX" {
		return []mail.Message{{Folder: folder, Validity: validity, UID: uids[0]}}, nil
	}
	return g.Store.Fetch(ctx, folder, validity, uids)
}

// refusalCause is one cause of an organize refusal or unknown: run
// drives it and returns the outcome; want is its words and class.
type refusalCause struct {
	name   string
	want   string
	result journal.Result
	run    func(t *testing.T) journal.Outcome
}

// lostArchive judges and archives a newsletter whose MOVE reply is lost,
// so attempt 1 is Unknown with its pin kept, and returns the harness,
// the intent and the ghost store.
func lostArchive(t *testing.T) (*h, journal.Intent, *ghost) {
	t.Helper()
	g := &ghost{}
	x := newH(t, func(c *mail.Config) {
		g.Store = &lossy{c.Store}
		c.Store = g
	})
	id := x.news(1)
	in := x.intent(mail.OpArchive, rec(id))
	if e, err := x.a.Escalate(ctx, in); err != nil || e.Verb != "" {
		t.Fatalf("recheck: %+v %v", e, err)
	}
	if out := x.a.Execute(ctx, in, 1); out.Result != journal.ResultUnknown {
		t.Fatalf("execute: %s %q", out.Result, out.Evidence)
	}
	return x, in, g
}

var refusalCauses = []refusalCause{
	{"Execute with no check", wNoCheck, journal.ResultNotApplied, func(t *testing.T) journal.Outcome {
		x := newH(t, nil)
		return x.a.Execute(ctx, x.intent(mail.OpArchive, rec(x.news(1))), 1)
	}},
	{"Execute with disagreeing checks", wDiffer, journal.ResultNotApplied, func(t *testing.T) journal.Outcome {
		x := newH(t, nil)
		id := x.news(1)
		in := x.intent(mail.OpArchive, rec(id))
		x.a.Escalate(ctx, in)
		x.swap(id, "INBOX")
		if e, err := x.a.Escalate(ctx, in); err != nil || e.Verb != verb.ChangeAccount {
			t.Fatalf("recheck: %+v %v", e, err)
		}
		return x.a.Execute(ctx, in, 1)
	}},
	{"Execute on a swapped message", wChanged, journal.ResultNotApplied, func(t *testing.T) journal.Outcome {
		x := newH(t, nil)
		id := x.news(1)
		in := x.intent(mail.OpArchive, rec(id))
		x.a.Escalate(ctx, in)
		x.swap(id, "INBOX")
		return x.a.Execute(ctx, in, 1)
	}},
	{"Execute newly hiding an alert", wChanged, journal.ResultNotApplied, func(t *testing.T) journal.Outcome {
		x := newH(t, nil)
		id := x.news(1)
		in := x.intent(mail.OpArchive, map[string]any{mail.ParamRecord: id, mail.ParamFolder: "INBOX"})
		x.a.Escalate(ctx, in)
		x.twin(id)
		return x.a.Execute(ctx, in, 1)
	}},
	{"Reconcile with no check", wCheckGone, journal.ResultUnknown, func(t *testing.T) journal.Outcome {
		x := newH(t, nil)
		x.deliver("INBOX", msg{id: "<al@x.example>", from: "someone@x.example", to: me, subject: "New sign-in", body: "x"})
		return x.a.Reconcile(ctx, x.intent(mail.OpArchive, rec("<al@x.example>")), 1)
	}},
	{"Reconcile with a check that did not escalate", wChanged, journal.ResultUnknown, func(t *testing.T) journal.Outcome {
		var accts []string
		x := newH(t, func(c *mail.Config) {
			c.Store = &lossy{c.Store}
			c.AccountSenders = func() []string { return accts }
		})
		id := "<news-f4@shop.example>"
		x.deliver("INBOX", msg{id: id, from: "Shop <deals@shop.example>", to: me, subject: "Autumn sale", body: "Twenty percent off boots.",
			extra: []string{"Authentication-Results: mx.example.test; spf=pass smtp.mailfrom=shop.example; dmarc=pass (p=reject) header.from=shop.example"}})
		in := x.intent(mail.OpArchive, rec(id))
		if e, err := x.a.Escalate(ctx, in); err != nil || e.Verb != "" {
			t.Fatalf("recheck: %+v %v", e, err)
		}
		if out := x.a.Execute(ctx, in, 1); out.Result != journal.ResultUnknown {
			t.Fatalf("execute: %s %q", out.Result, out.Evidence)
		}
		accts = []string{"shop.example"}
		return x.a.Reconcile(ctx, in, 1)
	}},
	{"Reconcile finds it outside the move's folder", wNotMoved, journal.ResultUnknown, func(t *testing.T) journal.Outcome {
		x, in, _ := lostArchive(t)
		id := in.Params[mail.ParamRecord].(string)
		x.srv.Remove("Archive", id)
		x.deliver("Receipts", msg{id: id, from: "Shop <deals@shop.example>", to: me, subject: "Autumn sale 1", body: "Twenty percent off boots."})
		return x.a.Reconcile(ctx, in, 1)
	}},
	{"Reconcile finds the pinned place still full", wStillThere, journal.ResultUnknown, func(t *testing.T) journal.Outcome {
		x, in, g := lostArchive(t)
		g.on = true
		return x.a.Reconcile(ctx, in, 1)
	}},
}

// TestOrganizeRefusalReasonsAreDistinct (SR3-5-f4 T1, T3): each cause
// gets its own fixed words, and keeps its result class: Execute refusals
// are NotApplied, Reconcile ones Unknown.
func TestOrganizeRefusalReasonsAreDistinct(t *testing.T) {
	for _, c := range refusalCauses {
		t.Run(c.name, func(t *testing.T) {
			out := c.run(t)
			if out.Evidence != c.want || out.Result != c.result {
				t.Fatalf("got %s %q, want %s %q", out.Result, out.Evidence, c.result, c.want)
			}
		})
	}
	ws := []string{wChanged, wNoCheck, wDiffer, wCheckGone, wNotMoved, wStillThere}
	seen := map[string]bool{}
	for _, w := range ws {
		if seen[w] {
			t.Fatalf("%q names two causes", w)
		}
		seen[w] = true
		if !strings.HasPrefix(w, "mail: ") {
			t.Fatalf("%q would not pass reason", w)
		}
	}
}

// TestChangedSinceApprovalOnlyWhenChanged (SR3-5-f4 T2): "changed since
// approval" is the evidence only where the message did change since the
// approval's check.
func TestChangedSinceApprovalOnlyWhenChanged(t *testing.T) {
	for _, c := range refusalCauses {
		t.Run(c.name, func(t *testing.T) {
			out := c.run(t)
			if got := strings.Contains(out.Evidence, "changed since approval"); got != (c.want == wChanged) {
				t.Fatalf("%q: says changed since approval = %v", out.Evidence, got)
			}
		})
	}
}
