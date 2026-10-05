package grants

import (
	"context"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/question"
)

// REQ: CAP-10, REV-2

// TestAQuestionCarriesNoAuthority: a question about an irreversible
// effect, whether it lapses to a "yes" default or the owner texts "yes"
// as its answer, does not approve that effect. The send still waits for
// its own approval request, and runs only when the owner approves that.
func TestAQuestionCarriesNoAuthority(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())

	var texts []string
	book, err := question.New(question.Config{
		Send:   func(s string) error { texts = append(texts, s); return nil },
		Now:    func(context.Context) (time.Time, error) { return r.now(), nil },
		Reveal: func(string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ask := func(req string) {
		t.Helper()
		if _, err := book.Ask(ctx, "agent", req, question.Spec{
			Text: "Send invoice 1042 to Sam now?", Default: "yes", Wait: 10 * time.Minute,
		}); err != nil {
			t.Fatal(err)
		}
	}
	requests := r.own.count()

	// 1. The default lapses to "yes".
	ask("ok-to-send")
	r.advance(11 * time.Minute)
	book.Tick(ctx)
	if st, _ := book.Status(ctx, "agent", "ok-to-send", "agent"); st.State != question.Defaulted || st.Answer != "yes" {
		t.Fatalf("question %+v", st)
	}
	// The guest cites the defaulted answer in its effect request.
	send := map[string]any{"record": "inv-1042", "template": "invoice", "question": "Q100", "answer": "yes"}
	st := r.effect("agent/s1", "invoice.send", send, "sam@example.com")
	if st.State != journal.Pending || st.Permission.Reason != "waiting for the owner's approval" || r.exec.runs("agent/s1") != 0 {
		t.Fatalf("a defaulted answer authorized the send: %s %q", st.State, st.Permission.Reason)
	}
	if err := r.g.Check(ctx, journal.PhaseAuthorize, r.state("agent/s1").Intent); err == nil {
		t.Fatal("the gate's check passed on a defaulted answer")
	}
	r.g.Flush()
	if r.own.count() != requests+1 {
		t.Fatalf("no separate approval request: %d -> %d", requests, r.own.count())
	}
	req, items := r.own.last(t)
	if len(items) != 1 || items[0].Ref != "agent/s1" {
		t.Fatalf("approval items %+v", items)
	}

	// 2. The owner answers a second question "yes" by text. An answer is
	// chat, not an approval code, so it does not authorize either.
	ask("ok-to-send-2")
	if _, ok := book.Answer(ctx, "Q101 yes"); !ok {
		t.Fatal("answer not matched")
	}
	st = r.effect("agent/s2", "invoice.send", map[string]any{"record": "inv-1042", "template": "invoice", "question": "Q101"}, "sam@example.com")
	if st.State != journal.Pending || r.exec.runs("agent/s2") != 0 {
		t.Fatalf("an owner's text answer authorized the send: %s", st.State)
	}

	// Only the approval decision runs the first send.
	r.g.Decide(owner.Decision{Request: req, Item: 1, Ref: "agent/s1", Approved: true, Why: "owner"})
	r.g.Wait()
	if st := r.state("agent/s1"); st.State != journal.Succeeded || r.exec.runs("agent/s1") != 1 {
		t.Fatalf("approved send: %s, ran %d", st.State, r.exec.runs("agent/s1"))
	}
}
