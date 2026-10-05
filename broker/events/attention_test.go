package events

// REQ: CAP-4

import "testing"

func TestOnlyIrreversibleDecisionsInterrupt(t *testing.T) {
	a := NewAttention("security", "family")
	cases := []struct {
		n    Notice
		want Route
	}{
		{Notice{Text: "New mail from bank", Class: "security"}, Digest},
		{Notice{Text: "Task done", Class: "family"}, Digest},
		{Notice{Text: "Reorganise drafts?", Decision: true, Class: "security"}, Digest},
		{Notice{Text: "Pay invoice 42?", Decision: true, Irreversible: true}, Batch},
		{Notice{Text: "Send reply to school?", Decision: true, Irreversible: true, Class: "work"}, Batch},
		{Notice{Text: "Confirm new device sign-in?", Decision: true, Irreversible: true, Class: "security"}, Interrupt},
	}
	for _, c := range cases {
		if got := a.Submit(c.n); got != c.want {
			t.Fatalf("%q: got %v want %v", c.n.Text, got, c.want)
		}
	}
	notes, decisions := a.TakeDigest()
	if len(notes) != 3 || len(decisions) != 2 {
		t.Fatalf("digest: %d notes, %d decisions", len(notes), len(decisions))
	}
	if n, d := a.TakeDigest(); n != nil || d != nil {
		t.Fatal("TakeDigest must clear")
	}
	a.SetUrgent(nil)
	if a.Route(Notice{Decision: true, Irreversible: true, Class: "security"}) != Batch {
		t.Fatal("with no urgent classes every irreversible decision is batched")
	}
}

// Work the owner asked for answers in the conversation at once; only
// event- and timer-started work follows the digest rule (review item 6).
func TestOwnerRequestsAnswerInConversation(t *testing.T) {
	a := NewAttention("security")
	for _, n := range []Notice{
		{Text: "Send this reply to Ann?", Origin: OwnerRequest, Decision: true, Irreversible: true},
		{Text: "Your trip summary is ready", Origin: OwnerRequest},
		{Text: "Couldn't reach the airline site", Origin: OwnerRequest, Class: "work"},
		{Text: "Rename the folder?", Origin: OwnerRequest, Decision: true},
	} {
		if got := a.Submit(n); got != Conversation {
			t.Fatalf("%q: got %v want conversation", n.Text, got)
		}
	}
	for _, c := range []struct {
		n    Notice
		want Route
	}{
		{Notice{Text: "Reply to the school newsletter?", Origin: Background, Decision: true, Irreversible: true}, Batch},
		{Notice{Text: "New invoice filed", Origin: Background}, Digest},
		{Notice{Text: "Approve new device?", Origin: Background, Decision: true, Irreversible: true, Class: "security"}, Interrupt},
	} {
		if got := a.Submit(c.n); got != c.want {
			t.Fatalf("%q: got %v want %v", c.n.Text, got, c.want)
		}
	}
	notes, decisions := a.TakeDigest()
	if len(notes) != 1 || len(decisions) != 1 {
		t.Fatalf("owner requests must not enter the digest: %v %v", notes, decisions)
	}
}
