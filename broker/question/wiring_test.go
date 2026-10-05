package question

// REQ: CAP-10, CH-15, ARC-6

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestGuestToolsServeTheBook (W9): the guest socket lists the question
// tools and calls the Book with the lineage the socket fixes as the asker,
// so one lineage cannot read another's question; other names are not
// handled, so the next tool set (or the effect tools) gets them.
func TestGuestToolsServeTheBook(t *testing.T) {
	r := newRig(t, nil)
	g := GuestTools{Book: r.b}
	if len(g.List()) != len(Tools) || g.List()[0]["name"] != ToolAsk {
		t.Fatalf("list %v", g.List())
	}
	text, handled, err := g.Call(context.Background(), "m1", "lin1", ToolAsk,
		json.RawMessage(`{"request_id":"q1","question":"Which slot?","default":"9:30","wait_minutes":30}`))
	if err != nil || !handled {
		t.Fatalf("ask: %v %v", handled, err)
	}
	var res ToolResult
	if err := json.Unmarshal([]byte(text), &res); err != nil || res.Question != "Q100" || res.State != string(Waiting) {
		t.Fatalf("ask result %s", text)
	}
	if _, handled, err := g.Call(context.Background(), "m2", "lin2", ToolStatus, json.RawMessage(`{"request_id":"q1"}`)); !handled || err == nil {
		t.Fatalf("another lineage read the question: %v", err)
	}
	if text, _, err := g.Call(context.Background(), "m1", "lin1", ToolStatus, json.RawMessage(`{"request_id":"q1"}`)); err != nil || !strings.Contains(text, `"Q100"`) {
		t.Fatalf("status %s %v", text, err)
	}
	if _, handled, _ := g.Call(context.Background(), "m1", "lin1", "effect_request", nil); handled {
		t.Fatal("handled a tool that is not a question tool")
	}
}

// TestQuestionsShareTheApprovalBudget (W9, Q3, UX-71-1): questions and
// approval requests draw on one CH-15 budget, and approval requests go
// first: a question is texted only while no approval request is waiting
// to be sent and the texts of both in the last hour are under the budget.
func TestQuestionsShareTheApprovalBudget(t *testing.T) {
	var mu sync.Mutex
	others, waiting := 0, false
	r := newRig(t, func(c *Config) {
		c.Shared = func(time.Time) (int, bool) {
			mu.Lock()
			defer mu.Unlock()
			return others, waiting
		}
	})
	set := func(n int, w bool) { mu.Lock(); others, waiting = n, w; mu.Unlock() }

	set(3, false) // three approval requests this hour: the budget is spent
	if st := r.ask("lin1", "a", slot()); st.State != Held {
		t.Fatalf("texted past the shared budget: %s", st.State)
	}
	set(1, true) // budget left, but an approval request waits: it goes first
	r.b.Tick(context.Background())
	if len(r.sent) != 0 {
		t.Fatalf("texted ahead of a waiting approval request: %q", r.sent)
	}
	set(1, false)
	r.b.Tick(context.Background())
	if len(r.sent) != 1 {
		t.Fatalf("sent %d with budget free", len(r.sent))
	}
	// The gate counts question texts toward its own budget.
	if n := r.b.Texts(r.clock); n != 1 {
		t.Fatalf("Texts %d", n)
	}
	set(2, false) // 2 approvals + 1 question: spent
	if st := r.ask("lin2", "b", slot()); st.State != Held {
		t.Fatalf("texted past the shared budget: %s", st.State)
	}
	r.b.Tick(context.Background())
	if len(r.sent) != 1 {
		t.Fatalf("sent %d: questions and approvals over 3 an hour", len(r.sent))
	}
	r.advance(time.Hour)
	set(0, false)
	r.b.Tick(context.Background())
	if len(r.sent) != 2 || r.b.Texts(r.clock) != 1 {
		t.Fatalf("after the hour: sent %d, Texts %d", len(r.sent), r.b.Texts(r.clock))
	}
}
