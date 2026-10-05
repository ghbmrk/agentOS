package question

// REQ: CAP-10, CH-15, ARC-6

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
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

// TestQuestionsReserveTheSharedBudget (W9, Q3, UX-71-1): a question is
// texted only when the owner channel's shared CH-15 budget grants its
// text, one Reserve per text; a refusal holds it for the next tick.
func TestQuestionsReserveTheSharedBudget(t *testing.T) {
	var mu sync.Mutex
	grant, asked := false, 0
	r := newRig(t, func(c *Config) {
		c.Reserve = func(bool) bool {
			mu.Lock()
			defer mu.Unlock()
			asked++
			return grant
		}
	})
	if st := r.ask("lin1", "a", slot()); st.State != Held || len(r.sent) != 0 {
		t.Fatalf("texted without a reservation: %s", st.State)
	}
	mu.Lock()
	grant = true
	mu.Unlock()
	r.b.Tick(context.Background())
	if len(r.sent) != 1 {
		t.Fatalf("sent %d with the budget granted", len(r.sent))
	}
	r.b.Tick(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if asked != 2 {
		t.Fatalf("Reserve called %d times for one text and one refusal", asked)
	}
}
