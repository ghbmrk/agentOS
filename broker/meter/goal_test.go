package meter

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// REQ: OP-8, OP-7

// TestOP8UsageIsCountedPerGoal: a call started for a goal counts against
// that goal as settled (refunds and overruns included), survives a
// restart, limits nothing, and is forgotten after a week idle.
func TestOP8UsageIsCountedPerGoal(t *testing.T) {
	m, c, _ := open(t, Config{MachineCap: Limits{Calls: 10, Tokens: 1 << 20}, OverallCap: Limits{Calls: 100, Tokens: 1 << 30}})
	k, err := m.StartFor("m1", "owner:a", 100, 50)
	must(t, err)
	k.Done(120) // 30 refunded
	k, err = m.StartFor("m2", "owner:a", 10, 0)
	must(t, err)
	k.Done(40) // 30 more
	must(t, call(m, "m1", 5, 5))
	if u := m.GoalUsage("owner:a"); u != (Limits{Calls: 2, Tokens: 160}) {
		t.Fatalf("goal usage %+v", u)
	}
	if u := m.GoalUsage(""); u != (Limits{}) {
		t.Fatalf("calls with no goal counted: %+v", u)
	}
	m2, err := Open(m.cfg)
	must(t, err)
	if u := m2.GoalUsage("owner:a"); u.Calls != 2 {
		t.Fatalf("after restart %+v", u)
	}
	c.add(8 * 24 * time.Hour)
	must(t, call(m2, "m1", 1, 1))
	if u := m2.GoalUsage("owner:a"); u != (Limits{}) {
		t.Fatalf("idle goal kept: %+v", u)
	}
}

// TestOP8WrapChargesTheRequestGoal: Wrap charges the goal the broker put
// on the request's context (WithGoal), never anything the guest sent.
func TestOP8WrapChargesTheRequestGoal(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: Limits{Calls: 10, Tokens: 1 << 20}, OverallCap: Limits{Calls: 100, Tokens: 1 << 30}})
	h := m.Wrap("m1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"usage":{"prompt_tokens":7,"completion_tokens":3}}`)
	}))
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(`{"messages":[]}`))
	req.Header.Set("X-Goal", "owner:b")
	req = req.WithContext(WithGoal(context.Background(), "owner:a"))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if u := m.GoalUsage("owner:a"); u != (Limits{Calls: 1, Tokens: 10}) {
		t.Fatalf("goal usage %+v", u)
	}
	if u := m.GoalUsage("owner:b"); u.Calls != 0 {
		t.Fatalf("guest header named a goal: %+v", u)
	}
}
