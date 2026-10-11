package meter

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// REQ: OP-8 (SR3-7-f1a, SR3-7-f1b, SR3-7-f1c)

// TestSR3_7f1aAttemptCharges: each failed attempt a report carries is
// charged on top of the served call: its input estimate when rejected at
// admission, plus the full reservation otherwise, or the usage its error
// body reported (never below the input estimate); a broken stream's
// output counts as for a served call. An unserved call is charged only
// its failed attempts.
func TestSR3_7f1aAttemptCharges(t *testing.T) {
	body := `{"max_tokens":100}`
	est := Tokens(int64(len(body)))
	served := Usage{Provider: "openai", Input: 7, Output: 3, Reported: true, Complete: true}
	with := func(u Usage, a ...Attempt) Usage { u.Failed = a; return u }
	for _, tc := range []struct {
		name string
		rep  Usage
		want int64
	}{
		{"none failed", served, 10},
		{"rejected", with(served, Attempt{Provider: "anthropic", Status: 429}), 10 + est},
		{"server error", with(served, Attempt{Provider: "anthropic", Status: 529, Full: true}), 10 + est + 100},
		{"two", with(served, Attempt{Status: 401}, Attempt{Status: 504, Full: true}), 10 + 2*est + 100},
		{"reported", with(served, Attempt{Provider: "openai", Status: 500, Full: true, Reported: true, Input: 4, Output: 50}), 10 + 54},
		{"reported below input", with(served, Attempt{Provider: "openai", Status: 500, Full: true, Reported: true, Input: 1}), 10 + est},
		{"stream past reservation", with(served, Attempt{Status: 502, Full: true, OutputChars: 800}), 10 + est + 200},
		{"rejected with output", with(served, Attempt{Status: 429, OutputChars: 40}), 10 + est + 10},
		{"unserved", Usage{Unserved: true, Failed: []Attempt{{Status: 503, Full: true}, {Status: 429}}}, 2*est + 100},
		{"unanswered after a failure", with(Usage{Unanswered: true}, Attempt{Status: 503, Full: true}), 2 * (est + 100)},
	} {
		m, _, _ := open(t, Config{MachineCap: Limits{Calls: 10, Tokens: 1 << 30}, OverallCap: big})
		h := m.Wrap("m1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			Report(r.Context(), tc.rep)
			io.WriteString(w, "{}")
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(body)))
		if u := m.Usage("m1"); u.Tokens != tc.want || u.Calls != 1 {
			t.Errorf("%s: charged %d tokens and %d calls, want %d and 1", tc.name, u.Tokens, u.Calls, tc.want)
		}
	}
}

// TestSR3_7f1bAnotherHoldsOneMoreAttempt: Another holds one more attempt
// at its worst charge against the call's limits, or refuses; it counts no
// call, and what the call did not use is refunded when it settles.
func TestSR3_7f1bAnotherHoldsOneMoreAttempt(t *testing.T) {
	body := `{"max_tokens":100}`
	worst := Tokens(int64(len(body))) + 100
	m, _, _ := open(t, Config{MachineCap: Limits{Calls: 10, Tokens: 2*worst + worst/2}, OverallCap: big})
	var got []bool
	var during Limits
	h := m.Wrap("m1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, Another(r.Context()), Another(r.Context()))
		during = m.Usage("m1")
		Report(r.Context(), Usage{Input: 1, Output: 1, Reported: true})
		io.WriteString(w, "{}")
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(body)))
	if len(got) != 2 || !got[0] || got[1] {
		t.Errorf("Another = %v, want room for one more attempt only", got)
	}
	if during != (Limits{Calls: 1, Tokens: 2 * worst}) {
		t.Errorf("held %+v during the call, want 1 call and %d tokens", during, 2*worst)
	}
	if u := m.Usage("m1"); u != (Limits{Calls: 1, Tokens: 2}) {
		t.Errorf("settled %+v, want the hold refunded", u)
	}
	if Another(context.Background()) {
		t.Error("Another outside a metered call")
	}
}
