package meter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// REQ: OP-8

// TestOP8ForwardedOutputLimitIsTheReservation: the body the provider gets
// carries an output limit no larger than what the meter reserved, so a
// provider honoring it cannot be charged past the reservation. A present
// limit is clamped, an absent one is inserted under the key the path's
// API reads (also when only another API's key is present), and a body
// that is not one JSON object with distinct, canonically spelled keys is
// refused (SR3-7).
func TestOP8ForwardedOutputLimitIsTheReservation(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: Limits{Calls: 100, Tokens: 1 << 30}, OverallCap: big, DefaultReserve: 2000, MaxReserve: 6000})
	var got []byte
	h := m.Wrap("m1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got, _ = io.ReadAll(r.Body) }))
	for _, tc := range []struct {
		path, body string
		want       map[string]float64
	}{
		{"/openai/v1/chat/completions", `{"max_tokens":1e6,"messages":[]}`, map[string]float64{"max_tokens": 6000}},
		{"/openai/v1/chat/completions", `{"max_completion_tokens":300,"max_tokens":9000000}`, map[string]float64{"max_completion_tokens": 300, "max_tokens": 6000}},
		{"/v1/chat/completions", `{"messages":[]}`, map[string]float64{"max_completion_tokens": 2000}},
		{"/anthropic/v1/messages", `{"messages":[]}`, map[string]float64{"max_tokens": 2000}},
		{"/openai/v1/responses", `{"input":"x","max_output_tokens":-5}`, map[string]float64{"max_output_tokens": 6000}},
		{"/openai/v1/chat/completions", `{"max_output_tokens":100}`, map[string]float64{"max_output_tokens": 100, "max_completion_tokens": 2000}},
		{"/anthropic/v1/messages", `{"max_completion_tokens":100}`, map[string]float64{"max_completion_tokens": 100, "max_tokens": 2000}},
		{"/openai/v1/chat/completions", `{"max_tokens":"lots"}`, map[string]float64{"max_tokens": 6000}},
		{"/openai/v1/chat/completions", `{"max_tokens":12.5}`, map[string]float64{"max_tokens": 6000}},
	} {
		got = nil
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body)))
		var fwd map[string]any
		if err := json.Unmarshal(got, &fwd); err != nil {
			t.Fatalf("%s: forwarded %q: %v", tc.body, got, err)
		}
		for k, v := range tc.want {
			if fwd[k] != v {
				t.Errorf("%s %s: forwarded %s = %v, want %v", tc.path, tc.body, k, fwd[k], v)
			}
		}
		if n := bytes.Count(got, []byte(`"max_tokens"`)); n > 1 {
			t.Errorf("%s: forwarded %d max_tokens keys", tc.body, n)
		}
	}
	// More than one choice per call would multiply output past the
	// reservation (n=128 is 128 times the limit): refused.
	for _, body := range []string{"not json", `["max_tokens"]`, `{"a":1} {"max_tokens":1e9}`, `{"n":128}`, `{"n":2,"max_tokens":10}`, `{"n":"2"}`, `{"n":0}`,
		// Duplicate and case-colliding keys: a case-insensitive decoder
		// downstream could read a value other than the one checked.
		`{"max_tokens":1,"max_tokens":1000000}`, `{"n":1,"n":1}`, `{"N":2}`, `{"n":1,"N":2}`,
		`{"MAX_TOKENS":1000000}`, `{"max_to\u212Aens":1000000}`, `{"model":"a","MODEL":"b"}`} {
		got = nil
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest || got != nil {
			t.Errorf("%q: status %d, forwarded %v", body, w.Code, got != nil)
		}
	}
}

// TestOP8ParallelLargeRequestsStayUnderTheCap: twenty calls in parallel,
// each asking for a million output tokens, from a provider that bills
// exactly the limit it was sent: the total charged stays within the cap.
func TestOP8ParallelLargeRequestsStayUnderTheCap(t *testing.T) {
	const capTokens = 100_000
	m, _, _ := open(t, Config{MachineCap: Limits{Calls: 1000, Tokens: capTokens}, OverallCap: big, MaxReserve: 10_000})
	start := make(chan struct{})
	h := m.Wrap("m1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-start
		var req struct {
			MaxTokens int64 `json:"max_tokens"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"choices":[{"message":{"content":"x"}}],"usage":{"prompt_tokens":10,"completion_tokens":%d}}`, req.MaxTokens)
	}))
	var wg sync.WaitGroup
	var done atomic.Int64 // calls answered
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(`{"max_tokens":1000000}`)))
			done.Add(1)
		}()
	}
	// Let every call reach Start before any is answered: nine are
	// admitted and wait, eleven are refused and return.
	for m.Usage("m1").Calls < 9 || done.Load() < 11 {
		runtime.Gosched()
	}
	close(start)
	wg.Wait()
	if u := m.Usage("m1"); u.Tokens > capTokens {
		t.Fatalf("charged %d tokens, cap %d", u.Tokens, capTokens)
	}
}

// TestOP8CutOffStreamIsChargedItsContent: a stream with no end marker is
// charged at least the content the broker counted, whatever usage it
// reported, and whatever content type it claims. Anthropic's stop_reason
// in message_delta marks a normal end like message_stop.
func TestOP8CutOffStreamIsChargedItsContent(t *testing.T) {
	text := strings.Repeat("w", 400)
	stream := "event: message_start\n" + `data: {"type":"message_start","message":{"usage":{"input_tokens":5,"output_tokens":1}}}` + "\n\n" +
		strings.Repeat("event: content_block_delta\n"+`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"`+text+`"}}`+"\n\n", 100)
	stopped := stream + "event: message_delta\n" + `data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":42}}` + "\n\n"
	for _, tc := range []struct {
		name, ctype, body string
		atLeast, atMost   int64
	}{
		{"cut-off", "text/event-stream", stream, 5 + 10_000, 1 << 30},
		{"cut-off-mislabeled", "application/json", stream, 5 + 10_000, 1 << 30},
		{"stop-reason", "text/event-stream", stopped, 5 + 42, 5 + 42},
		// A normal end whose only usage is message_start's placeholder
		// output count: the content counted sets the output.
		{"stop-reason-no-usage", "text/event-stream", stream + "event: message_delta\n" + `data: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}` + "\n\nevent: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n", 5 + 10_000, 5 + 10_000},
	} {
		m, _, _ := open(t, Config{MachineCap: Limits{Calls: 10, Tokens: 1 << 30}, OverallCap: big})
		h := m.Wrap("m1", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", tc.ctype)
			io.WriteString(w, tc.body)
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(`{"stream":true}`)))
		if u := m.Usage("m1"); u.Tokens < tc.atLeast || u.Tokens > tc.atMost {
			t.Errorf("%s: charged %d tokens, want %d..%d", tc.name, u.Tokens, tc.atLeast, tc.atMost)
		}
	}
}

// TestOP8ServerReportedUsageSettlesTheCall: the handler that served the
// call (the model router) reports the provider's usage through the
// request context, and the meter settles from it even when the guest's
// response carries none. Cached input is weighted by provider.
func TestOP8ServerReportedUsageSettlesTheCall(t *testing.T) {
	if Report(context.Background(), Usage{Reported: true}) {
		t.Fatal("Report outside a metered call claimed to deliver")
	}
	body := `{"messages":[]}`
	est := Tokens(int64(len(body)))
	for _, tc := range []struct {
		name string
		u    Usage
		want int64
	}{
		// 50 + 200*0.1 + 10*1.25 = 82.5
		{"anthropic", Usage{Provider: "anthropic", Input: 50, CacheRead: 200, CacheWrite: 10, Output: 777, Reported: true, Complete: true}, 83 + 777},
		// 200 + 800*0.5
		{"openai", Usage{Provider: "openai", Input: 200, CacheRead: 800, Output: 10, Reported: true, Complete: true}, 600 + 10},
		// An unknown provider's cache counts in full.
		{"other", Usage{Provider: "x", Input: 1, CacheRead: 100, CacheWrite: 100, Output: 1, Reported: true, Complete: true}, 1 + 100 + 125 + 1},
		{"cut-off", Usage{Provider: "anthropic", Input: 5, Output: 1, Reported: true, OutputChars: 40_000}, 5 + 10_000},
		{"unreported", Usage{Provider: "openai", Complete: true, OutputChars: 400}, est + 100},
	} {
		m, _, _ := open(t, Config{MachineCap: Limits{Calls: 10, Tokens: 1 << 30}, OverallCap: big})
		h := m.Wrap("m1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !Report(r.Context(), tc.u) {
				t.Error("Report inside a metered call did not deliver")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, `data: {"choices":[{"delta":{"content":"hi"}}]}`+"\n\ndata: [DONE]\n\n")
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(body)))
		if u := m.Usage("m1"); u.Tokens != tc.want {
			t.Errorf("%s: charged %d tokens, want %d", tc.name, u.Tokens, tc.want)
		}
	}
}

// TestOP8NoResponseChargesNoPageOutput: when the egress gives no
// response, the serving handler writes its own error page and says why.
// A call that never reached the egress is charged its input estimate; one
// that reached it and got no answer, its full output reservation too. The
// page is never charged as output.
func TestOP8NoResponseChargesNoPageOutput(t *testing.T) {
	body := `{"max_tokens":100}`
	est := Tokens(int64(len(body)))
	page := "model egress unavailable\n"
	for _, tc := range []struct {
		name string
		rep  *Usage
		want int64
	}{
		{"never reached", &Usage{NoResponse: true}, est},
		{"unanswered", &Usage{Unanswered: true}, est + 100},
		// Without a report the page is an unreadable body, charged by size.
		{"unreported", nil, est + Tokens(int64(len(page)))},
	} {
		m, _, _ := open(t, Config{MachineCap: Limits{Calls: 10, Tokens: 1 << 30}, OverallCap: big})
		h := m.Wrap("m1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tc.rep != nil {
				Report(r.Context(), *tc.rep)
			}
			http.Error(w, strings.TrimSuffix(page, "\n"), http.StatusServiceUnavailable)
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(body)))
		if u := m.Usage("m1"); u.Tokens != tc.want || u.Calls != 1 {
			t.Errorf("%s: charged %d tokens and %d calls, want %d and 1", tc.name, u.Tokens, u.Calls, tc.want)
		}
	}
}
