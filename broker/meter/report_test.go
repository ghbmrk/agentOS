package meter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// REQ: OP-8
//
// Usage the vault process reports beside the body (the model router's
// Decision.Usage, egress K9) is charged in place of what the router
// rendered into the body, by the same completion rule.

type reportUsage interface{ ReportUsage([]byte, bool) }

func TestOP8ReportedUsageCharged(t *testing.T) {
	anthropic := `{"input_tokens":50,"cache_read_input_tokens":200,"cache_creation_input_tokens":10,"output_tokens":777}`
	chunk := `data: {"choices":[{"delta":{"content":"` + strings.Repeat("y", 4000) + `"}}]}` + "\n\n"
	// The router renders Anthropic cache reads as OpenAI cached_tokens,
	// which the meter alone would weigh at 0.5 rather than 0.1.
	rendered := `{"choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":260,"completion_tokens":777,"prompt_tokens_details":{"cached_tokens":200}}}`
	for _, tc := range []struct {
		name, ctype, body string
		report            string
		complete          bool
		want              int64
	}{
		// 50 + 200*0.1 + 10*1.25 = 82.5 -> 83, plus 777 output.
		{"stream-without-usage", "text/event-stream", chunk + "data: [DONE]\n\n", anthropic, true, 83 + 777},
		{"replaces-rendered", "application/json", rendered, anthropic, true, 83 + 777},
		// The provider's answer did not complete: the 4000 counted
		// characters (1000 tokens) are the least output charged.
		{"report-incomplete", "text/event-stream", chunk + "data: [DONE]\n\n", anthropic, false, 83 + 1000},
		// The body to the guest was cut off although the report says
		// complete.
		{"body-cut-off", "text/event-stream", chunk, anthropic, true, 83 + 1000},
		// An unreadable report is ignored; the body's usage stands
		// (260 - 200*0.5 = 160).
		{"malformed", "application/json", rendered, `{"input_tokens":`, true, 160 + 777},
	} {
		m, _, _ := open(t, Config{MachineCap: Limits{Calls: 10, Tokens: 1 << 30}, OverallCap: big})
		h := m.Wrap("m1", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", tc.ctype)
			io.WriteString(w, tc.body)
			r, ok := w.(reportUsage)
			if !ok {
				t.Fatal("the meter's writer takes no reported usage")
			}
			r.ReportUsage([]byte(tc.report), tc.complete)
		}))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"stream":true,"max_tokens":4096}`)))
		if w.Body.String() != tc.body {
			t.Fatalf("%s: the guest got a different body", tc.name)
		}
		if u := m.Usage("m1"); u.Tokens != tc.want {
			t.Fatalf("%s: charged %d tokens, want %d", tc.name, u.Tokens, tc.want)
		}
	}
}
