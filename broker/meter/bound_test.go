package meter

// REQ: OP-8, RES-5

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func upload(n int) []byte {
	return []byte(`{"max_tokens":10,"messages":[{"role":"user","content":"` + strings.Repeat("a", n) + `"}]}`)
}

func post(h http.Handler, body []byte) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body)))
	return w
}

var ok = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body)
	io.WriteString(w, `{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
})

// OP-8, RES-5 (combined on #2327): a lone upload whose bytes exceed what
// is left of the cap, but whose estimate fits, is served, not refused
// with a spend-limit 429 the meter has not reached.
func TestBoundAdmitsALoneLargeCall(t *testing.T) {
	m, _, n := open(t, Config{MachineCap: DefaultMachineCap, OverallCap: DefaultOverallCap})
	if w := post(m.WrapBound("m1", ok), upload(4<<20)); w.Code != 200 {
		t.Fatalf("lone 4 MiB call: %d %s", w.Code, w.Body)
	}
	if n.count() != 0 {
		t.Fatalf("the owner was told of a spent limit")
	}
}

// OP-8: a lone call whose estimate does not fit is refused with 429.
func TestBoundRefusesALoneCallOverTheCap(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: Limits{Calls: 100, Tokens: 1000}, OverallCap: big, MaxReserve: 10})
	w := post(m.WrapBound("m1", ok), upload(8000))
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "spend limit reached") {
		t.Fatalf("over-cap call: %d %s", w.Code, w.Body)
	}
}

// OP-8, RES-5: a call that does not fit at its bound beside the machine's
// calls in flight waits for them, then runs; it is not refused.
func TestBoundCallWaitsForCallsInFlight(t *testing.T) {
	m, _, n := open(t, Config{MachineCap: Limits{Calls: 100, Tokens: 3000}, OverallCap: big, MaxReserve: 10, CallTimeout: 5 * time.Second})
	release, started := make(chan struct{}), make(chan struct{}, 2)
	var in atomic.Int32
	h := m.WrapBound("m1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if in.Add(1) > 1 {
			t.Error("the second call ran beside the first")
		}
		started <- struct{}{}
		<-release
		in.Add(-1)
		io.WriteString(w, `{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	first := make(chan int)
	go func() { first <- post(h, upload(2000)).Code }()
	<-started
	second := make(chan int)
	go func() { second <- post(h, upload(2000)).Code }()
	select {
	case <-started:
		t.Fatal("the second call was admitted at its bound beside the first")
	case c := <-second:
		t.Fatalf("the second call was answered %d instead of waiting", c)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if c := <-first; c != 200 {
		t.Fatalf("first call: %d", c)
	}
	if c := <-second; c != 200 {
		t.Fatalf("second call: %d", c)
	}
	if n.count() != 0 {
		t.Fatalf("the owner was told of a spent limit")
	}
}

// OP-8, RES-5: a call that waits past the call timeout gets 503 with
// Retry-After, not a spend-limit 429.
func TestBoundWaitEndsWithRetry(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: Limits{Calls: 100, Tokens: 3000}, OverallCap: big, MaxReserve: 10, CallTimeout: 200 * time.Millisecond})
	release, started := make(chan struct{}), make(chan struct{})
	h := m.WrapBound("m1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(started)
		<-release
	}))
	first := make(chan struct{})
	go func() { post(h, upload(2000)); close(first) }()
	<-started
	w := post(h, upload(2000))
	close(release)
	<-first
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" || strings.Contains(w.Body.String(), "spend limit reached") {
		t.Fatalf("timed-out wait: %d %q %s", w.Code, w.Header().Get("Retry-After"), w.Body)
	}
}

// OP-8 (combined and security on #2327): a call whose billed input its
// bytes do not bound is refused under WrapBound before it is charged or
// forwarded: images, audio, documents and files at any depth, by data:
// URL or address, provider-side tools and stored context. Text, the
// guest's own tools and their arguments pass.
func TestBoundRefusesInputItsBytesDoNotBound(t *testing.T) {
	img := `"data:image/png;base64,` + strings.Repeat("A", 508) + `"`
	for _, tc := range []struct {
		name, body string
		refused    bool
	}{
		{"chat image_url data", `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":` + img + `}}]}]}`, true},
		{"chat image_url remote", `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid/a.png"}}]}]}`, true},
		{"chat input_audio", `{"messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}]}`, true},
		{"chat file", `{"messages":[{"role":"user","content":[{"type":"file","file":{"file_data":"AAAA"}}]}]}`, true},
		{"anthropic image", `{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}}]}]}`, true},
		{"anthropic document", `{"messages":[{"role":"user","content":[{"type":"document","source":{"type":"url","url":"https://example.invalid/a.pdf"}}]}]}`, true},
		{"anthropic image in tool_result", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}}]}]}]}`, true},
		{"anthropic image in system", `{"system":[{"type":"image","source":{"type":"base64","data":"AAAA"}}],"messages":[]}`, true},
		{"case-folded key", `{"Messages":[{"role":"user","content":[{"TYPE":"image_url","image_url":{"url":` + img + `}}]}]}`, true},
		{"escaped key", `{"messages":[{"role":"user","content":[{"text":"a \"type\": \"text\"","\u0074ype":"image_url","image_url":{"url":` + img + `}}]}]}`, true},
		{"responses input_image", `{"input":[{"role":"user","content":[{"type":"input_image","image_url":` + img + `}]}]}`, true},
		{"responses image in function output", `{"input":[{"type":"function_call_output","call_id":"c","output":[{"type":"input_image","image_url":` + img + `}]}]}`, true},
		{"responses input_file", `{"input":[{"role":"user","content":[{"type":"input_file","file_data":"AAAA"}]}]}`, true},
		{"provider tool", `{"tools":[{"type":"web_search"}],"input":"hi"}`, true},
		{"anthropic server tool", `{"tools":[{"type":"web_search_20250305","name":"web_search"}],"messages":[]}`, true},
		{"web_search_options", `{"web_search_options":{},"messages":[]}`, true},
		{"mcp_servers", `{"mcp_servers":[{"type":"url","url":"https://example.invalid"}],"messages":[]}`, true},
		{"previous_response_id", `{"previous_response_id":"resp_1","input":"hi"}`, true},
		{"conversation", `{"conversation":"conv_1","input":"hi"}`, true},
		{"stored prompt", `{"prompt":{"id":"pmpt_1"},"input":"hi"}`, true},

		{"chat text", `{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`, false},
		{"chat string", `{"messages":[{"role":"user","content":"hi"}]}`, false},
		{"function tool with schema", `{"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object","properties":{"a":{"type":"string"}}}}}],"messages":[{"role":"assistant","tool_calls":[{"id":"c","type":"function","function":{"name":"f","arguments":"{\"type\":\"image\"}"}}]}]}`, false},
		{"anthropic custom tool and tool_use input", `{"tools":[{"name":"f","input_schema":{"type":"object"}}],"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"f","input":{"type":"image","url":"x"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"text","text":"ok","cache_control":{"type":"ephemeral"}}]}]}]}`, false},
		{"responses text and reasoning", `{"input":[{"type":"reasoning","summary":[{"type":"summary_text","text":"s"}]},{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]},{"type":"function_call","call_id":"c","name":"f","arguments":"{}"},{"type":"function_call_output","call_id":"c","output":"ok"}]}`, false},
		{"null stored context", `{"previous_response_id":null,"input":"hi"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _ := open(t, Config{MachineCap: big, OverallCap: big})
			forwarded := false
			h := m.WrapBound("m1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				ok.ServeHTTP(w, r)
			}))
			w := post(h, []byte(tc.body))
			if tc.refused {
				if w.Code != http.StatusBadRequest || forwarded || m.Usage("m1").Calls != 0 {
					t.Fatalf("got %d (forwarded %v, usage %+v) %s; want 400, not forwarded or charged", w.Code, forwarded, m.Usage("m1"), w.Body)
				}
				return
			}
			if w.Code != 200 || !forwarded {
				t.Fatalf("got %d %s; want it served", w.Code, w.Body)
			}
		})
	}
	// Wrap, unbound, still forwards an image call.
	m, _, _ := open(t, Config{MachineCap: big, OverallCap: big})
	if w := post(m.Wrap("m1", ok), []byte(`{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":`+img+`}}]}]}`)); w.Code != 200 {
		t.Fatalf("Wrap refused an image call: %d", w.Code)
	}
}
