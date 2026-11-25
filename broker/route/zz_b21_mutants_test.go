package route

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// REQ: CAP-9, ADP-4
//
// Package B2-1 (#1460, #1567), mutgate: the survivors on the lines this
// package's changed tests run, each killed by a check of what the line
// does (PR #6607).

// bareRouter is a one-route (openai) router whose proxy is h itself, with
// no Now, so New's defaults apply unless mod sets them.
func bareRouter(t *testing.T, h http.HandlerFunc, mod func(*Config)) *Router {
	t.Helper()
	cfg := Config{
		Providers: []Provider{OpenAI()},
		Rule:      Rule{"default": {{Provider: "openai", Model: "gpt-fixture"}}},
		Granted:   func(string, string) bool { return true },
		Label:     func(string) string { return LabelPublic },
		Upstream:  func(string) http.Handler { return h },
		Audit:     func(Decision) {},
	}
	if mod != nil {
		mod(&cfg)
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func bareDo(r *Router, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.Handler("m1").ServeHTTP(w, anyAttempt(req))
	return w
}

// bareDoWithin is bareDo, failing the test if the router has not answered
// within d.
func bareDoWithin(t *testing.T, r *Router, body string, d time.Duration) *httptest.ResponseRecorder {
	t.Helper()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- bareDo(r, body) }()
	select {
	case w := <-done:
		return w
	case <-time.After(d):
		t.Fatalf("the router did not answer within %v", d)
		return nil
	}
}

const streamChat = `{"model":"default","stream":true,"messages":[{"role":"user","content":"hi"}]}`

// --- route.go: New's defaults (212, 216-217, 228) ---

// The router keeps its own copy of PrivateOK: the caller's map changing
// later does not change who may receive private data.
func TestNewCopiesPrivateOK(t *testing.T) {
	ok := map[string]bool{"openai": true}
	r := bareRouter(t, serveFixture(200, "application/json", fixture(t, "openai_completion.json")), func(c *Config) {
		c.Label, c.PrivateOK = nil, ok // every machine private
	})
	delete(ok, "openai")
	if w := bareDo(r, simpleChat); w.Code != 200 {
		t.Fatalf("private call after the caller's map changed: %d %s", w.Code, w.Body)
	}
}

// A zero MaxOutputTokens is DefaultMaxOutputTokens, sent as the call's limit.
func TestNewDefaultsMaxOutputTokens(t *testing.T) {
	var sent []byte
	r := bareRouter(t, func(w http.ResponseWriter, req *http.Request) {
		sent, _ = io.ReadAll(req.Body)
		serveFixture(200, "application/json", fixture(t, "openai_completion.json"))(w, req)
	}, nil)
	if w := bareDo(r, simpleChat); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var got struct {
		Max *int `json:"max_completion_tokens"`
	}
	if err := json.Unmarshal(sent, &got); err != nil || got.Max == nil || *got.Max != DefaultMaxOutputTokens {
		t.Fatalf("sent %s, want max_completion_tokens %d", sent, DefaultMaxOutputTokens)
	}
}

// A nil Now is time.Now.
func TestNewDefaultsNow(t *testing.T) {
	r := bareRouter(t, serveFixture(200, "application/json", fixture(t, "openai_completion.json")), func(c *Config) { c.Now = nil })
	if w := bareDo(r, simpleChat); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// --- route.go: failedAttempt (400-401) ---

// Output a broken stream produced counts in the failed attempt's charge.
func TestFailedAttemptCountsStreamOutput(t *testing.T) {
	f := failedAttempt("openai", &attempt{status: 502, usage: &Usage{OutputChars: 7}})
	if f.OutputChars != 7 {
		t.Fatalf("OutputChars %d, want 7", f.OutputChars)
	}
}

// --- route.go: serve (495, 503-504, 606) ---

// The router's own refusal is JSON.
func TestRouterRefusalIsJSON(t *testing.T) {
	r := bareRouter(t, nil, nil)
	req := httptest.NewRequest("GET", "/v1/chat/completions", nil)
	w := httptest.NewRecorder()
	r.Handler("m1").ServeHTTP(w, req)
	if w.Code != 404 || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
}

// A body of exactly MaxBody bytes is read whole and served; one byte more
// is refused.
func TestMaxBodyIsInclusive(t *testing.T) {
	h := serveFixture(200, "application/json", fixture(t, "openai_completion.json"))
	n := int64(len(simpleChat))
	if w := bareDo(bareRouter(t, h, func(c *Config) { c.MaxBody = n }), simpleChat); w.Code != 200 {
		t.Fatalf("body of MaxBody bytes: %d %s", w.Code, w.Body)
	}
	if w := bareDo(bareRouter(t, h, func(c *Config) { c.MaxBody = n - 1 }), simpleChat); w.Code != http.StatusRequestEntityTooLarge || strings.Contains(w.Body.String(), "Hello from the fixture") {
		t.Fatalf("body of MaxBody+1 bytes: %d %s", w.Code, w.Body)
	}
}

// A cancelled call charges the attempt it spent, as unserved (#1567).
func TestCancelledCallReportsItsAttempt(t *testing.T) {
	r := newRig(t, rigOpts{})
	ctx, cancel := context.WithCancel(context.Background())
	r.up.set(hostAnthropic, func(w http.ResponseWriter, req *http.Request) {
		cancel()
		<-req.Context().Done()
		serveFixture(502, "application/json", []byte(`{"type":"error","error":{"type":"api_error","message":"x"}}`))(w, req)
	})
	var mu sync.Mutex
	var reports []Usage
	ctx = WithUsage(ctx, func(_ string, u Usage) {
		mu.Lock()
		reports = append(reports, u)
		mu.Unlock()
	})
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(simpleChat)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.router.Handler("m1").ServeHTTP(w, anyAttempt(req))
	assertTimedOut(t, r, w)
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 1 || !reports[0].Unserved || len(reports[0].Failed) != 1 || reports[0].Failed[0].Provider != "anthropic" {
		t.Fatalf("reports: %+v", reports)
	}
}

// --- route.go: try (713, 716, 726, 762, 773-774, 780-784, 791, 795, 804, 807, 814) ---

// The proxy call's context ends when the attempt does.
func TestTryCancelsTheProxyCall(t *testing.T) {
	ctxs := make(chan context.Context, 1)
	r := bareRouter(t, func(w http.ResponseWriter, req *http.Request) {
		ctxs <- req.Context()
		serveFixture(200, "application/json", fixture(t, "openai_completion.json"))(w, req)
	}, nil)
	if w := bareDo(r, simpleChat); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	select {
	case <-(<-ctxs).Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the proxy call's context outlived the attempt")
	}
}

// An attempt that stops reading a provider's body closes it, so the proxy
// stops writing.
func TestTryClosesTheProxyBody(t *testing.T) {
	werr := make(chan error, 1)
	r := bareRouter(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		chunk := []byte(strings.Repeat("x", 4<<10))
		for i := 0; i < 4096; i++ {
			if _, err := w.Write(chunk); err != nil {
				werr <- err
				return
			}
		}
		werr <- nil
	}, nil)
	if w := bareDo(r, simpleChat); w.Code != http.StatusTooManyRequests {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	select {
	case err := <-werr:
		if err == nil {
			t.Fatal("the proxy wrote 16 MiB unread")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the proxy's write still blocks after the attempt ended")
	}
}

// A route's latency is the time to the provider's response headers.
func TestStatsCountLatency(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1_790_000_000, 0)
	r := bareRouter(t, serveFixture(200, "application/json", fixture(t, "openai_completion.json")), func(c *Config) {
		c.Now = func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			now = now.Add(time.Second)
			return now
		}
	})
	if w := bareDo(r, simpleChat); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if st := r.Stats()["openai/gpt-fixture"]; st.Latency <= 0 {
		t.Fatalf("stats: %+v", st)
	}
}

// A 3xx is the provider's answer, passed on as an error, never translated.
func TestTry300IsAnError(t *testing.T) {
	r := bareRouter(t, serveFixture(300, "application/json", fixture(t, "openai_completion.json")), nil)
	w, reports := bareDoReports(r, simpleChat, nil)
	if w.Code != 300 || strings.Contains(w.Body.String(), "Hello from the fixture") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// Nothing was served or failed over, so nothing is charged here.
	if len(reports) != 0 {
		t.Fatalf("reports: %+v", reports)
	}
}

// A served stream is flushed, marked uncacheable, and counted OK.
func TestStreamFlushedAndCounted(t *testing.T) {
	r := bareRouter(t, serveFixture(200, "text/event-stream", fixture(t, "openai_stream.sse")), nil)
	w := bareDo(r, streamChat)
	if w.Code != 200 || !w.Flushed || w.Header().Get("Cache-Control") != "no-cache" || w.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("%d flushed=%v %v", w.Code, w.Flushed, w.Header())
	}
	if st := r.Stats()["openai/gpt-fixture"]; st.Calls != 1 || st.OK != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// A stream that ends before its first byte is a 502 with the router's own
// message.
func TestStreamBrokenBeforeStartIs502(t *testing.T) {
	r := bareRouter(t, serveFixture(200, "text/event-stream", nil), nil)
	w := bareDo(r, streamChat)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "provider stream failed") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// A stream whose first chunk is an error is an overload (529).
func TestStreamEarlyErrorIs529(t *testing.T) {
	r := bareRouter(t, serveFixture(200, "text/event-stream", []byte("data: {\"error\":{\"message\":\"busy\"}}\n\n")), nil)
	if w := bareDo(r, streamChat); w.Code != 529 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// A served answer is JSON and keeps the provider's success status.
func TestServedAnswerStatusAndType(t *testing.T) {
	r := bareRouter(t, serveFixture(201, "text/plain", fixture(t, "openai_completion.json")), nil)
	w := bareDo(r, simpleChat)
	if w.Code != 201 || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
}

// A body cut off by a proxy panic is unreadable, not a translation error.
func TestProxyPanicMidBodyIsUnreadable(t *testing.T) {
	r := bareRouter(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"id":`))
		panic("synthetic proxy failure")
	}, nil)
	w := bareDo(r, simpleChat)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "provider response unreadable") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// A proxy that panics before answering is a broken route.
func TestProxyPanicIsBrokenRoute(t *testing.T) {
	r := bareRouter(t, func(http.ResponseWriter, *http.Request) { panic("synthetic proxy failure") }, nil)
	if w := bareDo(r, simpleChat); w.Code != http.StatusBadGateway {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// A response of exactly MaxResponse bytes may have been cut, so it is
// refused as too large.
func TestMaxResponseReachedIsTooLarge(t *testing.T) {
	body := fixture(t, "openai_completion.json")
	r := bareRouter(t, serveFixture(200, "application/json", body), func(c *Config) { c.MaxResponse = int64(len(body)) })
	w := bareDo(r, simpleChat)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "too large") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// --- route.go: call (886, 894, 900) ---

// The proxy is sent JSON.
func TestCallSendsJSON(t *testing.T) {
	var ctype string
	r := bareRouter(t, func(w http.ResponseWriter, req *http.Request) {
		ctype = req.Header.Get("Content-Type")
		serveFixture(200, "application/json", fixture(t, "openai_completion.json"))(w, req)
	}, nil)
	bareDo(r, simpleChat)
	if ctype != "application/json" {
		t.Fatalf("Content-Type %q", ctype)
	}
}

// A proxy that returns without writing anything still answers (200, empty),
// which no provider translation accepts.
func TestCallProxySilentAnswers(t *testing.T) {
	r := bareRouter(t, func(http.ResponseWriter, *http.Request) {}, nil)
	if w := bareDoWithin(t, r, simpleChat, 5*time.Second); w.Code != http.StatusBadGateway {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// --- openai.go: Stream (75, 87, 109-111, 130) ---

// b21FailAfter accepts n writes, then fails every one with err.
type b21FailAfter struct {
	n   int
	err error
	b   strings.Builder
}

func (f *b21FailAfter) Write(p []byte) (int, error) {
	if f.n == 0 {
		return 0, f.err
	}
	f.n--
	return f.b.Write(p)
}

const oaChunk = `{"choices":[{"delta":{"content":"Hi"}}]}`

func TestOpenAIStreamFlushesEachWrite(t *testing.T) {
	flushes := 0
	src := "data: " + oaChunk + "\n\ndata: [DONE]\n\n"
	if _, err := OpenAI().Stream(io.Discard, func() { flushes++ }, strings.NewReader(src), "default", false); err != nil || flushes != 2 {
		t.Fatalf("err %v, %d flushes, want 2", err, flushes)
	}
	flushes = 0
	src = "data: " + oaChunk + "\n\ndata: {\"error\":{\"message\":\"late\"}}\n\n"
	if _, err := OpenAI().Stream(io.Discard, func() { flushes++ }, strings.NewReader(src), "default", false); err == nil || flushes != 2 {
		t.Fatalf("err %v, %d flushes, want 2", err, flushes)
	}
}

// A guest write that fails on the late error chunk is the error returned.
func TestOpenAIStreamLateErrorWriteFails(t *testing.T) {
	gone := errors.New("guest went away")
	dst := &b21FailAfter{n: 1, err: gone}
	src := "data: " + oaChunk + "\n\ndata: {\"error\":{\"message\":\"late\"}}\n\n"
	if _, err := OpenAI().Stream(dst, func() {}, strings.NewReader(src), "default", false); !errors.Is(err, gone) {
		t.Fatalf("err %v, want %v", err, gone)
	}
}

// A chunk longer than bufio's default 64 KiB token passes.
func TestOpenAIStreamLongChunk(t *testing.T) {
	long := `{"choices":[{"delta":{"content":"` + strings.Repeat("a", 100<<10) + `"}}]}`
	src := "data: " + long + "\n\ndata: [DONE]\n\n"
	if u, err := OpenAI().Stream(io.Discard, func() {}, strings.NewReader(src), "default", false); err != nil || !u.Complete {
		t.Fatalf("err %v %+v", err, u)
	}
}

// --- anthropic.go: Request, Response, Stream ---

func aReqMap(t *testing.T, body string) (map[string]any, error) {
	t.Helper()
	chat, err := parseChat([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Anthropic().Request(chat, "claude-fixture")
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	return m, nil
}

func aReqMsgs(t *testing.T, m map[string]any) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, v := range m["messages"].([]any) {
		out = append(out, v.(map[string]any))
	}
	return out
}

func aLastCached(msg map[string]any) bool {
	c := msg["content"].([]any)
	_, ok := c[len(c)-1].(map[string]any)["cache_control"]
	return ok
}

// An image the Messages API cannot take is refused, not dropped.
func TestAnthropicRequestRefusesBadImage(t *testing.T) {
	_, err := aReqMap(t, `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png,abc"}},{"type":"text","text":"hi"}]}]}`)
	if err == nil {
		t.Fatal("a non-base64 data URL was accepted")
	}
}

// parallel_tool_calls false without tools sets no tool_choice.
func TestAnthropicRequestParallelOffWithoutTools(t *testing.T) {
	m, err := aReqMap(t, `{"model":"m","parallel_tool_calls":false,"messages":[{"role":"user","content":"hi"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m["tool_choice"]; ok {
		t.Fatalf("tool_choice set: %v", m["tool_choice"])
	}
}

// The last two turns are cache breakpoints, including a lone first turn.
func TestAnthropicRequestCachesLastTwoTurns(t *testing.T) {
	m, err := aReqMap(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if ms := aReqMsgs(t, m); len(ms) != 1 || !aLastCached(ms[0]) {
		t.Fatalf("one turn: %v", ms)
	}
	m, err = aReqMap(t, `{"model":"m","messages":[{"role":"user","content":"a"},{"role":"assistant","content":"b"},{"role":"user","content":"c"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if ms := aReqMsgs(t, m); len(ms) != 3 || aLastCached(ms[0]) || !aLastCached(ms[1]) || !aLastCached(ms[2]) {
		t.Fatalf("three turns: %v", ms)
	}
}

// Empty text adds no block, and a turn with no blocks adds no turn.
func TestAnthropicRequestDropsEmpty(t *testing.T) {
	m, err := aReqMap(t, `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":""},{"type":"text","text":"hi"}]},{"role":"assistant","content":""}]}`)
	if err != nil {
		t.Fatal(err)
	}
	ms := aReqMsgs(t, m)
	if len(ms) != 1 || len(ms[0]["content"].([]any)) != 1 {
		t.Fatalf("messages: %v", ms)
	}
}

func TestAnthropicFinishReasonLength(t *testing.T) {
	if got := finishReason("max_tokens"); got != "length" {
		t.Fatalf("max_tokens -> %q", got)
	}
}

func aRespMsg(t *testing.T, body string) map[string]any {
	t.Helper()
	out, _, err := Anthropic().Response([]byte(body), "default")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Choices []struct {
			Message map[string]any `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(out, &c); err != nil || len(c.Choices) != 1 {
		t.Fatalf("%s: %v", out, err)
	}
	return c.Choices[0].Message
}

// Content is null only for a tool-call-only answer; tool_calls appear only
// when there are some.
func TestAnthropicResponseContentAndToolCalls(t *testing.T) {
	msg := aRespMsg(t, `{"id":"m1","stop_reason":"tool_use","content":[{"type":"tool_use","id":"t1","name":"f","input":{"a":1}}]}`)
	if v, ok := msg["content"]; !ok || v != nil {
		t.Fatalf("tool-only content: %v", msg)
	}
	if calls, _ := msg["tool_calls"].([]any); len(calls) != 1 {
		t.Fatalf("tool-only calls: %v", msg)
	}
	msg = aRespMsg(t, `{"id":"m1","stop_reason":"end_turn","content":[]}`)
	if v, ok := msg["content"]; !ok || v != "" {
		t.Fatalf("empty content: %v", msg)
	}
	msg = aRespMsg(t, `{"id":"m1","stop_reason":"end_turn","content":[{"type":"text","text":"hi"}]}`)
	if _, ok := msg["tool_calls"]; ok || msg["content"] != "hi" {
		t.Fatalf("text-only: %v", msg)
	}
}

// An event longer than bufio's default 64 KiB token passes.
func TestAnthropicStreamLongEvent(t *testing.T) {
	src := "data: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\",\"usage\":{\"input_tokens\":1}}}\n\n" +
		"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"" + strings.Repeat("a", 100<<10) + "\"}}\n\n" +
		"data: {\"type\":\"message_stop\"}\n\n"
	if _, err := Anthropic().Stream(io.Discard, func() {}, strings.NewReader(src), "default", false); err != nil {
		t.Fatalf("err %v", err)
	}
}

type b21ErrReader struct{ err error }

func (e b21ErrReader) Read([]byte) (int, error) { return 0, e.err }

// A provider read error is the error returned, not a cut-off stream.
func TestAnthropicStreamReadError(t *testing.T) {
	cut := errors.New("synthetic read failure")
	src := io.MultiReader(strings.NewReader("data: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\"}}\n\n"), b21ErrReader{cut})
	if _, err := Anthropic().Stream(io.Discard, func() {}, src, "default", false); !errors.Is(err, cut) {
		t.Fatalf("err %v, want %v", err, cut)
	}
}

// --- chat.go: content and parseChat (97-98, 121-122, 240, 243) ---

func TestContentUnmarshalTrimsAndRefusesEmpty(t *testing.T) {
	var c content
	if err := c.UnmarshalJSON([]byte(" \"hi\" ")); err != nil || c.Text == nil || *c.Text != "hi" {
		t.Fatalf("padded string: %v %+v", err, c)
	}
	var e content
	if err := e.UnmarshalJSON(nil); err == nil {
		t.Fatal("empty content accepted")
	}
}

func TestContentMarshalsText(t *testing.T) {
	s := "hi"
	if b, err := json.Marshal(content{Text: &s}); err != nil || string(b) != `"hi"` {
		t.Fatalf("%s %v", b, err)
	}
}

func TestParseChatRequiresModelAndMessages(t *testing.T) {
	if _, err := parseChat([]byte(`{"messages":[{"role":"user","content":"x"}]}`)); err == nil {
		t.Fatal("no model accepted")
	}
	if _, err := parseChat([]byte(`{"model":"m","messages":[]}`)); err == nil {
		t.Fatal("no messages accepted")
	}
}

// A stream that fails before its first byte still charges the output the
// provider produced: tool-argument characters for a block it never opened.
func TestStreamBrokenBeforeStartChargesOutput(t *testing.T) {
	src := "data: {\"type\":\"content_block_delta\",\"index\":5,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"a\\\":1}\"}}\n\n"
	r := bareRouter(t, serveFixture(200, "text/event-stream", []byte(src)), func(c *Config) {
		c.Providers = []Provider{Anthropic()}
		c.Rule = Rule{"default": {{Provider: "anthropic", Model: "claude-fixture"}}}
	})
	var got []Usage
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(streamChat))
	req = req.WithContext(WithUsage(req.Context(), func(_ string, u Usage) { got = append(got, u) }))
	w := httptest.NewRecorder()
	r.Handler("m1").ServeHTTP(w, anyAttempt(req))
	if w.Code != http.StatusBadGateway || len(got) != 1 || len(got[0].Failed) != 1 || got[0].Failed[0].OutputChars != int64(len(`{"a":1}`)) {
		t.Fatalf("%d %s %+v", w.Code, w.Body, got)
	}
}

// bareDoReports is bareDo with the call's usage reports collected and, if
// attempt is not nil, it as the call's attempt bound.
func bareDoReports(r *Router, body string, attempt func() bool) (*httptest.ResponseRecorder, []Usage) {
	var mu sync.Mutex
	var got []Usage
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithUsage(req.Context(), func(_ string, u Usage) {
		mu.Lock()
		got = append(got, u)
		mu.Unlock()
	})
	if attempt == nil {
		attempt = func() bool { return true }
	}
	w := httptest.NewRecorder()
	r.Handler("m1").ServeHTTP(w, req.WithContext(WithAttempt(ctx, attempt)))
	mu.Lock()
	defer mu.Unlock()
	return w, got
}

// decisionLog collects a router's audit decisions; after, if set, runs on
// each one.
type decisionLog struct {
	mu    sync.Mutex
	ds    []Decision
	after func(Decision)
}

func (l *decisionLog) audit(d Decision) {
	l.mu.Lock()
	l.ds = append(l.ds, d)
	l.mu.Unlock()
	if l.after != nil {
		l.after(d)
	}
}

func (l *decisionLog) all() []Decision {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Decision(nil), l.ds...)
}

// --- anthropic.go, second pass (141-142, 152, 248, 324, 392-393, 480, 533, 550) ---

func TestAnthropicRequestRefusesAssistantImage(t *testing.T) {
	_, err := aReqMap(t, `{"model":"m","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":[{"type":"image_url","image_url":{"url":"https://example.invalid/a.png"}},{"type":"text","text":"x"}]}]}`)
	if err == nil {
		t.Fatal("an assistant image was accepted")
	}
}

func TestAnthropicUserBlockRefusesImageWithoutURL(t *testing.T) {
	if _, err := userBlock(contentPart{Type: "image_url"}); err == nil {
		t.Fatal("image_url without a url accepted")
	}
	if _, err := userBlock(contentPart{Type: "image_url", ImageURL: &imageURL{}}); err == nil {
		t.Fatal("image_url with an empty url accepted")
	}
}

func TestAnthropicFinishReasonRefusal(t *testing.T) {
	if got := finishReason("refusal"); got != "content_filter" {
		t.Fatalf("refusal -> %q", got)
	}
}

// A provider error type the router does not map is a server error.
func TestAnthropicErrorUnknownTypeIsServerError(t *testing.T) {
	out := Anthropic().Error(500, []byte(`{"type":"error","error":{"type":"synthetic_kind","message":"m"}}`))
	var e struct {
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out, &e); err != nil || e.Error.Type != "server_error" {
		t.Fatalf("%s", out)
	}
}

const aStart = "data: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\"}}\n\n"

// The stream's chunks carry the message's id, and each write is flushed.
func TestAnthropicStreamIDAndFlushes(t *testing.T) {
	var out strings.Builder
	flushes := 0
	src := aStart + "data: {\"type\":\"message_stop\"}\n\n"
	if _, err := Anthropic().Stream(&out, func() { flushes++ }, strings.NewReader(src), "default", false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"id":"chatcmpl-m1"`) || flushes != 2 {
		t.Fatalf("%d flushes: %s", flushes, out.String())
	}
}

// A guest write that fails ends the stream with that error.
func TestAnthropicStreamWriteFails(t *testing.T) {
	gone := errors.New("guest went away")
	if _, err := Anthropic().Stream(&b21FailAfter{err: gone}, func() {}, strings.NewReader(aStart), "default", false); !errors.Is(err, gone) {
		t.Fatalf("err %v, want %v", err, gone)
	}
}

// --- route.go, second pass (638, 646-647, 653, 661-665, 746, 831-848) ---

// A call no route may take is charged nothing.
func TestNoRouteReportsNothing(t *testing.T) {
	r := bareRouter(t, nil, func(c *Config) { c.Granted = func(string, string) bool { return false } })
	w, reports := bareDoReports(r, simpleChat, nil)
	if w.Code != http.StatusForbidden || len(reports) != 0 {
		t.Fatalf("%d %+v", w.Code, reports)
	}
}

// When every route fails over, the guest gets the last failure, the
// owner a failover record then one denied record with no route, and the
// guest's Retry-After rounds the provider's up by a second.
func TestAllRoutesFailedAnswer(t *testing.T) {
	var log decisionLog
	now := time.Unix(1_790_000_000, 0)
	r := bareRouter(t, serveFixture(429, "application/json", []byte(`{"error":{"message":"slow down","type":"rate_limit_error"}}`), "Retry-After", "30"), func(c *Config) {
		c.Audit, c.Now = log.audit, func() time.Time { return now }
	})
	w, _ := bareDoReports(r, simpleChat, nil)
	if w.Code != 429 || w.Header().Get("Retry-After") != "31" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	ds := log.all()
	if len(ds) != 2 || ds[0].Outcome != Failover || ds[1].Outcome != Denied || ds[1].Status != 429 || ds[1].Route != "" ||
		ds[1].Reason != "every permitted route is exhausted or unavailable" {
		t.Fatalf("decisions: %+v", ds)
	}
}

// A refused further attempt names the meter as the reason.
func TestBoundedAttemptReason(t *testing.T) {
	var log decisionLog
	r := bareRouter(t, serveFixture(429, "application/json", []byte(`{"error":{"message":"slow down","type":"rate_limit_error"}}`)), func(c *Config) {
		c.Audit = log.audit
		c.Rule = Rule{"default": {{Provider: "openai", Model: "gpt-a"}, {Provider: "openai", Model: "gpt-b"}}}
	})
	w, _ := bareDoReports(r, simpleChat, func() bool { return false })
	ds := log.all()
	if w.Code != 429 || len(ds) != 2 || ds[1].Reason != "the call's meter cannot cover another attempt" {
		t.Fatalf("%d %+v", w.Code, ds)
	}
}

// A cooldown that has already ended by the time the guest is answered
// gives no Retry-After.
func TestEndedCooldownGivesNoRetryAfter(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(1_790_000_000, 0)
	log := decisionLog{after: func(d Decision) {
		if d.Outcome == Failover {
			mu.Lock()
			now = now.Add(2 * time.Second)
			mu.Unlock()
		}
	}}
	r := bareRouter(t, serveFixture(429, "application/json", []byte(`{"error":{"message":"slow down","type":"rate_limit_error"}}`), "Retry-After", "1"), func(c *Config) {
		c.Audit = log.audit
		c.Now = func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		}
	})
	w, _ := bareDoReports(r, simpleChat, nil)
	if w.Code != 429 || w.Header().Get("Retry-After") != "" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
}

// A provider's Retry-After past MaxCooldown is cut to it.
func TestRetryAfterCappedAtMaxCooldown(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	r := bareRouter(t, serveFixture(429, "application/json", []byte(`{"error":{"message":"slow down","type":"rate_limit_error"}}`), "Retry-After", "7200"), func(c *Config) {
		c.Now = func() time.Time { return now }
	})
	w, _ := bareDoReports(r, simpleChat, nil)
	if want := strconv.Itoa(int(MaxCooldown/time.Second) + 1); w.Code != 429 || w.Header().Get("Retry-After") != want {
		t.Fatalf("%d %v, want Retry-After %s", w.Code, w.Header(), want)
	}
}

// denyWith is a proxy that refuses every call itself.
func denyWith(status int, body string, hdr ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(deniedHeader, "1")
		for i := 0; i+1 < len(hdr); i += 2 {
			w.Header().Set(hdr[i], hdr[i+1])
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}
}

func errorOf(t *testing.T, w *httptest.ResponseRecorder) (msg, typ string) {
	t.Helper()
	var e struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("%s: %v", w.Body, err)
	}
	return e.Error.Message, e.Error.Type
}

// The proxy's own refusal reaches the guest as an OpenAI error: its
// "egress denied:" text up to 200 bytes, its Retry-After, and a type
// from its status.
func TestProxyDenialShape(t *testing.T) {
	msg := "egress denied: " + strings.Repeat("x", 200-len("egress denied: "))
	w := bareDo(bareRouter(t, denyWith(403, msg, "Retry-After", "7"), nil), simpleChat)
	if m, typ := errorOf(t, w); w.Code != 403 || m != msg || typ != "permission_error" ||
		w.Header().Get("Retry-After") != "7" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %q %q %v", w.Code, m, typ, w.Header())
	}
	for status, want := range map[int]string{400: "invalid_request_error", 500: "server_error"} {
		w := bareDo(bareRouter(t, denyWith(status, "egress denied: x"), nil), simpleChat)
		if _, typ := errorOf(t, w); w.Code != status || typ != want {
			t.Fatalf("status %d: type %q, want %q", status, typ, want)
		}
	}
}
