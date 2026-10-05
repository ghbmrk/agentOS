package meter

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// REQ: CRED-1, OP-8, ARC-7

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type notes struct {
	mu  sync.Mutex
	evs []Exhausted
}

func (n *notes) add(e Exhausted) { n.mu.Lock(); n.evs = append(n.evs, e); n.mu.Unlock() }
func (n *notes) count() int      { n.mu.Lock(); defer n.mu.Unlock(); return len(n.evs) }

func open(t *testing.T, cfg Config) (*Meter, *clock, *notes) {
	t.Helper()
	c := &clock{t: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)}
	n := &notes{}
	cfg.Now, cfg.Notify = c.now, n.add
	if cfg.Path == "" {
		cfg.Path = filepath.Join(t.TempDir(), "meter.json")
	}
	m, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m, c, n
}

func call(m *Meter, machine string, in, out int64) error {
	c, err := m.Start(machine, in, 0)
	if err != nil {
		return err
	}
	c.Done(in + out)
	return nil
}

var big = Limits{Calls: 1 << 40, Tokens: 1 << 40}

// TestOP8PerMachineRollingCap: with no task bound, each machine has its own
// rolling cap; on exhaustion calls are refused, the owner is told once, and
// the cap frees up as the window rolls.
func TestOP8PerMachineRollingCap(t *testing.T) {
	m, c, n := open(t, Config{MachineCap: Limits{Calls: 3, Tokens: 1000}, OverallCap: big, Window: 24 * time.Hour})
	for i := 0; i < 3; i++ {
		if err := call(m, "m1", 10, 10); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := call(m, "m1", 10, 10); !errors.Is(err, ErrExhausted) {
			t.Fatalf("over cap: %v", err)
		}
	}
	if n.count() != 1 {
		t.Fatalf("owner told %d times, want once", n.count())
	}
	if e := n.evs[0]; e.Machine != "m1" || e.Scope != ScopeMachine || e.Task != "" {
		t.Fatalf("notice %+v", e)
	}
	if err := call(m, "m2", 10, 10); err != nil {
		t.Fatalf("another machine is charged for m1: %v", err)
	}
	c.add(25 * time.Hour)
	if err := call(m, "m1", 10, 10); err != nil {
		t.Fatalf("window did not roll: %v", err)
	}
}

// TestOP8TokensCountFromBrokerObservation: tokens are counted from what the
// broker saw, and a call that would start past the token cap is refused.
func TestOP8TokensCountFromBrokerObservation(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: Limits{Calls: 100, Tokens: 1000}, OverallCap: big})
	if err := call(m, "m1", 600, 500); err != nil {
		t.Fatal(err)
	}
	if u := m.Usage("m1"); u.Tokens != 1100 || u.Calls != 1 {
		t.Fatalf("usage %+v", u)
	}
	if err := call(m, "m1", 1, 1); !errors.Is(err, ErrExhausted) {
		t.Fatalf("token cap: %v", err)
	}
}

// TestOP8TaskReservationAndOwnerExtension: a bound task is charged to its
// reservation instead of the machine cap. On exhaustion the owner is told
// with the task; an extension (the owner's YES with a code-generator code,
// checked by the owner channel) re-opens it, bounded by the daily
// extension ceiling, which the extension cannot raise.
func TestOP8TaskReservationAndOwnerExtension(t *testing.T) {
	m, c, n := open(t, Config{
		MachineCap:     Limits{Calls: 1, Tokens: 1},
		OverallCap:     big,
		DailyExtension: Limits{Calls: 5, Tokens: 1000},
	})
	if err := m.Bind("m1", "t1", Limits{Calls: 2, Tokens: 1000}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := call(m, "m1", 10, 10); err != nil {
			t.Fatalf("task call %d: %v", i, err)
		}
	}
	if err := call(m, "m1", 10, 10); !errors.Is(err, ErrExhausted) {
		t.Fatalf("over reservation: %v", err)
	}
	if n.count() != 1 || n.evs[0].Task != "t1" || n.evs[0].Scope != ScopeTask {
		t.Fatalf("notices %+v", n.evs)
	}
	if err := m.Extend("t1", Limits{Calls: 3, Tokens: 100}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := call(m, "m1", 10, 10); err != nil {
			t.Fatalf("extended call %d: %v", i, err)
		}
	}
	if err := m.Extend("t1", Limits{Calls: 3, Tokens: 100}); !errors.Is(err, ErrCeiling) {
		t.Fatalf("extension past the daily ceiling: %v", err)
	}
	c.add(24 * time.Hour)
	if err := m.Extend("t1", Limits{Calls: 3, Tokens: 100}); err != nil {
		t.Fatalf("next day's extension: %v", err)
	}
	if err := m.Extend("nope", Limits{Calls: 1}); err == nil {
		t.Fatal("extended an unknown task")
	}
}

// TestOP8OverallCapBoundsEverything: the box-wide cap applies across
// machines, tasks, and extensions.
func TestOP8OverallCapBoundsEverything(t *testing.T) {
	m, _, n := open(t, Config{MachineCap: big, OverallCap: Limits{Calls: 3, Tokens: 1 << 30}, DailyExtension: big})
	must(t, m.Bind("m1", "t1", big))
	must(t, call(m, "m1", 1, 1))
	must(t, call(m, "m2", 1, 1))
	must(t, call(m, "m3", 1, 1))
	if err := call(m, "m1", 1, 1); !errors.Is(err, ErrExhausted) {
		t.Fatalf("overall cap: %v", err)
	}
	must(t, m.Extend("t1", Limits{Calls: 10}))
	if err := call(m, "m1", 1, 1); !errors.Is(err, ErrExhausted) {
		t.Fatal("an extension raised the overall cap")
	}
	if n.count() == 0 || n.evs[0].Scope != ScopeOverall {
		t.Fatalf("notices %+v", n.evs)
	}
}

// TestOP8UsageSurvivesRestart: counts are durable, so restarting the
// broker does not hand a looping guest a fresh budget.
func TestOP8UsageSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meter.json")
	cfg := Config{Path: path, MachineCap: Limits{Calls: 2, Tokens: 1 << 20}, OverallCap: big}
	m, _, _ := open(t, cfg)
	must(t, m.Bind("m2", "t9", Limits{Calls: 1, Tokens: 100}))
	must(t, call(m, "m1", 1, 1))
	must(t, call(m, "m1", 1, 1))
	m2, _, _ := open(t, cfg)
	if err := call(m2, "m1", 1, 1); !errors.Is(err, ErrExhausted) {
		t.Fatalf("restart reset the machine's usage: %v", err)
	}
	must(t, call(m2, "m2", 1, 1))
	if err := call(m2, "m2", 1, 1); !errors.Is(err, ErrExhausted) {
		t.Fatalf("restart lost the task binding: %v", err)
	}
}

// TestOP8OpenRefusesMissingLimits: there is no unlimited default.
func TestOP8OpenRefusesMissingLimits(t *testing.T) {
	for _, cfg := range []Config{
		{OverallCap: big},
		{MachineCap: big},
		{MachineCap: Limits{Calls: 1}, OverallCap: big},
	} {
		cfg.Path = filepath.Join(t.TempDir(), "m.json")
		if _, err := Open(cfg); err == nil {
			t.Errorf("opened with %+v", cfg)
		}
	}
}

// TestOP8WrapMetersByListenerIdentity: the HTTP wrapper charges the machine
// it was built for, whatever the request claims (no guest-presented token,
// CRED-1, ARC-7), charges the usage the provider reported, and on
// exhaustion answers 429 without calling the model egress.
func TestOP8WrapMetersByListenerIdentity(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: Limits{Calls: 2, Tokens: 1 << 20}, OverallCap: big})
	upstream := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream++
		b, _ := io.ReadAll(r.Body)
		if string(b) != `{"messages":["hi"]}` {
			t.Errorf("body changed on the way: %q", b)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"hello"}}],"usage":{"prompt_tokens":7,"completion_tokens":40}}`)
	})
	h := m.Wrap("m1", next)
	req := func() *http.Request {
		r := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(`{"messages":["hi"]}`))
		r.Header.Set("Authorization", "Bearer m2")
		r.Header.Set("X-Machine", "m2")
		return r
	}
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req())
		if w.Code != 200 || !strings.Contains(w.Body.String(), "hello") {
			t.Fatalf("call %d: %d %s", i, w.Code, w.Body)
		}
	}
	if u := m.Usage("m1"); u.Calls != 2 || u.Tokens != 2*47 {
		t.Fatalf("m1 usage %+v, want 2 calls and the reported 94 tokens", u)
	}
	if u := m.Usage("m2"); u.Calls != 0 {
		t.Fatalf("m2 charged by a header: %+v", u)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req())
	if w.Code != http.StatusTooManyRequests || upstream != 2 {
		t.Fatalf("exhausted: %d, upstream calls %d", w.Code, upstream)
	}
	if !strings.Contains(w.Body.String(), "spend limit") {
		t.Fatalf("refusal body %q", w.Body.String())
	}
}

// TestOP8HangingUpDoesNotStopTheCharge: a guest that hangs up mid-stream
// does not cancel the call. The model egress keeps reading the provider's
// answer to the end, and the usage it reports is charged in full.
func TestOP8HangingUpDoesNotStopTheCharge(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: Limits{Calls: 10, Tokens: 1 << 30}, OverallCap: big})
	finished := make(chan error, 1)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, `data: {"choices":[{"delta":{"content":"a"}}]}`+"\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(300 * time.Millisecond) // the guest hangs up meanwhile
		for i := 0; i < 200; i++ {
			if _, err := io.WriteString(w, `data: {"choices":[{"delta":{"content":"`+strings.Repeat("x", 4000)+`"}}]}`+"\n\n"); err != nil {
				finished <- err
				return
			}
		}
		io.WriteString(w, `data: {"choices":[],"usage":{"prompt_tokens":12,"completion_tokens":200000}}`+"\n\ndata: [DONE]\n\n")
		finished <- r.Context().Err()
	})
	srv := httptest.NewServer(m.Wrap("m1", next))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL, strings.NewReader(`{"stream":true}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Read(make([]byte, 64))
	cancel()
	resp.Body.Close()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("the call was cut short after the guest hung up: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("model egress never finished")
	}
	deadline := time.Now().Add(5 * time.Second)
	for m.Usage("m1").Tokens != 200012 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if u := m.Usage("m1"); u.Tokens != 200012 {
		t.Fatalf("charged %+v, want the reported 200012 tokens", u)
	}
}

// TestOP8RecordedStreamsAreChargedByReportedUsage: the provider's usage is
// charged, not the stream's framing. OpenAI reports it in a last chunk
// (the egress proxy forces include_usage); Anthropic in message_start and
// message_delta, with cache tokens counted as input.
func TestOP8RecordedStreamsAreChargedByReportedUsage(t *testing.T) {
	openai := strings.Repeat(`data: {"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"tok"},"finish_reason":null}]}`+"\n\n", 1000) +
		`data: {"id":"c","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":321,"completion_tokens":1000,"completion_tokens_details":{"reasoning_tokens":600}}}` + "\n\ndata: [DONE]\n\n"
	anthropic := "event: message_start\n" +
		`data: {"type":"message_start","message":{"usage":{"input_tokens":50,"cache_read_input_tokens":200,"cache_creation_input_tokens":10,"output_tokens":1}}}` + "\n\n" +
		strings.Repeat("event: content_block_delta\n"+`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}}`+"\n\n", 500) +
		"event: message_delta\n" + `data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":777}}` + "\n\n"
	for _, tc := range []struct {
		name, stream string
		want         int64
	}{{"openai", openai, 1321}, {"anthropic", anthropic, 260 + 777}} {
		m, _, _ := open(t, Config{MachineCap: Limits{Calls: 10, Tokens: 1 << 30}, OverallCap: big})
		h := m.Wrap("m1", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			for s := tc.stream; len(s) > 0; s = s[min(len(s), 97):] {
				io.WriteString(w, s[:min(len(s), 97)]) // split mid-line
			}
		}))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"stream":true,"max_tokens":4096}`)))
		if w.Body.String() != tc.stream {
			t.Fatalf("%s: the guest got a different stream", tc.name)
		}
		if u := m.Usage("m1"); u.Tokens != tc.want {
			t.Fatalf("%s: charged %d tokens, want %d", tc.name, u.Tokens, tc.want)
		}
	}
}

// TestOP8NoUsageIsEstimatedFromContent: a response without usage is
// charged its content and tool-argument characters, not its framing.
func TestOP8NoUsageIsEstimatedFromContent(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: Limits{Calls: 10, Tokens: 1 << 30}, OverallCap: big})
	h := m.Wrap("m1", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"`+strings.Repeat("i", 5000)+`","choices":[{"message":{"content":"`+strings.Repeat("c", 400)+
			`","tool_calls":[{"function":{"name":"f","arguments":"`+strings.Repeat("a", 400)+`"}}]}}]}`)
	}))
	body := `{"messages":[]}`
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(body)))
	if u, want := m.Usage("m1"), Tokens(int64(len(body)))+200; u.Tokens != want {
		t.Fatalf("charged %d tokens, want %d (input estimate + 800 content chars)", u.Tokens, want)
	}
}

// TestOP8OutputIsReservedAtStart: a call reserves its output limit when it
// starts, so a call that could pass the cap is refused up front and
// parallel calls cannot overshoot together; the reservation is settled to
// actual use afterwards.
func TestOP8OutputIsReservedAtStart(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: Limits{Calls: 100, Tokens: 10_000}, OverallCap: big, MaxReserve: 6000})
	if m.reserve([]byte(`{"max_tokens":1e9}`)) != 6000 || m.reserve([]byte(`{"max_completion_tokens":300}`)) != 300 ||
		m.reserve([]byte(`{}`)) != 6000 || m.reserve([]byte(`not json`)) != 6000 {
		t.Fatal("reservation sizing")
	}
	c1, err := m.Start("m1", 100, 6000)
	must(t, err)
	if _, err := m.Start("m1", 100, 6000); !errors.Is(err, ErrExhausted) {
		t.Fatalf("a second call that could pass the cap started: %v", err)
	}
	c1.Done(500)
	c1.Done(9999) // only the first settles
	if u := m.Usage("m1"); u.Tokens != 500 {
		t.Fatalf("after settling: %+v", u)
	}
	if _, err := m.Start("m1", 100, 6000); err != nil {
		t.Fatalf("the refund did not free the cap: %v", err)
	}
}

// TestOP8ExtendCannotOverflowTheCeiling: an extension too large to add is
// refused, and the day's total never goes negative.
func TestOP8ExtendCannotOverflowTheCeiling(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: big, OverallCap: big, DailyExtension: Limits{Calls: 10, Tokens: 100}})
	must(t, m.Bind("m1", "t1", Limits{Calls: 1, Tokens: 1}))
	if err := m.Extend("t1", Limits{Calls: math.MaxInt64, Tokens: math.MaxInt64}); !errors.Is(err, ErrCeiling) {
		t.Fatalf("huge extension: %v", err)
	}
	must(t, m.Extend("t1", Limits{Calls: 10, Tokens: 100}))
	if err := m.Extend("t1", Limits{Calls: math.MaxInt64}); !errors.Is(err, ErrCeiling) {
		t.Fatalf("overflowing extension: %v", err)
	}
}

// TestOP8TaskNoticeOncePerTask: the owner is asked about an exhausted task
// once, until they extend it.
func TestOP8TaskNoticeOncePerTask(t *testing.T) {
	m, _, n := open(t, Config{MachineCap: big, OverallCap: big, DailyExtension: big})
	must(t, m.Bind("m1", "t1", Limits{Calls: 1, Tokens: 1 << 20}))
	must(t, m.Bind("m2", "t1", Limits{Calls: 1, Tokens: 1 << 20}))
	must(t, call(m, "m1", 1, 1))
	for i := 0; i < 5; i++ {
		call(m, "m1", 1, 1)
		call(m, "m2", 1, 1)
	}
	if n.count() != 1 {
		t.Fatalf("owner asked %d times", n.count())
	}
	must(t, m.Extend("t1", Limits{Calls: 1}))
	must(t, call(m, "m1", 1, 1))
	call(m, "m1", 1, 1)
	if n.count() != 2 {
		t.Fatalf("after an extension the owner was asked %d times, want 2", n.count())
	}
}

// TestOP8ConcurrentStartsCannotOvershootCalls: calls are counted at Start,
// so parallel requests cannot pass the call cap together.
func TestOP8ConcurrentStartsCannotOvershootCalls(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: Limits{Calls: 10, Tokens: 1 << 30}, OverallCap: big})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c, err := m.Start("m1", 1, 0); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
				c.Done(1)
			}
		}()
	}
	wg.Wait()
	if ok != 10 {
		t.Fatalf("%d calls admitted, cap 10", ok)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
