package meter

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// REQ: CRED-1
// SPEC v0.12 IDs (PR #15; move into REQ when it merges): OP-8, ARC-7

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
	c, err := m.Start(machine, in)
	if err != nil {
		return err
	}
	c.Done(out)
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
// CRED-1, ARC-7), counts request and response bytes it saw, and on
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
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, strings.Repeat("data: x\n\n", 100))
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
		if w.Code != 200 {
			t.Fatalf("call %d: %d", i, w.Code)
		}
	}
	if u := m.Usage("m1"); u.Calls != 2 || u.Tokens < 2*(900/4) {
		t.Fatalf("m1 usage %+v", u)
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
			if c, err := m.Start("m1", 1); err == nil {
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
