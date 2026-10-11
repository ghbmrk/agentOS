package modelroute

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/routerule"
)

// REQ: OP-8, ARC-7 (SR3-7-f2a, SR3-7-f2b, SR3-7-f2c)

// routes is a rule whose classes have the given numbers of routes.
func routes(counts ...int) routerule.Rule {
	r := routerule.Rule{}
	for i, n := range counts {
		var rs []routerule.Route
		for j := 0; j < n; j++ {
			rs = append(rs, routerule.Route{Provider: string(rune('a' + j)), Model: "m"})
		}
		r[string(rune('p'+i))] = rs
	}
	return r
}

// preholdCall sends one call for m1 through Forward with cfg's source,
// metered by m, and returns the allowance the vault process saw and the
// machine's tokens held while it was in flight. During, if set, runs
// while the call is in flight.
func preholdCall(t *testing.T, m *meter.Meter, retries func() int, reply string, during func()) (string, int64) {
	t.Helper()
	var got []string
	var held int64
	fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Values(HeaderAttempts)
		held = m.Usage("m1").Tokens
		if during != nil {
			during()
		}
		if reply == "" {
			io.WriteString(w, "{}")
			return
		}
		w.Header().Set("Trailer", HeaderUsage)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(502)
		io.WriteString(w, `{"error":{"message":"x"}}`)
		w.Header().Set(HeaderUsage, reply)
	}}
	fwd := Forward(Config{Socket: serveUnix(t, fe), Label: func(string) string { return "public" }, Denied: func(string, Denial) {}, Retries: retries})
	m.Wrap("m1", fwd("m1")).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(attemptsBody)))
	if len(got) != 1 {
		t.Fatalf("vault process saw allowance %q", got)
	}
	return got[0], held
}

func fixed(n int) func() int { return func() int { return n } }

// TestSR3_7f2aHoldsOnlyWhatTheRuleCanSpend: with two routes per class in
// the owner's rule the call can fail over once, so it holds one attempt
// past the first and says so.
func TestSR3_7f2aHoldsOnlyWhatTheRuleCanSpend(t *testing.T) {
	var s Spare
	s.Observe(routes(2, 2))
	got, held := preholdCall(t, attemptsMeter(t, 1<<30), s.Retries, "", nil)
	if got != "1" || held != 2*attemptWorst {
		t.Errorf("allowance %q holding %d tokens, want \"1\" holding %d (one extra hold)", got, held, 2*attemptWorst)
	}
}

// TestSR3_7f2aCapLeavesRoomForAnotherCall: holds a two-route rule can
// never spend do not refuse a concurrent call near the machine's cap,
// and no owner exhaustion notice goes out.
func TestSR3_7f2aCapLeavesRoomForAnotherCall(t *testing.T) {
	var notices []meter.Exhausted
	m, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"),
		MachineCap: meter.Limits{Calls: 10, Tokens: 3 * attemptWorst}, OverallCap: meter.Limits{Calls: 10, Tokens: 1 << 30},
		Notify: func(e meter.Exhausted) { notices = append(notices, e) }})
	if err != nil {
		t.Fatal(err)
	}
	var second error
	preholdCall(t, m, fixed(1), "", func() {
		var c *meter.Call
		if c, second = m.Start("m1", attemptWorst-100, 100); c != nil {
			c.Done(0)
		}
	})
	if second != nil || len(notices) != 0 {
		t.Errorf("a concurrent Start got %v with %d owner notices, want it admitted and none", second, len(notices))
	}
}

// TestSR3_7f2aOneRouteHoldsNothing: a single-route rule cannot fail over,
// so nothing past the first attempt is held; a failed answer is charged
// once, and a trailer claiming a retry is not believed.
func TestSR3_7f2aOneRouteHoldsNothing(t *testing.T) {
	var s Spare
	s.Observe(routes(1))
	for _, c := range []struct{ name, trailer string }{
		{"one failed attempt", `{"provider":"","unserved":true,"failed":[{"provider":"a","status":502,"full":true}]}`},
		{"a retry claimed", `{"provider":"","unserved":true,"failed":[{"provider":"a","status":502,"full":true},{"provider":"a","status":502,"full":true}]}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := attemptsMeter(t, 1<<30)
			got, held := preholdCall(t, m, s.Retries, c.trailer, nil)
			if got != "0" || held != attemptWorst {
				t.Errorf("allowance %q holding %d tokens, want \"0\" holding %d", got, held, attemptWorst)
			}
			if u := m.Usage("m1"); u.Tokens != attemptWorst || u.Calls != 1 {
				t.Errorf("charged %d tokens and %d calls, want %d and 1", u.Tokens, u.Calls, attemptWorst)
			}
		})
	}
}

// TestSR3_7f2bUnknownIsMaxRetries is a control: no source, a source that
// has read nothing, or one whose last read failed holds MaxRetries, as
// before SR3-7-f2; so does a count above it.
func TestSR3_7f2bUnknownIsMaxRetries(t *testing.T) {
	failed := &Spare{}
	failed.Observe(routes(2))
	failed.refresh(context.Background(), func(context.Context) (RoutingState, error) { return RoutingState{}, errors.New("down") })
	empty := &Spare{}
	empty.Observe(routerule.Rule{})
	many := &Spare{}
	many.Observe(routes(2, 9))
	for _, c := range []struct {
		name    string
		retries func() int
		want    string
	}{
		{"nil source", nil, "3"},
		{"nothing read", (&Spare{}).Retries, "3"},
		{"read failed", failed.Retries, "3"},
		{"empty owner rule", empty.Retries, "3"},
		{"negative", fixed(-1), "3"},
		{"over MaxRetries", many.Retries, "3"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got, _ := preholdCall(t, attemptsMeter(t, 1<<30), c.retries, "", nil); got != c.want {
				t.Errorf("allowance %q, want %q", got, c.want)
			}
		})
	}
}

// TestSR3_7f2cOwnerRuleChangeIsReadOffThePath: the owner's rule goes from
// two routes to four on the routing socket, as W3-route-a sees it; the
// next call after Spare's refresh holds 3, and no call reads the routing
// socket.
func TestSR3_7f2cOwnerRuleChangeIsReadOffThePath(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "routing.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	owner := routes(2, 2)
	var reads atomic.Int64
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		mu.Lock()
		defer mu.Unlock()
		json.NewEncoder(w).Encode(RoutingState{Rule: owner, Owner: owner})
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	var s Spare
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx, NewRouting(sock).State, 10*time.Millisecond)
	wait := func(want int) {
		t.Helper()
		for end := time.Now().Add(5 * time.Second); s.Retries() != want; time.Sleep(time.Millisecond) {
			if time.Now().After(end) {
				t.Fatalf("Spare reads %d, want %d", s.Retries(), want)
			}
		}
	}
	call := func() string {
		var during int64
		got, _ := preholdCall(t, attemptsMeter(t, 1<<30), func() int {
			n := reads.Load()
			r := s.Retries()
			during += reads.Load() - n
			return r
		}, "", nil)
		if during != 0 {
			t.Errorf("the call read the routing socket %d times", during)
		}
		return got
	}
	wait(1)
	if got := call(); got != "1" {
		t.Errorf("two routes: allowance %q, want \"1\"", got)
	}
	mu.Lock()
	owner = routes(4, 2)
	mu.Unlock()
	wait(3)
	if got := call(); got != "3" {
		t.Errorf("four routes: allowance %q, want \"3\"", got)
	}
}
