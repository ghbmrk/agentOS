package egress

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// REQ: CRED-8

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// inFlightRig is a proxy with a global in-flight cap of n whose provider
// holds every request open until released.
type inFlightRig struct {
	p       *Proxy
	entered chan struct{}
	block   chan struct{}
}

func newInFlightRig(t *testing.T, n int, machines int, cap Cap) *inFlightRig {
	t.Helper()
	r := newRig(t, nil)
	ir := &inFlightRig{entered: make(chan struct{}, 64), block: make(chan struct{})}
	r.provider.reply = func(w http.ResponseWriter, req *http.Request) {
		ir.entered <- struct{}{}
		<-ir.block
		io.WriteString(w, "{}")
	}
	grants := map[string][]string{}
	for i := 0; i < machines; i++ {
		grants[fmt.Sprintf("m%d", i)] = []string{"openai"}
	}
	p, err := New(Config{
		Adapters: []Adapter{OpenAI("openai-key")}, Grants: grants,
		Vault: r.vault, Audit: r.audit, Transport: r.transport, MaxInFlight: n, Cap: cap,
	})
	if err != nil {
		t.Fatal(err)
	}
	ir.p = p
	return ir
}

func (ir *inFlightRig) do(m string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	ir.p.Handler(m).ServeHTTP(w, chat("/openai/v1/chat/completions"))
	return w
}

// slots reports the global and every machine's in-flight count.
func (ir *inFlightRig) slots() (int, map[string]int) {
	ir.p.mu.Lock()
	defer ir.p.mu.Unlock()
	per := map[string]int{}
	for m, u := range ir.p.usage {
		if u.inFlight != 0 {
			per[m] = u.inFlight
		}
	}
	return ir.p.inFlight, per
}

func TestProxyGlobalInFlightCap(t *testing.T) {
	// T1: a cap of 6 held open across three machines (more than 6/4), two
	// each, so no machine is at its own cap of 4.
	const n = 6
	ir := newInFlightRig(t, n, 4, Cap{})
	done := make(chan int, n)
	for i := 0; i < n; i++ {
		m := fmt.Sprintf("m%d", i%3)
		go func() { done <- ir.do(m).Code }()
		<-ir.entered
	}
	// From here each machine may make one request in all, so a refusal
	// that charged the fresh machine m3 would leave its later request
	// refused by the request cap.
	ir.p.mu.Lock()
	ir.p.cap = Cap{Requests: 1}
	ir.p.mu.Unlock()
	w := ir.do("m3")
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "too many requests in flight") {
		t.Fatalf("request %d from a fresh machine: %d %q", n+1, w.Code, w.Body)
	}
	ir.p.mu.Lock()
	u := ir.p.usage["m3"]
	ir.p.mu.Unlock()
	if u != nil && (u.requests != 0 || u.bytes != 0 || u.inFlight != 0) {
		t.Fatalf("refused request charged m3: %+v", *u)
	}
	// One finishes; the next is admitted.
	ir.block <- struct{}{}
	if c := <-done; c != 200 {
		t.Fatalf("held request: %d", c)
	}
	next := make(chan int, 1)
	go func() { next <- ir.do("m3").Code }()
	<-ir.entered
	close(ir.block)
	if c := <-next; c != 200 {
		t.Fatalf("after a slot freed: %d", c)
	}
	for i := 1; i < n; i++ {
		if c := <-done; c != 200 {
			t.Fatalf("held request: %d", c)
		}
	}
	if g, per := ir.slots(); g != 0 || len(per) != 0 {
		t.Fatalf("slots left: global %d, machines %v", g, per)
	}
}

func TestProxyDefaultInFlightCap(t *testing.T) {
	ir := newInFlightRig(t, 0, 1, Cap{})
	if ir.p.maxTotal != DefaultMaxInFlight || DefaultMaxInFlight != 16 {
		t.Fatalf("default in-flight cap %d, constant %d", ir.p.maxTotal, DefaultMaxInFlight)
	}
}

// T2: a refused request takes no slot, and a panicking or cancelled one
// returns both of its slots.
func TestProxyInFlightSlotsReturned(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		ir := newInFlightRig(t, 2, 3, Cap{})
		done := make(chan int, 2)
		for _, m := range []string{"m0", "m1"} {
			go func() { done <- ir.do(m).Code }()
			<-ir.entered
		}
		for i := 0; i < 3; i++ {
			if c := ir.do("m2").Code; c != http.StatusTooManyRequests {
				t.Fatalf("over the cap: %d", c)
			}
		}
		if g, per := ir.slots(); g != 2 || len(per) != 2 || per["m2"] != 0 {
			t.Fatalf("after refusals: global %d, machines %v", g, per)
		}
		close(ir.block)
		<-done
		<-done
		if g, per := ir.slots(); g != 0 || len(per) != 0 {
			t.Fatalf("slots left: global %d, machines %v", g, per)
		}
	})
	t.Run("panic", func(t *testing.T) {
		r := newRig(t, nil)
		p, err := New(Config{
			Adapters: []Adapter{OpenAI("openai-key")}, Grants: map[string][]string{"m1": {"openai"}},
			Vault: r.vault, Audit: r.audit, MaxInFlight: 1,
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { panic("transport") }),
		})
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("no panic")
				}
			}()
			p.Handler("m1").ServeHTTP(httptest.NewRecorder(), chat("/openai/v1/chat/completions"))
		}()
		p.mu.Lock()
		g, m := p.inFlight, p.usage["m1"].inFlight
		p.mu.Unlock()
		if g != 0 || m != 0 {
			t.Fatalf("after a panic: global %d, machine %d", g, m)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		ir := newInFlightRig(t, 1, 2, Cap{})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			ir.p.Handler("m0").ServeHTTP(httptest.NewRecorder(), chat("/openai/v1/chat/completions").WithContext(ctx))
			close(done)
		}()
		<-ir.entered
		cancel()
		<-done
		if g, per := ir.slots(); g != 0 || len(per) != 0 {
			t.Fatalf("after a cancel: global %d, machines %v", g, per)
		}
		close(ir.block)
		if c := ir.do("m1").Code; c != 200 {
			t.Fatalf("after a cancel: %d", c)
		}
	})
}
