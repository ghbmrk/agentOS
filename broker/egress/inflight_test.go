package egress

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

// REQ: CRED-8

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// inFlightRig is a proxy with an in-flight budget of n bytes whose provider
// holds every request open until released.
type inFlightRig struct {
	p       *Proxy
	entered chan struct{}
	block   chan struct{}
}

func newInFlightRig(t *testing.T, n int64, machines int, cap Cap) *inFlightRig {
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
		Vault: r.vault, Audit: r.audit, Transport: r.transport, InFlightBytes: n, Cap: cap,
	})
	if err != nil {
		t.Fatal(err)
	}
	ir.p = p
	return ir
}

func (ir *inFlightRig) do(m string) *httptest.ResponseRecorder {
	return ir.post(m, chat("/openai/v1/chat/completions"))
}

func (ir *inFlightRig) post(m string, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	ir.p.Handler(m).ServeHTTP(w, req)
	return w
}

// slots reports the bytes reserved and every machine's in-flight count.
func (ir *inFlightRig) slots() (int64, map[string]int) {
	ir.p.mu.Lock()
	defer ir.p.mu.Unlock()
	per := map[string]int{}
	for m, u := range ir.p.usage {
		if u.inFlight != 0 {
			per[m] = u.inFlight
		}
	}
	return ir.p.reserved, per
}

// chatCost is what one chat() request holds while it is forwarded.
func chatCost(t *testing.T) int64 {
	b, err := io.ReadAll(chat("/x").Body)
	if err != nil {
		t.Fatal(err)
	}
	return bodyCost(b)
}

func chatOf(body []byte) *http.Request {
	req := chat("/openai/v1/chat/completions")
	req.Body, req.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
	return req
}

func TestProxyGlobalInFlightBudget(t *testing.T) {
	// T1: a budget of 6 chats held open across three machines, two each,
	// so no machine is at its own cap of 4.
	const n = 6
	ir := newInFlightRig(t, n*chatCost(t), 4, Cap{})
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
		t.Fatalf("slots left: reserved %d, machines %v", g, per)
	}
}

func TestProxyDefaultInFlightBudget(t *testing.T) {
	ir := newInFlightRig(t, 0, 1, Cap{})
	if ir.p.budget != DefaultInFlightBytes || DefaultInFlightBytes != 320<<20 {
		t.Fatalf("default in-flight budget %d, constant %d", ir.p.budget, DefaultInFlightBytes)
	}
	// A maximal body of plain or non-ASCII text, as an owner's long prompt
	// is, must fit the default budget on its own.
	for name, text := range map[string]string{"ascii": "a", "cjk": "\u6f22"} {
		body := bytes.Repeat([]byte(text), DefaultMaxBody/len(text))
		if c := bodyCost(body); c > DefaultInFlightBytes {
			t.Errorf("a maximal %s body costs %d, over the budget", name, c)
		}
	}
}

// T3: a request holds what its body costs, not one count: a body that is
// costly to check is refused outright, one the remaining budget cannot hold
// waits for room, and a long string is cheap.
func TestProxyBudgetFollowsBodyCost(t *testing.T) {
	str := []byte(`{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("a", 1<<20) + `"}]}`)
	objs := []byte(`{"model":"m","messages":[` + strings.Repeat(`{"":0},`, 120<<10/7) + `{}]}`)
	if len(objs) > len(str)/8 || bodyCost(objs) <= bodyCost(str) {
		t.Fatalf("objects: %d bytes cost %d; string: %d bytes cost %d", len(objs), bodyCost(objs), len(str), bodyCost(str))
	}
	t.Run("too costly", func(t *testing.T) {
		ir := newInFlightRig(t, bodyCost(objs)-1, 1, Cap{})
		close(ir.block)
		w := ir.post("m0", chatOf(objs))
		if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), "body too costly to check") {
			t.Fatalf("costly body: %d %q", w.Code, w.Body)
		}
		if c := ir.post("m0", chatOf(str)).Code; c != 200 {
			t.Fatalf("string body under the same budget: %d", c)
		}
		if g, per := ir.slots(); g != 0 || len(per) != 0 {
			t.Fatalf("slots left: reserved %d, machines %v", g, per)
		}
	})
	t.Run("waits for room", func(t *testing.T) {
		// Room for the string's read but not its check while a chat is
		// held: refused as a retry, then admitted once the chat ends.
		ir := newInFlightRig(t, chatCost(t)+bodyCost(str)-1, 2, Cap{})
		if readCost(int64(len(str))) > bodyCost(str)-1 {
			t.Fatal("rig: the read alone would not fit")
		}
		done := make(chan int, 1)
		go func() { done <- ir.do("m0").Code }()
		<-ir.entered
		w := ir.post("m1", chatOf(str))
		if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "too many requests in flight") {
			t.Fatalf("string body with a chat held: %d %q", w.Code, w.Body)
		}
		if g, per := ir.slots(); g != chatCost(t) || len(per) != 1 {
			t.Fatalf("after the refusal: reserved %d, machines %v", g, per)
		}
		close(ir.block)
		<-done
		if c := ir.post("m1", chatOf(str)).Code; c != 200 {
			t.Fatalf("after the chat ended: %d", c)
		}
		if g, per := ir.slots(); g != 0 || len(per) != 0 {
			t.Fatalf("slots left: reserved %d, machines %v", g, per)
		}
	})
}

// T4: bodyCost bounds what BodyRule.apply allocates for the body shapes
// that decode to the most memory per byte, so the budget holds for a
// hostile body (egress K18). Everything apply allocates is counted, live
// or not, so the bound is above apply's peak.
func TestBodyCostBoundsApply(t *testing.T) {
	op, ok := OpenAI("openai-key").match("POST", "/v1/chat/completions")
	if !ok || op.Body == nil {
		t.Fatal("no checked chat operation")
	}
	const size = 1 << 20
	array := func(elem string) []byte {
		var b strings.Builder
		b.WriteString(`{"model":"m","a":[`)
		for b.Len() < size {
			b.WriteString(elem + ",")
		}
		b.WriteString(elem + "]}")
		return []byte(b.String())
	}
	var uniq strings.Builder
	uniq.WriteString(`{"model":"m"`)
	for i := 0; uniq.Len() < size; i++ {
		fmt.Fprintf(&uniq, `,"%x":0`, i)
	}
	uniq.WriteString("}")
	depth := 9990 // under encoding/json's nesting limit of 10000
	shapes := map[string][]byte{
		"unique keys":  []byte(uniq.String()),
		"nested":       []byte(strings.Repeat(`{"a":`, depth) + "0" + strings.Repeat("}", depth)),
		"deep arrays":  []byte(`{"model":"m","a":` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + "}"),
		"deep mixed":   []byte(`{"model":"m","a":` + strings.Repeat(`[{"a":`, depth/2) + "0" + strings.Repeat("}]", depth/2) + "}"),
		"cjk":          array(`"` + strings.Repeat("\u6f22", 1365) + `"`),
		"string":       array(`"` + strings.Repeat("a", 4096) + `"`),
		"invalid utf8": array(`"` + strings.Repeat("\xff", 4096) + `"`),
		"u2028":        array(`"` + strings.Repeat("\u2028", 1365) + `"`),
	}
	for _, e := range []string{`0`, `{}`, `[]`, `""`, `null`, `[0]`, `[{}]`, `{"":0}`, `{"":{}}`, `{"":[]}`,
		`{"a":0,"b":0}`, `{"a":0,"b":0,"c":0,"d":0,"e":0,"f":0,"g":0,"h":0,"i":0}`, `"\u0000"`, `1e9`} {
		shapes[e] = array(e)
	}
	var worst float64
	for name, body := range shapes {
		// A fresh goroutine starts on a small stack, so what its stack
		// grows to while apply recurses is counted with the heap.
		var heap, stack int64
		var err error
		done := make(chan struct{})
		go func() {
			defer close(done)
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			var out []byte
			out, err = op.Body.apply(body, false)
			runtime.ReadMemStats(&after)
			runtime.KeepAlive(out)
			heap = int64(after.TotalAlloc - before.TotalAlloc)
			stack = int64(after.StackInuse) - int64(before.StackInuse)
		}()
		<-done
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		peak := int64(len(body)) + heap + max(stack, 0)
		c := bodyCost(body)
		if peak > c {
			t.Errorf("%s: %d bytes allocate %d, over bodyCost %d", name, len(body), peak, c)
		}
		if r := float64(peak) / float64(c); r > worst {
			worst = r
		}
		t.Logf("%-14.14s %8d bytes: %6.1fx (stack %d KiB), %3.0f%% of bodyCost", name, len(body), float64(peak)/float64(len(body)), stack>>10, 100*float64(peak)/float64(c))
	}
	t.Logf("tightest shape uses %.0f%% of its bodyCost", 100*worst)
}

// T2: a refused request takes no slot, and a panicking or cancelled one
// returns both of its slots.
func TestProxyInFlightSlotsReturned(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		ir := newInFlightRig(t, 2*chatCost(t), 3, Cap{})
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
		if g, per := ir.slots(); g != 2*chatCost(t) || len(per) != 2 || per["m2"] != 0 {
			t.Fatalf("after refusals: reserved %d, machines %v", g, per)
		}
		close(ir.block)
		<-done
		<-done
		if g, per := ir.slots(); g != 0 || len(per) != 0 {
			t.Fatalf("slots left: reserved %d, machines %v", g, per)
		}
	})
	t.Run("panic", func(t *testing.T) {
		r := newRig(t, nil)
		p, err := New(Config{
			Adapters: []Adapter{OpenAI("openai-key")}, Grants: map[string][]string{"m1": {"openai"}},
			Vault: r.vault, Audit: r.audit, InFlightBytes: chatCost(t),
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
		g, m := p.reserved, p.usage["m1"].inFlight
		p.mu.Unlock()
		if g != 0 || m != 0 {
			t.Fatalf("after a panic: reserved %d, machine %d", g, m)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		ir := newInFlightRig(t, chatCost(t), 2, Cap{})
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
			t.Fatalf("after a cancel: reserved %d, machines %v", g, per)
		}
		close(ir.block)
		if c := ir.do("m1").Code; c != 200 {
			t.Fatalf("after a cancel: %d", c)
		}
	})
}
