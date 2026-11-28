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
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/routerule"
)

// REQ: REV-5, OP-8, ARC-7, A14, RES-5

// Tests that pin what the vault process's clients do on each answer, so a
// changed line in them fails a test (mutgate, #6638). Each client's
// transport is swapped for replySpy where the answer matters; a socket
// nothing serves stands for a vault process that is down.

// replySpy answers every request with status and body, records the last
// request and its deadline, and records whether the body was closed.
type replySpy struct {
	mu       sync.Mutex
	status   int
	body     string
	req      *http.Request
	deadline time.Time
	closed   bool
}

func (s *replySpy) RoundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.req = r
	s.deadline, _ = r.Context().Deadline()
	s.closed = false
	return &http.Response{StatusCode: s.status, Status: http.StatusText(s.status), Header: http.Header{},
		Body: closeFlag{strings.NewReader(s.body), s}, Request: r}, nil
}

func (s *replySpy) wasClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

type closeFlag struct {
	io.Reader
	s *replySpy
}

func (c closeFlag) Close() error {
	c.s.mu.Lock()
	c.s.closed = true
	c.s.mu.Unlock()
	return nil
}

func absentSock(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.sock") }

// nilCtx returns a nil context, which http.NewRequestWithContext refuses.
func nilCtx() context.Context { return nil }

func isDialErr(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}

// A public machine is labelled public to the vault process (REV-5).
func TestREV5PublicMachineIsSentAsPublic(t *testing.T) {
	fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {}}
	fwd := Forward(Config{Socket: serveUnix(t, fe), Label: func(string) string { return "public" }, Denied: func(string, Denial) {}})
	fwd("m1").ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/openai/v1/chat/completions", nil))
	if l := fe.seen[0].Header.Get(HeaderLabel); l != "public" {
		t.Fatalf("label %q, want public", l)
	}
}

// A denial reaches the journal naming the machine the broker forwarded
// for, never the one the vault process wrote into it.
func TestDenialCarriesTheForwardedMachine(t *testing.T) {
	fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(Denial{Method: r.Method, Status: 403, Reason: "no", Machine: "someone-else"})
		w.Header().Set(HeaderDenial, string(b))
		w.WriteHeader(403)
	}}
	d := &denials{}
	fwd := Forward(Config{Socket: serveUnix(t, fe), Label: func(string) string { return "private" }, Denied: d.add})
	fwd("m1").ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/models", nil))
	if len(d.ds) != 1 || d.ds[0].Machine != "m1" {
		t.Fatalf("journaled %+v, want machine m1", d.ds)
	}
}

// A vault process that is down is logged.
func TestVaultProcessDownIsLogged(t *testing.T) {
	var mu sync.Mutex
	var logged []string
	logf := func(f string, a ...any) {
		mu.Lock()
		logged = append(logged, f)
		mu.Unlock()
	}
	fwd := Forward(Config{Socket: absentSock(t), Label: func(string) string { return "public" }, Denied: func(string, Denial) {}, Logf: logf})
	fwd("m1").ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`)))
	mu.Lock()
	defer mu.Unlock()
	if len(logged) != 1 || !strings.Contains(logged[0], "vault process") {
		t.Fatalf("logged %q", logged)
	}
}

// resetUnix serves a socket that takes the first byte of each request and
// then closes with the rest unread, so the broker's read of the answer
// fails with a connection reset: a non-dial *net.OpError after connecting.
func resetUnix(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "reset.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var b [1]byte
			c.Read(b[:])
			time.Sleep(50 * time.Millisecond) // the rest of the request lands unread
			c.Close()
		}
	}()
	return sock
}

// OP-8: a call that connected and then failed with a network error other
// than dialing may have reached a provider, so it is charged as
// unanswered (input, output reservation and every allowed attempt), not
// as a call that never left the broker (input only).
func TestOP8ResetAfterConnectingIsChargedAsUnanswered(t *testing.T) {
	fwd := Forward(Config{Socket: resetUnix(t), Label: func(string) string { return "public" }, Denied: func(string, Denial) {}})
	m := attemptsMeter(t, 1<<30)
	w := httptest.NewRecorder()
	m.Wrap("m1", fwd("m1")).ServeHTTP(w, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(attemptsBody)))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", w.Code)
	}
	in := estimate(int64(len(attemptsBody)))
	if u := m.Usage("m1"); u.Tokens <= in {
		t.Fatalf("charged %d tokens, want more than the input estimate %d", u.Tokens, in)
	}
}

// A count of exactly 1e12 is in range; one more is refused.
func TestOP8UsageCountBoundIsInclusive(t *testing.T) {
	if !(Usage{Input: 1e12}).valid(0) {
		t.Fatal("input 1e12 refused")
	}
	if (Usage{Input: 1e12 + 1}).valid(0) {
		t.Fatal("input 1e12+1 accepted")
	}
}

// SetupAPIKey waits SetupAPIKeyTimeout, longer than the verifier's own
// bound, so a provider's slow key check is not cut off; it sends JSON and
// closes the answer.
func TestSetupAPIKeyCallBoundAndShape(t *testing.T) {
	v := NewVerifier(absentSock(t))
	spy := &replySpy{status: 200, body: `{}`}
	v.c.Transport = spy
	start := time.Now()
	if err := v.SetupAPIKey("openai", "sk-synthetic-canary"); err != nil {
		t.Fatal(err)
	}
	if left := spy.deadline.Sub(start); left < SetupAPIKeyTimeout-time.Second || left > SetupAPIKeyTimeout+time.Second {
		t.Fatalf("key call bound %v, want %v", left, SetupAPIKeyTimeout)
	}
	if ct := spy.req.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q", ct)
	}
	if !spy.wasClosed() {
		t.Fatal("answer left open")
	}
}

// A refused key and an unchecked one are told apart; a vault process
// that is down is an error, not a panic.
func TestSetupAPIKeyMapsRefusedAndUnchecked(t *testing.T) {
	v := NewVerifier(absentSock(t))
	if err := v.SetupAPIKey("openai", "sk-synthetic-canary"); !isDialErr(err) {
		t.Fatalf("down: %v", err)
	}
	spy := &replySpy{}
	v.c.Transport = spy
	for st, want := range map[int]error{403: ErrKeyRefused, 502: ErrKeyUnchecked} {
		spy.status = st
		if err := v.SetupAPIKey("openai", "sk-synthetic-canary"); err != want {
			t.Fatalf("%d: %v, want %v", st, err, want)
		}
	}
}

// The routing client is bounded at 5 seconds, reads only a 200, reads a
// full-size answer, closes it, and refuses a nil context.
func TestRoutingStateAnswers(t *testing.T) {
	r := NewRouting(absentSock(t))
	if r.c.Timeout != 5*time.Second {
		t.Fatalf("routing timeout %v", r.c.Timeout)
	}
	if _, err := r.State(context.Background()); !isDialErr(err) {
		t.Fatalf("down: %v", err)
	}
	if _, err := r.State(nilCtx()); err == nil {
		t.Fatal("nil context accepted")
	}
	long := routerule.Rule{}
	for i := 0; i < 8; i++ {
		long["class-"+strings.Repeat("c", i+1)] = []routerule.Route{{Provider: "openai", Model: "gpt-synthetic"}}
	}
	b, err := json.Marshal(RoutingState{Rule: long, Owner: long})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) <= 128 {
		t.Fatalf("state of %d bytes is not long enough to test the bound", len(b))
	}
	spy := &replySpy{status: 200, body: string(b)}
	r.c.Transport = spy
	st, err := r.State(context.Background())
	if err != nil || len(st.Rule) != len(long) {
		t.Fatalf("state %v, %v", st, err)
	}
	if !spy.wasClosed() {
		t.Fatal("answer left open")
	}
	spy.status = 500
	if _, err := r.State(context.Background()); err == nil {
		t.Fatal("a 500 with a well-formed body was read")
	}
	// Three rules of MaxRule bytes each, the most the vault process sends,
	// are read in full.
	full := func(n int) RoutingState {
		r := routerule.Rule{"c": {{Provider: "p", Model: strings.Repeat("m", n)}}}
		return RoutingState{Rule: r, Candidate: r, Owner: r}
	}
	b, _ = json.Marshal(full(0))
	b, _ = json.Marshal(full((3*MaxRule - len(b)) / 3))
	if len(b) <= 3*MaxRule-64 || len(b) > 3*MaxRule {
		t.Fatalf("full state is %d bytes", len(b))
	}
	spy.status, spy.body = 200, string(b)
	if _, err := r.State(context.Background()); err != nil {
		t.Fatalf("a full state of %d bytes: %v", len(b), err)
	}
}

// A failed read leaves the count unknown, whatever the reader also
// returned, and its bound is released when the read ends.
func TestSR3_7f2FailedReadIsUnknown(t *testing.T) {
	var s Spare
	s.Observe(routes(2))
	var got context.Context
	s.refresh(context.Background(), func(ctx context.Context) (RoutingState, error) {
		got = ctx
		return RoutingState{Owner: routes(3)}, errors.New("read failed")
	})
	if n := s.Retries(); n != -1 {
		t.Fatalf("retries %d after a failed read, want -1", n)
	}
	if got.Err() == nil {
		t.Fatal("read's bound not released")
	}
}

// Run returns once its context ends.
func TestSR3_7f2RunStopsWithItsContext(t *testing.T) {
	var s Spare
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		s.Run(ctx, func(context.Context) (RoutingState, error) { return RoutingState{}, errors.New("x") }, time.Hour)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
}

// The state probe gives up on a vault process that never answers, and
// refuses a nil context as the zero state.
func TestStateProbeGivesUpOnAHungVaultProcess(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "hung.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	probe := NewStateProbe(sock)
	if st := probe(nilCtx()); st != (ModelState{}) {
		t.Fatalf("nil context: %+v", st)
	}
	done := make(chan ModelState, 1)
	go func() { done <- probe(context.Background()) }()
	select {
	case st := <-done:
		if st != (ModelState{}) {
			t.Fatalf("hung: %+v", st)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("probe still waiting on a hung vault process")
	}
}

// The state probe closes its answer: a vault process whose answer runs
// past what the probe reads is not left blocked writing it.
func TestStateProbeClosesTheAnswer(t *testing.T) {
	finished := make(chan struct{})
	sock := serveUnix(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(finished)
		w.WriteHeader(200)
		io.WriteString(w, `{"granted":true}`)
		pad := []byte(strings.Repeat(" ", 64<<10))
		for i := 0; i < 256; i++ { // 16 MiB, past any socket buffer
			if _, err := w.Write(pad); err != nil {
				return
			}
		}
	}))
	if st := NewStateProbe(sock)(context.Background()); !st.Reachable {
		t.Fatalf("state %+v", st)
	}
	select {
	case <-finished:
	case <-time.After(time.Second): // under the probe's own 2 s bound, which would close it too
		t.Fatal("the vault process is still writing: the probe left the answer open")
	}
}

// A vault process that is down is VerifyDown, not VerifyLost: nothing was
// sent, so no code was spent.
func TestVerifyTOTPDownIsDown(t *testing.T) {
	_, _, err := NewVerifier(absentSock(t)).VerifyTOTP("123456", 0, true)
	var ve *VerifyError
	if !errors.As(err, &ve) || ve.Kind != VerifyDown {
		t.Fatalf("got %v, want VerifyDown", err)
	}
}

// The enrolment, second-line and texts calls each fail cleanly on a
// vault process that is down, map a 503 to ErrVaultLocked, close their
// answers, and refuse a nil context.
func TestVerifierCallsMapDownLockedAndClose(t *testing.T) {
	calls := map[string]func(v *Verifier, ctx context.Context) error{
		"confirm": func(v *Verifier, _ context.Context) error { _, err := v.ConfirmEnroll("123456"); return err },
		"second":  func(v *Verifier, ctx context.Context) error { _, err := v.SecondLine(ctx); return err },
		"texts":   func(v *Verifier, ctx context.Context) error { _, err := v.SecondLineTexts(ctx); return err },
	}
	okBody := map[string]string{"confirm": `{"ok":true,"step":1}`, "second": `{"state":""}`, "texts": `{"texts":""}`}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			v := NewVerifier(absentSock(t))
			if err := call(v, context.Background()); !isDialErr(err) {
				t.Fatalf("down: %v", err)
			}
			spy := &replySpy{status: 503}
			v.c.Transport = spy
			if err := call(v, context.Background()); err != ErrVaultLocked {
				t.Fatalf("503: %v", err)
			}
			if !spy.wasClosed() {
				t.Fatal("503 answer left open")
			}
			spy.status, spy.body = 200, okBody[name]
			if err := call(v, context.Background()); err != nil {
				t.Fatal(err)
			}
			if !spy.wasClosed() {
				t.Fatal("answer left open")
			}
			if name != "confirm" {
				if err := call(v, nilCtx()); err == nil {
					t.Fatal("nil context accepted")
				}
			}
		})
	}
}

// Plan usage fails cleanly on a vault process that is down, reads only a
// 200, and closes the answer.
func TestRES5UsageAnswers(t *testing.T) {
	c := NewRouteControl(absentSock(t))
	if _, err := c.Usage("openai"); !isDialErr(err) {
		t.Fatalf("down: %v", err)
	}
	spy := &replySpy{status: 200, body: `{"Pools":[]}`}
	c.c.Transport = spy
	if _, err := c.Usage("openai"); err != nil {
		t.Fatal(err)
	}
	if !spy.wasClosed() {
		t.Fatal("answer left open")
	}
	spy.status = 500
	if _, err := c.Usage("openai"); err == nil {
		t.Fatal("a 500 with a well-formed body was read")
	}
}

// Close closes the vault process's answer, and is quiet when it is down.
func TestA14CloseClosesTheAnswer(t *testing.T) {
	c := NewRouteControl(absentSock(t))
	c.Close("pw-a")
	spy := &replySpy{status: 200}
	c.c.Transport = spy
	c.Close("pw-a")
	if !spy.wasClosed() {
		t.Fatal("answer left open")
	}
}

// SignInStored passes on the route control's own error, and an unreadable
// reply is an error, never "not stored".
func TestCRED5SignInStoredErrors(t *testing.T) {
	c := NewRouteControl(absentSock(t))
	if _, err := c.SignInStored("pw-a"); !isDialErr(err) {
		t.Fatalf("down: %v", err)
	}
	c.c.Transport = &replySpy{status: 200, body: "not json"}
	if stored, err := c.SignInStored("pw-a"); err == nil || stored {
		t.Fatalf("unreadable reply: %v, %v", stored, err)
	}
}
