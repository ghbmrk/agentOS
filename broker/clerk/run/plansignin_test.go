package run

// REQ: CLK-7, PLN-5, CLK-4, CLK-1

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/plan"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// fakeCLI is the guest host's sign-in sandbox: it asks its endpoint for a
// user code as the CLI does, prints what the test sets, and its code
// exchange is the test's.
type fakeCLI struct {
	login   *plan.Login
	mu      sync.Mutex
	printed string
	exited  bool
	starts  int
	plan    string
	guest   string
	stopped chan struct{}
	err     error
}

func newFakeCLI(login *plan.Login, printed string) *fakeCLI {
	return &fakeCLI{login: login, printed: printed, stopped: make(chan struct{})}
}

func (f *fakeCLI) Start(_ context.Context, planName, guest string) (SignInWorker, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	f.plan, f.guest = planName, guest
	if f.err != nil {
		return nil, f.err
	}
	if f.login != nil {
		serve(PlanGuest{Login: f.login, Guest: guest}, usercodeRequest())
	}
	return f, nil
}

// usercodeRequest is the CLI's device step that gets its user code.
func usercodeRequest() *http.Request {
	r := httptest.NewRequest("POST", "http://127.0.0.1:18432/api/accounts/deviceauth/usercode", strings.NewReader(`{"client_id":"app_x"}`))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func (f *fakeCLI) Read(context.Context) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.printed, f.exited
}

func (f *fakeCLI) Stop() { close(f.stopped) }

func (f *fakeCLI) exit() {
	f.mu.Lock()
	f.exited = true
	f.mu.Unlock()
}

func (f *fakeCLI) started() (int, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts, f.guest
}

func (f *fakeCLI) waitStopped(t *testing.T) {
	t.Helper()
	select {
	case <-f.stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the sign-in sandbox was not destroyed")
	}
}

const codexPrinted = "Welcome to Codex\n\x1b[94mhttp://127.0.0.1:18432/codex/device\x1b[0m\nEnter this one-time code \x1b[94mABCD-12345\x1b[0m\n"

var quick = SignInTimes{Poll: time.Millisecond, Link: 200 * time.Millisecond, Wall: 5 * time.Second}

// tokenProvider answers the code exchange with a login, a refresh with
// refresh(), and the models read with 200, counting every request.
func tokenProvider(calls *atomic.Int32, refresh func() map[string]any) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/oauth/token" && strings.Contains(string(body), "refresh_token\"") && refresh != nil:
			json.NewEncoder(w).Encode(refresh())
		case r.URL.Path == "/oauth/token":
			json.NewEncoder(w).Encode(map[string]any{"access_token": "real-access-1", "refresh_token": "real-refresh-1", "id_token": fakeJWT("acct-1")})
		case r.URL.Path == "/api/accounts/deviceauth/usercode":
			io.WriteString(w, `{"device_auth_id":"dev-1","user_code":"ABCD-12345","interval":"5"}`)
		case r.URL.Path == "/backend-api/codex/models":
			io.WriteString(w, `{"models":[]}`)
		default:
			w.WriteHeader(404)
		}
	})
}

func until(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// serve answers one guest request at its endpoint.
func serve(g PlanGuest, r *http.Request) (int, string) {
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, r)
	return rec.Code, rec.Body.String()
}

func modelsRead(ph string) *http.Request {
	r := httptest.NewRequest("GET", "http://127.0.0.1:18432/backend-api/codex/models?client_version=0.162.1", nil)
	r.Header.Set("Authorization", "Bearer "+ph)
	return r
}

// Use my plan (§12.1 step 6): the owner is shown the provider's own page,
// never the link the CLI printed, and the code the CLI printed, labelled
// with whom it is from. The CLI signs in through its own endpoint as the
// sign-in guest; the login it commits is the clerk's, the sandbox is then
// destroyed and the guest forgotten (PLN-5, CLK-7).
func TestPlanSignInShowsTheProvidersPageAndCode(t *testing.T) {
	var calls atomic.Int32
	login, _ := planLoginAt(t, plan.Permitted, tokenProvider(&calls, nil))
	cli := newFakeCLI(login, codexPrinted)
	h := &PlanHost{Login: login, Prompt: CodexSignIn(), Workers: cli, Times: quick}

	b := h.Begin(context.Background())
	if b != (PlanBegun{Page: "https://auth.openai.com/codex/device", Code: "ABCD-12345", From: "OpenAI"}) {
		t.Fatalf("begun: %+v", b)
	}
	st := h.State()
	if !st.Signing || st.Page != b.Page || st.Code != b.Code || st.From != "OpenAI" || st.SignedIn || st.Mode != plan.Permitted {
		t.Fatalf("while signing: %+v", st)
	}
	_, guest := cli.started()
	if code, body := serve(PlanGuest{Login: login, Guest: guest}, codeRequest()); code != 200 || strings.Contains(body, "real-") {
		t.Fatalf("the CLI's code exchange: %d %q", code, body)
	}
	cli.waitStopped(t)
	until(t, "the sign-in to end", func() bool { return h.State().Last != "" })
	if st := h.State(); !reflect.DeepEqual(bare(st), PlanState{Mode: plan.Permitted, SignedIn: true, Last: DSignedIn}) {
		t.Fatalf("after the sign-in: %+v", st)
	}
	if login.Signing(guest) {
		t.Fatal("the sign-in guest was not forgotten")
	}
	if _, err := login.Guest("run"); err != nil {
		t.Fatalf("a run guest after the sign-in: %v", err)
	}
}

// Success is the clerk's own record that this sign-in's code exchange
// committed the login. A login stored before, a CLI that exits, prints an
// undeclared link or no code, or is not approved in time does not sign in,
// and its sandbox is destroyed on every path. One sign-in waits at a time
// (CLK-7).
func TestPlanSignInSucceedsOnlyByTheClerksRecord(t *testing.T) {
	var calls atomic.Int32
	login, _ := planLoginAt(t, plan.Permitted, tokenProvider(&calls, nil))
	codeExchange(t, login, "earlier")
	login.Forget("earlier")

	t.Run("the CLI exits", func(t *testing.T) {
		cli := newFakeCLI(login, codexPrinted)
		h := &PlanHost{Login: login, Prompt: CodexSignIn(), Workers: cli, Times: quick}
		if b := h.Begin(context.Background()); b.Code == "" {
			t.Fatalf("begun: %+v", b)
		}
		if b := h.Begin(context.Background()); b.Detail != DSignInBusy {
			t.Fatalf("a second sign-in: %+v", b)
		}
		if n, _ := cli.started(); n != 1 {
			t.Fatalf("%d sandboxes started", n)
		}
		cli.exit()
		cli.waitStopped(t)
		until(t, "the sign-in to end", func() bool { return h.State().Last != "" })
		if st := h.State(); st.Last != DSignInFailed || st.Signing || !st.SignedIn {
			t.Fatalf("after the exit: %+v", st)
		}
	})
	t.Run("not approved in time", func(t *testing.T) {
		cli := newFakeCLI(login, codexPrinted)
		times := quick
		times.Wall = 20 * time.Millisecond
		h := &PlanHost{Login: login, Prompt: CodexSignIn(), Workers: cli, Times: times}
		if b := h.Begin(context.Background()); b.Code == "" {
			t.Fatalf("begun: %+v", b)
		}
		cli.waitStopped(t)
		until(t, "the sign-in to end", func() bool { return h.State().Last != "" })
		if st := h.State(); st.Last != DSignInTimedOut {
			t.Fatalf("after the wall: %+v", st)
		}
	})
	for name, c := range map[string]struct {
		printed string
		exited  bool
		err     error
		want    string
	}{
		"an undeclared link":         {printed: "https://auth.example.net/codex/device ABCD-12345", want: DSignInTimedOut},
		"no code":                    {printed: "http://127.0.0.1:18432/codex/device enter abc", want: DSignInTimedOut},
		"an exit before a code":      {printed: "error", exited: true, want: DSignInFailed},
		"a sandbox that won't start": {err: errors.New("no image"), want: DSignInFailed},
	} {
		t.Run(name, func(t *testing.T) {
			cli := newFakeCLI(login, c.printed)
			cli.exited, cli.err = c.exited, c.err
			h := &PlanHost{Login: login, Prompt: CodexSignIn(), Workers: cli, Times: quick}
			if b := h.Begin(context.Background()); b != (PlanBegun{Detail: c.want}) {
				t.Fatalf("begun: %+v", b)
			}
			if c.err == nil {
				cli.waitStopped(t)
			}
			if st := h.State(); st.Signing || st.Last != c.want {
				t.Fatalf("after: %+v", st)
			}
		})
	}
}

// The CLK-7 mode gate. A route the terms bar starts no sign-in and serves
// no request. An unconfirmed route lets the owner sign in, then runs only
// while consent stands, read at each request, so a withdrawal stops it
// before its next call. Nothing refused is sent.
func TestPlanModeGate(t *testing.T) {
	t.Run("not allowed", func(t *testing.T) {
		var calls atomic.Int32
		login, _ := planLoginAt(t, plan.NotAllowed, tokenProvider(&calls, nil))
		cli := newFakeCLI(login, codexPrinted)
		h := &PlanHost{Login: login, Prompt: CodexSignIn(), Workers: cli, Times: quick}
		if b := h.Begin(context.Background()); b.Detail != DPlanNotAllowed {
			t.Fatalf("begun: %+v", b)
		}
		if n, _ := cli.started(); n != 0 {
			t.Fatal("a sandbox was started")
		}
		codeExchange(t, login, "s") // a login from before the terms were re-read
		login.Forget("s")
		tok, err := login.Guest("g")
		if err != nil {
			t.Fatal(err)
		}
		sent := calls.Load()
		g := PlanGuest{Login: login, Guest: "g", Consent: func() bool { return true }}
		if code, body := serve(g, modelsRead(tok.Tokens["access_token"])); code != 503 || !strings.Contains(body, DPlanNotAllowed) || calls.Load() != sent {
			t.Fatalf("a request: %d %q", code, body)
		}
	})
	t.Run("unconfirmed", func(t *testing.T) {
		var calls atomic.Int32
		login, _ := planLoginAt(t, plan.Unconfirmed, tokenProvider(&calls, nil))
		cli := newFakeCLI(login, codexPrinted)
		h := &PlanHost{Login: login, Prompt: CodexSignIn(), Workers: cli, Times: quick}
		if b := h.Begin(context.Background()); b.Code == "" {
			t.Fatalf("begun: %+v", b)
		}
		_, guest := cli.started()
		if code, body := serve(PlanGuest{Login: login, Guest: guest}, codeRequest()); code != 200 {
			t.Fatalf("the sign-in without consent: %d %q", code, body)
		}
		cli.waitStopped(t)
		tok, err := login.Guest("g")
		if err != nil {
			t.Fatal(err)
		}
		var consent atomic.Bool
		g := PlanGuest{Login: login, Guest: "g", Consent: consent.Load}
		sent := calls.Load()
		if code, body := serve(g, modelsRead(tok.Tokens["access_token"])); code != 503 || !strings.Contains(body, DPlanConsent) || calls.Load() != sent {
			t.Fatalf("before consent: %d %q", code, body)
		}
		if code, body := serve(PlanGuest{Login: login, Guest: "g"}, modelsRead(tok.Tokens["access_token"])); code != 503 || calls.Load() != sent {
			t.Fatalf("with no consent reader: %d %q", code, body)
		}
		consent.Store(true)
		if code, body := serve(g, modelsRead(tok.Tokens["access_token"])); code != 200 || calls.Load() != sent+1 {
			t.Fatalf("with consent: %d %q", code, body)
		}
		consent.Store(false)
		if code, _ := serve(g, modelsRead(tok.Tokens["access_token"])); code != 503 || calls.Load() != sent+1 {
			t.Fatalf("after a withdrawal: %d", code)
		}
	})
}

// The owner's calls cross only the owner socket: begin, state, remove
// (which ends a waiting sign-in and destroys its sandbox) and resume, which
// refuses a route an unswappable answer stopped; that route also starts no
// sign-in until a release requalifies it (CLK-7, CLK-4).
func TestPlanOwnerSocket(t *testing.T) {
	var calls atomic.Int32
	var bad atomic.Bool
	login, _ := planLoginAt(t, plan.Permitted, tokenProvider(&calls, func() map[string]any {
		if bad.Load() {
			return map[string]any{"access_token": "real-access-2", "id_token": fakeJWT("acct-1"), "debug": "x"}
		}
		return map[string]any{"access_token": "real-access-2", "id_token": fakeJWT("acct-1")}
	}))
	cli := newFakeCLI(login, codexPrinted)
	h := &PlanHost{Plan: "codex", Login: login, Prompt: CodexSignIn(), Workers: cli, Times: quick}
	o := servedOwner(t, h)

	b, err := o.Begin("codex")
	if err != nil || b.Code != "ABCD-12345" || b.Page != CodexSignIn().Page {
		t.Fatalf("begin: %+v %v", b, err)
	}
	if st, err := o.State("codex"); err != nil || !st.Signing || st.Code != b.Code {
		t.Fatalf("state: %+v %v", st, err)
	}
	if err := o.Remove("codex"); err != nil {
		t.Fatal(err)
	}
	cli.waitStopped(t)
	if st, err := o.State("codex"); err != nil || !reflect.DeepEqual(bare(st), PlanState{Mode: plan.Permitted, Last: DSignInStopped}) {
		t.Fatalf("after remove: %+v %v", st, err)
	}
	if d, err := o.Resume("codex"); err != nil || d != "" {
		t.Fatalf("resume with nothing stopped: %q %v", d, err)
	}

	// An out-of-shape refresh answer stops the route as unswappable.
	codeExchange(t, login, "s")
	login.Forget("s")
	tok, err := login.Guest("g")
	if err != nil {
		t.Fatal(err)
	}
	bad.Store(true)
	r := httptest.NewRequest("POST", "http://127.0.0.1:18432/oauth/token",
		strings.NewReader(`{"client_id":"app_x","grant_type":"refresh_token","refresh_token":"`+tok.Tokens["refresh_token"]+`"}`))
	r.Header.Set("Content-Type", "application/json")
	if code, body := serve(PlanGuest{Login: login, Guest: "g"}, r); code == 200 || strings.Contains(body, "real-") {
		t.Fatalf("an unswappable refresh: %d %q", code, body)
	}
	if d, err := o.Resume("codex"); err != nil || d != DRequalify {
		t.Fatalf("resume after an unswappable answer: %q %v", d, err)
	}
	cli2 := newFakeCLI(login, codexPrinted)
	h.Workers = cli2
	if b, err := o.Begin("codex"); err != nil || b.Detail != plan.DStopped+" "+plan.StopUnswappable {
		t.Fatalf("begin while unswappable: %+v %v", b, err)
	}
	if n, _ := cli2.started(); n != 0 {
		t.Fatal("a sandbox was started")
	}
	if st, err := o.State("codex"); err != nil || st.Stopped != plan.StopUnswappable || !st.SignedIn {
		t.Fatalf("state while unswappable: %+v %v", st, err)
	}
}

// The prompt reader takes a code only after a declared link, and never
// past its bound.
func TestPlanSignInPromptCode(t *testing.T) {
	p := CodexSignIn()
	for printed, want := range map[string]string{
		codexPrinted: "ABCD-12345",
		"https://auth.openai.com/codex/device\n  WXYZ-0001":                                 "WXYZ-0001",
		"ABCD-12345 https://auth.openai.com/codex/device":                                   "",
		"https://auth.openai.com/codex/device?x ABCD-12345":                                 "",
		strings.Repeat(" ", maxPrinted) + "https://auth.openai.com/codex/device ABCD-12345": "",
	} {
		if got, _ := p.Code(printed); got != want {
			t.Errorf("%.40q: %q, want %q", printed, got, want)
		}
	}
}

// gated holds the provider's code exchange until the test opens it.
func gated(next http.Handler, reached chan<- struct{}, open <-chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" && strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			reached <- struct{}{}
			<-open
		}
		next.ServeHTTP(w, r)
	})
}

// An approval that lands after the wall is not stored behind a sign-in the
// owner was told timed out: the code exchange in flight when the wall
// passes is dropped, and the guest is not re-added (#3149 item 1, CLK-7).
func TestPlanSignInLateApprovalAfterTheWall(t *testing.T) {
	var calls atomic.Int32
	reached, open := make(chan struct{}, 1), make(chan struct{})
	login, _ := planLoginAt(t, plan.Permitted, gated(tokenProvider(&calls, nil), reached, open))
	cli := newFakeCLI(login, codexPrinted)
	times := quick
	times.Wall = 50 * time.Millisecond
	h := &PlanHost{Login: login, Prompt: CodexSignIn(), Workers: cli, Times: times}
	if b := h.Begin(context.Background()); b.Code == "" {
		t.Fatalf("begun: %+v", b)
	}
	_, guest := cli.started()
	exchanged := make(chan int, 1)
	go func() {
		code, _ := serve(PlanGuest{Login: login, Guest: guest}, codeRequest())
		exchanged <- code
	}()
	<-reached
	cli.waitStopped(t)
	until(t, "the sign-in to end", func() bool { return h.State().Last != "" })
	close(open)
	if code := <-exchanged; code == 200 {
		t.Fatal("the late code exchange was answered")
	}
	if st := h.State(); !reflect.DeepEqual(bare(st), PlanState{Mode: plan.Permitted, Last: DSignInTimedOut}) {
		t.Fatalf("after the late approval: %+v", st)
	}
	if login.Signing(guest) || login.SignedIn(guest) {
		t.Fatal("the late approval re-added the sign-in guest")
	}
}

// The code shown is the user code the clerk forwarded to this sign-in's
// guest: a CLI that prints another, or that never asked for one, shows the
// owner nothing and its sandbox is destroyed (#3149 item 3, CLK-7, PLN-5).
func TestPlanSignInShowsOnlyTheForwardedCode(t *testing.T) {
	var calls atomic.Int32
	login, _ := planLoginAt(t, plan.Permitted, tokenProvider(&calls, nil))
	for name, cli := range map[string]*fakeCLI{
		"another code":           newFakeCLI(login, strings.Replace(codexPrinted, "ABCD-12345", "WXYZ-0001", 1)),
		"no device step":         newFakeCLI(nil, codexPrinted),
		"the code before a link": newFakeCLI(login, "ABCD-12345 http://127.0.0.1:18432/codex/device WXYZ-0001"),
	} {
		t.Run(name, func(t *testing.T) {
			h := &PlanHost{Login: login, Prompt: CodexSignIn(), Workers: cli, Times: quick}
			if b := h.Begin(context.Background()); b != (PlanBegun{Detail: DSignInCode}) {
				t.Fatalf("begun: %+v", b)
			}
			cli.waitStopped(t)
			if st := h.State(); st.Signing || st.Last != DSignInCode {
				t.Fatalf("after: %+v", st)
			}
		})
	}
}

// stuckCLI is a sandbox whose start blocks until its context ends, or whose
// reads wait for the test before printing the code.
type stuckCLI struct {
	*fakeCLI
	stuck            bool
	reading, release chan struct{}
}

func (s *stuckCLI) Start(ctx context.Context, planName, guest string) (SignInWorker, error) {
	if s.stuck {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if _, err := s.fakeCLI.Start(ctx, planName, guest); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *stuckCLI) Read(ctx context.Context) (string, bool) {
	select {
	case s.reading <- struct{}{}:
	default:
	}
	<-s.release
	return s.fakeCLI.Read(ctx)
}

// A sign-in is bounded by Link and ended by Remove even while the guest
// host blocks, and a Remove that lands once the code is printed shows the
// owner no code for the ended sign-in (#3149 item 2).
func TestPlanSignInStuckHost(t *testing.T) {
	var calls atomic.Int32
	login, _ := planLoginAt(t, plan.Permitted, tokenProvider(&calls, nil))

	t.Run("a start past Link", func(t *testing.T) {
		h := &PlanHost{Login: login, Prompt: CodexSignIn(), Workers: &stuckCLI{fakeCLI: newFakeCLI(login, ""), stuck: true}, Times: quick}
		begun := make(chan PlanBegun, 1)
		go func() { begun <- h.Begin(context.Background()) }()
		select {
		case b := <-begun:
			if b != (PlanBegun{Detail: DSignInTimedOut}) {
				t.Fatalf("begun: %+v", b)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Begin ran past Link")
		}
	})
	t.Run("a remove during the start", func(t *testing.T) {
		times := quick
		times.Link = time.Minute
		h := &PlanHost{Login: login, Prompt: CodexSignIn(), Workers: &stuckCLI{fakeCLI: newFakeCLI(login, ""), stuck: true}, Times: times}
		begun := make(chan PlanBegun, 1)
		go func() { begun <- h.Begin(context.Background()) }()
		until(t, "the sign-in to start", func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.cur != nil })
		removed := make(chan error, 1)
		go func() { removed <- h.Remove() }()
		select {
		case err := <-removed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Remove waited on a stuck start")
		}
		if b := <-begun; b != (PlanBegun{Detail: DSignInStopped}) {
			t.Fatalf("begun: %+v", b)
		}
	})
	t.Run("a remove once the code is printed", func(t *testing.T) {
		cli := &stuckCLI{fakeCLI: newFakeCLI(login, codexPrinted), reading: make(chan struct{}), release: make(chan struct{})}
		h := &PlanHost{Login: login, Prompt: CodexSignIn(), Workers: cli, Times: quick}
		begun := make(chan PlanBegun, 1)
		go func() { begun <- h.Begin(context.Background()) }()
		<-cli.reading
		removed := make(chan error, 1)
		go func() { removed <- h.Remove() }()
		until(t, "the remove to begin", func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.removing > 0 })
		close(cli.release)
		if b := <-begun; b != (PlanBegun{Detail: DSignInStopped}) {
			t.Fatalf("begun: %+v", b)
		}
		if err := <-removed; err != nil {
			t.Fatal(err)
		}
		if st := h.State(); st.Signing || st.Code != "" || st.Last != DSignInStopped {
			t.Fatalf("after: %+v", st)
		}
	})
}

// No sign-in begins while a remove runs, so the remove's clearing of the
// sign-in guests cannot fail a sign-in begun after it (#3149 item 4).
func TestPlanSignInWaitsOutARemove(t *testing.T) {
	var calls atomic.Int32
	login, _ := planLoginAt(t, plan.Permitted, tokenProvider(&calls, nil))
	cli := newFakeCLI(login, codexPrinted)
	h := &PlanHost{Login: login, Prompt: CodexSignIn(), Workers: cli, Times: quick}
	h.mu.Lock()
	h.removing++
	h.mu.Unlock()
	if b := h.Begin(context.Background()); b != (PlanBegun{Detail: DSignInBusy}) {
		t.Fatalf("begun during a remove: %+v", b)
	}
	if n, _ := cli.started(); n != 0 {
		t.Fatal("a sandbox was started during a remove")
	}
	h.mu.Lock()
	h.removing--
	h.mu.Unlock()
	if b := h.Begin(context.Background()); b.Code == "" {
		t.Fatalf("begun after the remove: %+v", b)
	}
	if err := h.Remove(); err != nil {
		t.Fatal(err)
	}
	cli.waitStopped(t)
}

// servedOwner serves hosts on a fresh owner socket and returns its caller.
func servedOwner(t *testing.T, hosts ...*PlanHost) PlanOwner {
	t.Helper()
	sock := filepath.Join(shortDir(t), "owner.sock")
	ln, err := ListenPlanOwner(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go ServePlanOwner(ln, nil, hosts...)
	return PlanOwner{proc.Conn{Socket: sock, UID: os.Getuid()}}
}

// namedLogin is planLoginAt's Codex declaration under another plan's name,
// with a store of its own: a second wired plan.
func namedLogin(t *testing.T, name string, mode plan.Mode, h http.Handler) *plan.Login {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	d := plan.Codex(netguard.New(netguard.Config{Resolver: oneAddr(netip.MustParseAddr("8.8.8.8")), Connect: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}}))
	host := "example.com:" + srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	for i := range d.Endpoints {
		d.Endpoints[i].Host = host
	}
	d.Name, d.Version, d.Mode = name, name+"-1", mode
	k := make([]byte, 32)
	rand.Read(k)
	s, err := clerk.NewAESSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	p, err := plan.New(d, plan.NewStore(s, nil), roots)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// refusedRefresh answers a refresh with a code the declaration lists as a
// refused login while refuse is set, and otherwise as tokenProvider does.
func refusedRefresh(calls *atomic.Int32, refuse *atomic.Bool) http.Handler {
	next := tokenProvider(calls, nil)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse.Load() && r.URL.Path == "/oauth/token" && strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"refresh_token_expired"}`)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func refreshRequest(ph string) *http.Request {
	r := httptest.NewRequest("POST", "http://127.0.0.1:18432/oauth/token",
		strings.NewReader(`{"client_id":"app_x","grant_type":"refresh_token","refresh_token":"`+ph+`"}`))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// signedIn signs login in and returns a run guest's token set.
func signedIn(t *testing.T, login *plan.Login, guest string) plan.Tokens {
	t.Helper()
	codeExchange(t, login, "s-"+guest)
	login.Forget("s-" + guest)
	tok, err := login.Guest(guest)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// PLAN-slots (#1379 (a)): every owner call names its plan and acts on that
// plan's host alone; a call naming an unknown plan, or none, is refused
// with plan-unknown and changes nothing, never falling through to another
// plan (CLK-7).
func TestPlanOwnerCallsNameTheirPlan(t *testing.T) {
	var ca, cb atomic.Int32
	var bad atomic.Bool
	la, _ := planLoginAt(t, plan.Permitted, tokenProvider(&ca, func() map[string]any {
		if bad.Load() {
			return map[string]any{"access_token": "real-access-2", "id_token": fakeJWT("acct-1"), "debug": "x"}
		}
		return map[string]any{"access_token": "real-access-2", "id_token": fakeJWT("acct-1")}
	}))
	lb := namedLogin(t, "other", plan.Permitted, tokenProvider(&cb, nil))
	cliA, cliB := newFakeCLI(la, codexPrinted), newFakeCLI(lb, codexPrinted)
	ha := &PlanHost{Plan: "codex", Login: la, Prompt: CodexSignIn(), Workers: cliA, Times: quick}
	hb := &PlanHost{Plan: "other", Login: lb, Prompt: SignInPrompt{Links: CodexSignIn().Links, Page: "https://other.example/device", From: "Other"}, Workers: cliB, Times: quick}
	o := servedOwner(t, ha, hb)
	tokB := signedIn(t, lb, "g")

	unknown := func(what string, err error) {
		t.Helper()
		var rf *key.Refusal
		if !errors.As(err, &rf) || rf.Code != DPlanUnknown {
			t.Fatalf("%s: %v, want %s", what, err, DPlanUnknown)
		}
	}
	for _, name := range []string{"", "nope", "Codex"} {
		_, err := o.Begin(name)
		unknown("begin "+name, err)
		_, err = o.State(name)
		unknown("state "+name, err)
		_, err = o.Resume(name)
		unknown("resume "+name, err)
		unknown("remove "+name, o.Remove(name))
	}
	for _, op := range []string{"planbegin", "planstate", "planresume", "planremove"} {
		unknown(op+" with no arguments", o.Call(op, nil, nil))
	}
	if n, _ := cliA.started(); n != 0 {
		t.Fatal("a refused call started a sign-in")
	}
	if n, _ := cliB.started(); n != 0 {
		t.Fatal("a refused call started a sign-in")
	}
	if st, err := o.State("other"); err != nil || !st.SignedIn {
		t.Fatalf("a refused remove changed another plan: %+v %v", st, err)
	}

	// begin and state act on the named plan only.
	b, err := o.Begin("other")
	if err != nil || b != (PlanBegun{Page: "https://other.example/device", Code: "ABCD-12345", From: "Other"}) {
		t.Fatalf("begin other: %+v %v", b, err)
	}
	cliB.mu.Lock()
	started := cliB.plan
	cliB.mu.Unlock()
	if n, _ := cliA.started(); started != "other" || n != 0 {
		t.Fatalf("the sign-in started for %q, codex's host started %d", started, n)
	}
	if st, err := o.State("codex"); err != nil || st.Signing || st.SignedIn {
		t.Fatalf("codex while other signs in: %+v %v", st, err)
	}
	if st, err := o.State("other"); err != nil || !st.Signing || st.Code != b.Code {
		t.Fatalf("other while signing: %+v %v", st, err)
	}
	// One sign-in waits at a time per plan, not per clerk.
	if b, err := o.Begin("codex"); err != nil || b.Code == "" {
		t.Fatalf("begin codex while other signs in: %+v %v", b, err)
	}
	if b, err := o.Begin("other"); err != nil || b.Detail != DSignInBusy {
		t.Fatalf("a second sign-in on other: %+v %v", b, err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(o.Remove("codex"))
	cliA.waitStopped(t)
	if st, err := o.State("other"); err != nil || !st.Signing || !st.SignedIn {
		t.Fatalf("other after codex's remove: %+v %v", st, err)
	}
	must(o.Remove("other"))
	cliB.waitStopped(t)
	if lb.Signed() {
		t.Fatal("other's remove left its login")
	}
	sent := cb.Load()
	if code, _ := serve(PlanGuest{Login: lb, Guest: "g"}, modelsRead(tokB.Tokens["access_token"])); code == 200 || cb.Load() != sent {
		t.Fatalf("a removed login served: %d", code)
	}

	// resume acts on the named plan only.
	tokA := signedIn(t, la, "g")
	bad.Store(true)
	if code, _ := serve(PlanGuest{Login: la, Guest: "g"}, refreshRequest(tokA.Tokens["refresh_token"])); code == 200 {
		t.Fatal("an unswappable refresh was answered")
	}
	if d, err := o.Resume("other"); err != nil || d != "" {
		t.Fatalf("resume other: %q %v", d, err)
	}
	if st, err := o.State("codex"); err != nil || st.Stopped != plan.StopUnswappable {
		t.Fatalf("resume other touched codex: %+v %v", st, err)
	}
	if d, err := o.Resume("codex"); err != nil || d != DRequalify {
		t.Fatalf("resume codex: %q %v", d, err)
	}
}

// A placeholder one plan's Login minted resolves at no other plan's
// endpoint, even for the same account: it is refused and nothing is sent
// upstream (CLK-1).
func TestPlanPlaceholdersDoNotCrossPlans(t *testing.T) {
	var ca, cb atomic.Int32
	la, _ := planLoginAt(t, plan.Permitted, tokenProvider(&ca, nil))
	lb := namedLogin(t, "other", plan.Permitted, tokenProvider(&cb, nil))
	tokA, tokB := signedIn(t, la, "g"), signedIn(t, lb, "g")
	sentA, sentB := ca.Load(), cb.Load()
	gb := PlanGuest{Login: lb, Guest: "g"}
	if code, body := serve(gb, modelsRead(tokA.Tokens["access_token"])); code == 200 || strings.Contains(body, "real-") || cb.Load() != sentB {
		t.Fatalf("plan A's access placeholder at plan B: %d %q", code, body)
	}
	if code, body := serve(gb, refreshRequest(tokA.Tokens["refresh_token"])); code == 200 || strings.Contains(body, "real-") || cb.Load() != sentB {
		t.Fatalf("plan A's refresh placeholder at plan B: %d %q", code, body)
	}
	ga := PlanGuest{Login: la, Guest: "g"}
	if code, _ := serve(ga, modelsRead(tokB.Tokens["access_token"])); code == 200 || ca.Load() != sentA {
		t.Fatalf("plan B's placeholder at plan A: %d", code)
	}
	// Each still serves its own.
	if code, _ := serve(gb, modelsRead(tokB.Tokens["access_token"])); code != 200 || cb.Load() != sentB+1 {
		t.Fatalf("plan B's own placeholder: %d", code)
	}
	if code, _ := serve(ga, modelsRead(tokA.Tokens["access_token"])); code != 200 || ca.Load() != sentA+1 {
		t.Fatalf("plan A's own placeholder: %d", code)
	}
}

// A stop, a removal or a withdrawn consent on one plan leaves the other
// serving (CLK-7 Control: pause and stops are per plan).
func TestPlanStopsArePerPlan(t *testing.T) {
	serving := func(t *testing.T, l *plan.Login, g PlanGuest, calls *atomic.Int32) {
		t.Helper()
		if l.Stopped() != "" {
			t.Fatalf("the other plan stopped: %s", l.Stopped())
		}
		tok, err := l.Guest(g.Guest)
		if err != nil {
			t.Fatalf("the other plan issues no token set: %v", err)
		}
		sent := calls.Load()
		if code, body := serve(g, modelsRead(tok.Tokens["access_token"])); code != 200 || calls.Load() != sent+1 {
			t.Fatalf("the other plan: %d %q", code, body)
		}
	}
	t.Run("unswappable", func(t *testing.T) {
		var ca, cb atomic.Int32
		la, _ := planLoginAt(t, plan.Permitted, tokenProvider(&ca, func() map[string]any {
			return map[string]any{"access_token": "real-access-2", "id_token": fakeJWT("acct-1"), "debug": "x"}
		}))
		lb := namedLogin(t, "other", plan.Permitted, tokenProvider(&cb, nil))
		tokA := signedIn(t, la, "g")
		signedIn(t, lb, "g")
		serve(PlanGuest{Login: la, Guest: "g"}, refreshRequest(tokA.Tokens["refresh_token"]))
		if la.Stopped() != plan.StopUnswappable {
			t.Fatalf("plan A: %q", la.Stopped())
		}
		serving(t, lb, PlanGuest{Login: lb, Guest: "g"}, &cb)
	})
	t.Run("refused login", func(t *testing.T) {
		var ca, cb atomic.Int32
		var refuse atomic.Bool
		la, _ := planLoginAt(t, plan.Permitted, refusedRefresh(&ca, &refuse))
		lb := namedLogin(t, "other", plan.Permitted, tokenProvider(&cb, nil))
		tokA := signedIn(t, la, "g")
		signedIn(t, lb, "g")
		refuse.Store(true)
		serve(PlanGuest{Login: la, Guest: "g"}, refreshRequest(tokA.Tokens["refresh_token"]))
		if la.Stopped() != plan.StopRefused {
			t.Fatalf("plan A: %q", la.Stopped())
		}
		serving(t, lb, PlanGuest{Login: lb, Guest: "g"}, &cb)
	})
	t.Run("removal", func(t *testing.T) {
		var ca, cb atomic.Int32
		la, _ := planLoginAt(t, plan.Permitted, tokenProvider(&ca, nil))
		lb := namedLogin(t, "other", plan.Permitted, tokenProvider(&cb, nil))
		signedIn(t, la, "g")
		signedIn(t, lb, "g")
		o := servedOwner(t, &PlanHost{Plan: "codex", Login: la, Workers: newFakeCLI(la, "")},
			&PlanHost{Plan: "other", Login: lb, Workers: newFakeCLI(lb, "")})
		if err := o.Remove("codex"); err != nil {
			t.Fatal(err)
		}
		if la.Signed() {
			t.Fatal("plan A's login stayed")
		}
		serving(t, lb, PlanGuest{Login: lb, Guest: "g"}, &cb)
	})
	t.Run("withdrawn consent", func(t *testing.T) {
		var ca, cb atomic.Int32
		la, _ := planLoginAt(t, plan.Unconfirmed, tokenProvider(&ca, nil))
		lb := namedLogin(t, "other", plan.Unconfirmed, tokenProvider(&cb, nil))
		tokA := signedIn(t, la, "g")
		signedIn(t, lb, "g")
		sent := ca.Load()
		ga := PlanGuest{Login: la, Guest: "g", Consent: func() bool { return false }}
		if code, body := serve(ga, modelsRead(tokA.Tokens["access_token"])); code != 503 || !strings.Contains(body, DPlanConsent) || ca.Load() != sent {
			t.Fatalf("plan A without consent: %d %q", code, body)
		}
		serving(t, lb, PlanGuest{Login: lb, Guest: "g", Consent: func() bool { return true }}, &cb)
	})
}

// The owner socket refuses to serve two plans under one name, or one with
// none, so no call can reach a plan by a name it does not hold.
func TestPlanOwnerSocketNeedsDistinctNames(t *testing.T) {
	var calls atomic.Int32
	la, _ := planLoginAt(t, plan.Permitted, tokenProvider(&calls, nil))
	for name, hosts := range map[string][]*PlanHost{
		"a repeated name": {{Plan: "codex", Login: la}, {Plan: "codex", Login: la}},
		"no name":         {{Login: la}},
		"a nil host":      {nil},
	} {
		ln, err := ListenPlanOwner(filepath.Join(shortDir(t), "owner.sock"), os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		if err := ServePlanOwner(ln, nil, hosts...); err == nil {
			t.Errorf("%s served", name)
		}
		ln.Close()
	}
}

// bare is st without the plan's names, which TestPlanStateNamesThePoolWithoutFigures checks.
func bare(st PlanState) PlanState {
	st.Title, st.Pool = "", PlanPool{}
	return st
}

// planstate names the plan, its pool and its windows as the declaration
// does, and the routes that draw on the pool, with no figure: the owner side
// reads those from the kernel (CLK-7, ONB-9).
// REQ: CLK-7, ONB-9
func TestPlanStateNamesThePoolWithoutFigures(t *testing.T) {
	login, _ := planLoginAt(t, plan.Permitted, http.NotFoundHandler())
	h := &PlanHost{Plan: "codex", Login: login, Routes: []string{"codex-plan"}, Prompt: CodexSignIn(), Times: quick}
	o := servedOwner(t, h)
	want := PlanPool{ID: "codex", Name: "ChatGPT Codex", Windows: []PlanWindow{{"5h", "5-hour limit"}, {"7d", "week"}}, Routes: []string{"codex-plan"}}
	st, err := o.State("codex")
	if err != nil || st.Title != "ChatGPT" || !reflect.DeepEqual(st.Pool, want) || !reflect.DeepEqual(h.State(), st) {
		t.Fatalf("planstate %+v %v, want ChatGPT %+v", st, err, want)
	}
	b, _ := json.Marshal(st)
	for _, figure := range []string{"used", "reset", "percent", "reserve", "X-Codex"} {
		if strings.Contains(strings.ToLower(string(b)), strings.ToLower(figure)) {
			t.Fatalf("planstate carries %q: %s", figure, b)
		}
	}
}
