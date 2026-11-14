package run

// REQ: PLN-5, CLK-7

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/plan"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
)

// stubHost answers SignInSock's calls as agentosd's -signin-sock would,
// recording each, and makes and removes routes in dir as agentosd does;
// cmd/agentosd's TestSignInSockSpeaksTheHostsWire serves the real one.
type stubHost struct {
	dir   string
	mu    sync.Mutex
	calls []string
	args  []signInArgs
	fail  map[string]error
	route string // signinroute's answer, if not dir/guest
	ended bool   // signinread answers that the CLI exited
}

func (s *stubHost) serve(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "signin.sock")
	ln, err := ListenPlanOwner(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go proc.ServeConns(ln, proc.MaxConns, func(conn net.Conn) {
		proc.ServeOne(conn, func(op string, raw json.RawMessage) (json.RawMessage, error) {
			var a signInArgs
			json.Unmarshal(raw, &a)
			s.mu.Lock()
			s.calls, s.args = append(s.calls, op), append(s.args, a)
			err := s.fail[op]
			s.mu.Unlock()
			if err != nil {
				return nil, err
			}
			switch op {
			case "signinroute":
				route := filepath.Join(s.dir, a.Guest)
				os.Mkdir(route, 0o700)
				s.mu.Lock()
				if s.route != "" {
					route = s.route
				}
				s.mu.Unlock()
				return json.Marshal(signInRoute{Route: route})
			case "signinstop":
				os.RemoveAll(filepath.Join(s.dir, a.Guest))
			case "signinread":
				s.mu.Lock()
				ended := s.ended
				s.mu.Unlock()
				return json.Marshal(signInRead{Printed: "code", Exited: ended})
			}
			return nil, nil
		})
	})
	return sock
}

// Start has agentosd make the guest's route, serves the guest's endpoint
// in it and asks agentosd to start the CLI; Read relays signinread, a
// failed read ends the sign-in; Stop has agentosd destroy the machine and
// remove the route. A refused start, or a route agentosd names that is not
// the guest's, ends with signinstop.
func TestSignInSockStartsOnTheGuestsRoute(t *testing.T) {
	login, _ := planLoginAt(t, plan.Permitted, tokenProvider(new(atomic.Int32), nil))
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	host := &stubHost{dir: dir, fail: map[string]error{}}
	s := SignInSock{Host: proc.Conn{Socket: host.serve(t), UID: os.Getuid()}, Login: login, SandboxUID: os.Getuid()}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, err := s.Start(ctx, "codex", "signin-1")
	if err != nil {
		t.Fatal(err)
	}
	route := filepath.Join(dir, "signin-1")
	if _, err := os.Stat(filepath.Join(route, SignInRouteSocket)); err != nil {
		t.Fatalf("no endpoint in the route: %v", err)
	}
	if p, exited := w.Read(ctx); p != "code" || exited {
		t.Fatalf("read: %q %v", p, exited)
	}
	host.mu.Lock()
	host.fail["signinread"] = errors.New("signin: no sign-in runs for this guest")
	host.mu.Unlock()
	if _, exited := w.Read(ctx); !exited {
		t.Fatal("a failed read did not end the sign-in")
	}
	w.Stop()
	if _, err := os.Stat(route); !os.IsNotExist(err) {
		t.Fatalf("the route stayed: %v", err)
	}
	host.mu.Lock()
	want := []string{"signinroute", "signinstart", "signinread", "signinread", "signinstop"}
	if !slices.Equal(host.calls, want) || slices.ContainsFunc(host.args, func(a signInArgs) bool { return a != signInArgs{Guest: "signin-1", Plan: "codex"} }) {
		t.Fatalf("calls %v %+v", host.calls, host.args)
	}
	host.calls = nil
	host.fail["signinstart"] = errors.New("signin: the sign-in machine did not start")
	host.mu.Unlock()

	if _, err := s.Start(ctx, "codex", "signin-2"); err == nil {
		t.Fatal("a refused start returned a worker")
	}
	host.mu.Lock()
	delete(host.fail, "signinstart")
	host.route = filepath.Join(dir, "elsewhere")
	host.mu.Unlock()
	if _, err := s.Start(ctx, "codex", "signin-3"); err == nil {
		t.Fatal("a route not named for the guest was served")
	}
	host.mu.Lock()
	if !slices.Equal(host.calls, []string{"signinroute", "signinstart", "signinstop", "signinroute", "signinstop"}) {
		t.Fatalf("calls %v", host.calls)
	}
	host.route = ""
	host.fail["signinroute"] = errors.New("signin: a guest is lowercase letters, digits and dashes, at most 64")
	host.mu.Unlock()
	if _, err := s.Start(ctx, "codex", "../x"); err == nil {
		t.Fatal("a refused route started")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("left %v", ents)
	}
	done, stop := context.WithCancel(ctx)
	stop()
	if _, err := s.Start(done, "codex", "signin-3"); err == nil {
		t.Fatal("a start after ctx ended")
	}
}

// within bounds a call's timeout by ctx's deadline (#5325, signinsock.go):
// an ended ctx refuses the call, a deadline already past refuses it even
// before ctx says so, a nearer deadline shortens the timeout, and a farther
// one, or none, leaves it.
func TestWithinBoundsTheCallByTheDeadline(t *testing.T) {
	base := proc.Conn{Socket: "/nonexistent", Timeout: time.Hour}
	ended, stop := context.WithCancel(context.Background())
	stop()
	if _, err := within(ended, base); err != context.Canceled {
		t.Fatalf("an ended ctx: %v; want %v", err, context.Canceled)
	}
	// A deadline that has passed while ctx's timer has not yet fired: Err
	// is still nil, so only the deadline itself can tell.
	past, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	type deadliner interface{ Deadline() (time.Time, bool) }
	type rest interface {
		Done() <-chan struct{}
		Err() error
		Value(any) any
	}
	lagging := struct {
		deadliner
		rest
	}{past, context.Background()}
	if c, err := within(lagging, base); err != context.DeadlineExceeded || c.Timeout != time.Hour {
		t.Fatalf("a passed deadline: timeout %v, %v; want %v unchanged and %v", c.Timeout, err, time.Hour, context.DeadlineExceeded)
	}
	near, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, c := range []struct {
		name     string
		ctx      context.Context
		timeout  time.Duration
		min, max time.Duration
	}{
		{"no timeout, a deadline", near, 0, 50 * time.Second, time.Minute},
		{"a longer timeout, a deadline", near, time.Hour, 50 * time.Second, time.Minute},
		{"a shorter timeout, a deadline", near, time.Second, time.Second, time.Second},
		{"no deadline", context.Background(), time.Second, time.Second, time.Second},
		{"no deadline, no timeout", context.Background(), 0, 0, 0},
	} {
		in := base
		in.Timeout = c.timeout
		got, err := within(c.ctx, in)
		if err != nil || got.Timeout < c.min || got.Timeout > c.max || got.Socket != base.Socket {
			t.Errorf("%s: %+v, %v; want a timeout in [%v, %v]", c.name, got, err, c.min, c.max)
		}
	}
}

// SignInSock's calls each end where they should (#5325, signinsock.go): a
// start or read with ctx ended asks agentosd nothing; a refused route is
// the end of the start, with nothing to stop; a started sign-in serves its
// endpoint on the route; and Stop closes the endpoint even when agentosd
// refuses the stop.
func TestSignInSockCallsEndWhereTheyShould(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	host := &stubHost{dir: dir, fail: map[string]error{}}
	// No Login: these calls never reach a model, only the endpoint's server.
	s := SignInSock{Host: proc.Conn{Socket: host.serve(t), UID: os.Getuid()}, SandboxUID: os.Getuid()}
	calls := func() []string {
		host.mu.Lock()
		defer host.mu.Unlock()
		c := host.calls
		host.calls = nil
		return c
	}

	ended, stop := context.WithCancel(context.Background())
	stop()
	if w, err := s.Start(ended, "codex", "signin-1"); err == nil || w != nil {
		t.Fatalf("a start with ctx ended: %v, %v", w, err)
	}
	if c := calls(); len(c) != 0 {
		t.Fatalf("a start with ctx ended called %v", c)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	host.mu.Lock()
	host.fail["signinroute"] = errors.New("signin: no route for this guest")
	host.mu.Unlock()
	if _, err := s.Start(ctx, "codex", "signin-1"); err == nil {
		t.Fatal("a refused route started")
	}
	if c := calls(); !slices.Equal(c, []string{"signinroute"}) {
		t.Fatalf("a refused route called %v; want only signinroute", c)
	}
	host.mu.Lock()
	delete(host.fail, "signinroute")
	host.mu.Unlock()

	w, err := s.Start(ctx, "codex", "signin-1")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "signin-1", SignInRouteSocket)
	// A request the endpoint's HTTP server refuses before any handler: an
	// answer at all shows the endpoint is served.
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("NOT HTTP\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	var answer []byte
	for buf := make([]byte, 64); len(answer) < 12; {
		n, err := conn.Read(buf)
		answer = append(answer, buf[:n]...)
		if err != nil {
			break
		}
	}
	if !strings.HasPrefix(string(answer), "HTTP/1.1 400") {
		t.Fatalf("the endpoint answered %q; want a 400", answer)
	}
	conn.Close()
	calls()

	if p, exited := w.Read(ended); p != "" || exited {
		t.Fatalf("a read with ctx ended: %q, exited %v; want nothing, not exited", p, exited)
	}
	if c := calls(); len(c) != 0 {
		t.Fatalf("a read with ctx ended called %v", c)
	}

	// agentosd refuses the stop: the route stays, the endpoint still closes.
	host.mu.Lock()
	host.fail["signinstop"] = errors.New("signin: synthetic stop failure")
	host.mu.Unlock()
	w.Stop()
	if c := calls(); !slices.Equal(c, []string{"signinstop"}) {
		t.Fatalf("stop called %v", c)
	}
	if _, err := os.Stat(filepath.Dir(sock)); err != nil {
		t.Fatalf("the route should stay when the stop fails: %v", err)
	}
	if c, err := net.Dial("unix", sock); err == nil {
		c.Close()
		t.Fatal("the endpoint still accepts after Stop")
	}
}

// The sign-in endpoint's server (plan.go's servePlan and limitListener),
// which a started SignInSock runs and Stop ends: a closed listener ends it
// with no error; each accepted connection holds a slot until it closes; and
// an Accept that fails, as one past its deadline does again and again,
// holds none, so the server's retries cannot use the slots up (#5325; plan
// lines #5326 lists, reached by the sign-in socket's tests).
func TestTheSignInEndpointsServerHoldsItsSlots(t *testing.T) {
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "e.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if err := servePlan(ln, PlanGuest{}); err != nil {
		t.Fatalf("serving a closed listener: %v; want nil", err)
	}

	sock := filepath.Join(t.TempDir(), "l.sock")
	inner, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	l := &limitListener{Listener: inner, slots: make(chan struct{}, 2)}
	client, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(l.slots); n != 1 {
		t.Fatalf("an accepted connection holds %d slots; want 1", n)
	}
	conn.Close()
	conn.Close() // a second close frees nothing more
	if n := len(l.slots); n != 0 {
		t.Fatalf("after the connection closed %d slots are held; want 0", n)
	}

	inner.(*net.UnixListener).SetDeadline(time.Now().Add(-time.Second))
	for i := range 3 { // more failures than slots
		if c, err := l.Accept(); err == nil {
			c.Close()
			t.Fatalf("accept %d past the deadline gave a connection", i)
		}
		if n := len(l.slots); n != 0 {
			t.Fatalf("after failed accept %d, %d slots are held; want 0", i, n)
		}
	}
}

// Each of the four calls to agentosd's sign-in host carries the plan of the
// PlanHost that began the sign-in, beside its guest, so a host with one
// sign-in machine per plan (#3927) starts the right one (CLK-7, PLN-5).
func TestSignInSockNamesThePlan(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	host := &stubHost{dir: dir, fail: map[string]error{}, ended: true}
	sock := host.serve(t)
	var ca, cb atomic.Int32
	la, _ := planLoginAt(t, plan.Permitted, tokenProvider(&ca, nil))
	lb := namedLogin(t, "other", plan.Permitted, tokenProvider(&cb, nil))
	conn := proc.Conn{Socket: sock, UID: os.Getuid()}
	// Link only bounds a hang: the stub's CLI exits at its first read, so
	// each sign-in ends on that read, not on a timer.
	times := SignInTimes{Poll: time.Millisecond, Link: time.Minute, Wall: time.Minute}
	for _, h := range []*PlanHost{
		{Plan: "codex", Login: la, Prompt: CodexSignIn(), Workers: SignInSock{Host: conn, Login: la, SandboxUID: os.Getuid()}, Times: times},
		{Plan: "other", Login: lb, Prompt: CodexSignIn(), Workers: SignInSock{Host: conn, Login: lb, SandboxUID: os.Getuid()}, Times: times},
	} {
		host.mu.Lock()
		host.calls, host.args = nil, nil
		host.mu.Unlock()
		// The stub's CLI exits before printing a link: the sign-in fails at
		// its first read and is stopped, having made every call.
		if b := h.Begin(context.Background()); b.Detail != DSignInFailed {
			t.Fatalf("%s: begun %+v", h.Plan, b)
		}
		host.mu.Lock()
		calls, args := host.calls, host.args
		host.mu.Unlock()
		for _, op := range []string{"signinroute", "signinstart", "signinread", "signinstop"} {
			if !slices.Contains(calls, op) {
				t.Errorf("%s: no %s in %v", h.Plan, op, calls)
			}
		}
		for i, a := range args {
			if a.Plan != h.Plan || !strings.HasPrefix(a.Guest, "signin-") {
				t.Errorf("%s: %s carried %+v", h.Plan, calls[i], a)
			}
		}
	}
}
