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
				return json.Marshal(signInRead{Printed: "code", Exited: false})
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

// Each of the four calls to agentosd's sign-in host carries the plan of the
// PlanHost that began the sign-in, beside its guest, so a host with one
// sign-in machine per plan (#3927) starts the right one (CLK-7, PLN-5).
func TestSignInSockNamesThePlan(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	host := &stubHost{dir: dir, fail: map[string]error{}}
	sock := host.serve(t)
	var ca, cb atomic.Int32
	la, _ := planLoginAt(t, plan.Permitted, tokenProvider(&ca, nil))
	lb := namedLogin(t, "other", plan.Permitted, tokenProvider(&cb, nil))
	conn := proc.Conn{Socket: sock, UID: os.Getuid()}
	for _, h := range []*PlanHost{
		{Plan: "codex", Login: la, Prompt: CodexSignIn(), Workers: SignInSock{Host: conn, Login: la, SandboxUID: os.Getuid()}, Times: quick},
		{Plan: "other", Login: lb, Prompt: CodexSignIn(), Workers: SignInSock{Host: conn, Login: lb, SandboxUID: os.Getuid()}, Times: quick},
	} {
		host.mu.Lock()
		host.calls, host.args = nil, nil
		host.mu.Unlock()
		// The stub prints no link: the sign-in times out after Link and is
		// stopped, having made every call.
		if b := h.Begin(context.Background()); b.Detail != DSignInTimedOut {
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
