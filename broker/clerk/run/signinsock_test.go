package run

// REQ: PLN-5, CLK-7

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/plan"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
)

// stubHost answers SignInSock's calls as agentosd's -signin-sock would,
// recording each; cmd/agentosd's TestSignInSockSpeaksTheHostsWire serves
// the real one.
type stubHost struct {
	mu    sync.Mutex
	calls []string
	args  []signInArgs
	fail  map[string]error
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
			if op == "signinread" {
				return json.Marshal(signInRead{Printed: "code", Exited: false})
			}
			return nil, nil
		})
	})
	return sock
}

// Start serves the guest's endpoint in its own route directory, 0700, and
// names that directory to agentosd; Read relays signinread, a failed read
// ends the sign-in; Stop has agentosd destroy the machine and removes the
// route. A refused start leaves no route.
func TestSignInSockStartsOnTheGuestsRoute(t *testing.T) {
	login, _ := planLoginAt(t, plan.Permitted, tokenProvider(new(atomic.Int32), nil))
	host := &stubHost{fail: map[string]error{}}
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	s := SignInSock{Host: proc.Conn{Socket: host.serve(t), UID: os.Getuid()}, Dir: dir, Login: login, SandboxUID: os.Getuid()}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, err := s.Start(ctx, "signin-1")
	if err != nil {
		t.Fatal(err)
	}
	route := filepath.Join(dir, "signin-1")
	fi, err := os.Stat(route)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("route: %v %v", fi, err)
	}
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
	want := []string{"signinstart", "signinread", "signinread", "signinstop"}
	if len(host.calls) != len(want) || host.args[0] != (signInArgs{"signin-1", route}) || host.args[3] != (signInArgs{Guest: "signin-1"}) {
		t.Fatalf("calls %v %+v", host.calls, host.args)
	}
	for i := range want {
		if host.calls[i] != want[i] {
			t.Fatalf("calls %v", host.calls)
		}
	}
	host.fail["signinstart"] = errors.New("signin: the sign-in machine did not start")
	host.mu.Unlock()

	if _, err := s.Start(ctx, "signin-2"); err == nil {
		t.Fatal("a refused start returned a worker")
	}
	if _, err := s.Start(ctx, "../x"); err == nil {
		t.Fatal("a guest outside Dir started")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("left %v", ents)
	}
	done, stop := context.WithCancel(ctx)
	stop()
	if _, err := s.Start(done, "signin-3"); err == nil {
		t.Fatal("a start after ctx ended")
	}
}
