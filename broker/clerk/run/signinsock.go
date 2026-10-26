package run

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/plan"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
)

// SignInSock is SignInWorkers over agentosd's sign-in socket
// (MIG-4-untrusted-exit-b1, #2780(b), PLN-5, CLK-7): agentosd runs each
// sign-in CLI in a machine of its own whose only mount out is the guest's
// route directory, in which this process serves that guest's plan
// endpoint. Start makes the directory under Dir, serves the endpoint in it
// (ListenPlan, ServePlan) and asks agentosd to start the machine; Stop
// asks agentosd to destroy it and closes the endpoint. agentosd's
// signinhost.go is the other side; TestSignInSockSpeaksTheHostsWire, in
// cmd/agentosd, serves it to this client.
type SignInSock struct {
	// Host is agentosd's -signin-sock, called only on agentosd's uid.
	Host proc.Conn
	// Dir holds each sign-in guest's route directory; it is this
	// process's alone (agentosd checks each route is a directory owned by
	// this uid that no group or other may write, with no link on the way).
	Dir   string
	Login *plan.Login
	// SandboxUID is the uid the sign-in machine's connections to its
	// endpoint arrive as: agentosd's sandbox host, not the guest's own,
	// so the endpoint's directory, which only that machine mounts, is what
	// names the guest (ASSUMPTIONS MIG-4-untrusted-exit-b1).
	SandboxUID int
}

// SignInRouteSocket is the endpoint's socket in a route directory, where
// the sign-in machine sees it as /run/agentos/route.sock.
const SignInRouteSocket = "route.sock"

type signInArgs struct {
	Guest string `json:"guest"`
	Route string `json:"route,omitempty"`
}

type signInRead struct {
	Printed string `json:"printed"`
	Exited  bool   `json:"exited"`
}

// within is c with its timeout bounded by ctx's deadline.
func within(ctx context.Context, c proc.Conn) (proc.Conn, error) {
	if err := ctx.Err(); err != nil {
		return c, err
	}
	if dl, ok := ctx.Deadline(); ok {
		d := time.Until(dl)
		if d <= 0 {
			return c, context.DeadlineExceeded
		}
		if c.Timeout == 0 || d < c.Timeout {
			c.Timeout = d
		}
	}
	return c, nil
}

// Start serves guest's endpoint in a fresh route directory and has
// agentosd start the sign-in CLI on it.
func (s SignInSock) Start(ctx context.Context, guest string) (SignInWorker, error) {
	c, err := within(ctx, s.Host)
	if err != nil {
		return nil, err
	}
	route := filepath.Join(s.Dir, guest)
	if filepath.Dir(route) != filepath.Clean(s.Dir) {
		return nil, errors.New("run: a sign-in guest names one directory")
	}
	if err := os.Mkdir(route, 0o700); err != nil {
		return nil, err
	}
	ln, err := ListenPlan(filepath.Join(route, SignInRouteSocket), s.SandboxUID)
	if err != nil {
		os.RemoveAll(route)
		return nil, err
	}
	go ServePlan(ln, PlanGuest{Login: s.Login, Guest: guest})
	w := &signInSockWorker{s: s, guest: guest, route: route, ln: ln}
	if err := c.Call("signinstart", signInArgs{Guest: guest, Route: route}, nil); err != nil {
		// A lost answer may have started it: stop is idempotent.
		w.Stop()
		return nil, err
	}
	return w, nil
}

type signInSockWorker struct {
	s     SignInSock
	guest string
	route string
	ln    net.Listener
}

// Read asks agentosd what the CLI printed. A call that fails reads as an
// exited CLI: agentosd no longer runs it, or cannot be reached, and the
// sign-in ends rather than wait out its wall.
func (w *signInSockWorker) Read(ctx context.Context) (string, bool) {
	c, err := within(ctx, w.s.Host)
	if err != nil {
		return "", false
	}
	var r signInRead
	if err := c.Call("signinread", signInArgs{Guest: w.guest}, &r); err != nil {
		return "", true
	}
	return r.Printed, r.Exited
}

// Stop has agentosd destroy the machine, then closes the endpoint.
func (w *signInSockWorker) Stop() {
	c := w.s.Host
	if c.Timeout == 0 {
		c.Timeout = 45 * time.Second
	}
	c.Call("signinstop", signInArgs{Guest: w.guest}, nil)
	w.ln.Close()
	os.RemoveAll(w.route)
}
