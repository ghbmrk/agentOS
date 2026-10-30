package run

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/plan"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
)

// SignInSock is SignInWorkers over agentosd's sign-in socket
// (MIG-4-untrusted-exit-b1, #2780(b), PLN-5, CLK-7): agentosd runs each
// sign-in CLI in a machine of its own whose only mount out is the guest's
// route directory, in which this process serves that guest's plan
// endpoint. Start has agentosd make the directory (signinroute), serves
// the endpoint in it (ListenPlan, ServePlan) and asks agentosd to start
// the machine; Stop asks agentosd to destroy it and remove the directory,
// and closes the endpoint. agentosd makes each route in a directory this
// process cannot write, so this process cannot swap the route for another
// path between agentosd's check and the mount (#3248 Security 1). agentosd's
// signinhost.go is the other side; TestSignInSockSpeaksTheHostsWire, in
// cmd/agentosd, serves it to this client.
type SignInSock struct {
	// Host is agentosd's -signin-sock, called only on agentosd's uid.
	Host  proc.Conn
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

// signInArgs name the sign-in's guest and its plan, the PlanHost's that
// began it (#1379 (a)); agentosd's host ignores the plan until it runs one
// sign-in machine per plan (#3927).
type signInArgs struct {
	Guest string `json:"guest"`
	Plan  string `json:"plan"`
}

type signInRoute struct {
	Route string `json:"route"`
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

// Start has agentosd make guest's route afresh, serves guest's endpoint in
// it and has agentosd start planName's sign-in CLI on it.
func (s SignInSock) Start(ctx context.Context, planName, guest string) (SignInWorker, error) {
	c, err := within(ctx, s.Host)
	if err != nil {
		return nil, err
	}
	var r signInRoute
	args := signInArgs{Guest: guest, Plan: planName}
	if err := c.Call("signinroute", args, &r); err != nil {
		return nil, err
	}
	err = errors.New("run: agentosd named a route that is not the guest's")
	var ln net.Listener
	if filepath.IsAbs(r.Route) && filepath.Base(r.Route) == guest {
		ln, err = ListenPlan(filepath.Join(r.Route, SignInRouteSocket), s.SandboxUID)
	}
	if err != nil {
		(&signInSockWorker{s: s, args: args}).Stop()
		return nil, err
	}
	go servePlan(ln, PlanGuest{Login: s.Login, Guest: guest})
	w := &signInSockWorker{s: s, args: args, ln: ln}
	if err := c.Call("signinstart", args, nil); err != nil {
		// A lost answer may have started it: stop is idempotent.
		w.Stop()
		return nil, err
	}
	return w, nil
}

type signInSockWorker struct {
	s    SignInSock
	args signInArgs
	ln   net.Listener // nil once the endpoint did not open
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
	if err := c.Call("signinread", w.args, &r); err != nil {
		return "", true
	}
	return r.Printed, r.Exited
}

// Stop has agentosd destroy the machine and remove the route, then closes
// the endpoint.
func (w *signInSockWorker) Stop() {
	c := w.s.Host
	if c.Timeout == 0 {
		c.Timeout = 45 * time.Second
	}
	c.Call("signinstop", w.args, nil)
	if w.ln != nil {
		w.ln.Close()
	}
}
