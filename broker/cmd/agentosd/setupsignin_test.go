package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/provagent"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: ONB-3, CRED-5, RES-2

// machineHost is a provider-worker plane that records what it is asked.
type machineHost struct {
	mu        sync.Mutex
	live      map[string]bool
	destroyed []string
}

func (h *machineHost) CreateProviderWorker(_ context.Context, id string, _ vm.Spec, _ map[string][]byte) (vm.Machine, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.live[id] = true
	return vm.Machine{}, nil
}

func (h *machineHost) Exec(context.Context, string, vm.Command, time.Duration) (vm.ExecResult, error) {
	return vm.ExecResult{}, nil
}

func (h *machineHost) Destroy(_ context.Context, id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.live, id)
	h.destroyed = append(h.destroyed, id)
	return nil
}

// setupRig is a setupHost over a machineHost whose opens it counts; the
// first fail opens fail.
type setupRig struct {
	h     *machineHost
	opens int
	fail  int
	s     *setupHost
}

func newSetupRig(fail int) *setupRig {
	g := &setupRig{h: &machineHost{live: map[string]bool{}}, fail: fail}
	g.s = newSetupHost(func(context.Context) (provagent.Host, error) {
		g.opens++
		if g.opens <= g.fail {
			return nil, errors.New("no cgroup")
		}
		return g.h, nil
	})
	return g
}

// Setup's sign-in machines open only once a sign-in starts, and then once;
// one worker lives at a time; a failed open is not kept, so a later
// sign-in tries again (ONB-3, RES-2).
func TestONB3SetupMachinesOpenLazilyWithOneWorker(t *testing.T) {
	ctx := context.Background()
	g := newSetupRig(1)
	if g.opens != 0 {
		t.Fatal("setup opened machines before a sign-in")
	}
	if _, err := g.s.CreateProviderWorker(ctx, "pw-a", vm.Spec{}, nil); err == nil {
		t.Fatal("a worker started on machines that did not open")
	}
	if _, err := g.s.CreateProviderWorker(ctx, "pw-a", vm.Spec{}, nil); err != nil {
		t.Fatalf("a sign-in after a failed open: %v", err)
	}
	if _, err := g.s.CreateProviderWorker(ctx, "pw-b", vm.Spec{}, nil); !errors.Is(err, errOneWorker) {
		t.Fatalf("a second worker while one lives: %v", err)
	}
	if _, err := g.s.Exec(ctx, "pw-b", vm.Command{}, time.Second); !errors.Is(err, vm.ErrUnknown) {
		t.Fatalf("exec in a worker setup did not make: %v", err)
	}
	if _, err := g.s.Exec(ctx, "pw-a", vm.Command{}, time.Second); err != nil {
		t.Fatalf("exec in the live worker: %v", err)
	}
	if err := g.s.Destroy(ctx, "pw-a"); err != nil {
		t.Fatal(err)
	}
	if err := g.s.Destroy(ctx, "pw-x"); err != nil || len(g.h.destroyed) != 1 {
		t.Fatalf("destroying a worker setup did not make reached the machines: %v %v", err, g.h.destroyed)
	}
	if _, err := g.s.CreateProviderWorker(ctx, "pw-b", vm.Spec{}, nil); err != nil {
		t.Fatalf("a sign-in after the last one ended: %v", err)
	}
	if g.opens != 2 {
		t.Fatalf("opens = %d, want 2 (one failed, one kept)", g.opens)
	}
}

// Setup's end destroys the live sign-in worker before agentosd opens its
// own machines, and refuses every later call, so no worker outlives setup.
func TestONB3SetupEndDestroysTheSignInWorker(t *testing.T) {
	ctx := context.Background()
	g := newSetupRig(0)
	if _, err := g.s.CreateProviderWorker(ctx, "pw-a", vm.Spec{}, nil); err != nil {
		t.Fatal(err)
	}
	g.s.Close(ctx)
	if len(g.h.live) != 0 || fmt.Sprint(g.h.destroyed) != "[pw-a]" {
		t.Fatalf("after setup: live %v, destroyed %v", g.h.live, g.h.destroyed)
	}
	if _, err := g.s.CreateProviderWorker(ctx, "pw-b", vm.Spec{}, nil); !errors.Is(err, errSetupOver) {
		t.Fatalf("a worker after setup: %v", err)
	}
	if _, err := g.s.Exec(ctx, "pw-a", vm.Command{}, time.Second); !errors.Is(err, errSetupOver) {
		t.Fatalf("exec after setup: %v", err)
	}
	if err := g.s.Destroy(ctx, "pw-a"); err != nil || len(g.h.destroyed) != 1 {
		t.Fatalf("destroy after setup: %v %v", err, g.h.destroyed)
	}
	// Closing a setup that never signed in opens nothing.
	n := newSetupRig(0)
	n.s.Close(ctx)
	if n.opens != 0 {
		t.Fatal("closing setup opened machines")
	}
}

// The shipped Codex route's gate is closed until its image pins a CLI
// version (#1877): setup neither offers nor starts its sign-in, and opens
// no machine trying (ONB-3 fails closed).
func TestONB3SetupOffersNoSignInWhileTheGateIsClosed(t *testing.T) {
	g := newSetupRig(0)
	s := newSetupSignIn(g.s, modelroute.NewRouteControl(t.TempDir()+"/none.sock"))
	if s.Ready("codex") || s.Ready("nosuch") {
		t.Fatal("a sign-in is offered behind a closed gate")
	}
	if _, _, _, err := s.Start(context.Background(), "codex"); err == nil {
		t.Fatal("a sign-in started behind a closed gate")
	}
	if g.opens != 0 {
		t.Fatal("a refused sign-in opened machines")
	}
	if got := s.r.Decls["codex"].SignInFrom; got != "OpenAI" {
		t.Fatalf("codex's issuer = %q, want OpenAI (SPEC §8.1 step 6)", got)
	}
}

// A sign-in already running reads on the page as busy; other refusals
// pass as they are.
func TestONB3SetupBusySignInIsThePagesBusy(t *testing.T) {
	if !errors.Is(signInErr(provagent.ErrSignInBusy), localsrv.SignInBusy) {
		t.Fatal("busy is not the page's busy")
	}
	other := errors.New("gate")
	if signInErr(other) != other {
		t.Fatal("another refusal changed")
	}
}
