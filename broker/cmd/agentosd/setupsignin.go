package main

import (
	"context"
	"errors"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/provagent"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

// imageVersion is the CLI version a provider image pins. No image records
// one yet (#1877 fills it), so every plan route's gate stays closed and
// no sign-in is offered: the page fails closed.
func imageVersion(string) string { return "" }

// setupSignInMB is the memory a setup sign-in worker asks for: the CLI's
// login and nothing else.
const setupSignInMB = 1024

// setupSignIn is setup's plan sign-in (ONB-3, CRED-5; #1264 c4e2b): the
// page's "Use my plan" starts the provider's own CLI login in one private
// provider worker on a sign-in route, and the login it brings back lands
// in the vault, never here. It implements localsrv.SignIn.
type setupSignIn struct{ r *provagent.Runner }

// newSetupSignIn builds the sign-in over host. rc is the vault process's
// route control: it marks the worker's route a sign-in route and says
// whether the login took. Consent (CRED-5c) stays closed: Codex's route is
// Allowed and needs none, and Claude's opt-in is #1380's.
func newSetupSignIn(host provagent.Host, rc *modelroute.RouteControl) setupSignIn {
	return setupSignIn{&provagent.Runner{
		Host: host, Seeder: planSeeder{rc}, Decls: provagent.Builtins(),
		ImageVersion: imageVersion,
		Consent:      func(string) bool { return false },
		HasLogin:     func(p string) bool { return planLogin(rc, p) },
		SignInFor:    rc.SignInFor,
		Logf:         log.Printf,
		NewID:        func() string { return vm.ProviderPrefix + randHex(6) },
	}}
}

// Ready is whether provider's sign-in would start now.
func (s setupSignIn) Ready(provider string) bool { return s.r.CanSignIn(provider) }

// Start starts provider's sign-in and returns its page, code and issuer.
// Nothing the CLI printed but those crosses.
func (s setupSignIn) Start(ctx context.Context, provider string) (link, code, from string, err error) {
	link, code, err = s.r.StartSignIn(ctx, provider, admission.Accepted, setupSignInMB)
	if err != nil {
		return "", "", "", signInErr(err)
	}
	return link, code, s.r.Decls[provider].SignInFrom, nil
}

// signInErr is what the page hears of a refused sign-in: busy as the
// page's own busy, so it says to wait rather than that it failed.
func signInErr(err error) error {
	if errors.Is(err, provagent.ErrSignInBusy) {
		return localsrv.SignInBusy
	}
	return err
}

// errSetupOver refuses a machine call once setup has ended.
var errSetupOver = errors.New("setup: sign-in machines are closed")

// errOneWorker refuses a second sign-in worker while one lives.
var errOneWorker = errors.New("setup: a sign-in worker is already running")

// setupHost is setup mode's machine plane: at most one provider worker,
// on a machine manager opened on first use, so a box that never offers a
// sign-in opens none. Close destroys what it made and refuses all later
// calls; agentosd calls it before it opens its own manager on the same
// state directory.
type setupHost struct {
	open func(context.Context) (provagent.Host, error)

	mu     sync.Mutex
	h      provagent.Host
	live   map[string]bool
	closed bool
}

func newSetupHost(open func(context.Context) (provagent.Host, error)) *setupHost {
	return &setupHost{open: open, live: map[string]bool{}}
}

// CreateProviderWorker starts the one worker. The lock is held across the
// create, so Close cannot miss a worker half made.
func (s *setupHost) CreateProviderWorker(ctx context.Context, id string, sp vm.Spec, seed map[string][]byte) (vm.Machine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return vm.Machine{}, errSetupOver
	}
	if len(s.live) > 0 {
		return vm.Machine{}, errOneWorker
	}
	if s.h == nil {
		h, err := s.open(ctx)
		if err != nil {
			log.Printf("setup: sign-in machines: %v", err)
			return vm.Machine{}, err
		}
		s.h = h
	}
	m, err := s.h.CreateProviderWorker(ctx, id, sp, seed)
	if err == nil {
		s.live[id] = true
	}
	return m, err
}

// host is the manager, if id is a live worker of an open setup.
func (s *setupHost) host(id string) (provagent.Host, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errSetupOver
	}
	if !s.live[id] {
		return nil, vm.ErrUnknown
	}
	return s.h, nil
}

func (s *setupHost) Exec(ctx context.Context, id string, c vm.Command, timeout time.Duration) (vm.ExecResult, error) {
	h, err := s.host(id)
	if err != nil {
		return vm.ExecResult{}, err
	}
	return h.Exec(ctx, id, c, timeout)
}

// Destroy destroys a live worker; one Close already destroyed is gone.
func (s *setupHost) Destroy(ctx context.Context, id string) error {
	s.mu.Lock()
	h, ok := s.h, s.live[id]
	s.mu.Unlock()
	if !ok {
		return nil
	}
	err := h.Destroy(ctx, id)
	if err == nil {
		s.mu.Lock()
		delete(s.live, id)
		s.mu.Unlock()
	}
	return err
}

// Close ends setup's machines: every live worker is destroyed and every
// later call refused. A sign-in still waiting then ends without a login
// (one the owner already approved is in the vault).
func (s *setupHost) Close(ctx context.Context) {
	s.mu.Lock()
	s.closed = true
	h := s.h
	var ids []string
	for id := range s.live {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		if err := h.Destroy(ctx, id); err != nil {
			log.Printf("setup: destroy sign-in worker %s: %v", id, err)
			continue
		}
		s.mu.Lock()
		delete(s.live, id)
		s.mu.Unlock()
	}
}

// setupMachines is what setup's sign-in worker needs of the box: the
// same runtime, images, state directory, budgets and quotas as agentosd's
// own machines, opened only once a sign-in starts.
type setupMachines struct {
	runsc, stateDir, routes, diskQuota string
	images                             images
	cgroups                            func() (*cgroup.Group, error)
	admit                              admission.Config
	diskReserveMB, machineDiskMB       int64
	workerLayerMB                      int64
}

// open opens the manager. Admission is a controller of its own over the
// box's budget that preempts nothing: nothing else runs during setup.
func (c setupMachines) open(ctx context.Context) (provagent.Host, error) {
	g, err := c.cgroups()
	if err != nil {
		return nil, err
	}
	var notes []func() string
	md := openMachineDisk(c.diskQuota, c.stateDir, &notes)
	if md.err != nil {
		return nil, md.err
	}
	adm, err := admission.New(c.admit, noPreempt{})
	if err != nil {
		return nil, err
	}
	vmc := vm.Config{
		StateDir: c.stateDir,
		Images:   c.images,
		Runtime:  &gvisor.Runtime{Bin: c.runsc, StateDir: filepath.Join(c.stateDir, "runsc")},
		Admit:    adm,
		Cgroups:  g,

		DiskReserveBytes: c.diskReserveMB << 20,
		MachineDiskBytes: c.machineDiskMB << 20,
		WorkerLayerBytes: workerLayerBytes(c.workerLayerMB),
		ProviderRoutes:   modelroute.NewRouteControl(c.routes),
	}
	md.set(&vmc)
	m, err := vm.Open(ctx, vmc)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// noPreempt preempts nothing.
type noPreempt struct{}

func (noPreempt) Preempt(string) error { return errors.New("setup: nothing to preempt") }
