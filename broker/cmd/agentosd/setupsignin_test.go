package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
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

// With no image pin (#1877) and no qualification record (#809), the
// shipped Codex route's gate is closed: setup neither offers nor starts its
// sign-in, and opens no machine trying (ONB-3 fails closed).
func TestONB3SetupOffersNoSignInWhileTheGateIsClosed(t *testing.T) {
	g := newSetupRig(0)
	s := newSetupSignIn(g.s, modelroute.NewRouteControl(t.TempDir()+"/none.sock"), nil)
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

// signInMachine is a provider worker whose sign-in CLI has printed its
// link and code and still waits for the owner.
type signInMachine struct{ machineHost }

func (h *signInMachine) Exec(_ context.Context, _ string, c vm.Command, _ time.Duration) (vm.ExecResult, error) {
	if len(c.Argv) == 2 && c.Argv[0] == "cat" && strings.HasSuffix(c.Argv[1], "/.agentos-signin") {
		return vm.ExecResult{Stdout: []byte("Open https://auth.openai.com/codex/device and enter ABCD-EF23\n")}, nil
	}
	return vm.ExecResult{}, nil // the CLI's status file: not written yet
}

// openSetupSignIn is setup's sign-in over a setupHost on h, with the
// codex gate open (#809/#1877 stand-ins) and a fast poll, against a vault
// process that holds an earlier plan login (/plan granted) and answers
// /signedin with stored. asked counts the /signedin calls.
func openSetupSignIn(t *testing.T, h *signInMachine, stored *atomic.Bool, asked *atomic.Int32) (setupSignIn, *setupHost) {
	t.Helper()
	host := newSetupHost(func(context.Context) (provagent.Host, error) { return h, nil })
	rc := planServerStored(t, http.StatusOK, `{"granted":true}`, http.StatusOK, "{}", func(string) (int, string) {
		asked.Add(1)
		if stored.Load() {
			return http.StatusOK, `{"stored":true}`
		}
		return http.StatusOK, `{"stored":false}`
	})
	s := newSetupSignIn(host, rc, nil)
	d := s.r.Decls["codex"]
	d.Q = provagent.Qualification{CLIVersion: "1", Evidence: "e", TermsURL: "https://t.test", TermsRead: "2026-10-01", Verdict: provagent.Allowed}
	s.r.Decls["codex"] = d
	s.r.ImageVersion = func(string) string { return "1" }
	s.r.SignInTimes = provagent.SignInTimes{Poll: 5 * time.Millisecond, Link: time.Second, Wall: time.Hour}
	return s, host
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Security B1 (#1888): a plan login the vault already held when setup's
// sign-in started does not sign this sign-in in; only the vault's record
// that this worker's own sign-in stored the login does.
func TestONB3SetupSignInIgnoresAnEarlierLogin(t *testing.T) {
	var stored atomic.Bool
	var asked atomic.Int32
	h := &signInMachine{machineHost{live: map[string]bool{}}}
	s, host := openSetupSignIn(t, h, &stored, &asked)
	defer host.Close(context.Background())
	var signed atomic.Int32
	s.r.OnSignedIn = func(string) { signed.Add(1) }
	if !s.Ready("codex") {
		t.Fatal("the open gate offers no sign-in")
	}
	link, code, from, err := s.Start(context.Background(), "codex")
	if err != nil || link != "https://auth.openai.com/codex/device" || code != "ABCD-EF23" || from != "OpenAI" {
		t.Fatalf("start: %q %q %q %v", link, code, from, err)
	}
	waitFor(t, "the vault to be asked three times", func() bool { return asked.Load() >= 3 })
	if signed.Load() != 0 {
		t.Fatal("an earlier stored login signed this sign-in in")
	}
	if _, _, _, err := s.Start(context.Background(), "codex"); !errors.Is(err, localsrv.SignInBusy) {
		t.Fatalf("a second sign-in while the first waits: %v", err)
	}
	stored.Store(true)
	waitFor(t, "the sign-in to land", func() bool { return signed.Load() == 1 })
	waitFor(t, "the worker to be destroyed", func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.destroyed) == 1 && len(h.live) == 0
	})
}

// Security B1, PUX L2 (#1888): setup's end stops a sign-in still waiting
// for the owner (Background), rather than leaving it polling the vault
// process until its code expires.
func TestONB3SetupEndStopsTheSignInWait(t *testing.T) {
	var stored atomic.Bool
	var asked atomic.Int32
	h := &signInMachine{machineHost{live: map[string]bool{}}}
	s, host := openSetupSignIn(t, h, &stored, &asked)
	if _, _, _, err := s.Start(context.Background(), "codex"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the wait to poll", func() bool { return asked.Load() >= 1 })
	host.Close(context.Background())
	// The wait's end releases the busy claim: a later Start fails on the
	// closed machines, not as busy.
	waitFor(t, "the wait to end", func() bool {
		_, _, _, err := s.Start(context.Background(), "codex")
		return err != nil && !errors.Is(err, localsrv.SignInBusy)
	})
	n := asked.Load()
	time.Sleep(50 * time.Millisecond)
	if asked.Load() != n {
		t.Fatal("the vault is still polled after setup ended")
	}
}

// fixedSignIn is a setup sign-in ready for codex alone.
type fixedSignIn struct{ starts atomic.Int32 }

func (f *fixedSignIn) Ready(p string) bool { return p == "codex" }
func (f *fixedSignIn) Start(context.Context, string) (string, string, string, error) {
	f.starts.Add(1)
	return "https://auth.openai.com/codex/device", "ABCD-EF23", "OpenAI", nil
}

// planVault serves the verify socket's provider list with an API-key
// provider and the codex plan.
func planVault(t *testing.T) enroller {
	t.Helper()
	path := filepath.Join(shortDir(t), "v.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/setup/providers" {
			io.WriteString(w, `{"providers":[{"id":"openai","name":"OpenAI"},{"id":"codex","name":"ChatGPT plan","plan":true}]}`)
			return
		}
		io.WriteString(w, `{}`)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return enroller{modelroute.NewVerifier(path)}
}

// PUX R2 (#1888): agentosd's setup mode wires the vault's plan route to
// the page as a device-code sign-in and starts it through setup's SignIn:
// the plan lists device_code and no key, an adapter the reverse, and the
// op reaches SignIn.
func TestONB3SetupModeWiresThePlanSignIn(t *testing.T) {
	m := newSetupMode(t)
	m.Enroll = planVault(t)
	si := &fixedSignIn{}
	m.SignIn = si
	ctx, cancel := context.WithCancel(context.Background())
	done := start(ctx, m)
	defer func() { cancel(); <-done }()
	call := setupCall(t, m)
	var ps localapi.SetupProviders
	if err := call(localapi.OpSetupProviders, nil, &ps); err != nil {
		t.Fatal(err)
	}
	want := map[string][2]bool{"openai": {true, false}, "codex": {false, true}}
	if len(ps.Providers) != 2 {
		t.Fatalf("providers %+v", ps.Providers)
	}
	for _, p := range ps.Providers {
		if w, ok := want[p.ID]; !ok || p.APIKey != w[0] || p.DeviceCode != w[1] {
			t.Fatalf("%s: api_key %v, device_code %v", p.ID, p.APIKey, p.DeviceCode)
		}
	}
	var d localapi.DeviceCode
	if err := call(localapi.OpSetupDeviceCode, localapi.DeviceCodeStart{Provider: "codex"}, &d); err != nil {
		t.Fatalf("plan sign-in: %v", err)
	}
	if d.Link != "https://auth.openai.com/codex/device" || d.Code != "ABCD-EF23" || d.From != "OpenAI" || si.starts.Load() != 1 {
		t.Fatalf("plan sign-in answered %q %q %q after %d starts", d.Link, d.Code, d.From, si.starts.Load())
	}
}

// verbSock is a fake provider control socket: it records each verb and
// answers an open with the worker's route directory.
func verbSock(t *testing.T) (string, func() []string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "vs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "c.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var verbs []string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		verbs = append(verbs, strings.TrimPrefix(r.URL.Path, "/"))
		mu.Unlock()
		fmt.Fprintf(w, `{"Dir":%q}`, "/routes/"+r.URL.Query().Get("machine"))
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return path, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), verbs...)
	}
}

// The worker a setup sign-in marks opens its route as a sign-in route: the
// runner that marks it and the machines that open it share one route
// control. Two controls opened setup's sign-in worker on a run route,
// which refuses the CLI's device-code calls (#1701, G1 guest-task).
func TestONB3SetupSignInWorkerOpensASignInRoute(t *testing.T) {
	sock, verbs := verbSock(t)
	c := setupMachines{rc: modelroute.NewRouteControl(sock)}
	_, si := newSetupPlane(c, nil)
	id := vm.ProviderPrefix + "abc123"
	si.r.SignInFor(id)
	if _, err := c.providerRoutes().Open(id); err != nil {
		t.Fatal(err)
	}
	if got := verbs(); len(got) != 1 || got[0] != "signin" {
		t.Fatalf("the sign-in worker's route opened with %v, not signin", got)
	}
}
