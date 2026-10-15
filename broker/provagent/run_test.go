package provagent

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: CAP-11, CAP-9, CRED-5, CRED-7, RES-5, OP-8, A3, A14

// stub is a fake host: Exec plays the CLI. The "drive" holds every file the
// worker wrote and is emptied when the worker is destroyed.
type stub struct {
	mu         sync.Mutex
	created    []string
	specs      []vm.Spec
	seeds      []map[string][]byte
	destroyed  []string
	runs       []vm.Command
	drive      map[string]string
	live       map[string]bool
	cli        func(c vm.Command, s *stub) vm.ExecResult // the CLI's behaviour
	hang       bool
	createErr  error
	destroyErr error
}

func newStub(cli func(c vm.Command, s *stub) vm.ExecResult) *stub {
	return &stub{drive: map[string]string{}, live: map[string]bool{}, cli: cli}
}

func (s *stub) CreateProviderWorker(_ context.Context, id string, sp vm.Spec, seed map[string][]byte) (vm.Machine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.createErr != nil {
		return vm.Machine{}, s.createErr
	}
	s.created, s.specs, s.seeds = append(s.created, id), append(s.specs, sp), append(s.seeds, seed)
	s.live[id] = true
	return vm.Machine{ID: id}, nil
}

func (s *stub) Destroy(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.destroyed = append(s.destroyed, id)
	delete(s.live, id)
	s.drive = map[string]string{}
	return s.destroyErr
}

func (s *stub) Exec(ctx context.Context, id string, c vm.Command, to time.Duration) (vm.ExecResult, error) {
	s.mu.Lock()
	if !s.live[id] {
		s.mu.Unlock()
		return vm.ExecResult{}, errors.New("no such machine")
	}
	if len(c.Argv) > 0 && c.Argv[0] == "cat" { // the result read
		out := s.drive[c.Argv[1]]
		s.mu.Unlock()
		r := vm.ExecResult{Stdout: []byte(out)}
		if c.MaxOutput > 0 && len(r.Stdout) > c.MaxOutput {
			r.Stdout, r.Truncated = r.Stdout[:c.MaxOutput], true
		}
		return r, nil
	}
	s.runs = append(s.runs, c)
	hang := s.hang
	s.mu.Unlock()
	if hang {
		select {
		case <-ctx.Done():
			return vm.ExecResult{TimedOut: true, ExitCode: -1}, nil
		case <-time.After(5 * time.Second):
		}
	}
	return s.cli(c, s), nil
}

func (s *stub) write(path, text string) { s.mu.Lock(); s.drive[path] = text; s.mu.Unlock() }

// outPath is where Command redirects the CLI's stdout: the declared result.
func ok(text string) func(vm.Command, *stub) vm.ExecResult {
	return func(c vm.Command, s *stub) vm.ExecResult {
		s.write("/work/.result", text)
		return vm.ExecResult{}
	}
}

type seeder struct {
	mu        sync.Mutex
	err       error
	calls     []string
	providers []string
	closed    []string
}

func (s *seeder) Close(id string) { s.mu.Lock(); s.closed = append(s.closed, id); s.mu.Unlock() }

func (s *seeder) Seed(provider, id string) (map[string][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls, s.providers = append(s.calls, id), append(s.providers, provider)
	if s.err != nil {
		return nil, s.err
	}
	return map[string][]byte{"auth.json": []byte(`{"placeholder":true}`)}, nil
}

type rig struct {
	h       *stub
	sd      *seeder
	r       *Runner
	events  []Event
	signins []string
	granted bool
	private bool
	consent bool
	logs    []string

	// mu guards what concurrent runs touch: the broker's usage view, the
	// clock, the journal and the IDs.
	mu       sync.Mutex
	usage    Usage
	usageErr error
	now      time.Time
	ids      int
}

// t0 is the rig's clock at the start of every test.
var t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// fresh is a reading of pool taken now, with left of it remaining.
func fresh(pool string, left float64) Reading { return Reading{Pool: pool, Left: left, At: t0} }

func (g *rig) setUsage(u Usage)        { g.mu.Lock(); g.usage = u; g.mu.Unlock() }
func (g *rig) advance(d time.Duration) { g.mu.Lock(); g.now = g.now.Add(d); g.mu.Unlock() }
func (g *rig) clock() time.Time        { g.mu.Lock(); defer g.mu.Unlock(); return g.now }
func (g *rig) refuseLogin(c vm.Command, s *stub) vm.ExecResult {
	// The broker saw the provider refuse the login's refresh during the run.
	g.mu.Lock()
	g.usage.LoginRefused = g.now
	g.mu.Unlock()
	return ok("partial")(c, s)
}

func newRig(cli func(vm.Command, *stub) vm.ExecResult) *rig {
	g := &rig{h: newStub(cli), sd: &seeder{}, granted: true, private: true, now: t0, usage: Usage{Readings: []Reading{fresh("5h", 0.9)}}}
	d := good()
	d.Q = qualified()
	dd := good()
	dd.ID, dd.TaskClasses = "credit", []string{"code"}
	dd.Q = qualified()
	g.r = &Runner{
		Host: g.h, Seeder: g.sd,
		Decls:        map[string]Declaration{"stub": d, "credit": dd, "codex": Builtins()["codex"], "claude": Builtins()["claude"]},
		ImageVersion: func(string) string { return "1.0.0" },
		Granted:      func(string) bool { return g.granted },
		PrivateOK:    func(string) bool { return g.private },
		Consent:      func(string) bool { return g.consent },
		Usage: func(string) (Usage, error) {
			g.mu.Lock()
			defer g.mu.Unlock()
			u := g.usage
			u.Readings = append([]Reading(nil), u.Readings...)
			return u, g.usageErr
		},
		Reserve: func(string, string) float64 { return 0.1 },
		Now:     g.clock,
		Journal: func(e Event) { g.mu.Lock(); g.events = append(g.events, e); g.mu.Unlock() },
		SignIn:  func(p string) { g.mu.Lock(); g.signins = append(g.signins, p); g.mu.Unlock() },
		Logf:    func(f string, a ...any) { g.mu.Lock(); g.logs = append(g.logs, fmt.Sprintf(f, a...)); g.mu.Unlock() },
		Caps:    Caps{Wall: 2 * time.Second, Result: 1 << 10, Brief: 1 << 10},
		NewID:   func() string { g.mu.Lock(); defer g.mu.Unlock(); g.ids++; return fmt.Sprintf("pw-%04d", g.ids) },
	}
	return g
}

func req(brief string) Request {
	return Request{Provider: "stub", Brief: brief, TaskClass: "code", Label: vm.Public, Class: admission.Accepted, MemMB: 512}
}

func reasonOf(err error) Reason {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}

func TestRunsAStubEndToEnd(t *testing.T) {
	g := newRig(ok("the answer"))
	out, err := g.r.Run(context.Background(), req("do the thing"))
	if err != nil || out != "the answer" {
		t.Fatalf("run: %q %v", out, err)
	}
	if len(g.h.created) != 1 || !strings.HasPrefix(g.h.created[0], "pw-") || len(g.h.destroyed) != 1 {
		t.Errorf("worker lifecycle: %v %v", g.h.created, g.h.destroyed)
	}
	if len(g.sd.calls) != 1 || g.sd.calls[0] != g.h.created[0] || g.sd.providers[0] != "stub" {
		t.Errorf("seed for %v: %v %v", g.h.created, g.sd.calls, g.sd.providers)
	}
}

func TestRunInheritsLabelAndReservationAndIsGoneAfter(t *testing.T) {
	g := newRig(ok("x"))
	rq := req("b")
	rq.Label, rq.Class, rq.MemMB = vm.Public, admission.Experiment, 300
	if _, err := g.r.Run(context.Background(), rq); err != nil {
		t.Fatal(err)
	}
	sp := g.h.specs[0]
	if sp.Class != admission.Experiment || sp.MemMB != 300 || sp.Image != "stub-image" {
		t.Errorf("spec %+v", sp)
	}
	if sp.Label != vm.Private {
		t.Errorf("a provider worker is always private: %v", sp.Label)
	}
	if len(g.h.live) != 0 {
		t.Errorf("worker left: %v", g.h.live)
	}
}

func TestRefusalsAreClosedReasons(t *testing.T) {
	cases := []struct {
		name string
		set  func(g *rig, r *Request)
		want Reason
	}{
		{"ungranted", func(g *rig, _ *Request) { g.granted = false }, Ungranted},
		{"unsigned", func(g *rig, _ *Request) { g.sd.err = fmt.Errorf("x: %w", ErrNoLogin) }, Unsigned},
		{"private unmarked", func(g *rig, r *Request) { g.private, r.Label = false, vm.Private }, PrivateUnmarked},
		{"unknown provider", func(_ *rig, r *Request) { r.Provider = "nope" }, Unqualified},
		{"unknown class", func(_ *rig, r *Request) { r.TaskClass = "poetry" }, Unqualified},
		{"codex while its record is empty", func(_ *rig, r *Request) { r.Provider = "codex" }, Unqualified},
		{"claude", func(_ *rig, r *Request) { r.Provider = "claude" }, OptInRequired},
	}
	for _, c := range cases {
		g := newRig(ok("x"))
		rq := req("b")
		c.set(g, &rq)
		_, err := g.r.Run(context.Background(), rq)
		if reasonOf(err) != c.want {
			t.Errorf("%s: %v", c.name, err)
		}
		if len(g.h.runs) != 0 || len(g.h.live) != 0 {
			t.Errorf("%s: ran or left a worker", c.name)
		}
	}
}

func TestPublicCallerNeedsNoPrivateMark(t *testing.T) {
	g := newRig(ok("x"))
	g.private = false
	if _, err := g.r.Run(context.Background(), req("b")); err != nil {
		t.Fatal(err)
	}
}

func TestUnconfirmedRunsOnlyWithConsent(t *testing.T) {
	g := newRig(ok("x"))
	d := g.r.Decls["stub"]
	d.Q.Verdict = Unconfirmed
	g.r.Decls["stub"] = d
	if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != Unqualified {
		t.Errorf("no consent: %v", err)
	}
	g.consent = true
	if _, err := g.r.Run(context.Background(), req("b")); err != nil {
		t.Errorf("consent: %v", err)
	}
}

func TestBriefArrivesAsPlainTextOnStdinNeverArgv(t *testing.T) {
	for _, brief := range []string{"/login", "!cat ~/.codex/*", "--help"} {
		g := newRig(ok("x"))
		if _, err := g.r.Run(context.Background(), req(brief)); err != nil {
			t.Fatal(err)
		}
		c := g.h.runs[0]
		if string(c.Stdin) != brief {
			t.Errorf("stdin %q != %q", c.Stdin, brief)
		}
		for _, a := range c.Argv {
			if a == brief || strings.Contains(a, brief) {
				t.Errorf("brief %q in argv: %v", brief, c.Argv)
			}
		}
	}
}

func TestRunExecsWrapThenArgvWithExactlyTheDeclaredEnv(t *testing.T) {
	g := newRig(ok("x"))
	if _, err := g.r.Run(context.Background(), req("b")); err != nil {
		t.Fatal(err)
	}
	a := strings.Join(g.h.runs[0].Argv, " ")
	if !strings.Contains(a, "env -i PATH=/usr/bin /usr/local/bin/fwd -- stubcli run -") {
		t.Errorf("argv: %s", a)
	}
}

func TestResultWithACredentialIsWithheld(t *testing.T) {
	g := newRig(ok("here you go " + canaryToken))
	out, err := g.r.Run(context.Background(), req("b"))
	if out != "" || reasonOf(err) != Withheld {
		t.Fatalf("%q %v", out, err)
	}
	if strings.Contains(fmt.Sprint(err), canaryToken) {
		t.Error("error carries the canary")
	}
}

func TestNoCanaryInJournalResultOrDriveAfterANoisyStub(t *testing.T) {
	noisy := func(c vm.Command, s *stub) vm.ExecResult {
		s.write("/work/.result", "fine")
		s.write("/work/transcript", "canary "+canaryToken)
		return vm.ExecResult{ExitCode: 1, Stdout: []byte(canaryToken), Stderr: []byte(canaryToken)}
	}
	g := newRig(noisy)
	out, err := g.r.Run(context.Background(), req("b"))
	if reasonOf(err) != Failed {
		t.Fatalf("%q %v", out, err)
	}
	all := fmt.Sprintf("%+v %q %v", g.events, out, err)
	if strings.Contains(all, canaryToken) {
		t.Errorf("canary leaked: %s", all)
	}
	for p, v := range g.h.drive {
		t.Errorf("drive keeps %s: %s", p, v)
	}
	if len(g.events) != 1 {
		t.Errorf("journal: %d events", len(g.events))
	}
}

func TestCapsStopAHungStub(t *testing.T) {
	g := newRig(ok("late"))
	g.h.hang = true
	g.r.Caps.Wall = 50 * time.Millisecond
	start := time.Now()
	_, err := g.r.Run(context.Background(), req("b"))
	if reasonOf(err) != TimedOut || time.Since(start) > time.Second {
		t.Errorf("%v after %v", err, time.Since(start))
	}
	if len(g.h.destroyed) != 1 {
		t.Error("worker kept")
	}
}

func TestOversizeResultAndBriefFail(t *testing.T) {
	g := newRig(ok(strings.Repeat("a", 5000)))
	if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != Failed {
		t.Errorf("oversize result: %v", err)
	}
	g = newRig(ok("x"))
	if _, err := g.r.Run(context.Background(), req(strings.Repeat("b", 5000))); reasonOf(err) != Failed {
		t.Errorf("oversize brief: %v", err)
	}
	if len(g.h.created) != 0 {
		t.Error("worker made for an oversize brief")
	}
}

func TestUsedUpFallsBack(t *testing.T) {
	g := newRig(ok(`{"type":"error","message":"usage_limit_reached"}`))
	_, err := g.r.Run(context.Background(), req("b"))
	if reasonOf(err) != UsedUp || !FallsBack(err) {
		t.Errorf("%v", err)
	}
}

// RES-5, W8: a pool the broker saw exhausted during the run (a credit
// draw or a reached limit on its own connection) is used-up, whatever the
// result says. An exhausted reading from before the run is not this run's.
func TestAPoolExhaustedDuringTheRunIsUsedUp(t *testing.T) {
	g := newRig(nil)
	g.h.cli = func(c vm.Command, s *stub) vm.ExecResult {
		g.setUsage(Usage{Readings: []Reading{fresh("5h", 0.9), {Pool: "5h", Left: 0, At: g.clock(), Exhausted: true}}})
		return ok("fine")(c, s)
	}
	_, err := g.r.Run(context.Background(), req("b"))
	if reasonOf(err) != UsedUp || !FallsBack(err) {
		t.Errorf("%v", err)
	}
	g = newRig(nil)
	g.setUsage(Usage{Readings: []Reading{fresh("5h", 0.9), {Pool: "7d", Left: 0, At: t0.Add(-DefaultMaxAge), Exhausted: true}}})
	g.advance(time.Second)
	g.h.cli = ok("fine")
	if out, err := g.r.Run(context.Background(), req("b")); err != nil || out != "fine" {
		t.Errorf("an exhaustion before the run: %q %v", out, err)
	}
}

// CRED-5: a refused login stops the route for later runs too. The refusal
// is the broker's own reading of the refresh on its upstream connection,
// never the result file. The second run seeds nothing, starts no worker or
// CLI, and the owner is told once.
func TestARefusedLoginStopsTheRouteOnceAndDoesNotRetry(t *testing.T) {
	g := newRig(nil)
	g.h.cli = g.refuseLogin
	_, err := g.r.Run(context.Background(), req("b"))
	if reasonOf(err) != LoginRefused || !FallsBack(err) {
		t.Fatalf("%v", err)
	}
	_, err = g.r.Run(context.Background(), req("b"))
	if reasonOf(err) != LoginRefused || !FallsBack(err) {
		t.Fatalf("second run: %v", err)
	}
	if len(g.h.runs) != 1 || len(g.h.created) != 1 || len(g.sd.calls) != 1 {
		t.Errorf("CLI started %d times, %d workers, %d seeds", len(g.h.runs), len(g.h.created), len(g.sd.calls))
	}
	if len(g.signins) != 1 || g.signins[0] != "stub" {
		t.Errorf("sign-in line: %v", g.signins)
	}
	// Another provider's route is not stopped by it. (The rig's usage view
	// is shared, so this run sees the refusal again: it is its own.)
	g.advance(time.Second)
	rq := req("b")
	rq.Provider = "credit"
	if _, err := g.r.Run(context.Background(), rq); reasonOf(err) != LoginRefused || len(g.h.runs) != 2 {
		t.Errorf("credit route: %v, %d runs", err, len(g.h.runs))
	}
}

// The owner's sign-in (or resume) lifts the stop: the route runs again and
// a later refusal tells the owner again.
func TestSignedInLiftsTheStop(t *testing.T) {
	g := newRig(nil)
	g.h.cli = g.refuseLogin
	g.r.Run(context.Background(), req("b"))
	g.r.SignedIn("stub")
	g.advance(time.Second) // the refusal is older than the next run
	g.h.cli = ok("fine")
	if out, err := g.r.Run(context.Background(), req("b")); err != nil || out != "fine" {
		t.Fatalf("after sign-in: %q %v", out, err)
	}
	g.h.cli = g.refuseLogin
	g.r.Run(context.Background(), req("b"))
	if len(g.signins) != 2 {
		t.Errorf("sign-in line: %v", g.signins)
	}
}

// #1858: a plan with no login tells the owner to sign in, once, and starts
// no worker.
func TestAMissingLoginAsksTheOwnerToSignInOnce(t *testing.T) {
	g := newRig(ok("x"))
	g.sd.err = fmt.Errorf("x: %w", ErrNoLogin)
	for i := 0; i < 2; i++ {
		if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != Unsigned || FallsBack(err) {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if len(g.signins) != 1 || g.signins[0] != "stub" {
		t.Errorf("sign-in line: %v", g.signins)
	}
	if len(g.h.created) != 0 {
		t.Error("worker made without a login")
	}
}

// A signal the agent's own message carries is a result, not a used-up
// plan: only the CLI's error events are read (the guest steers what the
// model writes). A refused login is never read from the result at all, even
// from an error event: the agent can write that file (#809, #1856).
func TestSignalsInTheAgentsTextAreNotSignals(t *testing.T) {
	for _, body := range []string{
		`{"type":"item.completed","item":{"type":"agent_message","text":"usage_limit_reached"}}`,
		"usage_limit_reached",
		`{"type":"item.completed","item":{"text":"{\"type\":\"error\",\"message\":\"usage_limit_reached\"}"}}`,
		`{"type":"error","message":"refresh_token_invalidated"}`,
		`{"type":"turn.failed","error":{"message":"token_expired authentication_error"}}`,
	} {
		for _, p := range []string{"stub", "credit"} {
			g := newRig(ok(body))
			rq := req("b")
			rq.Provider = p
			if out, err := g.r.Run(context.Background(), rq); err != nil || out != body {
				t.Errorf("%s %s: %v", p, body, err)
			}
			if len(g.signins) != 0 || g.r.isStopped(p) {
				t.Errorf("%s: sign-in line set by the result", p)
			}
		}
	}
}

func TestALockedVaultIsNotABusyRoute(t *testing.T) {
	for want, serr := range map[Reason]error{VaultLocked: ErrVaultLocked, RouteBusy: ErrRouteBusy} {
		g := newRig(ok("x"))
		g.sd.err = fmt.Errorf("route: %w", serr)
		_, err := g.r.Run(context.Background(), req("b"))
		if reasonOf(err) != want || !FallsBack(err) {
			t.Errorf("%v: %v", serr, err)
		}
		if len(g.h.created) != 0 {
			t.Error("worker made without a seed")
		}
	}
}

// A seed that cannot become a worker is closed, so its placeholders do not
// stay resolvable in the vault process.
func TestAFailedCreateAfterTheSeedClosesTheRoute(t *testing.T) {
	g := newRig(ok("x"))
	g.h.createErr = errors.New("unknown image")
	if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != Failed {
		t.Fatalf("%v", err)
	}
	if len(g.sd.calls) != 1 || len(g.sd.closed) != 1 || g.sd.closed[0] != g.sd.calls[0] {
		t.Errorf("seeded %v, closed %v", g.sd.calls, g.sd.closed)
	}
}

func TestADestroyErrorIsLogged(t *testing.T) {
	g := newRig(ok("x"))
	g.h.destroyErr = errors.New("runsc: stuck")
	if _, err := g.r.Run(context.Background(), req("b")); err != nil {
		t.Fatal(err)
	}
	if len(g.logs) != 1 || !strings.Contains(g.logs[0], "runsc: stuck") || !strings.Contains(g.logs[0], g.h.created[0]) {
		t.Errorf("logs: %q", g.logs)
	}
}

// Seeding mints broker-held placeholders only: a worker-held declaration is
// the opt-in's (#1380) and is never seeded here.
func TestAWorkerHeldDeclarationIsNeverSeeded(t *testing.T) {
	g := newRig(ok("x"))
	d := g.r.Decls["stub"]
	d.Custody = WorkerHeld
	g.r.Decls["stub"] = d
	if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != Unqualified {
		t.Fatalf("%v", err)
	}
	if len(g.sd.calls) != 0 || len(g.h.created) != 0 {
		t.Error("worker-held declaration seeded")
	}
}

func TestAFailedRunFallsBack(t *testing.T) {
	g := newRig(func(vm.Command, *stub) vm.ExecResult { return vm.ExecResult{ExitCode: 2} })
	_, err := g.r.Run(context.Background(), req("b"))
	if reasonOf(err) != Failed || !FallsBack(err) {
		t.Errorf("%v", err)
	}
}

func TestPoolAtOrBelowTheReserveRefusesAdmission(t *testing.T) {
	for _, left := range []float64{0.1, 0.05, 0} {
		g := newRig(ok("x"))
		g.setUsage(Usage{Readings: []Reading{fresh("5h", 0.9), fresh("7d", left)}})
		_, err := g.r.Run(context.Background(), req("b"))
		if reasonOf(err) != PoolAtReserve || len(g.h.created) != 0 {
			t.Errorf("left %v: %v", left, err)
		}
	}
	g := newRig(ok("x"))
	g.setUsage(Usage{Readings: []Reading{fresh("5h", 0.5)}})
	if _, err := g.r.Run(context.Background(), req("b")); err != nil {
		t.Errorf("headroom: %v", err)
	}
}

// The reserve is the owner's, per provider and pool (RES-5, OP-5).
func TestTheReserveIsAskedPerProviderAndPool(t *testing.T) {
	g := newRig(ok("x"))
	g.setUsage(Usage{Readings: []Reading{fresh("5h", 0.5), fresh("7d", 0.3)}})
	var asked []string
	g.r.Reserve = func(provider, pool string) float64 {
		asked = append(asked, provider+"/"+pool)
		if pool == "7d" {
			return 0.4
		}
		return 0
	}
	if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != PoolAtReserve {
		t.Errorf("7d under its own reserve: %v", err)
	}
	if strings.Join(asked, " ") != "stub/5h stub/7d" {
		t.Errorf("asked %v", asked)
	}
}

// A pool at its reserve stays refused until its reset time, however old
// the reading: the reset time is the pool's cooldown (RES-5). After the
// reset, or once a reading with no reset time is stale, the pool is unread.
func TestAPoolAtReserveIsRefusedUntilItsReset(t *testing.T) {
	g := newRig(ok("x"))
	g.setUsage(Usage{Readings: []Reading{{Pool: "5h", Left: 0, At: t0, ResetAt: t0.Add(time.Hour)}}})
	g.advance(59 * time.Minute)
	if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != PoolAtReserve {
		t.Fatalf("before the reset: %v", err)
	}
	g.advance(time.Minute)
	if _, err := g.r.Run(context.Background(), req("b")); err != nil {
		t.Errorf("after the reset (a probe): %v", err)
	}
	g = newRig(ok("x"))
	g.setUsage(Usage{Readings: []Reading{fresh("5h", 0)}})
	g.advance(DefaultMaxAge)
	if _, err := g.r.Run(context.Background(), req("b")); err != nil {
		t.Errorf("a stale reading with no reset time (a probe): %v", err)
	}
}

// RES-5 fails closed where nothing can be read: no usage source, no
// reserve, an unreadable reading. An unreachable usage view is a busy
// route, a fallback. None starts a worker or panics.
func TestUnreadableUsageRefusesAdmission(t *testing.T) {
	cases := map[string]struct {
		set  func(g *rig)
		want Reason
	}{
		"no usage source": {func(g *rig) { g.r.Usage = nil }, PoolAtReserve},
		"no reserve":      {func(g *rig) { g.r.Reserve = nil }, PoolAtReserve},
		"NaN reading":     {func(g *rig) { g.setUsage(Usage{Readings: []Reading{fresh("5h", math.NaN())}}) }, PoolAtReserve},
		"NaN reserve": {func(g *rig) {
			g.r.Reserve = func(string, string) float64 { return math.NaN() }
		}, PoolAtReserve},
		"usage unreachable": {func(g *rig) { g.usageErr = errors.New("control socket down") }, RouteBusy},
	}
	for name, c := range cases {
		g := newRig(ok("x"))
		c.set(g)
		_, err := g.r.Run(context.Background(), req("b"))
		if reasonOf(err) != c.want || !FallsBack(err) || len(g.h.created) != 0 || len(g.sd.calls) != 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// RES-5 before the first reading: readings come only from the provider's
// responses on the broker's connection, so a pool nobody has run against
// is unread. One probe run is admitted per provider while it is unread or
// stale, alone, and at most once per MaxAge; its own responses are the
// reading the next admission uses.
func TestAnUnreadPoolAdmitsOneProbeRun(t *testing.T) {
	for name, u := range map[string]Usage{
		"no reading":           {},
		"declared pool unread": {Readings: []Reading{fresh("other", 0.9)}},
		"stale reading":        {Readings: []Reading{{Pool: "5h", Left: 0.9, At: t0.Add(-DefaultMaxAge)}}},
	} {
		g := newRig(nil)
		g.setUsage(u)
		var during error
		g.h.cli = func(c vm.Command, s *stub) vm.ExecResult {
			// A second run while the probe is out is refused.
			_, during = g.r.Run(context.Background(), req("b"))
			return ok("probe")(c, s)
		}
		if out, err := g.r.Run(context.Background(), req("b")); err != nil || out != "probe" {
			t.Fatalf("%s: probe: %q %v", name, out, err)
		}
		if reasonOf(during) != PoolAtReserve {
			t.Errorf("%s: run during the probe: %v", name, during)
		}
		// The probe brought no reading: no second probe until MaxAge.
		g.h.cli = ok("x")
		g.advance(DefaultMaxAge - time.Second)
		if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != PoolAtReserve {
			t.Errorf("%s: second probe within MaxAge: %v", name, err)
		}
		g.advance(time.Second)
		if _, err := g.r.Run(context.Background(), req("b")); err != nil {
			t.Errorf("%s: probe after MaxAge: %v", name, err)
		}
		if len(g.h.created) != 2 {
			t.Errorf("%s: %d workers", name, len(g.h.created))
		}
	}
	// A probe that brings a reading opens the route at once.
	g := newRig(nil)
	g.setUsage(Usage{})
	g.h.cli = func(c vm.Command, s *stub) vm.ExecResult {
		g.setUsage(Usage{Readings: []Reading{{Pool: "5h", Left: 0.8, At: g.clock()}}})
		return ok("x")(c, s)
	}
	for i := 0; i < 3; i++ {
		if _, err := g.r.Run(context.Background(), req("b")); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
}

// A probe that never reached the CLI (no login yet, a failed seed) read
// nothing, so it does not hold the next probe back.
func TestAProbeThatNeverRanIsForgotten(t *testing.T) {
	g := newRig(ok("x"))
	g.setUsage(Usage{})
	g.sd.err = fmt.Errorf("x: %w", ErrNoLogin)
	if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != Unsigned {
		t.Fatalf("%v", err)
	}
	g.sd.err = nil
	if _, err := g.r.Run(context.Background(), req("b")); err != nil {
		t.Errorf("probe after sign-in: %v", err)
	}
}

// RES-5: at most PerPool runs of one provider at once (2 by default); a
// third is a busy route, and another provider is not counted with it.
func TestConcurrentRunsAreCappedPerProvider(t *testing.T) {
	g := newRig(nil)
	g.setUsage(Usage{Readings: []Reading{fresh("5h", 0.9)}})
	in, release := make(chan struct{}, 2), make(chan struct{})
	g.h.cli = func(c vm.Command, s *stub) vm.ExecResult {
		in <- struct{}{}
		<-release
		return ok("x")(c, s)
	}
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, err := g.r.Run(context.Background(), req("b")); errs <- err }()
	}
	<-in
	<-in
	if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != RouteBusy || !FallsBack(err) {
		t.Errorf("third run: %v", err)
	}
	other := make(chan error, 1)
	go func() {
		rq := req("b")
		rq.Provider = "credit"
		_, err := g.r.Run(context.Background(), rq)
		other <- err
	}()
	<-in
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Errorf("capped run: %v", err)
		}
	}
	if err := <-other; err != nil {
		t.Errorf("other provider: %v", err)
	}
	// The slots are released on exit.
	g.h.cli = ok("x")
	if _, err := g.r.Run(context.Background(), req("b")); err != nil {
		t.Errorf("after: %v", err)
	}
}

func TestEveryRunIsJournaledWithoutOutput(t *testing.T) {
	g := newRig(ok("secret-looking but fine result text"))
	if _, err := g.r.Run(context.Background(), req("the brief text")); err != nil {
		t.Fatal(err)
	}
	all := fmt.Sprintf("%+v", g.events)
	if len(g.events) != 1 || strings.Contains(all, "result text") || strings.Contains(all, "the brief text") {
		t.Errorf("journal: %s", all)
	}
	if g.events[0].Provider != "stub" || g.events[0].Outcome != "ok" {
		t.Errorf("event %+v", g.events[0])
	}
}
