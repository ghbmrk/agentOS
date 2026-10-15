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
	err       error
	calls     []string
	providers []string
	closed    []string
}

func (s *seeder) Close(id string) { s.closed = append(s.closed, id) }

func (s *seeder) Seed(provider, id string) (map[string][]byte, error) {
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
	pools   []Reading
	logs    []string
}

func newRig(cli func(vm.Command, *stub) vm.ExecResult) *rig {
	g := &rig{h: newStub(cli), sd: &seeder{}, granted: true, private: true, pools: []Reading{{Pool: "5h", Left: 0.9}}}
	d := good()
	d.Q = qualified()
	dd := good()
	dd.ID, dd.TaskClasses = "credit", []string{"code"}
	dd.Q = qualified()
	dd.CreditDraw = []string{"credits_drawn"}
	g.r = &Runner{
		Host: g.h, Seeder: g.sd,
		Decls:        map[string]Declaration{"stub": d, "credit": dd, "codex": Builtins()["codex"], "claude": Builtins()["claude"]},
		ImageVersion: func(string) string { return "1.0.0" },
		Granted:      func(string) bool { return g.granted },
		PrivateOK:    func(string) bool { return g.private },
		Consent:      func(string) bool { return g.consent },
		Readings:     func(string) []Reading { return g.pools },
		Reserve:      func() float64 { return 0.1 },
		Journal:      func(e Event) { g.events = append(g.events, e) },
		SignIn:       func(p string) { g.signins = append(g.signins, p) },
		Logf:         func(f string, a ...any) { g.logs = append(g.logs, fmt.Sprintf(f, a...)) },
		Caps:         Caps{Wall: 2 * time.Second, Result: 1 << 10, Brief: 1 << 10},
		NewID:        func() string { return fmt.Sprintf("pw-%04d", len(g.h.created)) },
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

func TestACreditDrawIsUsedUp(t *testing.T) {
	g := newRig(ok(`{"type":"error","note":"credits_drawn"}`))
	rq := req("b")
	rq.Provider = "credit"
	_, err := g.r.Run(context.Background(), rq)
	if reasonOf(err) != UsedUp || !FallsBack(err) {
		t.Errorf("%v", err)
	}
	// The same text from a declaration with no credit signal is a result.
	g = newRig(ok(`{"type":"error","note":"credits_drawn"}`))
	if out, err := g.r.Run(context.Background(), req("b")); err != nil || out == "" {
		t.Errorf("plain declaration: %v", err)
	}
}

const refused = `{"type":"error","message":"login_refused"}`

// CRED-5: a refused login stops the route for later runs too. The second run
// seeds nothing, starts no worker or CLI, and the owner is told once.
func TestARefusedLoginStopsTheRouteOnceAndDoesNotRetry(t *testing.T) {
	g := newRig(ok(refused))
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
	// Another provider's route is not stopped by it.
	rq := req("b")
	rq.Provider = "credit"
	if _, err := g.r.Run(context.Background(), rq); reasonOf(err) != LoginRefused || len(g.h.runs) != 2 {
		t.Errorf("credit route: %v, %d runs", err, len(g.h.runs))
	}
}

// The owner's sign-in (or resume) lifts the stop: the route runs again and
// a later refusal tells the owner again.
func TestSignedInLiftsTheStop(t *testing.T) {
	g := newRig(ok(refused))
	g.r.Run(context.Background(), req("b"))
	g.r.SignedIn("stub")
	g.h.cli = ok("fine")
	if out, err := g.r.Run(context.Background(), req("b")); err != nil || out != "fine" {
		t.Fatalf("after sign-in: %q %v", out, err)
	}
	g.h.cli = ok(refused)
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

// A signal the agent's own message carries is a result, not a refused login
// or a used-up plan: only the CLI's error events are read (the guest steers
// what the model writes).
func TestSignalsInTheAgentsTextAreNotSignals(t *testing.T) {
	for _, body := range []string{
		`{"type":"item.completed","item":{"type":"agent_message","text":"login_refused usage_limit_reached credits_drawn"}}`,
		"login_refused usage_limit_reached credits_drawn",
		`{"type":"item.completed","item":{"text":"{\"type\":\"error\",\"message\":\"login_refused\"}"}}`,
	} {
		for _, p := range []string{"stub", "credit"} {
			g := newRig(ok(body))
			rq := req("b")
			rq.Provider = p
			if out, err := g.r.Run(context.Background(), rq); err != nil || out != body {
				t.Errorf("%s %s: %v", p, body, err)
			}
			if len(g.signins) != 0 {
				t.Errorf("%s: sign-in line set by model text", p)
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
		g.pools = []Reading{{Pool: "5h", Left: 0.9}, {Pool: "7d", Left: left}}
		_, err := g.r.Run(context.Background(), req("b"))
		if reasonOf(err) != PoolAtReserve || len(g.h.created) != 0 {
			t.Errorf("left %v: %v", left, err)
		}
	}
	g := newRig(ok("x"))
	g.pools = []Reading{{Pool: "5h", Left: 0.5}}
	if _, err := g.r.Run(context.Background(), req("b")); err != nil {
		t.Errorf("headroom: %v", err)
	}
}

// RES-5 fails closed: no readings, no reserve, an unread declared pool or an
// unreadable reading each refuse admission, and none panics.
func TestUnreadPoolsRefuseAdmission(t *testing.T) {
	cases := map[string]func(g *rig){
		"no readings source":   func(g *rig) { g.r.Readings = nil },
		"no reserve":           func(g *rig) { g.r.Reserve = nil },
		"no reading":           func(g *rig) { g.pools = nil },
		"declared pool unread": func(g *rig) { g.pools = []Reading{{Pool: "other", Left: 0.9}} },
		"NaN reading":          func(g *rig) { g.pools = []Reading{{Pool: "5h", Left: math.NaN()}} },
	}
	for name, set := range cases {
		g := newRig(ok("x"))
		set(g)
		_, err := g.r.Run(context.Background(), req("b"))
		if reasonOf(err) != PoolAtReserve || len(g.h.created) != 0 || len(g.sd.calls) != 0 {
			t.Errorf("%s: %v", name, err)
		}
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
