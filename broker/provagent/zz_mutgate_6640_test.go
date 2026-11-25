package provagent

// REQ: CAP-11, CRED-5, CRED-7, ONB-3, OP-8, CRED-RS-2

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/vm"
)

// logged reports whether a line of logs holds want.
func logged(logs []string, want string) bool {
	for _, l := range logs {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}

func (g *signRig) logLines() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.logs...)
}

func (g *rig) logLines() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.logs...)
}

// Each zero or negative sign-in bound takes its own default.
func TestSignInTimesDefaultEachUnsetBound(t *testing.T) {
	want := SignInTimes{Poll: time.Second, Link: time.Minute, Wall: 15 * time.Minute}
	for _, in := range []SignInTimes{{}, {Poll: -1, Link: -1, Wall: -1}} {
		if got := in.orDefault(); got != want {
			t.Errorf("%+v: %+v, want %+v", in, got, want)
		}
	}
	set := SignInTimes{Poll: 2, Link: 3, Wall: 4}
	if got := set.orDefault(); got != set {
		t.Errorf("set bounds changed: %+v", got)
	}
}

// The sign-in CLI runs under env -i with exactly the declared environment,
// then the declared wrapper, then its own argv, as Command runs the headless one.
func TestSignInCommandRunsUnderTheDeclaredEnvAndWrapper(t *testing.T) {
	d := signInDecl()
	argv := SignInCommand(d).Argv
	i := 0
	for i < len(argv)-1 && !(argv[i] == "env" && argv[i+1] == "-i") {
		i++
	}
	var want []string
	want = append(append(append(want, d.Env...), d.Wrap...), d.SignInArgv...)
	if i == len(argv)-1 || !reflect.DeepEqual(argv[i+2:], want) {
		t.Fatalf("argv %q, want env -i then %q", argv, want)
	}
}

// Validate refuses an id out of shape, a credential in the idle argv, the
// cloud-off pins or the qualification, and an env entry with no name.
func TestValidateRefusesTheOtherShapes(t *testing.T) {
	cases := map[string]func(d *Declaration){
		"id out of shape":         func(d *Declaration) { d.ID = "Stub" },
		"credential in idle argv": func(d *Declaration) { d.Idle = append(d.Idle, canaryToken) },
		"credential in cloud-off": func(d *Declaration) { d.CloudOff = append(d.CloudOff, "key = "+canaryToken) },
		"credential in a sign-in link": func(d *Declaration) {
			*d = signInDecl()
			d.SignInLinks = append(d.SignInLinks, "https://x.test/"+canaryToken)
		},
		"credential in evidence": func(d *Declaration) { d.Q = qualified(); d.Q.Evidence = canaryToken },
		"env entry with no =":    func(d *Declaration) { d.Env = append(d.Env, "NOVALUE") },
		"env entry with no name": func(d *Declaration) { d.Env = append(d.Env, "=x") },
	}
	for name, mut := range cases {
		d := good()
		mut(&d)
		if err := d.Validate(); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// A sign-in whose worker is not created stops there: one log line, no CLI.
func TestASignInWhoseWorkerFailsStopsAtTheCreate(t *testing.T) {
	g := newSignRig(printed)
	g.h.createErr = errors.New("no room")
	if _, _, err := g.start(t); reasonOf(err) != Failed {
		t.Fatalf("%v", err)
	}
	if logs := g.logLines(); len(logs) != 1 || !strings.Contains(logs[0], "no room") {
		t.Fatalf("logs: %q", logs)
	}
	if len(g.h.destroyed) != 0 {
		t.Fatalf("destroyed %v, a worker that was never created", g.h.destroyed)
	}
}

// A sign-in CLI that cannot be started fails the sign-in at once, without
// waiting for a link.
func TestASignInWhoseCLIDoesNotStartFails(t *testing.T) {
	g := newSignRig(printed)
	g.h.execErr = errors.New("exec lost")
	if _, _, err := g.start(t); reasonOf(err) != Failed {
		t.Fatalf("%v, want %s", err, Failed)
	}
	g.gone(t)
	if logs := g.logLines(); len(logs) != 1 || !strings.Contains(logs[0], "exec lost") {
		t.Fatalf("logs: %q", logs)
	}
}

// failingCat is a host whose reads of the sign-in output exit non-zero
// while still printing the prompt: a failed read is no read.
type failingCat struct{ *stub }

func (h failingCat) Exec(ctx context.Context, id string, c vm.Command, to time.Duration) (vm.ExecResult, error) {
	if len(c.Argv) == 2 && c.Argv[0] == "cat" && strings.HasSuffix(c.Argv[1], signInOut) {
		return vm.ExecResult{ExitCode: 1, Stdout: []byte(printed)}, nil
	}
	return h.stub.Exec(ctx, id, c, to)
}

func TestAFailedReadOfTheSignInOutputIsNotRead(t *testing.T) {
	g := newSignRig(printed)
	g.r.Host = failingCat{g.h}
	if _, _, err := g.start(t); reasonOf(err) != TimedOut {
		t.Fatalf("%v, want %s: a failed read was taken as the prompt", err, TimedOut)
	}
	g.gone(t)
}

// A sign-in stopped while it waits for the link says so, rather than
// waiting out the link's time.
func TestASignInStoppedBeforeItsLinkSaysSo(t *testing.T) {
	g := newSignRig("")
	g.r.SignInTimes.Link = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	began := time.Now()
	if _, _, err := g.r.StartSignIn(ctx, "stub", admission.Accepted, 512); reasonOf(err) != TimedOut {
		t.Fatalf("%v", err)
	}
	if time.Since(began) > time.Second {
		t.Fatalf("a stopped sign-in waited %v", time.Since(began))
	}
	g.gone(t)
	if logs := g.logLines(); !logged(logs, "before it was stopped") {
		t.Fatalf("logs: %q", logs)
	}
}

// Each way the wait for the owner ends without a login is logged, by cause.
func TestEachUnapprovedSignInEndIsLoggedByCause(t *testing.T) {
	for name, c := range map[string]struct {
		set  func(g *signRig)
		want string
	}{
		"the CLI exited": {func(g *signRig) { g.h.write("/work"+signInStatus, "0\n") }, "ended without storing a login"},
		"not in time":    {func(g *signRig) { g.r.SignInTimes.Wall = 20 * time.Millisecond }, "not approved in time"},
		"stopped": {func(g *signRig) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			g.r.Background = ctx
		}, "stopped before it was approved"},
	} {
		t.Run(name, func(t *testing.T) {
			g := newSignRig(printed)
			c.set(g)
			if _, _, err := g.start(t); err != nil {
				t.Fatal(err)
			}
			g.gone(t)
			if logs := g.logLines(); len(logs) != 1 || !strings.Contains(logs[0], c.want) {
				t.Fatalf("logs %q, want one line holding %q", logs, c.want)
			}
		})
	}
}

// reopens counts the reopenings a Runner asks of its RouteStops.
type reopens struct {
	RouteStops
	n int
}

func (r *reopens) ReopenRoute(route, cause string) error {
	r.n++
	return r.RouteStops.ReopenRoute(route, cause)
}

// CRED-5t: a route stopped for a cause that is not the owner's to lift is
// not even asked to reopen.
func TestSignedInAsksNoReopeningOfAnotherCause(t *testing.T) {
	st := journalStops(t, &journal.MemStore{})
	if err := st.StopRoute("stub", StopUnswappable); err != nil {
		t.Fatal(err)
	}
	rs := &reopens{RouteStops: st}
	g := newRig(ok("fine"))
	g.r.Stops = rs
	g.r.SignInStored = func(string) bool { return true }
	if g.r.SignedIn("stub", "pw-ok") {
		t.Fatal("signed in over an unswappable stop")
	}
	if rs.n != 0 || len(g.logLines()) != 0 {
		t.Fatalf("%d reopenings asked, logs %q", rs.n, g.logLines())
	}
}

// A stop the journal cannot record is logged and held in memory, and the
// owner's sign-in lifts that in-memory stop; a reopening it cannot record
// is logged too.
func TestUnrecordedStopsAreLoggedAndTheSignInLiftsTheHeldOne(t *testing.T) {
	g := newRig(nil)
	g.r.Stops = journalStops(t, &stopStore{fail: true})
	g.h.cli = g.refuseLogin
	g.r.Run(context.Background(), req("b"))
	if !logged(g.logLines(), "route stop was not recorded") {
		t.Fatalf("logs: %q", g.logLines())
	}
	g.advance(1)
	g.h.cli = ok("fine")
	g.r.SignInStored = func(string) bool { return true }
	if !g.r.SignedIn("stub", "pw-ok") {
		t.Fatal("the sign-in did not lift the stop held in memory")
	}
	if out, err := g.r.Run(context.Background(), req("b")); err != nil || out != "fine" {
		t.Fatalf("after the sign-in: %q %v", out, err)
	}

	store := &stopStore{}
	st := journalStops(t, store)
	if err := st.StopRoute("stub", StopLoginRefused); err != nil {
		t.Fatal(err)
	}
	store.fail = true
	g = newRig(ok("fine"))
	g.r.Stops = st
	g.r.SignInStored = func(string) bool { return true }
	if g.r.SignedIn("stub", "pw-ok") || !logged(g.logLines(), "route stays stopped") {
		t.Fatalf("unrecorded reopening: logs %q", g.logLines())
	}
}

// A run whose worker is not created destroys nothing and reads no usage
// after it: there was no run.
func TestARunWhoseWorkerFailsStopsAtTheCreate(t *testing.T) {
	g := newRig(ok("x"))
	g.h.createErr = errors.New("no room")
	if _, err := g.r.Run(context.Background(), req("b")); reasonOf(err) != Failed {
		t.Fatalf("%v", err)
	}
	g.mu.Lock()
	n := g.usageN
	g.mu.Unlock()
	if len(g.h.destroyed) != 0 || n != 1 {
		t.Fatalf("destroyed %v, %d usage reads", g.h.destroyed, n)
	}
}

// OP-8: an unreadable usage view is logged, before admission and after a run.
func TestUnreadableUsageIsLogged(t *testing.T) {
	g := newRig(ok("x"))
	g.usageErr = errors.New("control socket down")
	g.r.Run(context.Background(), req("b"))
	if !logged(g.logLines(), "usage for stub: control socket down") {
		t.Errorf("before admission: logs %q", g.logLines())
	}
	g = newRig(nil)
	g.h.cli = func(c vm.Command, s *stub) vm.ExecResult {
		g.mu.Lock()
		g.usageErr = errors.New("control socket down")
		g.mu.Unlock()
		return ok("finished")(c, s)
	}
	g.r.Run(context.Background(), req("b"))
	if !logged(g.logLines(), "usage for stub after a run: control socket down") {
		t.Errorf("after the run: logs %q", g.logLines())
	}
}
