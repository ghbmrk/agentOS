package localsrv

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-3, CH-7, CH-10, CH-11, CH-18, ARC-2

// SR3-1: a session is bound to the lock generation its sign-in
// authenticated under, not one read after the sign-in returns, and RESUME
// checks that generation where it commits. These run the real owner
// channel on a synthetic modem whose texts can be held mid-delivery.

var genSeed = []byte("SR3-1 synthetic seed, not a key!")

type stillEngine struct {
	mu      sync.Mutex
	stopped bool
}

func (e *stillEngine) Stop(context.Context) (journal.StopReport, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopped = true
	return journal.StopReport{}, nil
}
func (e *stillEngine) Resume() error          { e.mu.Lock(); defer e.mu.Unlock(); e.stopped = false; return nil }
func (e *stillEngine) Stopped() bool          { e.mu.Lock(); defer e.mu.Unlock(); return e.stopped }
func (e *stillEngine) List() []journal.Status { return nil }

// heldLine holds texts while hold is set, telling entered of each held one.
type heldLine struct {
	modem.Modem
	mu      sync.Mutex
	hold    bool
	entered chan struct{}
	let     chan struct{}
}

func (l *heldLine) Send(to, text string) error {
	l.mu.Lock()
	hold := l.hold
	l.mu.Unlock()
	if hold {
		l.entered <- struct{}{}
		<-l.let
	}
	return l.Modem.Send(to, text)
}

// holdNext holds the next text; it returns when the text is held and a
// function that lets it go.
func (l *heldLine) holdNext() (wait func(), let func()) {
	l.mu.Lock()
	l.hold, l.entered, l.let = true, make(chan struct{}), make(chan struct{})
	entered, ch := l.entered, l.let
	l.mu.Unlock()
	return func() { <-entered }, func() {
		l.mu.Lock()
		l.hold = false
		l.mu.Unlock()
		close(ch)
	}
}

type genRig struct {
	t    *testing.T
	mu   sync.Mutex
	now  time.Time
	eng  *stillEngine
	line *heldLine
	ch   *owner.Channel
	own  Owner // what the server calls; ch unless a test wraps it
	ops  map[string]sockets.Handler
}

func newGenRig(t *testing.T) *genRig {
	g := &genRig{t: t, now: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC), eng: &stillEngine{stopped: true}}
	g.line = &heldLine{Modem: modem.NewCarrier().Line("+15550000001")}
	ch, err := owner.New(owner.Config{Owner: "+15550000002", Modem: g.line, Engine: g.eng, Store: &owner.MemStore{},
		Secrets: owner.Secrets{TOTPSeed: genSeed}, Now: g.clock, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	g.ch, g.own = ch, ch
	g.ops = New(Config{Owner: ownerFunc(func() Owner { return g.own }), Now: g.clock}).Ops()
	return g
}

func (g *genRig) clock() time.Time { g.mu.Lock(); defer g.mu.Unlock(); return g.now }

// code is the next code-generator code, a step on so it is unspent.
func (g *genRig) code() string {
	g.mu.Lock()
	g.now = g.now.Add(30 * time.Second)
	g.mu.Unlock()
	return owner.TOTP(genSeed, g.clock())
}

func (g *genRig) advance(d time.Duration) { g.mu.Lock(); g.now = g.now.Add(d); g.mu.Unlock() }

func (g *genRig) call(op string, args any) (any, error) {
	g.t.Helper()
	return (&rig{t: g.t, ops: g.ops}).call(op, args)
}

func (g *genRig) signIn() string {
	g.t.Helper()
	out, err := g.call(localapi.OpSignIn, localapi.SignIn{Code: g.code()})
	if err != nil || out.(localapi.Session).Token == "" {
		g.t.Fatalf("sign-in: %+v %v", out, err)
	}
	return out.(localapi.Session).Token
}

// lockDuring runs op while the owner's next text is held, locks the
// session (RequireUnlock) while it is held, then lets it go.
func (g *genRig) lockDuring(op func() (any, error)) (any, error) {
	g.t.Helper()
	wait, let := g.line.holdNext()
	type res struct {
		out any
		err error
	}
	done := make(chan res, 1)
	go func() { out, err := op(); done <- res{out, err} }()
	wait()
	if err := g.ch.RequireUnlock(); err != nil {
		g.t.Fatal(err)
	}
	let()
	r := <-done
	return r.out, r.err
}

// ownerFunc lets a test swap the owner the server calls.
type ownerFunc func() Owner

func (f ownerFunc) LocalStatus() owner.LocalStatus { return f().LocalStatus() }
func (f ownerFunc) LocalGridCell() string          { return f().LocalGridCell() }
func (f ownerFunc) LocalSignIn(c string) (time.Time, uint64, error) {
	return f().LocalSignIn(c)
}
func (f ownerFunc) LocalStop(ctx context.Context) error      { return f().LocalStop(ctx) }
func (f ownerFunc) LocalResume(locks uint64) (string, error) { return f().LocalResume(locks) }
func (f ownerFunc) LocalRequests() []owner.LocalRequest      { return f().LocalRequests() }
func (f ownerFunc) LocalWaiting() string                     { return f().LocalWaiting() }
func (f ownerFunc) LocalStatusLines() string                 { return f().LocalStatusLines() }
func (f ownerFunc) UnlockPeriod() time.Duration              { return f().UnlockPeriod() }
func (f ownerFunc) LocalAnswer(id, sum string, a bool, c string) (string, error) {
	return f().LocalAnswer(id, sum, a, c)
}

// Acceptance 1: a sign-in whose code was accepted, then overlapped by a
// session lock while its sign-in text was out, yields no token that
// reaches a protected op or RESUME; a new sign-in is needed.
func TestSignInOverlappingALockGivesNoLiveToken(t *testing.T) {
	g := newGenRig(t)
	totp := g.code()
	out, err := g.lockDuring(func() (any, error) { return g.call(localapi.OpSignIn, localapi.SignIn{Code: totp}) })
	if st := g.ch.LocalStatus(); st.Unlocked || st.Locks != 1 {
		t.Fatalf("setup: the lock did not land after the code: %+v", st)
	}
	tok := ""
	if ses, ok := out.(localapi.Session); ok && err == nil {
		tok = ses.Token
	}
	if _, err := g.call(localapi.OpLines, localapi.Auth{Token: tok}); code(err) != localapi.ErrUnauthorized {
		t.Fatalf("protected op with the overlapped token: %v", err)
	}
	if _, err := g.call(localapi.OpResume, localapi.Resume{Token: tok}); code(err) != localapi.ErrUnauthorized || !g.eng.Stopped() {
		t.Fatalf("RESUME with the overlapped token: %v, stopped %v", err, g.eng.Stopped())
	}
	// A new sign-in works and may resume.
	tok = g.signIn()
	if out, err := g.call(localapi.OpResume, localapi.Resume{Token: tok}); err != nil || g.eng.Stopped() {
		t.Fatalf("RESUME after a new sign-in: %+v %v", out, err)
	}
}

// Acceptance 2, refresh: a stale session's RESUME with a code, overlapped
// by a lock while the code's sign-in text is out, does not resume and
// leaves no live session.
func TestRefreshOverlappingALockDoesNotResume(t *testing.T) {
	g := newGenRig(t)
	tok := g.signIn()
	// Past FreshFor, and past the sign-in texts' hour so the refresh's
	// own sign-in is texted (the point the lock lands in).
	g.advance(owner.SignInAlertEvery + localapi.FreshFor)
	totp := g.code()
	out, err := g.lockDuring(func() (any, error) {
		return g.call(localapi.OpResume, localapi.Resume{Token: tok, Code: totp})
	})
	if !g.eng.Stopped() {
		t.Fatalf("resumed across the lock: %+v %v", out, err)
	}
	if code(err) != localapi.ErrUnauthorized {
		t.Fatalf("refresh across the lock: %+v %v", out, err)
	}
	if _, err := g.call(localapi.OpLines, localapi.Auth{Token: tok}); code(err) != localapi.ErrUnauthorized {
		t.Fatalf("session after the lock: %v", err)
	}
}

// lockFirst locks the session just before RESUME commits: the lock lands
// after the server's token check, as a concurrent RequireUnlock can.
type lockFirst struct{ *owner.Channel }

func (l lockFirst) LocalResume(locks uint64) (string, error) {
	_ = l.Channel.RequireUnlock()
	return l.Channel.LocalResume(locks)
}

// Acceptance 2, commit point: a fresh session's code-free RESUME checks
// the authenticated generation where the resume commits, not only at the
// token check before it.
func TestResumeChecksTheGenerationAtItsCommit(t *testing.T) {
	g := newGenRig(t)
	tok := g.signIn()
	g.own = lockFirst{g.ch}
	if out, err := g.call(localapi.OpResume, localapi.Resume{Token: tok}); code(err) != localapi.ErrUnauthorized || !g.eng.Stopped() {
		t.Fatalf("RESUME with a lock before its commit: %+v %v, stopped %v", out, err, g.eng.Stopped())
	}
	g.own = g.ch
	if _, err := g.call(localapi.OpLines, localapi.Auth{Token: tok}); code(err) != localapi.ErrUnauthorized {
		t.Fatalf("session after the lock: %v", err)
	}
}

// Acceptance 3: without a lock, sign-in, refresh and RESUME work as
// before, and STOP needs no session.
func TestSignInRefreshAndResumeWithoutALock(t *testing.T) {
	g := newGenRig(t)
	g.eng.Resume()
	if _, err := g.call(localapi.OpStop, nil); err != nil || !g.eng.Stopped() {
		t.Fatalf("STOP: %v", err)
	}
	tok := g.signIn()
	g.advance(localapi.FreshFor)
	if out, err := g.call(localapi.OpResume, localapi.Resume{Token: tok}); err != nil || out.(localapi.Answered).Refusal != localapi.RefusedCodeNeeded {
		t.Fatalf("stale RESUME without a code: %+v %v", out, err)
	}
	if out, err := g.call(localapi.OpResume, localapi.Resume{Token: tok, Code: g.code()}); err != nil || g.eng.Stopped() {
		t.Fatalf("refreshed RESUME: %+v %v", out, err)
	}
	if _, err := g.call(localapi.OpLines, localapi.Auth{Token: tok}); err != nil {
		t.Fatalf("session after refresh: %v", err)
	}
}
