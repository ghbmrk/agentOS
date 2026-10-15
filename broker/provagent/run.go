package provagent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm"
)

// Host is the machine manager's provider-worker surface.
type Host interface {
	CreateProviderWorker(ctx context.Context, id string, s vm.Spec, seed map[string][]byte) (vm.Machine, error)
	Exec(ctx context.Context, id string, c vm.Command, timeout time.Duration) (vm.ExecResult, error)
	Destroy(ctx context.Context, id string) error
}

// Seeder fetches a provider worker's placeholder seed from the vault
// process and closes the worker's route. The wiring adapts the model
// route's control client to it and maps that client's errors onto the
// sentinels below, so this package links no network client (ARC-2).
type Seeder interface {
	// Seed mints provider's placeholders for worker id. ErrNoLogin: the
	// owner has not signed in to the plan; ErrVaultLocked: the vault is
	// locked; ErrRouteBusy: the route is stalled or contended (a 503).
	Seed(provider, id string) (map[string][]byte, error)
	// Close closes id's route and forgets its placeholders.
	Close(id string)
}

// The Seeder's sentinels.
var (
	ErrNoLogin     = errors.New("provagent: no plan login stored")
	ErrVaultLocked = errors.New("provagent: the vault is locked")
	ErrRouteBusy   = errors.New("provagent: the plan route is busy")
)

// Reading is one usage pool's remaining share, 0..1, read by the broker on
// its own upstream connection (RES-5).
type Reading struct {
	Pool string
	Left float64
}

// Caps bound a run. Wall is the wall clock; Result and Brief are bytes.
type Caps struct {
	Wall          time.Duration
	Result, Brief int
}

// Event is one run's journal entry (OP-8). It carries metadata only: never
// the brief, the result, or anything the CLI printed.
type Event struct {
	Provider, TaskClass, Outcome string
	ResultBytes                  int
	Elapsed                      time.Duration
}

// Request is one provider_run call.
type Request struct {
	Provider, Brief, TaskClass string
	Label                      vm.Label // the caller's data label
	Class                      admission.Class
	MemMB                      int64 // the caller's reservation
}

// Runner runs provider agents.
type Runner struct {
	Host   Host
	Seeder Seeder
	Decls  map[string]Declaration

	ImageVersion func(image string) string // the CLI version an image pins
	Granted      func(provider string) bool
	PrivateOK    func(provider string) bool // the owner's per-plan private mark
	Consent      func(provider string) bool // CRED-5c
	Readings     func(provider string) []Reading
	Reserve      func() float64 // the owner's reserve, 0..1
	Scan         func(string) bool
	Journal      func(Event)
	// SignIn sets the ONB-9 sign-in line and OnSignedIn clears it. Both are
	// called with the runner's lock held, in the same hold that changes
	// the route's stopped state, so the line always matches it; neither
	// may call back into the Runner.
	SignIn     func(provider string)
	OnSignedIn func(provider string)
	// SignInFor marks worker id's route, before the worker is created, as a
	// sign-in route: the vault process opens only the sign-in endpoints for
	// it and stores the login it brings back (StartSignIn).
	SignInFor func(id string)
	// SignInStored is whether sign-in worker id's own sign-in stored the
	// plan login (the vault process's record of that worker's commit):
	// false when the vault cannot say. It is the only signal that a
	// sign-in took; a login stored earlier, or the CLI's exit status, is
	// not one.
	SignInStored func(id string) bool
	// Background bounds a sign-in's wait for the owner, which outlives
	// StartSignIn's caller; nil is never cancelled.
	Background  context.Context
	SignInTimes SignInTimes
	Logf        func(format string, args ...any)
	Caps        Caps
	NewID       func() string // a fresh "pw-" worker ID

	// mu guards stopped, told and signing, and orders the sign-in line's
	// changes. A refused login stops the provider's route for every later
	// run (CRED-5: no retry, since retries can worsen a restriction), and
	// the owner is told once, until SignedIn.
	mu      sync.Mutex
	stopped map[string]bool // provider: a refused login stopped its route
	told    map[string]bool // provider: SignIn already called
	signing map[string]bool // provider: a sign-in is running (StartSignIn)
}

// SignedIn is the owner's sign-in or resume for provider: its route runs
// again, and a later refusal tells the owner again.
func (r *Runner) SignedIn(provider string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.stopped, provider)
	delete(r.told, provider)
	if r.OnSignedIn != nil {
		r.OnSignedIn(provider) // under mu: a refusal racing it cannot be undone
	}
}

func (r *Runner) isStopped(provider string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopped[provider]
}

// signIn sets provider's sign-in line once until SignedIn; stop also stops
// its route.
func (r *Runner) signIn(provider string, stop bool) {
	r.mu.Lock()
	if stop {
		if r.stopped == nil {
			r.stopped = map[string]bool{}
		}
		r.stopped[provider] = true
	}
	first := !r.told[provider]
	if first {
		if r.told == nil {
			r.told = map[string]bool{}
		}
		r.told[provider] = true
		if r.SignIn != nil {
			r.SignIn(provider) // under mu, ordered with SignedIn's clear
		}
	}
	r.mu.Unlock()
}

func (r *Runner) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

const outputKeep = 4 << 10 // stdout/stderr are read to this bound and dropped

// Command is the one process a run starts. The brief is stdin, never argv.
// The shell only enters the workspace and redirects stdout to the declared
// result file (stderr is dropped); env -i then gives the CLI exactly the
// declared environment, and wrap then argv is exec'd.
func Command(d Declaration, brief string) vm.Command {
	argv := []string{
		"sh", "-c", `cd "$1" || exit 125; out=$2; shift 2; exec "$@" >"$out" 2>/dev/null`,
		"sh", d.Cwd, d.ResultPath, "env", "-i",
	}
	argv = append(argv, d.Env...)
	argv = append(argv, d.Wrap...)
	argv = append(argv, d.Argv...)
	return vm.Command{Argv: argv, Stdin: []byte(brief), MaxOutput: outputKeep, As: vm.Private}
}

// Run admits, runs and cleans up one provider agent, returning its scanned
// result. Every refusal is a *Refusal with a closed reason; FallsBack says
// which the caller answers with another route.
func (r *Runner) Run(ctx context.Context, q Request) (string, error) {
	start := time.Now()
	out, n, outcome, err := r.run(ctx, q)
	if r.Journal != nil {
		r.Journal(Event{Provider: q.Provider, TaskClass: q.TaskClass, Outcome: outcome, ResultBytes: n, Elapsed: time.Since(start)})
	}
	return out, err
}

func (r *Runner) run(ctx context.Context, q Request) (text string, n int, outcome string, err error) {
	fail := func(re Reason) (string, int, string, error) { return "", 0, string(re), refuse(re) }
	d, ok := r.Decls[q.Provider]
	if !ok || !contains(d.TaskClasses, q.TaskClass) {
		return fail(Unqualified)
	}
	g := Gate{ImageVersion: r.ImageVersion(d.Image), Consent: r.Consent != nil && r.Consent(d.ID)}
	if err := g.Check(d); err != nil {
		return fail(err.(*Refusal).Reason)
	}
	if r.Granted == nil || !r.Granted(d.ID) {
		return fail(Ungranted)
	}
	if q.Label == vm.Private && (r.PrivateOK == nil || !r.PrivateOK(d.ID)) {
		return fail(PrivateUnmarked)
	}
	// Only a broker-held route is seeded here: a worker-held login is the
	// Claude opt-in's (#1380), which this path does not build.
	if d.Custody != BrokerHeld {
		return fail(Unqualified)
	}
	if r.isStopped(d.ID) {
		return fail(LoginRefused)
	}
	if len(q.Brief) > r.Caps.Brief {
		return fail(Failed)
	}
	if !r.poolsAboveReserve(d) {
		return fail(PoolAtReserve)
	}

	id := r.NewID()
	seed, serr := r.Seeder.Seed(d.ID, id)
	switch {
	case serr == nil:
	case errors.Is(serr, ErrNoLogin):
		r.signIn(d.ID, false)
		return fail(Unsigned)
	case errors.Is(serr, ErrVaultLocked):
		return fail(VaultLocked)
	case errors.Is(serr, ErrRouteBusy):
		return fail(RouteBusy)
	default:
		r.Seeder.Close(id)
		return fail(Failed)
	}
	// The worker is always private (it is given owner data); its class and
	// reservation are the caller's.
	spec := vm.Spec{Image: d.Image, Class: q.Class, MemMB: q.MemMB, Label: vm.Private}
	if _, err := r.Host.CreateProviderWorker(ctx, id, spec, seed); err != nil {
		// No worker, so no Destroy closes the route: close it here, so the
		// minted placeholders do not outlive the run in the vault process.
		r.Seeder.Close(id)
		return fail(Failed)
	}
	defer func() {
		// Destroying the worker takes its route, logs and transcripts with it.
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := r.Host.Destroy(dctx, id); err != nil {
			r.logf("provagent: destroy provider worker %s: %v", id, err)
		}
	}()

	wctx, wcancel := context.WithTimeout(ctx, r.Caps.Wall)
	defer wcancel()
	res, err := r.Host.Exec(wctx, id, Command(d, q.Brief), r.Caps.Wall)
	if res.TimedOut || wctx.Err() != nil {
		return fail(TimedOut)
	}
	if err != nil {
		return fail(Failed)
	}
	// The CLI's stdout and stderr (res.Stdout, res.Stderr) are dropped here:
	// only the declared result file leaves the worker.
	rr, err := r.Host.Exec(wctx, id, vm.Command{Argv: []string{"cat", d.ResultPath}, MaxOutput: r.Caps.Result + 1, As: vm.Private}, r.Caps.Wall)
	if err != nil || rr.Truncated || len(rr.Stdout) > r.Caps.Result {
		return fail(Failed)
	}
	body := string(rr.Stdout)

	// Signals first: a refused login or a used-up plan is a fallback even
	// when the CLI exited non-zero. They are read from the CLI's own error
	// events only, never from text the model wrote, which the brief steers.
	if signalled(body, d.ErrorEvents, d.LoginRefused) {
		r.signIn(d.ID, true)
		return fail(LoginRefused)
	}
	if signalled(body, d.ErrorEvents, d.UsedUp) || signalled(body, d.ErrorEvents, d.CreditDraw) {
		return fail(UsedUp)
	}
	if res.ExitCode != 0 {
		return fail(Failed)
	}
	scan := r.Scan
	if scan == nil {
		scan = LooksLikeCredential
	}
	if scan(body) {
		return fail(Withheld)
	}
	return body, len(body), "ok", nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// poolsAboveReserve is RES-5's admission check, closed by default: every
// declared pool must have a reading, and every reading must be above the
// owner's reserve. No readings, no reserve, or an unread pool refuses.
func (r *Runner) poolsAboveReserve(d Declaration) bool {
	if r.Readings == nil || r.Reserve == nil {
		return false
	}
	reserve := r.Reserve()
	read := map[string]bool{}
	for _, p := range r.Readings(d.ID) {
		if !(p.Left > reserve) { // a NaN reading refuses too
			return false
		}
		read[p.Pool] = true
	}
	for _, p := range d.Pools {
		if !read[p.Name] {
			return false
		}
	}
	return true
}

// signalled reports whether a JSON event line of the result whose "type" is
// one of events carries one of signals. Lines that are not such events (the
// agent's own messages, plain text) are never matched.
func signalled(body string, events, signals []string) bool {
	if len(events) == 0 || len(signals) == 0 {
		return false
	}
	for _, line := range strings.Split(body, "\n") {
		var ev struct {
			Type string `json:"type"`
		}
		if json.Unmarshal([]byte(line), &ev) != nil || !contains(events, ev.Type) {
			continue
		}
		for _, s := range signals {
			if s != "" && strings.Contains(line, s) {
				return true
			}
		}
	}
	return false
}
