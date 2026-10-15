package provagent

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/vm"
)

// Host is the machine manager's provider-worker surface.
type Host interface {
	CreateProviderWorker(ctx context.Context, id string, s vm.Spec, seed map[string][]byte) (vm.Machine, error)
	Exec(ctx context.Context, id string, c vm.Command, timeout time.Duration) (vm.ExecResult, error)
	Destroy(ctx context.Context, id string) error
}

// Seeder fetches a provider worker's placeholder seed from the vault
// process (modelroute.RouteControl). ErrNoPlanLogin means the owner has not
// signed in; ErrVaultLocked means the route is locked, stalled or contended.
type Seeder interface {
	Seed(id string) (map[string][]byte, error)
}

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
	SignIn       func(provider string) // sets the ONB-9 sign-in line
	Caps         Caps
	NewID        func() string // a fresh "pw-" worker ID
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
	if len(q.Brief) > r.Caps.Brief {
		return fail(Failed)
	}
	if r.Readings != nil {
		for _, p := range r.Readings(d.ID) {
			if p.Left <= r.Reserve() {
				return fail(PoolAtReserve)
			}
		}
	}

	id := r.NewID()
	seed, serr := r.Seeder.Seed(id)
	switch {
	case errors.Is(serr, modelroute.ErrNoPlanLogin):
		return fail(Unsigned)
	case serr != nil && modelroute.FallsBack(serr):
		return fail(RouteBusy)
	case serr != nil:
		return fail(Failed)
	}
	// The worker is always private (it is given owner data); its class and
	// reservation are the caller's.
	spec := vm.Spec{Image: d.Image, Class: q.Class, MemMB: q.MemMB, Label: vm.Private}
	if _, err := r.Host.CreateProviderWorker(ctx, id, spec, seed); err != nil {
		return fail(Failed)
	}
	defer func() {
		// Destroying the worker takes its route, logs and transcripts with it.
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_ = r.Host.Destroy(dctx, id)
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
	// when the CLI exited non-zero.
	if hasAny(body, d.LoginRefused) {
		if r.SignIn != nil {
			r.SignIn(d.ID)
		}
		return fail(LoginRefused)
	}
	if hasAny(body, d.UsedUp) || hasAny(body, d.CreditDraw) {
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

func hasAny(body string, signals []string) bool {
	for _, s := range signals {
		if s != "" && strings.Contains(body, s) {
			return true
		}
	}
	return false
}
