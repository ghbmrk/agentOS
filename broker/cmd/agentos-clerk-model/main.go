// Command agentos-clerk-model is the model clerk's process
// (MIG-4-untrusted-exit-b2b, #2780(b), CLK-1, CLK-7): the only process that
// holds the owner's plan logins and API keys, under its own uid. It holds
// each wired plan's login sealed in a slot of its own, plan-<name>
// (plan.Login, PLAN-slots #1379 (a)), and serves the plan routes' owner
// calls (planbegin, planstate, planresume, planremove, each naming its plan)
// to agentosd, whose setup and Wi-Fi pages call them (#2780(b3)). Each sign-in's CLI runs in a
// machine agentosd hosts, reached on agentosd's sign-in socket
// (run.SignInSock), whose only way out is that sign-in guest's endpoint,
// served here. It holds the API keys sealed in a second slot
// (model.Keys), set on the same owner socket (apikeyset, apikeyprivate,
// apikeyremove, apikeystate), and with -model-sock serves model calls on
// them to the planner's uid, metered through the kernel's meter socket
// (run.ServeModel, MIG-4-exit m1):
//
//	agentos-clerk-model -dir /var/lib/agentos-model \
//	    -owner-sock /run/agentos-model/owner.sock \
//	    -signin-sock /run/agentos-signin/signin.sock -agentosd-uid 0 \
//	    -model-sock /run/agentos-model/model.sock -planner-uid 981 \
//	    -meter-sock /run/agentos-kernel/meter.sock -kernel-uid 980
//
// Its key comes from the kernel on descriptor 3 at each start (clerkkey,
// MAIL-keys #3419), and it derives its sealer from it. Every refusal of
// the process comes before the key is read, so a clerk that cannot start
// never takes it.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/model"
	"github.com/ghbmrk/agentos/broker/clerk/plan"
	"github.com/ghbmrk/agentos/broker/clerk/run"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/procguard"
)

// clerkName is this clerk's name in its key's hand-off.
const clerkName = "model"

func main() {
	log.SetFlags(0)
	if err := start(os.Args[1:], os.Stderr, os.NewFile(clerkkey.FD, "clerk-key")); err != nil {
		log.Fatal(err)
	}
}

type config struct {
	dir                   string
	ownerSock, signInSock string
	// agentosdUID is agentosd's: the only caller of the owner socket, the
	// only server of the sign-in socket, and the uid a sign-in machine's
	// connections to its endpoint arrive as, since agentosd hosts it
	// (ASSUMPTIONS MIG-4-untrusted-exit-b1-1).
	agentosdUID int
	// modelSock is the planner's model socket, admitting plannerUID only;
	// each call is metered on meterSock, served by kernelUID. All four go
	// together; none serves no model call.
	modelSock, meterSock  string
	plannerUID, kernelUID int
}

func parse(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("agentos-clerk-model", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config
	fs.StringVar(&c.dir, "dir", "", "the clerk's own state directory, closed to every other uid; it holds the sealed plan login")
	fs.StringVar(&c.ownerSock, "owner-sock", "", "the socket agentosd calls the plan route's owner calls on")
	fs.StringVar(&c.signInSock, "signin-sock", "", "agentosd's -signin-sock, where each plan sign-in's machine is started, read and stopped")
	fs.IntVar(&c.agentosdUID, "agentosd-uid", -1, "agentosd's uid, root in the image: the only peer on owner-sock and signin-sock, and the host of the sign-in machines")
	fs.StringVar(&c.modelSock, "model-sock", "", "the socket the planner makes model calls on")
	fs.IntVar(&c.plannerUID, "planner-uid", -1, "the planner's uid: the only peer on model-sock")
	fs.StringVar(&c.meterSock, "meter-sock", "", "the kernel's meter socket, where every model call is admitted and metered")
	fs.IntVar(&c.kernelUID, "kernel-uid", -1, "the kernel's uid: the only server of meter-sock")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	serving := c.modelSock != "" || c.meterSock != "" || c.plannerUID >= 0 || c.kernelUID >= 0
	switch {
	case serving && (!filepath.IsAbs(c.modelSock) || !filepath.IsAbs(c.meterSock) || c.plannerUID < 0 || c.kernelUID < 0):
		return c, errors.New("-model-sock, -planner-uid, -meter-sock and -kernel-uid go together, the sockets as absolute paths")
	case serving && (c.plannerUID == 0 || c.kernelUID == 0):
		return c, errors.New("-planner-uid and -kernel-uid never name root")
	case fs.NArg() != 0:
		return c, fmt.Errorf("unexpected arguments: %q", fs.Args())
	case !filepath.IsAbs(c.dir) || !filepath.IsAbs(c.ownerSock) || !filepath.IsAbs(c.signInSock):
		return c, errors.New("-dir, -owner-sock and -signin-sock are required, as absolute paths")
	case c.agentosdUID < 0:
		return c, errors.New("-agentosd-uid is required")
	}
	return c, nil
}

func start(args []string, stderr io.Writer, keyFile *os.File) error {
	c, err := parse(args, stderr)
	if err != nil {
		return err
	}
	if err := guard(c); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return serve(ctx, c, keyFile)
}

// guard refuses the process itself, before the key is read: not as root,
// not as agentosd's uid, and not while dumpable, since a peer could then
// read the key from its memory (CLK-1); and not on a state directory
// another uid can reach.
func guard(c config) error {
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		return errors.New("agentos-clerk-model: the model clerk never runs as root")
	}
	if err := procguard.Isolate(c.agentosdUID); err != nil {
		return err
	}
	if c.modelSock != "" && (os.Getuid() == c.plannerUID || os.Geteuid() == c.plannerUID) {
		return errors.New("agentos-clerk-model: the model clerk never runs as the planner's uid")
	}
	return privfile.Check(c.dir, true)
}

// keySlot is the API keys' sealed slot in -dir; maxPlanSlot is a plan
// login's slot's or the keys' most bytes: a login's tokens, or a few keys,
// with room to spare. A form the next start would refuse is never written.
const (
	keySlot     = "api-keys"
	maxPlanSlot = 64 << 10
)

// planSlot is plan name's sealed slot in -dir. Codex's is plan-codex, the
// name it had as the only plan, so a stored login survives.
func planSlot(name string) string { return "plan-" + name }

// planRoute is one wired plan: its declaration and how its sign-in CLI
// shows its link and code.
type planRoute struct {
	d      plan.Declaration
	prompt run.SignInPrompt
}

// declarations are the wired plans, each a qualified route (HLD-3): a plan
// is listed only once a release wires it. A variable so tests can wire a
// second plan.
var declarations = func(guard *netguard.Policy) []planRoute {
	return []planRoute{{plan.Codex(guard), run.CodexSignIn()}}
}

var errSlotTooLarge = errors.New("agentos-clerk-model: the plan login's slot is too large")

// openStore opens the slot in dir: a plain file of this uid's alone, or
// none; anything else refuses the start, since it is the directory's
// tampering, not the slot's. Its value is opened, and checked against the
// plan, when plan.New binds it (newLogin).
func openStore(dir, slot string, s clerk.Sealer) (*plan.Store, error) {
	store := plan.NewStore(s, func(b []byte) error {
		if len(b) > maxPlanSlot {
			return errSlotTooLarge
		}
		return privfile.WriteAtomic(dir, slot, b, nil)
	})
	b, err := readSlot(dir, slot)
	if err != nil {
		return nil, err
	}
	if len(b) > maxPlanSlot {
		// Not a form this process writes: it starts signed out (newLogin).
		log.Printf("agentos-clerk-model: the plan login's slot %s is over %d bytes; starting signed out", slot, maxPlanSlot)
		b = nil
	}
	store.Load(b)
	clear(b)
	return store, nil
}

// readSlot reads the slot name in dir: a plain file of this uid's alone,
// or none (nil); anything else is an error. It reads at most one byte past
// maxPlanSlot, so a caller sees an oversized slot.
func readSlot(dir, name string) ([]byte, error) {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := privfile.CheckFile(f); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(f, maxPlanSlot+1))
}

var errKeysTooLarge = errors.New("agentos-clerk-model: the API keys' slot is too large")

// openKeys opens the API keys' slot in dir as openStore opens the plan
// login's. A value that does not open, or one over the limit, starts the
// clerk with no key, logging one line, so the owner can set a key again
// and that write replaces the slot (as newLogin does).
func openKeys(dir string, s clerk.Sealer) (*model.Keys, error) {
	keys := model.NewKeys(s, func(b []byte) error {
		if len(b) > maxPlanSlot {
			return errKeysTooLarge
		}
		return privfile.WriteAtomic(dir, keySlot, b, nil)
	})
	b, err := readSlot(dir, keySlot)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	if len(b) > maxPlanSlot || keys.Load(b) != nil {
		log.Printf("agentos-clerk-model: the API keys' slot does not open under this key; starting with no key")
	}
	return keys, nil
}

// serve reads the key from keyFile, opens each wired plan's login and
// serves the owner socket until ctx ends or it stops serving. A slot
// another key sealed, or one sealed for another plan, starts that plan
// signed out and leaves the others as they were (newLogin).
func serve(ctx context.Context, c config, keyFile *os.File) error {
	k, err := clerkkey.Read(keyFile, clerkName)
	if err != nil {
		return err
	}
	sk, err := k.Sealer()
	k.Wipe()
	if err != nil {
		return err
	}
	sealer, err := clerk.NewAESSealer(sk)
	clear(sk)
	if err != nil {
		return err
	}
	guard, err := netGuard(ctx, &netguard.Sources{}, netWatchEvery)
	if err != nil {
		return err
	}
	signIns := proc.Conn{Socket: c.signInSock, UID: c.agentosdUID}
	var hosts []*run.PlanHost
	for _, r := range declarations(guard) {
		// Each plan has its own slot and its own Login, so a placeholder
		// one mints resolves at no other.
		store, err := openStore(c.dir, planSlot(r.d.Name), sealer)
		if err != nil {
			return err
		}
		login, err := newLogin(r.d, store)
		if err != nil {
			return err
		}
		hosts = append(hosts, &run.PlanHost{
			Plan:    r.d.Name,
			Login:   login,
			Prompt:  r.prompt,
			Workers: run.SignInSock{Host: signIns, Login: login, SandboxUID: c.agentosdUID},
		})
	}
	keys, err := openKeys(c.dir, sealer)
	if err != nil {
		return err
	}
	// The system's roots: the providers' hosts are public.
	apis, err := model.NewAPIs(model.Shipped, keys, guard, nil)
	if err != nil {
		return err
	}
	apis.Log = func(line string) { log.Print(line) }
	ln, err := run.ListenPlanOwner(c.ownerSock, c.agentosdUID)
	if err != nil {
		return err
	}
	done := make(chan error, 2)
	go func() { done <- fmt.Errorf("the owner socket: %w", run.ServePlanOwner(ln, apis, hosts...)) }()
	if c.modelSock != "" {
		mln, err := run.ListenModel(c.modelSock, c.plannerUID)
		if err != nil {
			ln.Close()
			return err
		}
		defer mln.Close()
		mc := &model.Clerk{Routes: apis.Prices(), Ledger: proc.Meter{Conn: proc.Conn{Socket: c.meterSock, UID: c.kernelUID}}}
		mh := run.ModelHost{Clerk: mc, APIs: apis, Clock: func() int64 { return time.Now().UnixMilli() }}
		go func() { done <- fmt.Errorf("the model socket: %w", run.ServeModel(mln, mh)) }()
	}
	select {
	case <-ctx.Done():
		err = nil
	case err = <-done:
	}
	ln.Close()
	return err
}

// newLogin binds store to d. A slot whose value does not open under this
// key or for this plan (another key's, damaged) is never opened: the clerk
// logs one line and starts signed out, so the owner can sign in again and
// that sign-in's write replaces the slot, as the mail clerk does
// (MAIL-main-a-4). Refusing the start instead would leave planremove, the
// owner's only remedy, unreachable (#3568 UX 1).
func newLogin(d plan.Declaration, store *plan.Store) (*plan.Login, error) {
	// The system's roots: the provider's hosts are public (nil RootCAs).
	login, err := plan.New(d, store, nil)
	if b, _ := store.MarshalBinary(); err == nil || len(b) == 0 {
		return login, err
	}
	log.Printf("agentos-clerk-model: the %s plan login's slot does not open under this key or plan; starting signed out", d.Name)
	store.Load(nil)
	return plan.New(d, store, nil)
}
