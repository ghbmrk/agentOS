// Command agentos-clerk-model is the model clerk's process
// (MIG-4-untrusted-exit-b2b, #2780(b), CLK-1, CLK-7): the only process that
// holds the owner's plan login, under its own uid. It holds the login
// sealed in its own slot (plan.Login) and serves the plan route's owner
// calls (planbegin, planstate, planresume, planremove) to agentosd, whose
// setup and Wi-Fi pages call them (#2780(b3)). Each sign-in's CLI runs in a
// machine agentosd hosts, reached on agentosd's sign-in socket
// (run.SignInSock), whose only way out is that sign-in guest's endpoint,
// served here:
//
//	agentos-clerk-model -dir /var/lib/agentos-model \
//	    -owner-sock /run/agentos-model/owner.sock \
//	    -signin-sock /run/agentos-signin/signin.sock -agentosd-uid 0
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

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
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
}

func parse(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("agentos-clerk-model", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config
	fs.StringVar(&c.dir, "dir", "", "the clerk's own state directory, closed to every other uid; it holds the sealed plan login")
	fs.StringVar(&c.ownerSock, "owner-sock", "", "the socket agentosd calls the plan route's owner calls on")
	fs.StringVar(&c.signInSock, "signin-sock", "", "agentosd's -signin-sock, where each plan sign-in's machine is started, read and stopped")
	fs.IntVar(&c.agentosdUID, "agentosd-uid", -1, "agentosd's uid, root in the image: the only peer on owner-sock and signin-sock, and the host of the sign-in machines")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	switch {
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
	return privfile.Check(c.dir, true)
}

// planSlot is the plan login's sealed slot in -dir, and maxPlanSlot its
// most bytes: a login's tokens with room to spare. A form the next start
// would refuse is never written.
const (
	planSlot    = "plan-codex"
	maxPlanSlot = 64 << 10
)

var errSlotTooLarge = errors.New("agentos-clerk-model: the plan login's slot is too large")

// openStore opens the plan login's slot in dir: a plain file of this uid's
// alone, or none; anything else refuses the start, since it is the
// directory's tampering, not the slot's. Its value is opened, and checked
// against the plan, when plan.New binds it (newLogin).
func openStore(dir string, s clerk.Sealer) (*plan.Store, error) {
	store := plan.NewStore(s, func(b []byte) error {
		if len(b) > maxPlanSlot {
			return errSlotTooLarge
		}
		return privfile.WriteAtomic(dir, planSlot, b, nil)
	})
	f, err := os.OpenFile(filepath.Join(dir, planSlot), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := privfile.CheckFile(f); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxPlanSlot+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxPlanSlot {
		// Not a form this process writes: it starts signed out (newLogin).
		log.Printf("agentos-clerk-model: the plan login's slot is over %d bytes; starting signed out", maxPlanSlot)
		b = nil
	}
	store.Load(b)
	clear(b)
	return store, nil
}

// serve reads the key from keyFile, opens the plan login and serves the
// owner socket until ctx ends or it stops serving. A slot another key
// sealed, or one sealed for another plan, refuses the start.
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
	store, err := openStore(c.dir, sealer)
	if err != nil {
		return err
	}
	guard, err := netGuard(ctx, &netguard.Sources{}, netWatchEvery)
	if err != nil {
		return err
	}
	login, err := newLogin(plan.Codex(guard), store)
	if err != nil {
		return err
	}
	h := &run.PlanHost{
		Login:  login,
		Prompt: run.CodexSignIn(),
		Workers: run.SignInSock{
			Host:       proc.Conn{Socket: c.signInSock, UID: c.agentosdUID},
			Login:      login,
			SandboxUID: c.agentosdUID,
		},
	}
	ln, err := run.ListenPlanOwner(c.ownerSock, c.agentosdUID)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- fmt.Errorf("the owner socket: %w", run.ServePlanOwner(ln, h)) }()
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
	log.Printf("agentos-clerk-model: the plan login's slot does not open under this key; starting signed out")
	store.Load(nil)
	return plan.New(d, store, nil)
}
