// Command agentos-holder is one account's key holder (SIM-split): it keeps
// that account's login and nothing else, and spends it only on a request
// in a shape the account's adapters declare (package holder).
//
//	agentos-holder -dir /run/agentos-holder/openai -credential openai \
//	    -adapter openai -request-uid 991 -hand-uid 992 \
//	    -checker /run/agentos-checker/redeem.sock
//
// It listens on dir/request.sock for egress (request-uid) and on
// dir/hand.sock for the unlock step (hand-uid), and starts empty: the
// unlock step's keeper hands it the login, and hands it again after a
// restart. With -checker it also serves the adapters' irreversible
// operations, each only once the CH-4 checker approved that exact request;
// without it, reads only. It refuses to run as either peer uid and makes
// itself non-dumpable. Adapters whose operations exchange credentials need a swapper
// the holder does not have yet, and are refused.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/checker"
	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/holder"
	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/procguard"
)

const netWatchEvery = time.Minute

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:], os.Stderr); err != nil {
		log.Fatal(err)
	}
}

// catalog is every adapter a holder can serve, by name.
func catalog(credential string) map[string]egress.Adapter {
	return map[string]egress.Adapter{
		"openai":    egress.OpenAI(credential),
		"anthropic": egress.Anthropic(credential),
	}
}

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

// config is a parsed command line.
type config struct {
	dir, checker        string
	adapters            []egress.Adapter
	requestUID, handUID int
	publicFetch         bool
}

func parse(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("agentos-holder", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config
	var names list
	cred := fs.String("credential", "", "the vault entry this holder keeps")
	fs.StringVar(&c.dir, "dir", "", "run directory for the two sockets")
	fs.Var(&names, "adapter", "an adapter to serve (repeatable)")
	fs.IntVar(&c.requestUID, "request-uid", -1, "uid of egress, the only peer on request.sock")
	fs.StringVar(&c.checker, "checker", "", "the CH-4 checker's redeem socket; without it, reads only")
	fs.IntVar(&c.handUID, "hand-uid", -1, "uid of the unlock step, the only peer on hand.sock")
	fs.BoolVar(&c.publicFetch, "public-fetch", false, "the owner lets public machines use provider-side fetch with this login; without it, every body is held to the strict form")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	switch {
	case c.dir == "" || *cred == "" || len(names) == 0:
		return c, errors.New("-dir, -credential and -adapter are required")
	case c.requestUID < 0 || c.handUID < 0:
		return c, errors.New("-request-uid and -hand-uid are required")
	case c.requestUID == c.handUID:
		return c, errors.New("egress and the unlock step must be different uids")
	}
	cat := catalog(*cred)
	for _, n := range names {
		a, ok := cat[n]
		if !ok {
			return c, fmt.Errorf("unknown adapter %q", n)
		}
		for _, op := range a.Operations {
			if op.Response != nil {
				return c, fmt.Errorf("adapter %s exchanges credentials; holders cannot store them yet", n)
			}
		}
		c.adapters = append(c.adapters, a)
	}
	return c, nil
}

// holderConfig is the holder's declaration. Provider-side fetch for public
// machines is the owner's per-login choice, passed as -public-fetch; with
// no flag the login is held to the strict form (ADP-10, #1061 P1).
func (c config) holderConfig(guard *netguard.Policy) holder.Config {
	var redeem func(context.Context, string, bool) (bool, error)
	if c.checker != "" {
		redeem = checker.Redeemer(c.checker)
	}
	return holder.Config{Adapters: c.adapters, Guard: guard, Redeem: redeem, PublicFetch: c.publicFetch}
}

func run(args []string, stderr io.Writer) error {
	c, err := parse(args, stderr)
	if err != nil {
		return err
	}
	if err := procguard.Isolate(c.requestUID, c.handUID); err != nil {
		return err
	}
	guard, err := netGuard(context.Background())
	if err != nil {
		return err
	}
	h, err := holder.New(c.holderConfig(guard))
	if err != nil {
		return err
	}
	if err := runDir(c.dir); err != nil {
		return err
	}
	reqs, err := holder.Listen(filepath.Join(c.dir, holder.RequestSocket), c.requestUID)
	if err != nil {
		return err
	}
	hand, err := holder.Listen(filepath.Join(c.dir, holder.HandSocket), c.handUID)
	if err != nil {
		reqs.Close()
		return err
	}
	return h.Serve(reqs, hand)
}

// netGuard is the holder's address policy, as egress builds its own
// (DEV-2): the learned home network is refused, refreshed every minute,
// and no pin is carried.
func netGuard(ctx context.Context) (*netguard.Policy, error) {
	src := &netguard.Sources{}
	p := netguard.New(netguard.Config{
		Source: src.Read,
		OnDeny: func(e netguard.DenyEvent) {
			log.Printf("netguard: refused %v port %d purpose %d: %s", e.Addr, e.Port, e.Purpose, e.Reason)
		},
	})
	if err := p.SetPins(nil); err != nil {
		return nil, err
	}
	if err := p.Refresh(); err != nil {
		log.Printf("netguard: first read of the home network failed: %v", err)
	}
	go p.WatchEvery(ctx, netWatchEvery)
	return p, nil
}

// runDir creates dir 0711, or checks that an existing one is a directory
// owned by this uid and resets its mode.
func runDir(dir string) error {
	if err := os.Mkdir(dir, 0o711); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not a directory owned by uid %d", dir, os.Getuid())
	}
	return os.Chmod(dir, 0o711)
}
