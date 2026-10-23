// Command agentos-kernel is the kernel's process (STO-2b, MIG-4-run). The
// unlock step (agentos-unlock) execs it under the kernel's own uid, with the
// log key, the head key and the owner's anchors on descriptor 3:
//
//	agentos-kernel -log /var/lib/agentos-kernel/log \
//	    -owner-sock /run/agentos-kernel/owner.sock -owner-uid 981 \
//	    -meter-sock /run/agentos-kernel/meter.sock -meter-uid 982 \
//	    -clerk exit=/run/agentos-exit/kernel.sock,983
//
// It refuses to run as root or as any peer's uid, makes itself non-dumpable,
// serves the owner side and the model clerk's meter on their sockets, and
// runs plans every second. It holds no credential and never the store key.
// It needs a log anchor off the log's disk (LOG-2); until the TPM counter
// anchor lands (LOG-anchor-tpm, #2682) it refuses to start.
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/clerk/run"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/procguard"
)

func main() {
	log.SetFlags(0)
	if err := start(os.Args[1:], os.Stderr, productionAnchor, os.NewFile(handoff.KeyFD, "unlock-keys")); err != nil {
		log.Fatal(err)
	}
}

// errNoAnchor: no production log anchor exists yet. MemAnchor would forget
// every head at a restart, so a rolled-back log would pass (LOG-2).
var errNoAnchor = errors.New("agentos-kernel: no log anchor off this disk yet (LOG-anchor-tpm); I start nothing")

func productionAnchor() (kernel.Anchor, error) { return nil, errNoAnchor }

type clerks map[string]run.Remote

func (c clerks) String() string { return fmt.Sprint(map[string]run.Remote(c)) }

// Set reads name=socket,uid.
func (c clerks) Set(v string) error {
	name, rest, ok := strings.Cut(v, "=")
	sock, uidText, ok2 := strings.Cut(rest, ",")
	uid, err := strconv.Atoi(uidText)
	if !ok || !ok2 || name == "" || !strings.HasPrefix(sock, "/") || err != nil || uid <= 0 {
		return errors.New("a clerk is name=/abs/socket,uid")
	}
	if _, dup := c[name]; dup {
		return fmt.Errorf("clerk %q given twice", name)
	}
	c[name] = run.Remote{Socket: sock, UID: uid}
	return nil
}

func parse(args []string, stderr io.Writer) (run.MainConfig, error) {
	fs := flag.NewFlagSet("agentos-kernel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	c := run.MainConfig{Clerks: map[string]run.Remote{}}
	fs.StringVar(&c.Log, "log", "", "the log file")
	fs.StringVar(&c.OwnerSock, "owner-sock", "", "the owner side's socket")
	fs.IntVar(&c.OwnerUID, "owner-uid", -1, "the owner side's uid, the only peer on owner-sock")
	fs.StringVar(&c.MeterSock, "meter-sock", "", "the model clerk's meter socket")
	fs.IntVar(&c.MeterUID, "meter-uid", -1, "the model clerk's uid, the only peer on meter-sock")
	fs.Var(clerks(c.Clerks), "clerk", "a clerk the kernel runs, name=/abs/socket,uid (repeatable)")
	fs.DurationVar(&c.Tick, "tick", time.Second, "how often plans run")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	switch {
	case fs.NArg() != 0:
		return c, fmt.Errorf("unexpected arguments: %q", fs.Args())
	case c.Log == "" || c.OwnerSock == "" || c.MeterSock == "":
		return c, errors.New("-log, -owner-sock and -meter-sock are required")
	case c.OwnerUID <= 0 || c.MeterUID <= 0:
		return c, errors.New("-owner-uid and -meter-uid are required, and never root")
	}
	c.Peers = []int{c.OwnerUID, c.MeterUID}
	for _, r := range c.Clerks {
		c.Peers = append(c.Peers, r.UID)
	}
	return c, nil
}

// start runs the kernel with the unlock step's hand-off on keyFile. Every
// refusal comes before the keys are read, so a kernel that cannot start
// never takes them: not as root, not as a peer's uid, and not while
// dumpable, since a peer could then read them from its memory (CLK-1).
func start(args []string, stderr io.Writer, anchor func() (kernel.Anchor, error), keyFile *os.File) error {
	cfg, err := parse(args, stderr)
	if err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return errors.New("agentos-kernel: the kernel never runs as root")
	}
	if err := procguard.Isolate(cfg.Peers...); err != nil {
		return err
	}
	a, err := anchor()
	if err != nil {
		return err
	}
	keys, err := handoff.ReadKeys(keyFile)
	if err != nil {
		return err
	}
	defer keys.Wipe()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return run.RunKernel(ctx, cfg, keys, a)
}
