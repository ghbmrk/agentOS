// Command agentos-kernel is the kernel's process (STO-2b, MIG-4-run). The
// unlock step (agentos-unlock) execs it under the kernel's own uid, with the
// log key, the head key and the owner's anchors on descriptor 3:
//
//	agentos-kernel -log /var/lib/agentos-kernel/log -keys-dir /var/lib/agentos-kernel/keys \
//	    -content-dir /var/lib/agentos-kernel/content -backup-dir /var/lib/agentos-kernel/backups \
//	    -owner-sock /run/agentos-kernel/owner.sock -owner-uid 981 \
//	    -meter-sock /run/agentos-kernel/meter.sock -meter-uid 982 \
//	    -link-sock /run/agentos-kernel/link.sock -link-uid 980 \
//	    -clerk exit=/run/agentos-exit/kernel.sock,983 \
//	    -clerk-key mail=/run/agentos-kernel/clerk-mail.key,/agentos-keeper.slice/agentos-keeper-mail.service \
//	    -content vision=/run/agentos-kernel/vision.sock,985
//
// It opens the subject-key table in -keys-dir, sealed under the log key, so
// content opens and every logged erase is re-applied at start (KRN-erase),
// its content stores in -content-dir, one per -content clerk, which seals
// into its own on its own socket (KRN-content),
// and its backups' records in -backup-dir, so an erase reaches every
// backup taken before (BAK-1, LOG-4).
// It refuses to run as root or as any peer's uid, makes itself non-dumpable,
// serves the owner side and the model clerk's meter on their sockets, and
// agentos-link on its own when -link-sock is given (EDGE-link-core c2b),
// hands each -clerk-key clerk its key at every start of that clerk's unit
// (MAIL-keys), and runs plans every second. It holds no credential and never the store key.
// Its log anchor is the TPM counter enrollment defined (LOG-2, STO-1): the
// signed head lives in -anchor-dir and the counter numbers its writes, so a
// drive rolled back, log and anchor together, is refused at start.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/cmd/agentos-kernel/anchor"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/procguard"
)

func main() {
	log.SetFlags(0)
	if err := start(os.Args[1:], os.Stderr, anchor.Open, os.NewFile(handoff.KeyFD, "unlock-keys"), os.NewFile(handoff.TPMFD, "tpm")); err != nil {
		log.Fatal(err)
	}
}

// anchorFunc opens the log's anchor in dir with the unlock step's keys and
// the TPM connection it handed over.
type anchorFunc func(dir string, keys handoff.KernelKeys, tpm *os.File) (kernel.Anchor, error)

type clerks map[string]proc.Remote

func (c clerks) String() string { return fmt.Sprint(map[string]proc.Remote(c)) }

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
	c[name] = proc.Remote{Socket: sock, UID: uid}
	return nil
}

type keyClerks map[string]proc.KeyClerk

func (c keyClerks) String() string { return fmt.Sprint(map[string]proc.KeyClerk(c)) }

// Set reads name=socket,cgroup: the clerk unit's whole cgroup path, which
// must be name's own (clerkCgroup), whatever the rest of the command line.
func (c keyClerks) Set(v string) error {
	name, rest, ok := strings.Cut(v, "=")
	sock, cg, ok2 := strings.Cut(rest, ",")
	if !ok || !ok2 || !clerkkey.ValidName(name) || !filepath.IsAbs(sock) || cg != clerkCgroup(name) {
		return fmt.Errorf("a clerk's key socket is name=/abs/socket,%s", clerkCgroup("name"))
	}
	if _, dup := c[name]; dup {
		return fmt.Errorf("clerk %q's key given twice", name)
	}
	c[name] = proc.KeyClerk{Socket: sock, Cgroup: cg}
	return nil
}

// clerkCgroup is the one cgroup name's key goes to (KEYS-route-by-cgroup,
// #4210): its own keeper unit, so an entry's name is its unit's and no key
// reaches a unit outside the keeper; a device driver's, driver-<d>, goes to
// each instance of its template (DEVSLOT-host-unit-2-k).
func clerkCgroup(name string) string {
	if d, ok := strings.CutPrefix(name, "driver-"); ok && d != "" {
		return "/agentos.slice/agentos-drivers.slice/agentos-driver-" + d + "@.service"
	}
	return "/agentos.slice/agentos-keeper.slice/agentos-keeper-" + name + ".service"
}

// config is the kernel process's: proc.MainConfig and the anchor's
// directory.
type config struct {
	proc.MainConfig
	AnchorDir string
}

func parse(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("agentos-kernel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	c := config{MainConfig: proc.MainConfig{Clerks: map[string]proc.Remote{}, ClerkKeys: map[string]proc.KeyClerk{}, Content: map[string]proc.Remote{}}}
	fs.StringVar(&c.Log, "log", "", "the log file")
	fs.StringVar(&c.KeyDir, "keys-dir", "", "the subject-key table's directory, beside the log")
	fs.StringVar(&c.ContentDir, "content-dir", "", "the content stores' directory, beside the log")
	fs.StringVar(&c.BackupDir, "backup-dir", "", "the backups' records directory, beside the log")
	fs.StringVar(&c.AnchorDir, "anchor-dir", "", "the log anchor's directory, beside the log")
	fs.StringVar(&c.OwnerSock, "owner-sock", "", "the owner side's socket")
	fs.IntVar(&c.OwnerUID, "owner-uid", -1, "the owner side's uid, the only peer on owner-sock")
	fs.StringVar(&c.MeterSock, "meter-sock", "", "the model clerk's meter socket")
	fs.IntVar(&c.MeterUID, "meter-uid", -1, "the model clerk's uid, the only peer on meter-sock")
	fs.StringVar(&c.LinkSock, "link-sock", "", "agentos-link's socket; none without it")
	fs.IntVar(&c.LinkUID, "link-uid", -1, "agentos-link's uid, the only peer on link-sock")
	fs.Var(clerks(c.Clerks), "clerk", "a clerk the kernel runs, name=/abs/socket,uid (repeatable)")
	fs.Var(keyClerks(c.ClerkKeys), "clerk-key", "a clerk the kernel hands its key to at each start of its unit, name=/abs/socket,/agentos.slice/agentos-keeper.slice/agentos-keeper-<name>.service (repeatable)")
	fs.Var(clerks(c.Content), "content", "a content clerk's socket, store=/abs/socket,uid (repeatable)")
	fs.DurationVar(&c.Tick, "tick", time.Second, "how often plans run")
	fs.StringVar(&c.Up, "up", "", "a file to make once both sockets listen, an absolute path")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	switch {
	case fs.NArg() != 0:
		return c, fmt.Errorf("unexpected arguments: %q", fs.Args())
	case c.Log == "" || c.OwnerSock == "" || c.MeterSock == "":
		return c, errors.New("-log, -owner-sock and -meter-sock are required")
	case !filepath.IsAbs(c.AnchorDir):
		return c, errors.New("an absolute -anchor-dir is required")
	case !filepath.IsAbs(c.KeyDir):
		return c, errors.New("an absolute -keys-dir is required")
	case !filepath.IsAbs(c.BackupDir):
		return c, errors.New("an absolute -backup-dir is required")
	case !filepath.IsAbs(c.ContentDir):
		return c, errors.New("an absolute -content-dir is required")
	case c.Up != "" && !filepath.IsAbs(c.Up):
		return c, errors.New("-up must be an absolute path")
	case c.OwnerUID <= 0 || c.MeterUID <= 0:
		return c, errors.New("-owner-uid and -meter-uid are required, and never root")
	case (c.LinkSock == "") != (c.LinkUID == -1):
		return c, errors.New("-link-sock and -link-uid come together")
	case c.LinkSock != "" && (!filepath.IsAbs(c.LinkSock) || c.LinkUID <= 0):
		return c, errors.New("-link-sock is an absolute path and -link-uid never root")
	}
	c.Peers = []int{c.OwnerUID, c.MeterUID}
	for _, r := range c.Clerks {
		c.Peers = append(c.Peers, r.UID)
	}
	if c.LinkSock != "" {
		// The link socket admits the link's uid alone: a peer sharing it
		// could log a candidate the page step enrols (decision 8).
		if slices.Contains(c.Peers, c.LinkUID) {
			return c, errors.New("-link-uid is agentos-link's own, no other peer's")
		}
		c.Peers = append(c.Peers, c.LinkUID)
	}
	// A content socket hands its store's plaintext to its peer, so that
	// uid is its content clerk's alone: never the owner side's, the model
	// clerk's, the link's or another content clerk's (KRN-content). A
	// clerk the kernel also calls may share it, being the same process.
	taken := []int{c.OwnerUID, c.MeterUID}
	if c.LinkSock != "" {
		taken = append(taken, c.LinkUID)
	}
	for _, store := range slices.Sorted(maps.Keys(c.Content)) {
		r := c.Content[store]
		switch {
		case !proc.ValidStoreName(store):
			return c, fmt.Errorf("-content %q: %w", store, proc.ErrStoreName)
		case slices.Contains(taken, r.UID):
			return c, fmt.Errorf("-content %q: its uid is its clerk's own, no other side's", store)
		}
		taken = append(taken, r.UID)
		if !slices.Contains(c.Peers, r.UID) {
			c.Peers = append(c.Peers, r.UID)
		}
	}
	return c, nil
}

// start runs the kernel with the unlock step's hand-off on keyFile and its
// TPM connection on tpmFile. Every refusal of the process itself comes
// before the keys are read, so a kernel that cannot start never takes them:
// not as root, not as a peer's uid, and not while dumpable, since a peer
// could then read them from its memory (CLK-1). The anchor is opened after,
// since it signs with the head key; a refused anchor wipes the keys.
func start(args []string, stderr io.Writer, anchor anchorFunc, keyFile, tpmFile *os.File) error {
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
	keys, err := handoff.ReadKeys(keyFile)
	if err != nil {
		return err
	}
	defer keys.Wipe()
	a, err := anchor(cfg.AnchorDir, keys, tpmFile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return proc.RunKernel(ctx, cfg.MainConfig, keys, a)
}
