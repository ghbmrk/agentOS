// Command agentos-clerk-mail is the mail clerk's process (MAIL-main-a): one
// mail account's clerk, under its own uid, holding that account's Secrets and
// no others (CLK-1). It serves three sockets, each admitting one side's uid:
// the kernel's calls (kernel/proc ServeClerk), the owner side's setup, sign-in
// and status (clerk/run MailOwnerSide), and the planner's listing
// (MailPlannerSide):
//
//	agentos-clerk-mail -dir /var/lib/agentos-mail -anchors /run/agentos-keeper/anchors \
//	    -kernel-sock /run/agentos-mail/kernel.sock -kernel-uid 980 \
//	    -owner-sock /run/agentos-mail/owner.sock -owner-uid 0 \
//	    -planner-sock /run/agentos-mail/planner.sock -planner-uid 982 \
//	    -imap-conn /run/agentos-imapconn/conn.sock \
//	    -reader-sock /run/agentos-reader/reader.sock -reader-uid 984
//
// Its key comes from the kernel on descriptor 3 at each start
// (clerkkey.Key; Mark's option A, #2682 comment 6428111900), and it
// derives its sealer and its handle secret from it. The owner's anchors, which
// it checks every view against (D-146), come from a file only root writes,
// never from the kernel. Its quarantined read (PLN-2) goes over a frame to
// the reader process on the main side (clerk/readerwire, D-154 rule 4).
// Every refusal of the process comes before the key is
// read, so a clerk that cannot start never takes it.
package main

import (
	"container/list"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/clerk/readerwire"
	"github.com/ghbmrk/agentos/broker/clerk/run"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/procguard"
)

// clerkName is this clerk's name in its key's hand-off.
const clerkName = "mail"

func main() {
	log.SetFlags(0)
	if err := start(os.Args[1:], os.Stderr, os.NewFile(clerkkey.FD, "clerk-key")); err != nil {
		log.Fatal(err)
	}
}

type config struct {
	dir, anchors                       string
	kernelSock, ownerSock, plannerSock string
	kernelUID, ownerUID, plannerUID    int
	imapConn                           string // the IMAP connection process's socket; "": no IMAP account
	readerSock                         string // the reader process's socket; "": no reader, so no mail is classed
	readerUID                          int
	// anchorsOwner is the uid the anchors file and its directory must belong
	// to: root, or the test's own uid in tests; the command line never sets it.
	anchorsOwner int
}

func parse(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("agentos-clerk-mail", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config
	fs.StringVar(&c.dir, "dir", "", "the clerk's own state directory, closed to every other uid")
	fs.StringVar(&c.anchors, "anchors", "", "the owner's anchors, in a file only root writes")
	fs.StringVar(&c.kernelSock, "kernel-sock", "", "the socket the kernel calls the clerk on")
	fs.IntVar(&c.kernelUID, "kernel-uid", -1, "the kernel's uid, the only peer on kernel-sock")
	fs.StringVar(&c.ownerSock, "owner-sock", "", "the owner side's socket")
	fs.IntVar(&c.ownerUID, "owner-uid", -1, "the owner side's uid, the only peer on owner-sock (agentosd's, root)")
	fs.StringVar(&c.plannerSock, "planner-sock", "", "the planner's socket")
	fs.IntVar(&c.plannerUID, "planner-uid", -1, "the planner's uid, the only peer on planner-sock")
	fs.StringVar(&c.imapConn, "imap-conn", "", "the IMAP connection process's socket, one process per session (#3015); empty, an IMAP account is refused")
	fs.StringVar(&c.readerSock, "reader-sock", "", "the reader process's socket, for the quarantined read; with -reader-uid")
	fs.IntVar(&c.readerUID, "reader-uid", -1, "the reader process's uid, the only listener the clerk sends a mail's text to")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	switch {
	case fs.NArg() != 0:
		return c, fmt.Errorf("unexpected arguments: %q", fs.Args())
	case !abs(c.dir, c.anchors, c.kernelSock, c.ownerSock, c.plannerSock):
		return c, errors.New("-dir, -anchors, -kernel-sock, -owner-sock and -planner-sock are required, as absolute paths")
	case c.imapConn != "" && !filepath.IsAbs(c.imapConn):
		return c, errors.New("-imap-conn must be an absolute path")
	case c.kernelUID <= 0 || c.plannerUID <= 0 || c.ownerUID < 0:
		return c, errors.New("-kernel-uid, -planner-uid and -owner-uid are required; only the owner side's may be root")
	case c.kernelUID == c.plannerUID || c.kernelUID == c.ownerUID || c.plannerUID == c.ownerUID:
		return c, errors.New("the kernel, the owner side and the planner each need a uid of their own")
	case (c.readerSock == "") != (c.readerUID == -1):
		return c, errors.New("-reader-sock and -reader-uid go together")
	case c.readerSock != "" && !filepath.IsAbs(c.readerSock):
		return c, errors.New("-reader-sock must be an absolute path")
	case c.readerSock != "" && c.readerUID <= 0:
		return c, errors.New("-reader-uid must be positive: the reader never runs as root")
	case c.readerSock != "" && (c.readerUID == c.kernelUID || c.readerUID == c.ownerUID || c.readerUID == c.plannerUID):
		return c, errors.New("the reader needs a uid of its own, apart from the kernel's, the owner side's and the planner's")
	}
	return c, nil
}

func abs(paths ...string) bool {
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			return false
		}
	}
	return true
}

func start(args []string, stderr io.Writer, keyFile *os.File) error {
	c, err := parse(args, stderr)
	if err != nil {
		return err
	}
	anchors, err := guard(c)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return serve(ctx, c, anchors, keyFile)
}

// guard refuses the process itself, before the key is read: not as root,
// not as a peer's uid, and not while dumpable, since a peer could then read
// the key from its memory (CLK-1). Then it reads the owner's anchors.
func guard(c config) ([]key.PublicKey, error) {
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		return nil, errors.New("agentos-clerk-mail: the mail clerk never runs as root")
	}
	peers := []int{c.kernelUID, c.ownerUID, c.plannerUID}
	if c.readerSock != "" {
		peers = append(peers, c.readerUID)
	}
	if err := procguard.Isolate(peers...); err != nil {
		return nil, err
	}
	return readAnchors(c.anchors, c.anchorsOwner)
}

// maxAnchorsFile bounds the anchors file: handoff.MaxAnchors keys of the
// longest kind, with room for the form's tag.
const maxAnchorsFile = 16 << 10

// readAnchors reads the owner's anchors from path, which must be a regular
// file, not a link, owned by owner and writable by no one else, in a
// directory the same holds for: so neither the kernel's uid nor this
// clerk's can put anchors of its own there (D-146).
func readAnchors(path string, owner int) ([]key.PublicKey, error) {
	refuse := func(why string) error {
		return fmt.Errorf("agentos-clerk-mail: the owner's anchors at %s: %s", path, why)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Dir(path), &st); err != nil {
		return nil, refuse(err.Error())
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || int(st.Uid) != owner || st.Mode&0o022 != 0 {
		return nil, refuse("its directory is not root's alone")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, refuse(err.Error())
	}
	defer f.Close()
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return nil, refuse(err.Error())
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || int(st.Uid) != owner || st.Mode&0o022 != 0 {
		return nil, refuse("not a file root alone writes")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxAnchorsFile+1))
	if err != nil {
		return nil, refuse(err.Error())
	}
	if len(b) > maxAnchorsFile {
		return nil, refuse("too long")
	}
	anchors, err := handoff.ParseAnchors(b)
	if err != nil {
		return nil, refuse("does not read as the owner's anchors")
	}
	return anchors, nil
}

// errNoReader is every quarantined read's answer with no -reader-sock: no
// mail is classed, so the clerk acts on none.
var errNoReader = errors.New("agentos-clerk-mail: no reader is wired")

// reader is the quarantined read: with no socket it always fails; with one,
// each call goes to the reader process over its frame, behind a cache.
func reader(c config) inbox.Ask {
	if c.readerSock == "" {
		return func(context.Context, string) (string, error) { return "", errNoReader }
	}
	return cache(inbox.Ask(readerwire.Dial(c.readerSock, c.readerUID, readerwire.DefaultTimeout)), cacheMax)
}

// cacheMax bounds the cache: inbox.DailyCap's mails many times over.
const cacheMax = 4096

// cache wraps ask in a per-process cache of successful replies, keyed by the
// prompt's SHA-256 and evicting the least recently used past max entries.
// Each read re-classes the newest mails, so without it every read would
// re-send them all to a metered route (CLK-7). A failure is never cached,
// so the next read asks again; nothing is written to the drive, so a
// restart asks again too.
func cache(ask inbox.Ask, max int) inbox.Ask {
	var mu sync.Mutex
	lru := list.New()
	at := map[[sha256.Size]byte]*list.Element{}
	type entry struct {
		key   [sha256.Size]byte
		reply string
	}
	return func(ctx context.Context, prompt string) (string, error) {
		k := sha256.Sum256([]byte(prompt))
		mu.Lock()
		if e, ok := at[k]; ok {
			lru.MoveToFront(e)
			r := e.Value.(entry).reply
			mu.Unlock()
			return r, nil
		}
		mu.Unlock()
		reply, err := ask(ctx, prompt)
		if err != nil {
			return "", err
		}
		mu.Lock()
		defer mu.Unlock()
		if _, ok := at[k]; !ok {
			at[k] = lru.PushFront(entry{k, reply})
			for lru.Len() > max {
				delete(at, lru.Remove(lru.Back()).(entry).key)
			}
		}
		return reply, nil
	}
}

// serve reads the key from keyFile, opens the clerk and serves its three
// sockets until ctx ends or one stops serving.
func serve(ctx context.Context, c config, anchors []key.PublicKey, keyFile *os.File) error {
	k, err := clerkkey.Read(keyFile, clerkName)
	if err != nil {
		return err
	}
	sk, err := k.Sealer()
	if err != nil {
		k.Wipe()
		return err
	}
	handles, err := k.HandleSecret()
	k.Wipe()
	if err != nil {
		clear(sk)
		return err
	}
	sealer, err := clerk.NewAESSealer(sk)
	clear(sk)
	if err != nil {
		return err
	}
	sec, err := run.OpenSecrets(c.dir, sealer)
	if err != nil {
		return err
	}
	guard, err := netGuard(ctx, &netguard.Sources{}, netWatchEvery)
	if err != nil {
		return err
	}
	cfg := run.MailConfig{
		Anchors:      anchors,
		HandleSecret: handles,
		Sealer:       sealer,
		Ask:          reader(c),
		// Every name this process resolves, for IMAP, Gmail and the key
		// records, goes through the learned resolver (DEV-2).
		Guard: guard,
		// The world is the host's own (run's world.go, D-154 rule 5): no
		// World is passed, and each read looks up its own key records.
		DKIM: func(ctx context.Context, names []string) map[string]string {
			return inbox.LookupDKIM(ctx, guard.Resolver(), names)
		},
	}
	cfg.Conn = imapConn(c.imapConn)
	h := run.NewMailHost(ctx, c.dir, sec, cfg)

	kernelLn, err := proc.ListenClerk(c.kernelSock, c.kernelUID)
	if err != nil {
		return err
	}
	ownerLn, err := run.ListenMail(c.ownerSock, c.ownerUID)
	if err != nil {
		kernelLn.Close()
		return err
	}
	plannerLn, err := run.ListenMail(c.plannerSock, c.plannerUID)
	if err != nil {
		kernelLn.Close()
		ownerLn.Close()
		return err
	}
	lns := []net.Listener{kernelLn, ownerLn, plannerLn}
	done := make(chan error, len(lns))
	go func() { done <- fmt.Errorf("the kernel's socket: %w", proc.ServeClerk(kernelLn, h, anchors)) }()
	go func() {
		done <- fmt.Errorf("the owner side's socket: %w", run.ServeMail(ownerLn, h, run.MailOwnerSide))
	}()
	go func() {
		done <- fmt.Errorf("the planner's socket: %w", run.ServeMail(plannerLn, h, run.MailPlannerSide))
	}()
	select {
	case <-ctx.Done():
		err = nil
	case err = <-done:
	}
	for _, ln := range lns {
		ln.Close()
	}
	return err
}

// errNoIMAPConn is every IMAP session's answer with no -imap-conn.
var errNoIMAPConn = errors.New("agentos-clerk-mail: no IMAP connection process is wired")

// imapConn starts a fresh IMAP connection process for each session by
// connecting to its socket unit at path (#3015) and returns the control
// connection. With no path every session is refused: a nil Conn would make
// imapsmtp parse IMAP in this process (imapconn.Pipe), undoing #2937 gap 2.
func imapConn(path string) func(context.Context) (*net.UnixConn, error) {
	if path == "" {
		return func(context.Context) (*net.UnixConn, error) { return nil, errNoIMAPConn }
	}
	return func(ctx context.Context) (*net.UnixConn, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "unix", path)
		if err != nil {
			return nil, err
		}
		return conn.(*net.UnixConn), nil
	}
}
