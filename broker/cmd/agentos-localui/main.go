// Command agentos-localui serves the box's Wi-Fi page (P2-2w; CH-7 to
// CH-10, ARC-2, L15). It runs as its own user, agentos-localui, and
// decodes untrusted input (forms and photos from any phone on the access
// point), so it holds no authority: every owner action goes to agentosd's
// localui.sock, which admits only this uid, mints and checks the session
// tokens and counts wrong codes (localapi; Security L1, L2 on the P2-2w
// plan). It listens on the access point's address and interface only
// (Security L5) and logs no request or form field.
//
// Setup runs through agentosd (P2-2w c4; Security L6): the page asks
// localui.sock's setup ops, which agentosd serves only until setup's
// finish, and keeps setup's state in memory only (L18), so a restart of
// the page starts the steps over. The one exception is a private-content
// answer agentosd did not record: its hold is kept on disk (-held), so a
// reboot cannot finish setup on an earlier answer.
//
// With the vault process's unlock socket, a box whose setup is open runs
// firstboot.Begin here (#1115): the claim gate of a preloaded box, the
// reinstall route of one that lost its claim state, and the Owner Card
// step, whose provision and reset go over the unlock socket and whose
// confirm the page reports to agentosd before finish. Without that
// socket an open setup fails closed: the page exits and serves no step.
//
// The page decides once whether setup is open: agentosd's answer, never
// its silence, so a transient error neither skips the first boot nor
// opens setup later without it (#1270). Only the download's image passes
// -download-box; on any other a box without a claim state is told to
// reinstall, never served setup without the claim gate.
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/firstboot"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localui"
)

// memoryLimit is the Go heap's soft ceiling, under the unit's MemoryMax,
// so a decoder worst case cannot press on the broker (L18 on #50).
const memoryLimit = 384 << 20

func main() {
	var sock, vaultSock, held, iface, addr string
	var fb boxFiles
	var port int
	flag.StringVar(&sock, "sock", "/run/agentos/localui.sock", "agentosd's localui.sock (agentosd -localui-uid)")
	flag.StringVar(&vaultSock, "vault-sock", "", "the vault process's unlock socket, for the unknown-host unlock page; empty: not served")
	flag.StringVar(&held, "held", "/var/lib/agentos-localui/unsaved.json", "setup's private-content answers agentosd has not recorded, kept across a reboot (localui.HeldStore)")
	flag.StringVar(&fb.Claim, "claim-state", claim.StatePath, "a preloaded box's claim state, as its seller sealed it (HW-10)")
	flag.StringVar(&fb.Latch, "card-latch", "/var/lib/agentos/card-latch.json", "the Owner Card step's latch (HW-1)")
	flag.BoolVar(&fb.Download, "download-box", false, "the download's image, which ships no claim state; unset, a box without one is told to reinstall (#1270)")
	flag.StringVar(&iface, "iface", "wlan0", "the access point's interface")
	flag.StringVar(&addr, "addr", "10.42.0.1/24", "the Wi-Fi page's address on the access point, with the subnet's length")
	flag.IntVar(&port, "port", localui.UIPort, "TCP port")
	flag.Parse()
	log.SetFlags(0)
	debug.SetMemoryLimit(memoryLimit)
	ap, err := netip.ParsePrefix(addr)
	if err != nil {
		log.Fatalf("-addr: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fb.VaultSock = vaultSock
	cfg := config(localui.APConfig{Iface: iface, Addr: ap}, port, sock, vaultSock, held)
	cfg.Station = station(sysClassNet, iface)
	if err := run(ctx, cfg, sock, fb); err != nil {
		log.Fatal(err)
	}
}

// config is the page's configuration: setup through agentosd's socket
// with an in-memory store (P2-2w c4) but for its unsaved private-content
// answers, which the file at held keeps across a reboot
// (ONB-private-save-fail s3), and no setup secret (Security L6).
// The vault process's unlock socket serves both the unlock page and the
// Owner Card rotation (REC-4), the AI providers page and setup's host
// step (P2-2w c4d); ARC-2 keeps the card's display here, not in agentosd.
func config(ap localui.APConfig, port int, sock, vaultSock, held string) localui.Config {
	hooks := localui.AgentosdSetup{Owner: localui.Socket{Path: sock}}
	cfg := localui.Config{AP: ap, Port: port, Store: localui.HeldStore{Inner: &localui.MemStore{}, Path: held}}
	if vaultSock != "" {
		client := localui.NewUnlockClient(vaultSock)
		cfg.Vault = client
		cfg.Rotation = localui.NewRotation(client)
		// The AI providers page: the owner's private-data answer after
		// setup (#1266).
		cfg.Providers = client
		// Setup's host step (P2-2w c4d, §8.1).
		hooks.Vault = client
	}
	cfg.Hooks = hooks
	return cfg
}

// sysClassNet is the kernel's list of network interfaces; the unit's
// sandbox leaves it readable.
const sysClassNet = "/sys/class/net"

// station reports, each time setup asks, whether a Wi-Fi device other
// than the access point's can join the home network (P2-2w c4 r1): one
// may appear after boot, such as a USB adapter.
func station(netClass, iface string) func() bool {
	return func() bool { return localui.StationDevice(netClass, iface) }
}

// withFirstBoot runs firstboot.Begin and gives the page its steps: the
// claim screen (nil on the download route), the card step, and the
// report of its confirm before agentosd's finish.
func withFirstBoot(cfg localui.Config, box firstboot.BoxConfig, void *localui.CodesVoid) (localui.Config, firstboot.Route, error) {
	fb, err := firstboot.Begin(withCardNet(cfg.Hooks, box))
	if err != nil {
		return cfg, "", err
	}
	if fb.Claim != nil {
		cfg.Claim = fb.Claim
	}
	cfg.Card, cfg.CodesVoid = fb.Card, void
	if h, ok := cfg.Hooks.(localui.AgentosdSetup); ok {
		cfg.Hooks = localui.CardFinish{AgentosdSetup: h, Card: fb.Card}
	}
	return cfg, fb.Route, nil
}

// withCardNet has the card step report the card's network to agentosd
// before the confirm latches, for agentos-ap to serve at it (#1185).
func withCardNet(hooks localui.Hooks, box firstboot.BoxConfig) firstboot.BoxConfig {
	if h, ok := hooks.(localui.AgentosdSetup); ok && box.Card.Provision != nil {
		box.Card.Provision = localui.ServeCardNet(box.Card.Provision, h)
	}
	return box
}

// agentosdWait bounds the wait for agentosd's socket; past it the page
// exits and its unit restarts it.
const agentosdWait = 30 * time.Second

// boxFiles is what the page's first boot reads: the vault process's
// unlock socket, the claim state and the card step's latch, and whether
// the image is the download's (firstboot.BoxConfig.Download).
type boxFiles struct {
	VaultSock, Claim, Latch string
	Download                bool
}

func run(ctx context.Context, cfg localui.Config, sock string, fb boxFiles) error {
	cfg, err := prepare(ctx, cfg, sock, fb)
	if err != nil {
		return err
	}
	s, err := localui.New(cfg)
	if err != nil {
		return err
	}
	s.SetOwner(localui.Socket{Path: sock})
	// PAIR texts that reach the box come through agentosd while setup is
	// open (P2-2w c4c; §8.1 pairing).
	// AgentosdSetup has it, and so does CardFinish, which embeds it.
	if a, ok := cfg.Hooks.(interface {
		PairTexts(context.Context, *localui.Server, time.Duration)
	}); ok {
		go a.PairTexts(ctx, s, 5*time.Second)
	}
	ln, err := localui.Listen(ctx, cfg.AP, cfg.Port)
	if err != nil {
		return err
	}
	hs := newHTTPServer(s)
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(sh)
	}()
	if err := hs.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// errNoVault: setup is open but the page has no unlock socket, so it could
// run neither the claim gate (HW-10) nor the card step (HW-1).
var errNoVault = errors.New("setup is open and -vault-sock is unset: no claim gate or card step can run")

// prepare waits for agentosd and, while setup is open, runs the first
// boot. An owned box never runs it: its reset could remove a vault in use.
// An open setup without the unlock socket fails closed, serving no step:
// the claim gate of a preloaded box runs only with the first boot.
func prepare(ctx context.Context, cfg localui.Config, sock string, fb boxFiles) (localui.Config, error) {
	// New asks agentosd whether setup is open and takes no answer as
	// closed, so it waits until agentosd's socket accepts.
	if err := awaitSocket(ctx, sock, agentosdWait); err != nil {
		return cfg, err
	}
	open, err := setupOpen(ctx, cfg.Hooks, agentosdWait)
	if err != nil {
		return cfg, err
	}
	if !open {
		if a, ok := cfg.Hooks.(localui.AgentosdSetup); ok {
			cfg.Hooks = ownedSetup{a}
		}
		return cfg, nil
	}
	if fb.VaultSock == "" {
		return cfg, errNoVault
	}
	if err := awaitSocket(ctx, fb.VaultSock, agentosdWait); err != nil {
		return cfg, err
	}
	void := &localui.CodesVoid{}
	box := localui.CardBox(localui.NewUnlockClient(fb.VaultSock), change.FileStore{Path: fb.Claim},
		change.FileStore{Path: fb.Latch}, void)
	box.Download = fb.Download
	cfg, _, err = withFirstBoot(cfg, box, void)
	return cfg, err
}

// setupOpen is the page's one decision whether setup is open: agentosd's
// answer to OpSetupProgress, open on an answer and closed on a refusal.
// No answer is no decision: it asks again until wait has passed, then
// errors, so the unit restarts the page (#1270). Hooks other than
// agentosd's answer through AlreadySetUp.
func setupOpen(ctx context.Context, hooks localui.Hooks, wait time.Duration) (bool, error) {
	a, ok := hooks.(localui.AgentosdSetup)
	if !ok {
		return hooks != nil && !hooks.AlreadySetUp(), nil
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	for {
		var r localui.Refused
		err := a.Owner.Call(ctx, localapi.OpSetupProgress, nil, nil)
		switch {
		case err == nil:
			return true, nil
		case errors.As(err, &r):
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, errors.New("agentosd does not answer whether setup is open")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// ownedSetup is agentosd's setup on a box whose setup prepare found
// closed: closed for good, whatever agentosd answers later, so a later
// answer never opens setup without the first boot (#1270).
type ownedSetup struct{ localui.AgentosdSetup }

func (ownedSetup) AlreadySetUp() bool { return true }

// awaitSocket returns once the Unix socket at path accepts a connection,
// or an error after wait.
func awaitSocket(ctx context.Context, path string, wait time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	var d net.Dialer
	for {
		c, err := d.DialContext(ctx, "unix", path)
		if err == nil {
			return c.Close()
		}
		select {
		case <-ctx.Done():
			return errors.New("agentosd's socket does not accept connections")
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// newHTTPServer bounds slow clients and logs nothing a request carries
// (Security L5): net/http's own error log can quote a client's bytes.
func newHTTPServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       90 * time.Second, // a photo upload (L18) has 60 s
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
}
