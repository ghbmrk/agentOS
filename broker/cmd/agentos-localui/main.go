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
//
// The page is also served over HTTPS on its name (-page-name) on port 443
// (OWN-page-https, #3153; CH-9): at start the page makes a serving key in
// memory and asks agentosd to certify it under the page authority, and
// renews it daily. agentosd holds the authority's key; with none (no
// sealer before STO-2, or a claimed box that lost it) the page serves
// plain HTTP only, with no redirect.
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
	var sock, vaultSock, held, iface, addr, pageName, passkeyRPID string
	var fb boxFiles
	var port int
	var connectGmail bool
	flag.StringVar(&sock, "sock", "/run/agentos/localui.sock", "agentosd's localui.sock (agentosd -localui-uid)")
	flag.StringVar(&vaultSock, "vault-sock", "", "the vault process's unlock socket, for the unknown-host unlock page; empty: not served")
	flag.StringVar(&held, "held", "/var/lib/agentos-localui/unsaved.json", "setup's private-content answers agentosd has not recorded, kept across a reboot (localui.HeldStore)")
	flag.StringVar(&fb.Claim, "claim-state", claim.StatePath, "a preloaded box's claim state, as its seller sealed it (HW-10)")
	flag.StringVar(&fb.Latch, "card-latch", "/var/lib/agentos/card-latch.json", "the Owner Card step's latch (HW-1)")
	flag.BoolVar(&fb.Download, "download-box", false, "the download's image, which ships no claim state; unset, a box without one is told to reinstall (#1270)")
	flag.StringVar(&iface, "iface", "wlan0", "the access point's interface")
	flag.StringVar(&addr, "addr", "10.42.0.1/24", "the Wi-Fi page's address on the access point, with the subnet's length")
	flag.IntVar(&port, "port", localui.UIPort, "TCP port")
	flag.StringVar(&pageName, "page-name", localui.DefaultPageName, "the owner page's name over HTTPS, the one name its authority admits (#3153)")
	flag.StringVar(&passkeyRPID, "passkey-rp-id", "", "serve the passkey page at /passkeys/ (#2779a) with this WebAuthn RP ID, through agentosd's passkey ops (agentosd -passkey-rp-id, the same name); it must be -page-name, and the page refuses to start unless the HTTPS listener is up")
	flag.BoolVar(&connectGmail, "connect-gmail", false, "serve the Connect page for Gmail at /accounts/ (#3006), through agentosd's account ops to the mail clerk; set only where agentosd runs with -mail-owner")
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
	cfg := config(localui.APConfig{Iface: iface, Addr: ap, PageName: pageName}, port, sock, vaultSock, held)
	if connectGmail {
		connect(&cfg, sock)
	}
	if passkeyRPID != "" {
		passkeys(&cfg, sock, passkeyRPID)
	}
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

// connect serves the Connect page for Gmail (#2853, #3006): its frames go
// to agentosd's localui.sock, which checks the session and relays them to
// the mail clerk across the keeper boundary (D-154 rule 1); the page holds
// nothing of the sign-in.
func connect(cfg *localui.Config, sock string) {
	cfg.Accounts = localui.AgentosdAccounts{Owner: localui.Socket{Path: sock}}
	cfg.Connect = []localui.ConnectDeclaration{localui.GmailConnect}
}

// passkeys serves the passkey page through agentosd's passkey ops
// (#2779a); run refuses to start it without HTTPS (checkPasskeyRPID).
func passkeys(cfg *localui.Config, sock, rpID string) {
	cfg.Passkeys = localui.AgentosdPasskeys{Owner: localui.Socket{Path: sock}}
	cfg.PasskeyRPID = rpID
}

// withFirstBoot runs firstboot.Begin and gives the page its steps: the
// claim screen (nil on the download route), the card step, its confirm
// reported in agentosd's finish, and the card step's rerun when that
// finish finds the vault holds no card (#1330).
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
		cfg.Hooks = localui.CardFinish{AgentosdSetup: h, Card: fb.Card, Again: fb.Again}
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
	pt := pageTLS(ctx, &cfg, localui.Socket{Path: sock}, nil)
	if err := checkPasskeyRPID(cfg.PasskeyRPID, cfg); err != nil {
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
	var lns []net.Listener
	for _, p := range ports(cfg, pt) {
		ln, err := localui.Listen(ctx, cfg.AP, p)
		if err != nil {
			for _, l := range lns {
				l.Close()
			}
			return err
		}
		lns = append(lns, ln)
	}
	errs := make(chan error, len(lns))
	var hss []*http.Server
	for i, ln := range lns {
		hs := newHTTPServer(s)
		hss = append(hss, hs)
		if i == 0 {
			go func() { errs <- hs.Serve(ln) }()
			continue
		}
		hs.TLSConfig = pt.Config()
		go func() { errs <- hs.ServeTLS(ln, "", "") }()
	}
	if pt != nil {
		go pt.Run(ctx)
	}
	var err1 error
	select {
	case <-ctx.Done():
	case err1 = <-errs:
	}
	sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, hs := range hss {
		hs.Shutdown(sh)
	}
	if err1 != nil && !errors.Is(err1, http.ErrServerClosed) {
		return err1
	}
	return nil
}

// pageTLS asks agentosd for the HTTPS listener's first certificate and
// sets cfg to match: HTTPS when one came back, PageRestore when agentosd
// says the box's authority must be restored. nil is plain HTTP only, said
// once in the log with a fixed line (logf; log.Print when nil).
func pageTLS(ctx context.Context, cfg *localui.Config, o localui.Owner, logf func(string)) *localui.PageTLS {
	if logf == nil {
		logf = func(s string) { log.Print(s) }
	}
	name := cfg.AP.PageName
	if name == "" {
		name = localui.DefaultPageName
	}
	pt, err := localui.NewPageTLS(ctx, name, o, nil, logf)
	switch {
	case errors.Is(err, localui.ErrRestore):
		logf(localui.LogRestore)
		cfg.PageRestore = true
		return nil
	case err != nil:
		logf(localui.LogNoHTTPS)
		return nil
	}
	cfg.HTTPS = true
	return pt
}

// ports are the listeners run serves: the plain page, then 443 only with
// a certificate.
func ports(cfg localui.Config, pt *localui.PageTLS) []int {
	if pt == nil || !cfg.HTTPS {
		return []int{cfg.Port}
	}
	return []int{cfg.Port, localui.HTTPSPort}
}

// errPasskeyRPID: a passkey RP ID other than the page name, or with no
// HTTPS listener up.
var errPasskeyRPID = errors.New("-passkey-rp-id must equal -page-name and needs the HTTPS listener up (a page authority from agentosd)")

// checkPasskeyRPID is the start-up gate for #2779a's -passkey-rp-id
// (#3153): a passkey runs only on the HTTPS page, under its name, as
// WebAuthn needs a secure context and the kernel checks the assertion's
// origin is https://<RP ID> (MIG-2-a). Empty is no passkey pages.
func checkPasskeyRPID(rpID string, cfg localui.Config) error {
	if rpID == "" {
		return nil
	}
	name := cfg.AP.PageName
	if name == "" {
		name = localui.DefaultPageName
	}
	if rpID != name || !cfg.HTTPS {
		return errPasskeyRPID
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
