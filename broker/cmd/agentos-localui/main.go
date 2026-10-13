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
// the page starts the steps over.
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

	"github.com/ghbmrk/agentos/broker/localui"
)

// memoryLimit is the Go heap's soft ceiling, under the unit's MemoryMax,
// so a decoder worst case cannot press on the broker (L18 on #50).
const memoryLimit = 384 << 20

func main() {
	var sock, vaultSock, iface, addr string
	var port int
	flag.StringVar(&sock, "sock", "/run/agentos/localui.sock", "agentosd's localui.sock (agentosd -localui-uid)")
	flag.StringVar(&vaultSock, "vault-sock", "", "the vault process's unlock socket, for the unknown-host unlock page; empty: not served")
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
	if err := run(ctx, config(localui.APConfig{Iface: iface, Addr: ap}, port, sock, vaultSock), sock); err != nil {
		log.Fatal(err)
	}
}

// config is the page's configuration: setup through agentosd's socket
// with an in-memory store (P2-2w c4), and no setup secret (Security L6).
// The vault process's unlock socket serves both the unlock page and the
// Owner Card rotation (REC-4); ARC-2 keeps the card's display here, not
// in agentosd.
func config(ap localui.APConfig, port int, sock, vaultSock string) localui.Config {
	cfg := localui.Config{AP: ap, Port: port,
		Hooks: localui.AgentosdSetup{Owner: localui.Socket{Path: sock}}, Store: &localui.MemStore{}}
	if vaultSock != "" {
		client := localui.NewUnlockClient(vaultSock)
		cfg.Vault = client
		cfg.Rotation = localui.NewRotation(client)
	}
	return cfg
}

// agentosdWait bounds the wait for agentosd's socket; past it the page
// exits and its unit restarts it.
const agentosdWait = 30 * time.Second

func run(ctx context.Context, cfg localui.Config, sock string) error {
	// New asks agentosd whether setup is open and takes no answer as
	// closed, so it waits until agentosd's socket accepts.
	if err := awaitSocket(ctx, sock, agentosdWait); err != nil {
		return err
	}
	s, err := localui.New(cfg)
	if err != nil {
		return err
	}
	s.SetOwner(localui.Socket{Path: sock})
	// PAIR texts that reach the box come through agentosd while setup is
	// open (P2-2w c4c; §8.1 pairing).
	if a, ok := cfg.Hooks.(localui.AgentosdSetup); ok {
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
