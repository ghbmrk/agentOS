// Command agentos-localui serves the box's Wi-Fi page (P2-2w; CH-7 to
// CH-10, ARC-2, L15). It runs as its own user, agentos-localui, and
// decodes untrusted input (forms and photos from any phone on the access
// point), so it holds no authority: every owner action goes to agentosd's
// localui.sock, which admits only this uid, mints and checks the session
// tokens and counts wrong codes (localapi; Security L1, L2 on the P2-2w
// plan). It listens on the access point's address and interface only
// (Security L5) and logs no request or form field.
//
// It serves no setup until setup moves into agentosd (P2-2w c; Security
// L6): a box agentosd does not serve yet gets a fixed not-ready page.
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
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
	flag.StringVar(&addr, "addr", "10.42.0.1/24", "the box's address on the access point, with the subnet's length")
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
	if err := run(ctx, config(localui.APConfig{Iface: iface, Addr: ap}, port, vaultSock), sock); err != nil {
		log.Fatal(err)
	}
}

// config is the page's configuration: agentosd's socket, and no setup
// hooks (Security L6).
func config(ap localui.APConfig, port int, vaultSock string) localui.Config {
	cfg := localui.Config{AP: ap, Port: port}
	if vaultSock != "" {
		cfg.Vault = localui.NewUnlockClient(vaultSock)
	}
	return cfg
}

func run(ctx context.Context, cfg localui.Config, sock string) error {
	s, err := localui.New(cfg)
	if err != nil {
		return err
	}
	s.SetOwner(localui.Socket{Path: sock})
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
