package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/modelroute"
)

// REQ: CRED-5

// seedRoutes serves /seed from seed alone: no route config, nothing to forget.
func seedRoutes(t *testing.T, seed func(string) (map[string][]byte, error)) *workerRoutes {
	t.Helper()
	dir, err := os.MkdirTemp("", "sd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return newWorkerRoutes(dir, nil, nil, seed)
}

// SEED-NOLOGIN-1 (#1858): a seed asked before the owner signed in to the plan is a
// one-line 409, not a 500: the refusal is the owner's to fix, not a fault
// (#1858). Any other seed failure stays a 500.
func TestCRED5SeedWithNoLoginIsOneLine409(t *testing.T) {
	p := seedRoutes(t, func(worker string) (map[string][]byte, error) {
		return nil, fmt.Errorf("codex: %w", egress.ErrNoLogin)
	})
	r := &workerRig{p: p, ctl: p.handler()}
	w := r.call("seed", "pw-a")
	if body := strings.TrimSpace(w.Body.String()); w.Code != http.StatusConflict || body != egress.ErrNoLogin.Error() {
		t.Fatalf("no-login seed: %d %q", w.Code, body)
	}

	p = seedRoutes(t, func(worker string) (map[string][]byte, error) { return nil, errors.New("disk on fire") })
	r = &workerRig{p: p, ctl: p.handler()}
	if w := r.call("seed", "pw-a"); w.Code != http.StatusInternalServerError {
		t.Fatalf("failed seed: %d %q", w.Code, w.Body)
	}
}

// SEED-NOLOGIN-2 (#1858): over the control socket, modelroute.RouteControl reads the
// 409 as modelroute.ErrNoPlanLogin (the sign-in line), never as a locked
// vault or a fallback, however the vault wrapped the refusal.
func TestCRED5SeedWithNoLoginIsErrNoPlanLogin(t *testing.T) {
	p := seedRoutes(t, func(worker string) (map[string][]byte, error) {
		return nil, fmt.Errorf("codex: %w", egress.ErrNoLogin)
	})
	sock := filepath.Join(p.dir, "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: p.handler()}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	_, err = modelroute.NewRouteControl(sock).Seed("pw-a", false)
	if !errors.Is(err, modelroute.ErrNoPlanLogin) || errors.Is(err, modelroute.ErrVaultLocked) || modelroute.FallsBack(err) {
		t.Fatalf("no-login seed over the socket = %v, want ErrNoPlanLogin", err)
	}
}
