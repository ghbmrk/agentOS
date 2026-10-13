package main

import (
	"context"
	"encoding/json"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/firstboot"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localui"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: ARC-2, CH-9, REC-4, ONB-3, HW-1, HW-10

// P2-2w c4: the page runs setup over agentosd's localui.sock, which
// serves setup's ops only until finish (Security L6), and keeps its
// state in memory only (L18). It holds no setup secret and no Wi-Fi
// password.
func TestThePageRunsSetupThroughAgentosd(t *testing.T) {
	cfg := config(localui.APConfig{Iface: "wlan0", Addr: netip.MustParsePrefix("10.42.0.1/24")}, 80, "/run/agentos/localui.sock", "")
	if h, ok := cfg.Hooks.(localui.AgentosdSetup); !ok || h.Owner != (localui.Socket{Path: "/run/agentos/localui.sock"}) {
		t.Fatalf("hooks %#v", cfg.Hooks)
	}
	if _, ok := cfg.Store.(*localui.MemStore); !ok {
		t.Fatalf("store %#v", cfg.Store)
	}
	if cfg.SetupSecret != "" || cfg.Card != nil || cfg.SecondLine != nil || cfg.Vault != nil || cfg.Rotation != nil || cfg.AP.Password != "" {
		t.Fatalf("config %+v", cfg)
	}
	if _, err := localui.New(cfg); err != nil {
		t.Fatalf("no Wi-Fi password is needed to serve the page: %v", err)
	}
}

// The page waits for agentosd's socket before it asks whether setup is
// open, so a page that starts first does not close setup for its life.
func TestThePageWaitsForAgentosd(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "localui.sock")
	if err := awaitSocket(context.Background(), sock, 300*time.Millisecond); err == nil {
		t.Fatal("no socket, no error")
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		ln, err := net.Listen("unix", sock)
		if err != nil {
			return
		}
		t.Cleanup(func() { ln.Close() })
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if err := awaitSocket(context.Background(), sock, 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

// REC-4: with the vault process's socket the page serves the Owner Card
// rotation over that same socket (ARC-2: the display lives here).
func TestTheVaultSocketWiresTheCardRotation(t *testing.T) {
	cfg := config(localui.APConfig{Iface: "wlan0", Addr: netip.MustParsePrefix("10.42.0.1/24")}, 80, "/run/agentos/localui.sock", "/run/agentos/unlock.sock")
	if _, ok := cfg.Rotation.(*localui.Rotation); !ok || cfg.Vault == nil {
		t.Fatalf("config %+v", cfg)
	}
}

// Security L5: net/http's error log, which can quote a client's bytes,
// goes nowhere.
func TestTheServerLogsNothingARequestCarries(t *testing.T) {
	if hs := newHTTPServer(nil); hs.ErrorLog == nil || hs.ErrorLog.Writer() != io.Discard || hs.ReadHeaderTimeout == 0 {
		t.Fatalf("server %+v", hs)
	}
}

// Security L9: the page's process links none of agentosd's deciding
// parts, and agentosd links none of the page (localui TestDaemonAnd-
// VaultProcessLinkNoScanner).
func TestThePageLinksNoneOfAgentosd(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, p := range strings.Fields(string(out)) {
		for _, bad := range []string{"/broker/daemon", "/broker/localsrv", "/broker/grants", "/broker/vault", "/broker/egress", "/broker/modemlink"} {
			if strings.HasSuffix(p, bad) {
				t.Errorf("agentos-localui links %s", p)
			}
		}
	}
}

// Security L5: the unit runs as its own user with no secret, two
// network capabilities, a read-only system and a memory ceiling.
func TestTheUnitIsHardened(t *testing.T) {
	b, err := os.ReadFile("agentos-localui.service")
	if err != nil {
		t.Fatal(err)
	}
	set := map[string][]string{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "[") {
			continue
		}
		k, v, _ := strings.Cut(l, "=")
		set[k] = append(set[k], v)
	}
	for k, want := range map[string][]string{
		"User":                    {"agentos-localui"},
		"Group":                   {"agentos-localui"},
		"AmbientCapabilities":     {"CAP_NET_BIND_SERVICE CAP_NET_RAW"},
		"ProtectHome":             {"yes"},
		"PrivateDevices":          {"yes"},
		"RestrictNamespaces":      {"yes"},
		"IPAddressAllow":          {"10.42.0.0/24"},
		"NoNewPrivileges":         {"yes"},
		"CapabilityBoundingSet":   {"CAP_NET_BIND_SERVICE CAP_NET_RAW"},
		"ProtectSystem":           {"strict"},
		"MemoryDenyWriteExecute":  {"yes"},
		"MemoryMax":               {"512M"},
		"SystemCallFilter":        {"@system-service", "~@privileged @resources"},
		"RestrictAddressFamilies": {"AF_UNIX AF_INET"},
		"IPAddressDeny":           {"any"},
	} {
		if got := set[k]; strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if _, ok := set["EnvironmentFile"]; ok {
		t.Error("the page's unit reads an environment file: it holds no secret")
	}
	if memoryLimit >= 512<<20 {
		t.Error("the heap's soft limit is not under MemoryMax")
	}
}

// openSetup is agentosd's localui.sock while setup is open: progress
// answers, so the page is not set up.
var openSetup = localui.AgentosdSetup{Owner: localui.InProcess{
	localapi.OpSetupProgress: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
		return localapi.SetupProgress{Phase: "ready"}, nil
	}}}

// beginBox is the page's first boot over files in dir, with a reset the
// test counts in place of the vault process's /card/reset.
func beginBox(t *testing.T, dir string, resets *int) (localui.Config, firstboot.Route) {
	t.Helper()
	cfg := config(localui.APConfig{Iface: "wlan0", Addr: netip.MustParsePrefix("10.42.0.1/24")}, 80, "/run/agentos/localui.sock", "")
	cfg.Hooks = openSetup
	void := &localui.CodesVoid{}
	box := localui.CardBox(localui.NewUnlockClient(filepath.Join(dir, "none.sock")),
		change.FileStore{Path: filepath.Join(dir, "claim.json")}, change.FileStore{Path: filepath.Join(dir, "latch.json")}, void)
	box.Reset = func() error { *resets++; return nil }
	cfg, route, err := withFirstBoot(cfg, box, void)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Hooks.(localui.CardFinish); !ok || cfg.Card == nil || cfg.CodesVoid != void {
		t.Fatalf("route %s: hooks %T, card %v", route, cfg.Hooks, cfg.Card)
	}
	return cfg, route
}

// get asks the page for path as a phone on the box's Wi-Fi.
func get(t *testing.T, cfg localui.Config, path string) *httptest.ResponseRecorder {
	t.Helper()
	s, err := localui.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://10.42.0.1"+path, nil)
	req.RemoteAddr = "10.42.0.23:51000"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

// Brief test 5 (HW-10, HW-1): Begin in the page's wiring. A claim state
// sealed the way agentos-seller seals it (claim.Seal, then the bytes at
// claim.StatePath) routes to claim and gates /setup; a preloaded latch
// with no claim state routes to reinstall; neither routes to download.
func TestThePageRunsTheFirstBoot(t *testing.T) {
	t.Run("claim", func(t *testing.T) {
		dir := t.TempDir()
		st := &change.MemStore{}
		if err := claim.Seal(st, "CANA-RYCL-AXMC-KDE2", mrand.New(mrand.NewSource(3)), nil); err != nil {
			t.Fatal(err)
		}
		b, err := st.Load()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "claim.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		var resets int
		cfg, route := beginBox(t, dir, &resets)
		if route != firstboot.RouteClaim || cfg.Claim == nil || resets != 1 {
			t.Fatalf("route %q, claim %v, resets %d", route, cfg.Claim, resets)
		}
		if w := get(t, cfg, "/setup"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/claim" {
			t.Fatalf("/setup before the claim: %d %q", w.Code, w.Header().Get("Location"))
		}
	})
	t.Run("reinstall", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "latch.json"), []byte(`{"card_confirmed":false,"preloaded":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		var resets int
		cfg, route := beginBox(t, dir, &resets)
		if route != firstboot.RouteReinstall || cfg.Claim == nil || resets != 0 {
			t.Fatalf("route %q, claim %v, resets %d", route, cfg.Claim, resets)
		}
		if body := get(t, cfg, "/claim").Body.String(); !strings.Contains(body, "To set me up again, reinstall me.") {
			t.Fatalf("no reinstall text: %s", body)
		}
	})
	t.Run("download", func(t *testing.T) {
		var resets int
		cfg, route := beginBox(t, t.TempDir(), &resets)
		if route != firstboot.RouteDownload || cfg.Claim != nil || resets != 1 {
			t.Fatalf("route %q, claim %v, resets %d", route, cfg.Claim, resets)
		}
		if w := get(t, cfg, "/setup"); w.Code != http.StatusOK {
			t.Fatalf("/setup on a downloaded box: %d %q", w.Code, w.Header().Get("Location"))
		}
	})
}
