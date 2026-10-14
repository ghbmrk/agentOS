package main

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/firstboot"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localui"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: ARC-2, CH-9, REC-4, ONB-3, HW-1, HW-10, CAP-9

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
	if cfg.SetupSecret != "" || cfg.Card != nil || cfg.SecondLine != nil || cfg.Providers != nil || cfg.Vault != nil || cfg.Rotation != nil || cfg.AP.Password != "" {
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

// #1266 (CAP-9, CH-3): the same socket serves the AI providers page,
// where the owner changes a provider's private-data answer after setup.
func TestTheVaultSocketWiresTheProvidersPage(t *testing.T) {
	cfg := config(localui.APConfig{Iface: "wlan0", Addr: netip.MustParsePrefix("10.42.0.1/24")}, 80, "/run/agentos/localui.sock", "/run/agentos/unlock.sock")
	if _, ok := cfg.Providers.(*localui.UnlockClient); !ok {
		t.Fatalf("config %+v", cfg)
	}
	if _, err := localui.New(cfg); err != nil {
		t.Fatal(err)
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

// shortDir is a temp dir short enough for a unix socket path.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "lu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// listenSock is agentosd's socket for awaitSocket: it accepts and hangs up.
func listenSock(t *testing.T, path string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
}

// fakeVault is the vault process's unlock socket; it counts the requests
// it is sent and answers each as a reset that remade nothing.
func fakeVault(t *testing.T, path string, calls *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"remade":false}`)
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
}

// Security B1 on #1226 (HW-10): run()'s preparation, as the unit starts
// the page. A sealed claim state at -claim-state gates /setup; an open
// setup without -vault-sock fails closed; an owned box never resets.
func TestRunGatesSetupOnTheClaim(t *testing.T) {
	dir := shortDir(t)
	sock, vsock := filepath.Join(dir, "a.sock"), filepath.Join(dir, "u.sock")
	listenSock(t, sock)
	var calls atomic.Int32
	fakeVault(t, vsock, &calls)
	base := func(h localui.Hooks) localui.Config {
		cfg := config(localui.APConfig{Iface: "wlan0", Addr: netip.MustParsePrefix("10.42.0.1/24")}, 80, sock, "")
		cfg.Hooks = h
		return cfg
	}

	t.Run("sealed", func(t *testing.T) {
		st := &change.MemStore{}
		if err := claim.Seal(st, "CANA-RYCL-AXMC-KDE2", mrand.New(mrand.NewSource(3)), nil); err != nil {
			t.Fatal(err)
		}
		b, err := st.Load()
		if err != nil {
			t.Fatal(err)
		}
		cs := filepath.Join(dir, "claim.json")
		if err := os.WriteFile(cs, b, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := prepare(context.Background(), base(openSetup), sock,
			boxFiles{VaultSock: vsock, Claim: cs, Latch: filepath.Join(dir, "latch.json")})
		if err != nil || cfg.Claim == nil {
			t.Fatalf("err %v, claim %v", err, cfg.Claim)
		}
		if w := get(t, cfg, "/setup"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/claim" {
			t.Fatalf("/setup on a sealed box: %d %q", w.Code, w.Header().Get("Location"))
		}
	})

	t.Run("no vault socket", func(t *testing.T) {
		if _, err := prepare(context.Background(), base(openSetup), sock, boxFiles{Claim: filepath.Join(dir, "claim.json")}); !errors.Is(err, errNoVault) {
			t.Fatalf("err %v", err)
		}
		if err := run(context.Background(), base(openSetup), sock, boxFiles{}); !errors.Is(err, errNoVault) {
			t.Fatalf("run serves a setup with no claim gate: %v", err)
		}
	})

	t.Run("owned", func(t *testing.T) {
		before := calls.Load()
		owned := localui.AgentosdSetup{Owner: localui.InProcess{}}
		cfg, err := prepare(context.Background(), base(owned), sock,
			boxFiles{VaultSock: vsock, Claim: filepath.Join(dir, "none.json"), Latch: filepath.Join(dir, "none-latch.json")})
		if err != nil || cfg.Claim != nil || cfg.Card != nil || calls.Load() != before {
			t.Fatalf("err %v, claim %v, card %v, vault calls %d", err, cfg.Claim, cfg.Card, calls.Load()-before)
		}
	})
}

// #1270 (CTRL-card-sock s1): on the image the page reaches the vault
// process's unlock socket and keeps its claim state and the card step's
// latch in its own state directory, which agentos-localui-claim.service
// fills from the seller's sealed claim before the first start; it never dumps core, since
// the claim verifiers and codes pass through it (IMG-nodump).
// REQ: HW-10, HW-1, CRED-9
func TestTheUnitWiresTheSetupFiles(t *testing.T) {
	b, err := os.ReadFile("agentos-localui.service")
	if err != nil {
		t.Fatal(err)
	}
	set := map[string][]string{}
	var exec []string
	for _, l := range strings.Split(strings.ReplaceAll(string(b), "\\\n", " "), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "[") {
			continue
		}
		k, v, _ := strings.Cut(l, "=")
		set[k] = append(set[k], v)
		if k == "ExecStart" {
			exec = strings.Fields(v)
		}
	}
	arg := func(name string) string {
		for i, w := range exec {
			if w == "-"+name && i+1 < len(exec) {
				return exec[i+1]
			}
		}
		return ""
	}
	for name, want := range map[string]string{
		"vault-sock":  "/run/agentos-egress/unlock.sock",
		"claim-state": "/var/lib/agentos-localui/claim.json",
		"card-latch":  "/var/lib/agentos-localui/card-latch.json",
	} {
		if got := arg(name); got != want {
			t.Errorf("-%s = %q, want %q", name, got, want)
		}
	}
	for k, want := range map[string][]string{
		"StateDirectory":     {"agentos-localui"},
		"StateDirectoryMode": {"0700"},
		"LimitCORE":          {"0"},
		// #1688: the mask below binds `+` commands too, so the hand-over is a unit of its own.
		"ExecStartPre": nil,
	} {
		if got := set[k]; strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	// B3 on #1302: other processes stay invisible, but not ProcSubset=pid, which hides
	// /proc/sys/kernel/random/boot_id: claim.Open reads it, and the page would fail at every start.
	if got := set["ProtectProc"]; strings.Join(got, "|") != "invisible" {
		t.Errorf("ProtectProc = %q, want invisible", got)
	}
	if got := set["ProcSubset"]; len(got) != 0 {
		t.Errorf("ProcSubset = %q: it hides the boot_id the claim reads", got)
	}
	// Security B2 on #1302: the broker's state stays hidden (L18), and nothing hides or freezes the
	// page's own state or the vault's sockets, which the page must write and reach.
	if got := set["TemporaryFileSystem"]; strings.Join(got, "|") != "/var/lib/agentos:ro" {
		t.Errorf("TemporaryFileSystem = %q, want /var/lib/agentos:ro", got)
	}
	for _, k := range []string{"TemporaryFileSystem", "InaccessiblePaths", "ReadOnlyPaths"} {
		for _, v := range set[k] {
			for _, f := range strings.Fields(v) {
				p := strings.TrimSuffix(strings.TrimLeft(f, "-+"), ":ro")
				for _, need := range []string{"/var/lib/agentos-localui", "/run/agentos-egress", "/run/agentos"} {
					if p == need || strings.HasPrefix(need, strings.TrimSuffix(p, "/")+"/") {
						t.Errorf("%s=%s covers %s", k, v, need)
					}
				}
			}
		}
	}
}

// #1688: the seller's sealed claim reaches the page through a root unit
// of its own, ordered before the page and pulled in by it. As a `+`
// ExecStartPre of the page it ran under the page's
// TemporaryFileSystem=/var/lib/agentos:ro, which systemd applies to `+`
// commands too, never saw the sealed file, and the box never showed the
// claim screen. The page Requires= the hand-over, not Wants=: with Wants=
// a failed move still started the page with no claim state, and a
// preloaded box served setup without the sticker code. Requires= keeps a
// download box or an already-moved claim working, because systemd does not
// fail a Requires= dependent when the hand-over's ConditionPathExists= is
// false (systemd.unit(5), Requires=: "failing condition checks ... do not
// cause the start job of a unit with a Requires= dependency on it to fail").
// REQ: HW-10
func TestTheClaimHandOverRunsOutsideThePagesMask(t *testing.T) {
	keys := func(name string) map[string][]string {
		b, err := os.ReadFile(name)
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
			set[k] = append(set[k], strings.Fields(v)...)
		}
		return set
	}
	has := func(vs []string, want string) bool {
		for _, v := range vs {
			if v == want {
				return true
			}
		}
		return false
	}
	h := keys("agentos-localui-claim.service")
	if strings.Join(h["ExecStart"], " ") != "/usr/lib/agentos/localui-claim" || strings.Join(h["Type"], "") != "oneshot" {
		t.Errorf("hand-over runs %q as %q, want oneshot /usr/lib/agentos/localui-claim", h["ExecStart"], h["Type"])
	}
	for _, k := range []string{"User", "DynamicUser", "TemporaryFileSystem", "InaccessiblePaths", "ProtectSystem", "ReadOnlyPaths"} {
		if len(h[k]) != 0 {
			t.Errorf("hand-over sets %s=%q: it must move a file between two root-owned directories", k, h[k])
		}
	}
	if !has(h["Before"], "agentos-localui.service") {
		t.Errorf("hand-over Before = %q, want agentos-localui.service", h["Before"])
	}
	p := keys("agentos-localui.service")
	for _, k := range []string{"Requires", "After"} {
		if !has(p[k], "agentos-localui-claim.service") {
			t.Errorf("page %s = %q, want agentos-localui-claim.service", k, p[k])
		}
	}
	if has(p["Wants"], "agentos-localui-claim.service") {
		t.Errorf("page Wants = %q: a failed hand-over must stop the page, so it belongs in Requires only", p["Wants"])
	}
}

// The page still answers PAIR texts once its hooks carry the card step:
// run starts PairTexts on any hooks that have it (P2-2w c4c with #1115).
// REQ: CH-12, ONB-6
func TestCardHooksStillPairTexts(t *testing.T) {
	var h localui.Hooks = localui.CardFinish{AgentosdSetup: openSetup}
	if _, ok := h.(interface {
		PairTexts(context.Context, *localui.Server, time.Duration)
	}); !ok {
		t.Fatal("CardFinish hooks do not start the PAIR text loop")
	}
}

// #1185: on agentosd's setup the card step reports the card's network
// before it provisions, so agentos-ap has it at the confirm.
func TestTheCardStepReportsTheCardsNetwork(t *testing.T) {
	var calls []string
	hooks := localui.AgentosdSetup{Owner: localui.InProcess{
		localapi.OpSetupAPNet: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
			calls = append(calls, "report")
			return struct{}{}, nil
		}}}
	box := firstboot.BoxConfig{Card: card.DisplayConfig{Provision: func(*card.Card) error {
		calls = append(calls, "provision")
		return nil
	}}}
	c, err := card.Generate(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := withCardNet(hooks, box).Card.Provision(c); err != nil || fmt.Sprint(calls) != "[report provision]" {
		t.Fatalf("%v, calls %v", err, calls)
	}
	calls = nil
	if err := withCardNet(nil, box).Card.Provision(c); err != nil || fmt.Sprint(calls) != "[provision]" {
		t.Fatalf("without agentosd: %v, calls %v", err, calls)
	}
}

// Production wiring (#1185): withFirstBoot hands firstboot.Begin the box
// wrapped by withCardNet, so the page's card step reports the network
// before it provisions.
func TestFirstBootWiresTheCardNetwork(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	wired := false
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "withFirstBoot" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || len(c.Args) != 1 {
				return true
			}
			if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Begin" {
				if in, ok := c.Args[0].(*ast.CallExpr); ok {
					if id, ok := in.Fun.(*ast.Ident); ok && id.Name == "withCardNet" {
						wired = true
					}
				}
			}
			return true
		})
	}
	if !wired {
		t.Fatal("withFirstBoot does not pass firstboot.Begin the box through withCardNet")
	}
}
