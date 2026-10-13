package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localui"
)

// REQ: ARC-2, CH-9, REC-4, ONB-3

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

// CRED-9, §8.1: setup's host step goes to the same socket, where the
// vault process allows it only between the code generator's confirmation
// and finish; without the socket the step is not served.
func TestTheVaultSocketServesSetupsHostStep(t *testing.T) {
	cfg := config(localui.APConfig{Iface: "wlan0", Addr: netip.MustParsePrefix("10.42.0.1/24")}, 80, "/run/agentos/localui.sock", "/run/agentos/unlock.sock")
	h, ok := cfg.Hooks.(localui.AgentosdSetup)
	if c, isClient := h.Vault.(*localui.UnlockClient); !ok || !isClient || c != cfg.Vault {
		t.Fatalf("hooks %#v", cfg.Hooks)
	}
	cfg = config(localui.APConfig{Iface: "wlan0", Addr: netip.MustParsePrefix("10.42.0.1/24")}, 80, "/run/agentos/localui.sock", "")
	if h := cfg.Hooks.(localui.AgentosdSetup); h.Vault != nil || h.TrustHost(true) == nil {
		t.Fatalf("hooks %#v", cfg.Hooks)
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
