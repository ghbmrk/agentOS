package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: HW-10, CH-7, ARC-1

// HW-10 (#1692): at the claim the page rotates the setup network's
// password through agentosd, which writes it root-only (ARC-1) where
// agentos-ap reads it: the same name, the page's password, marked
// rotated, as claim.ParseSetupNet reads it. Only once; a password the box
// would not make, or the sticker's own, is refused and leaves the file.
func TestTheClaimRotatesTheSetupWiFiOnce(t *testing.T) {
	m := newBareSetupMode(t)
	m.Card = pageCardStep
	m.SetupNet = filepath.Join(t.TempDir(), "setup-net.json")
	sticker := claim.SetupNet{SSID: "AgentOS-Setup-AB2C", Password: "ABCD-EFGH-JKLM-NP23"}
	b, err := sticker.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.SetupNet, b, 0o600); err != nil {
		t.Fatal(err)
	}
	start(context.Background(), m)
	call := setupCall(t, m)

	var name localapi.SetupWiFiName
	if err := call(localapi.OpSetupWiFiName, nil, &name); err != nil || name != (localapi.SetupWiFiName{SSID: sticker.SSID}) {
		t.Fatalf("name %+v %v", name, err)
	}
	for _, bad := range []string{"", "password", "abcd-efgh-jklm-np23", "ABCD-EFGH", sticker.Password} {
		if err := call(localapi.OpSetupWiFi, localapi.SetupWiFi{Password: bad}, nil); err == nil || !strings.Contains(err.Error(), localapi.ErrBadArgs) {
			t.Fatalf("took %q: %v", bad, err)
		}
	}
	if got, _ := os.ReadFile(m.SetupNet); string(got) != string(b) {
		t.Fatalf("a refused rotation wrote %s", got)
	}

	const pw = "ZZZZ-YYYY-XXXX-WWWW"
	if err := call(localapi.OpSetupWiFi, localapi.SetupWiFi{Password: pw}, nil); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(m.SetupNet)
	if err != nil {
		t.Fatal(err)
	}
	n, err := claim.ParseSetupNet(got)
	if err != nil || n != (claim.SetupNet{SSID: sticker.SSID, Password: pw, Rotated: true}) {
		t.Fatalf("file %+v %v", n, err)
	}
	if fi, _ := os.Stat(m.SetupNet); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if err := call(localapi.OpSetupWiFiName, nil, &name); err != nil || name != (localapi.SetupWiFiName{SSID: sticker.SSID, Rotated: true}) {
		t.Fatalf("name after %+v %v", name, err)
	}
	if err := call(localapi.OpSetupWiFi, localapi.SetupWiFi{Password: "QQQQ-RRRR-SSSS-TTTT"}, nil); err == nil || !strings.Contains(err.Error(), localapi.ErrWiFiRotated) {
		t.Fatalf("second rotation: %v", err)
	}

	// Burned at the confirm (an empty file), or absent: no setup network.
	if err := os.WriteFile(m.SetupNet, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := call(localapi.OpSetupWiFi, localapi.SetupWiFi{Password: "QQQQ-RRRR-SSSS-TTTT"}, nil); err == nil || !strings.Contains(err.Error(), localapi.ErrNoSetupWiFi) {
		t.Fatalf("rotated a burned network: %v", err)
	}
	if got, _ := os.ReadFile(m.SetupNet); len(got) != 0 {
		t.Fatalf("resurrected a burned network: %s", got)
	}
	os.Remove(m.SetupNet)
	if err := call(localapi.OpSetupWiFiName, nil, &name); err == nil || !strings.Contains(err.Error(), localapi.ErrNoSetupWiFi) {
		t.Fatalf("name of no network: %v", err)
	}
	if err := call(localapi.OpSetupWiFi, localapi.SetupWiFi{Password: "QQQQ-RRRR-SSSS-TTTT"}, nil); err == nil || !strings.Contains(err.Error(), localapi.ErrNoSetupWiFi) {
		t.Fatalf("rotated no network: %v", err)
	}
	if _, err := os.Lstat(m.SetupNet); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created a setup network: %v", err)
	}
}

// With no -setup-net path, or a card step the page does not hold, neither
// op is served.
func TestNoSetupNetPathServesNoWiFiOp(t *testing.T) {
	m := newBareSetupMode(t)
	m.Card = pageCardStep
	start(context.Background(), m)
	if err := setupCall(t, m)(localapi.OpSetupWiFiName, nil, nil); err == nil {
		t.Fatal("served with no path")
	}

	m2, f := newCardSetup(t)
	m2.SetupNet = filepath.Join(t.TempDir(), "setup-net.json")
	start(context.Background(), m2)
	f.step(t)
	call := setupCall(t, m2)
	if err := call(localapi.OpSetupWiFiName, nil, nil); err == nil {
		t.Fatal("name served for a card step the page does not hold")
	}
	if err := call(localapi.OpSetupWiFi, localapi.SetupWiFi{Password: "ZZZZ-YYYY-XXXX-WWWW"}, nil); err == nil {
		t.Fatal("rotation served for a card step the page does not hold")
	}
}

// agentosd keeps its own copy of the setup file's path and fields, since
// it may not link the claim code (ARC-2); these keep them in step.
func TestSetupWiFiMatchesTheClaimsFile(t *testing.T) {
	if defaultSetupNet != claim.SetupNetPath {
		t.Fatalf("-setup-net defaults to %s, claim keeps %s", defaultSetupNet, claim.SetupNetPath)
	}
	pw, err := claim.NewSetupPassword(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "setup-net.json")
	n, err := claim.NewSetupNet(nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := n.Marshal()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	args, _ := json.Marshal(localapi.SetupWiFi{Password: pw})
	if _, err := setupWiFiOp(path)(context.Background(), sockets.Peer{}, args); err != nil {
		t.Fatalf("a password the claim makes was refused: %v", err)
	}
	got, _ := os.ReadFile(path)
	r, err := n.Rotate(pw)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := r.Marshal(); string(got) != string(want) {
		t.Fatalf("file %s, claim would write %s", got, want)
	}
}

func TestSetupWiFiKeepsThePasswordOutOfLogs(t *testing.T) {
	w := localapi.SetupWiFi{Password: "CANA-RYCA-NARY-CANA"}
	if s := fmt.Sprintf("%v %+v %#v %s", w, w, w, w); strings.Contains(s, "CANA") {
		t.Fatal(s)
	}
}
