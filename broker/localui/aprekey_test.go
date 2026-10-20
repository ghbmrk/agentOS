package localui

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// REQ: REC-4, CH-7, DEV-net-h

// A synthetic canary; no real card's password.
const rotatedPW = "CANARY-ROTATED-WIFI-PW"

// upLoader starts a loader on wlan0 with the access point up under testAP's
// password.
func upLoader(t *testing.T) (*APLoader, *fakeAP, *netHost) {
	t.Helper()
	h := newNetHost()
	l, _ := newLoader(h)
	if err := l.Start(context.Background(), "wlan0"); err != nil {
		t.Fatal(err)
	}
	if err := l.Up(context.Background(), apCfg("wlan0")); err != nil {
		t.Fatal(err)
	}
	return l, l.AP.(*fakeAP), h
}

// REC-4: after a Wi-Fi rotation commit the loader brings the access point
// down and up again with the new password, so the phone joins with the new
// card. The SSID stays and the network stays WPA3-SAE with MFP required
// (CH-7); the interface is never left exempt without agentos_ap.
func TestRekeyRestartsTheAccessPointWithTheNewPassword(t *testing.T) {
	l, ap, h := upLoader(t)
	old := ap.cfg
	n := len(h.log)
	if err := l.Rekey(context.Background(), rotatedPW); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(h.log[n:], "\n")
	if i, j := strings.Index(got, "stop agentos-ap-exempt@"), strings.LastIndex(got, "start agentos-ap-exempt@"); i < 0 || j < i {
		t.Fatalf("Rekey did not bring the access point down then up:\n%s", got)
	}
	if !ap.started || ap.cfg.Password != rotatedPW || ap.cfg.SSID != old.SSID || ap.cfg.Iface != "wlan0" {
		t.Fatalf("access point started %v with %+v", ap.started, ap.cfg)
	}
	conf, err := HostapdConf(ap.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sae_password=" + rotatedPW + "\n", "wpa_key_mgmt=SAE\n", "ieee80211w=2\n"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("hostapd.conf lacks %q", want)
		}
	}
	if strings.Contains(conf, old.Password) || strings.Contains(conf, "wpa_passphrase") {
		t.Fatal("hostapd.conf keeps the old password or WPA2")
	}
	if h.apFor != "wlan0" || !h.exempt["wlan0"] || len(h.open()) != 0 {
		t.Fatalf("exempt %v, agentos_ap for %q", h.exempt, h.apFor)
	}
	// The loader keeps the new password: a second rotation back succeeds.
	if err := l.Rekey(context.Background(), old.Password); err != nil || ap.cfg.Password != old.Password {
		t.Fatalf("second Rekey: %v, password %q", err, ap.cfg.Password)
	}
}

// CH-7: a running access point that was brought up with WPA2 comes back
// WPA3-SAE only, with MFP required.
func TestRekeyDropsWPA2(t *testing.T) {
	h := newNetHost()
	l, _ := newLoader(h)
	if err := l.Start(context.Background(), "wlan0"); err != nil {
		t.Fatal(err)
	}
	c := apCfg("wlan0")
	c.WPA2 = true
	if err := l.Up(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if err := l.Rekey(context.Background(), rotatedPW); err != nil {
		t.Fatal(err)
	}
	conf, _ := HostapdConf(l.AP.(*fakeAP).cfg)
	if !strings.Contains(conf, "ieee80211w=2\n") || strings.Contains(conf, "WPA-PSK") {
		t.Fatalf("rekeyed access point is not WPA3-only:\n%s", conf)
	}
}

// With the access point down, Rekey touches nothing: the next Up takes the
// stored password from its caller.
func TestRekeyWhileDownIsANoOp(t *testing.T) {
	h := newNetHost()
	l, log := newLoader(h)
	if err := l.Start(context.Background(), "wlan0"); err != nil {
		t.Fatal(err)
	}
	n, m := len(h.log), len(*log)
	if err := l.Rekey(context.Background(), rotatedPW); err != nil {
		t.Fatal(err)
	}
	if len(h.log) != n || len(*log) != m {
		t.Fatalf("Rekey touched a down access point: %q %q", h.log[n:], (*log)[m:])
	}
	// After Down, Rekey still has nothing to restart.
	l2, _, h2 := upLoader(t)
	if err := l2.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	n = len(h2.log)
	if err := l2.Rekey(context.Background(), rotatedPW); err != nil || len(h2.log) != n {
		t.Fatalf("Rekey after Down: %v, %q", err, h2.log[n:])
	}
}

// A password hostapd would refuse is refused before the access point goes
// down, so the phone keeps its connection; the same password is a no-op.
func TestRekeyRefusesBeforeTakingTheAccessPointDown(t *testing.T) {
	l, ap, h := upLoader(t)
	old := ap.cfg.Password
	n := len(h.log)
	for _, pw := range []string{"short", "has|bar-1234", " leading-space", strings.Repeat("x", 64)} {
		if err := l.Rekey(context.Background(), pw); err == nil {
			t.Fatalf("Rekey accepted %q", pw)
		}
	}
	if err := l.Rekey(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if len(h.log) != n || !ap.started || ap.cfg.Password != old {
		t.Fatalf("a refused or unchanged Rekey touched the access point: %q", h.log[n:])
	}
}

// DEV-net-h: if the new access point fails to start, it stays down with no
// interface left exempt, and the old password is not brought back (a
// rotation presumes it lost). A later Rekey or Up can bring it up.
func TestRekeyFailureLeavesTheAccessPointDown(t *testing.T) {
	l, ap, h := upLoader(t)
	ap.startErr = errors.New("hostapd refused")
	if err := l.Rekey(context.Background(), rotatedPW); err == nil {
		t.Fatal("Rekey hid a failed start")
	}
	if ap.started || h.exempt["wlan0"] || h.apFor != "" || len(h.open()) != 0 {
		t.Fatalf("started %v, exempt %v, agentos_ap for %q", ap.started, h.exempt, h.apFor)
	}
	ap.startErr = nil
	n := len(h.log)
	if err := l.Rekey(context.Background(), rotatedPW); err != nil || len(h.log) != n {
		t.Fatalf("Rekey restarted a down access point: %v", err)
	}
	c := apCfg("wlan0")
	c.Password = rotatedPW
	if err := l.Up(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

// DEV-net-h (c): if the bring-down fails, Rekey does not bring the access
// point up again over an interface that may still be exempt.
func TestRekeyStopsWhenBringDownFails(t *testing.T) {
	l, ap, h := upLoader(t)
	h.fail["nft unexempt wlan0"] = true
	if err := l.Rekey(context.Background(), rotatedPW); err == nil {
		t.Fatal("Rekey hid a failed BringDown")
	}
	if ap.started || ap.cfg.Password == rotatedPW {
		t.Fatal("Rekey brought the access point up after a failed BringDown")
	}
}

// REC-4, DEV-net-h: if hostapd will not stop, the access point may still
// run with the old password, which a rotation presumes lost. Rekey reports
// it, and so does every retry until a Down succeeds; it never returns nil
// while the old password may be on the air (#1193).
func TestRekeyReportsAnAccessPointThatWillNotStop(t *testing.T) {
	l, ap, _ := upLoader(t)
	old := ap.cfg.Password
	ap.stopErr = errors.New("hostapd will not stop")
	if err := l.Rekey(context.Background(), rotatedPW); err == nil {
		t.Fatal("Rekey hid a failed Stop")
	}
	if !ap.started || ap.cfg.Password != old {
		t.Fatalf("fake: started %v, password %q", ap.started, ap.cfg.Password)
	}
	for i := 0; i < 2; i++ {
		if err := l.Rekey(context.Background(), rotatedPW); err == nil || !strings.Contains(err.Error(), "wlan0") {
			t.Fatalf("retry %d: Rekey returned %v while the old password may still be on the air", i+1, err)
		}
	}
	if ap.cfg.Password == rotatedPW {
		t.Fatal("Rekey started the access point after a failed Stop")
	}
	// Up with the new password is refused too: hostapd may still run on
	// wlan0, so the loader would track an access point it did not start,
	// and a same-password Rekey would then pass.
	c := apCfg("wlan0")
	c.Password = rotatedPW
	if err := l.Up(context.Background(), c); err == nil || !strings.Contains(err.Error(), "wlan0") {
		t.Fatalf("Up after a failed Stop: %v", err)
	}
	if err := l.Rekey(context.Background(), rotatedPW); err == nil {
		t.Fatal("Rekey to the password Up was given returned nil after a failed Stop")
	}
	// A Down that still cannot stop it keeps Rekey refusing.
	if err := l.Down(context.Background()); err == nil {
		t.Fatal("Down hid a failed Stop")
	}
	if err := l.Rekey(context.Background(), rotatedPW); err == nil {
		t.Fatal("Rekey returned nil after a failed Down")
	}
	// Once a Down succeeds, the access point is off and Rekey is a no-op
	// again; the next Up takes the new password.
	ap.stopErr = nil
	if err := l.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := l.Rekey(context.Background(), rotatedPW); err != nil {
		t.Fatalf("Rekey after a clean Down: %v", err)
	}
	if err := l.Up(context.Background(), c); err != nil || ap.cfg.Password != rotatedPW {
		t.Fatalf("Up with the new password: %v", err)
	}
}
