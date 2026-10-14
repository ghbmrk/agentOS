package localui

// REQ: CH-7, CH-9, DEV-net-h

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A synthetic canary, never a real network's password.
const canaryPass = "canary-wifi-0000"

func testAPConfig() APConfig {
	return APConfig{Iface: "wlan0", Addr: netip.MustParsePrefix("10.42.0.1/24"),
		SSID: "agentOS-test", Password: canaryPass}
}

// hostapdRig is a Hostapd over stub binaries: hostapd runs hostapdBody,
// dnsmasq runs dnsmasqBody, and ip logs its arguments.
func hostapdRig(t *testing.T, hostapdBody, dnsmasqBody string) (*Hostapd, string) {
	t.Helper()
	hp, _ := stub(t, "hostapd", hostapdBody)
	dp, _ := stub(t, "dnsmasq", dnsmasqBody)
	ip, ipLog := stub(t, "ip", "")
	return &Hostapd{HostapdPath: hp, DnsmasqPath: dp, IPPath: ip, Dir: filepath.Join(t.TempDir(), "ap"),
		Ready: 2 * time.Second, Settle: 100 * time.Millisecond, StopWait: 2 * time.Second}, ipLog
}

const (
	hostapdUp   = "echo wlan0: interface state COUNTRY_UPDATE-\\>ENABLED\necho AP-ENABLED\nexec sleep 30"
	dnsmasqRuns = "exec sleep 30"
)

// Stop returns nil when no access point runs: APLoader.Start brings down
// every interface on a box that may never have run one (DEV-net-h a).
func TestHostapdStopWithNothingRunningIsNil(t *testing.T) {
	h, ipLog := hostapdRig(t, hostapdUp, dnsmasqRuns)
	if err := h.Stop(); err != nil {
		t.Fatalf("Stop on an idle access point = %v, want nil", err)
	}
	if _, err := os.Stat(ipLog); err == nil {
		t.Fatal("an idle Stop ran ip")
	}
}

func TestHostapdStartsAndStops(t *testing.T) {
	h, ipLog := hostapdRig(t, hostapdUp, dnsmasqRuns)
	if err := h.Start(context.Background(), testAPConfig()); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(h.Dir, "hostapd.conf")
	fi, err := os.Stat(conf)
	if err != nil {
		t.Fatal(err)
	}
	// It holds the Wi-Fi password (CH-7).
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("hostapd.conf mode %v, want 0600", fi.Mode().Perm())
	}
	if err := h.Start(context.Background(), testAPConfig()); err == nil {
		t.Fatal("a second Start while running returned nil")
	}
	select {
	case <-h.Exited():
		t.Fatal("Exited fired while both children run")
	default:
	}
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(conf); !os.IsNotExist(err) {
		t.Fatalf("hostapd.conf left after Stop: %v", err)
	}
	log := readLog(t, ipLog)
	for _, want := range []string{"ARGS addr replace 10.42.0.1/24 dev wlan0", "ARGS link set wlan0 up",
		"ARGS addr del 10.42.0.1/24 dev wlan0"} {
		if !strings.Contains(log, want) {
			t.Errorf("ip log lacks %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, canaryPass) {
		t.Fatal("the password reached a command line")
	}
	if err := h.Stop(); err != nil {
		t.Fatalf("a second Stop = %v, want nil", err)
	}
}

// dnsmasq keeps no lease file: leases name client MAC addresses, and the
// setup network needs none across a restart.
func TestHostapdDnsmasqKeepsNoLeaseFile(t *testing.T) {
	hp, _ := stub(t, "hostapd", hostapdUp)
	dp, dLog := stub(t, "dnsmasq", dnsmasqRuns)
	ip, _ := stub(t, "ip", "")
	h := &Hostapd{HostapdPath: hp, DnsmasqPath: dp, IPPath: ip, Dir: filepath.Join(t.TempDir(), "ap"),
		Ready: 2 * time.Second, Settle: 100 * time.Millisecond, StopWait: 2 * time.Second}
	if err := h.Start(context.Background(), testAPConfig()); err != nil {
		t.Fatal(err)
	}
	defer h.Stop()
	if !strings.Contains(readLog(t, dLog), "--leasefile-ro") {
		t.Fatalf("dnsmasq ran without --leasefile-ro: %s", readLog(t, dLog))
	}
}

func TestHostapdFailsWithoutAPEnabled(t *testing.T) {
	for name, body := range map[string]string{
		"exits": "echo nl80211: Could not configure driver mode\nexit 1",
		"hangs": "exec sleep 30",
	} {
		t.Run(name, func(t *testing.T) {
			h, ipLog := hostapdRig(t, body, dnsmasqRuns)
			h.Ready = 300 * time.Millisecond
			if err := h.Start(context.Background(), testAPConfig()); err == nil {
				t.Fatal("Start without AP-ENABLED returned nil")
			}
			if !strings.Contains(readLog(t, ipLog), "addr del") {
				t.Error("a failed Start left the address")
			}
			if err := h.Stop(); err != nil {
				t.Fatalf("Stop after a failed Start = %v, want nil", err)
			}
		})
	}
}

func TestHostapdFailsWhenDnsmasqExits(t *testing.T) {
	h, _ := hostapdRig(t, hostapdUp, "exit 2")
	if err := h.Start(context.Background(), testAPConfig()); err == nil {
		t.Fatal("Start with a dnsmasq that exits returned nil")
	}
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
}

// A child that dies after Start fires Exited, so the loader brings the
// access point down rather than leave the interface exempt with nothing
// serving it.
func TestHostapdExitedFiresWhenAChildDies(t *testing.T) {
	h, _ := hostapdRig(t, "echo AP-ENABLED\nsleep 0.4\nexit 1", dnsmasqRuns)
	if err := h.Start(context.Background(), testAPConfig()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.Exited():
	case <-time.After(5 * time.Second):
		t.Fatal("Exited did not fire when hostapd died")
	}
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestHostapdRefusesAnInvalidConfig(t *testing.T) {
	h, ipLog := hostapdRig(t, hostapdUp, dnsmasqRuns)
	cfg := testAPConfig()
	cfg.Password = "short"
	if err := h.Start(context.Background(), cfg); err == nil {
		t.Fatal("Start with a 5-character password returned nil")
	}
	if _, err := os.Stat(ipLog); err == nil {
		t.Fatal("an invalid config ran ip")
	}
}

func TestHostapdPassthroughIsRefused(t *testing.T) {
	h, _ := hostapdRig(t, hostapdUp, dnsmasqRuns)
	if err := h.SetPassthrough(true, "eth0"); err == nil {
		t.Fatal("SetPassthrough returned nil; passthrough is not implemented")
	}
	var _ AccessPoint = h
}
