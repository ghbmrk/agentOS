package localui

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// REQ: DEV-2, CH-7, DEV-net-f, DEV-net-g

type fakeAP struct {
	log      *[]string
	started  bool
	startErr error
	stopErr  error    // Stop fails and leaves the access point running
	cfg      APConfig // the configuration the last Start was given
}

func (f *fakeAP) Start(ctx context.Context, cfg APConfig) error {
	*f.log = append(*f.log, "ap start "+cfg.Iface)
	f.cfg = cfg
	if f.startErr != nil {
		return f.startErr
	}
	f.started = true
	return nil
}
func (f *fakeAP) SetPassthrough(on bool, uplink string) error { return nil }
func (f *fakeAP) Stop() error {
	*f.log = append(*f.log, "ap stop")
	if f.stopErr != nil {
		return f.stopErr
	}
	f.started = false
	return nil
}

// fakeHost logs what BringUp and BringDown ask of nftables and systemd. An
// nft script is logged by what it does; fail names the step that fails.
type fakeHost struct {
	log  *[]string
	fail string
}

func nftStep(script string) string {
	switch {
	case strings.Contains(script, "delete element inet agentos_inbound exempt"):
		return "nft unexempt"
	case strings.Contains(script, "chain input"):
		return "nft load agentos_ap"
	case script == APTableUnload:
		return "nft unload agentos_ap"
	}
	return "nft ?"
}

func (h *fakeHost) step(s string) error {
	*h.log = append(*h.log, s)
	if s == h.fail {
		return errors.New("FAIL " + s)
	}
	return nil
}
func (h *fakeHost) Nft(ctx context.Context, script string) error { return h.step(nftStep(script)) }

// APTableIface reports agentos_ap as not loaded, so BringDown unloads it
// as before (DEV-net-i; the netHost tests cover the read).
func (h *fakeHost) APTableIface(ctx context.Context) (string, error) { return "", nil }
func (h *fakeHost) StartUnit(ctx context.Context, unit string) error {
	return h.step("start " + unit)
}
func (h *fakeHost) StopUnit(ctx context.Context, unit string) error { return h.step("stop " + unit) }

func joined(log []string) string { return strings.Join(log, " | ") }

const unit0 = "agentos-ap-exempt@wlan0.service"

// The exemption is undone in this order, and agentos_ap unloaded only once
// the interface is out of the set.
var teardown = []string{"stop " + unit0, "nft unexempt", "nft unload agentos_ap"}

// DEV-net-f, DEV-net-g (a): agentos_ap is loaded, then the interface joins
// the inbound exempt set, then the access point starts.
func TestBringUpLoadsTheAPTableThenExempts(t *testing.T) {
	var log []string
	ap := &fakeAP{log: &log}
	if err := BringUp(context.Background(), ap, testAP(), &fakeHost{log: &log}); err != nil {
		t.Fatal(err)
	}
	want := []string{"nft load agentos_ap", "start " + unit0, "ap start wlan0"}
	if joined(log) != joined(want) {
		t.Fatalf("got %q, want %q", log, want)
	}
}

func TestBringUpFailsClosed(t *testing.T) {
	// The table does not load: nothing is exempted and nothing starts.
	var log []string
	ap := &fakeAP{log: &log}
	err := BringUp(context.Background(), ap, testAP(), &fakeHost{log: &log, fail: "nft load agentos_ap"})
	if err == nil || ap.started || joined(log) != "nft load agentos_ap" {
		t.Fatalf("err %v, log %q: a failed agentos_ap load must stop bring-up before the exemption", err, log)
	}
	// The add fails: the access point is not started and whatever the unit
	// added is taken out again.
	log = nil
	err = BringUp(context.Background(), ap, testAP(), &fakeHost{log: &log, fail: "start " + unit0})
	want := append([]string{"nft load agentos_ap", "start " + unit0}, teardown...)
	if err == nil || ap.started || joined(log) != joined(want) {
		t.Fatalf("err %v, log %q; want %q", err, log, want)
	}
	// An invalid configuration reaches neither nftables, the unit nor the
	// access point.
	log = nil
	bad := testAP()
	bad.Iface = "wl;x"
	if err := BringUp(context.Background(), ap, bad, &fakeHost{log: &log}); err == nil || len(log) != 0 {
		t.Fatalf("an invalid interface got through: %v %q", err, log)
	}
}

// DEV-net-g (a), acceptance 2: ap.Start fails after the add, so the
// interface is removed from the exempt set before agentos_ap goes.
func TestBringUpUnexemptsWhenTheAccessPointFails(t *testing.T) {
	var log []string
	boom := errors.New("hostapd: radio busy")
	ap := &fakeAP{log: &log, startErr: boom}
	err := BringUp(context.Background(), ap, testAP(), &fakeHost{log: &log})
	want := append([]string{"nft load agentos_ap", "start " + unit0, "ap start wlan0"}, teardown...)
	if !errors.Is(err, boom) || joined(log) != joined(want) {
		t.Fatalf("err %v, log %q; want %q", err, log, want)
	}
}

// DEV-net-g: if the interface cannot be taken out of the set, agentos_ap
// stays loaded, so the interface stays limited to the page, DHCP and DNS.
func TestAFailedUnexemptKeepsTheAPTable(t *testing.T) {
	var log []string
	ap := &fakeAP{log: &log, startErr: errors.New("hostapd: radio busy")}
	err := BringUp(context.Background(), ap, testAP(), &fakeHost{log: &log, fail: "nft unexempt"})
	if err == nil || strings.Contains(joined(log), "unload") {
		t.Fatalf("err %v, log %q: agentos_ap unloaded while the interface may still be exempt", err, log)
	}
	log = nil
	err = BringDown(context.Background(), ap, "wlan0", &fakeHost{log: &log, fail: "nft unexempt"})
	if err == nil || strings.Contains(joined(log), "unload") {
		t.Fatalf("err %v, log %q: agentos_ap unloaded while the interface may still be exempt", err, log)
	}
}

// DEV-net-g (b), acceptance 1 and 5: stopping the access point takes its
// interface out of the set, then unloads agentos_ap. A failed systemd stop
// does not skip the removal, which is idempotent.
func TestBringDownUnexemptsBeforeUnloading(t *testing.T) {
	var log []string
	ap := &fakeAP{log: &log}
	if err := BringDown(context.Background(), ap, "wlan0", &fakeHost{log: &log}); err != nil {
		t.Fatal(err)
	}
	want := append([]string{"ap stop"}, teardown...)
	if joined(log) != joined(want) {
		t.Fatalf("got %q, want %q", log, want)
	}
	log = nil
	err := BringDown(context.Background(), ap, "wlan0", &fakeHost{log: &log, fail: "stop " + unit0})
	if err == nil || joined(log) != joined(want) {
		t.Fatalf("err %v, log %q", err, log)
	}
	for _, bad := range []string{"wl;x", "lo", ""} {
		log = nil
		if err := BringDown(context.Background(), ap, bad, &fakeHost{log: &log}); err == nil || len(log) != 0 {
			t.Errorf("BringDown(%q): %v %q", bad, err, log)
		}
	}
}

// The scripts BringUp and BringDown hand nft are the ones
// tests/test_inbound_netns.py loads in network namespaces: agentos_ap for
// a synthetic access point on ap0, its removal from the exempt set, and the
// unload. Regenerate with AGENTOS_WRITE_TESTDATA=1 go test ./localui.
func TestNetnsScriptsAreWhatBringUpLoads(t *testing.T) {
	cfg := APConfig{Iface: "ap0", Addr: netip.MustParsePrefix("10.42.0.1/24"), SSID: "AgentOS-TEST", Password: "TEST-CANARY-0000"}
	load, err := APTableLoad(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rm, err := netguard.InboundExemptRemove("ap0")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"agentos_ap-ap0.nft":    load,
		"exempt-remove-ap0.nft": rm,
		"agentos_ap-unload.nft": APTableUnload,
	} {
		f := filepath.Join("testdata", name)
		if os.Getenv("AGENTOS_WRITE_TESTDATA") == "1" {
			if err := os.WriteFile(f, []byte(want), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		b, err := os.ReadFile(f)
		if err != nil || string(b) != want {
			t.Errorf("%s differs from what BringUp loads (%v); regenerate it", f, err)
		}
	}
	// ap-exempt admits an interface only when agentos_ap ends its input
	// chain for it in this drop (DEV-net-g c).
	if !strings.Contains(load, "\n    iifname \"ap0\" drop\n") {
		t.Fatal("agentos_ap has no final drop for its interface")
	}
	// The load replaces an earlier agentos_ap in the same transaction.
	if !strings.HasPrefix(load, APTableUnload) {
		t.Fatal("the load does not replace an earlier table")
	}
}

func TestExemptUnitEscapesTheInterface(t *testing.T) {
	for iface, want := range map[string]string{
		"wlan0":     "agentos-ap-exempt@wlan0.service",
		"wl-ap":     `agentos-ap-exempt@wl\x2dap.service`,
		".ap":       `agentos-ap-exempt@\x2eap.service`,
		"wlx_00.ap": "agentos-ap-exempt@wlx_00.ap.service",
	} {
		got, err := ExemptUnit(iface)
		if err != nil || got != want {
			t.Errorf("ExemptUnit(%q) = %q, %v; want %q", iface, got, err, want)
		}
	}
	for _, bad := range []string{"", "wl;x", "a/b", "abcdefghijklmnop", "lo"} {
		if _, err := ExemptUnit(bad); err == nil {
			t.Errorf("ExemptUnit(%q) accepted", bad)
		}
	}
}

// The unit BringUp starts is the template the image ships.
func TestExemptUnitIsInTheImage(t *testing.T) {
	b, err := os.ReadFile("../../image/mkosi/mkosi.extra/usr/lib/systemd/system/" + ExemptUnitTemplate)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "ExecStart=/usr/lib/agentos/ap-exempt %I\n") {
		t.Fatal("the image's template does not run ap-exempt")
	}
	if !strings.Contains(string(b), "ExecStop=/usr/lib/agentos/ap-exempt --remove %I\n") {
		t.Fatal("stopping the image's template does not take the interface out of the set")
	}
}
