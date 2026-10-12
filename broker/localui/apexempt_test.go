package localui

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// REQ: DEV-2, CH-7, DEV-net-f

type fakeAP struct {
	log     *[]string
	started bool
}

func (f *fakeAP) Start(ctx context.Context, cfg APConfig) error {
	*f.log = append(*f.log, "ap start "+cfg.Iface)
	f.started = true
	return nil
}
func (f *fakeAP) SetPassthrough(on bool, uplink string) error { return nil }
func (f *fakeAP) Stop() error                                 { return nil }

// DEV-net-f: the access point starts only after its interface is in the
// inbound exempt set, and not at all if that fails.
func TestBringUpExemptsTheInterfaceFirst(t *testing.T) {
	var log []string
	ap := &fakeAP{log: &log}
	start := func(ctx context.Context, unit string) error {
		log = append(log, "unit "+unit)
		return nil
	}
	cfg := testAP()
	if err := BringUp(context.Background(), ap, cfg, start); err != nil {
		t.Fatal(err)
	}
	want := []string{"unit agentos-ap-exempt@" + cfg.Iface + ".service", "ap start " + cfg.Iface}
	if strings.Join(log, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, want %q", log, want)
	}
}

func TestBringUpFailsClosed(t *testing.T) {
	var log []string
	ap := &fakeAP{log: &log}
	boom := errors.New("agentos-ap-exempt: FAIL the inbound rules are not loaded")
	err := BringUp(context.Background(), ap, testAP(), func(context.Context, string) error { return boom })
	if !errors.Is(err, boom) || ap.started {
		t.Fatalf("err %v, started %v: a failed add must fail bring-up before the access point starts", err, ap.started)
	}
	// An invalid configuration starts nothing at all.
	bad := testAP()
	bad.Iface = "wl;x"
	called := false
	err = BringUp(context.Background(), ap, bad, func(context.Context, string) error { called = true; return nil })
	if err == nil || called || ap.started {
		t.Fatal("an invalid interface reached the exempt unit or the access point")
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
	for _, bad := range []string{"", "wl;x", "a/b", "abcdefghijklmnop"} {
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
}
