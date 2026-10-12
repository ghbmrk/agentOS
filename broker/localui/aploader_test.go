package localui

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// REQ: DEV-2, DEV-net-h

// netHost models what BringUp and BringDown change on the box: the inbound
// exempt set, whether agentos_ap is loaded and for which interface, and
// which exempt units are active. The exempt unit's start adds its interface
// as ap-exempt does, and its stop removes it. fail names steps that fail;
// with ctxBound set, every step fails once its context is done, as a real
// nft or systemctl run under that context would.
type netHost struct {
	exempt   map[string]bool
	apFor    string // "" when agentos_ap is not loaded
	fail     map[string]bool
	ctxBound bool
	log      []string
}

func newNetHost() *netHost { return &netHost{exempt: map[string]bool{}, fail: map[string]bool{}} }

var (
	quotedRe = regexp.MustCompile(`"([^"]+)"`)
	unitRe   = regexp.MustCompile(`^agentos-ap-exempt@(.+)\.service$`)
)

func (h *netHost) step(ctx context.Context, s string) error {
	h.log = append(h.log, s)
	if h.ctxBound && ctx.Err() != nil {
		return ctx.Err()
	}
	if h.fail[s] {
		return errors.New("FAIL " + s)
	}
	return nil
}

func (h *netHost) Nft(ctx context.Context, script string) error {
	switch step := nftStep(script); step {
	case "nft unexempt":
		iface := quotedRe.FindStringSubmatch(script)[1]
		if err := h.step(ctx, step+" "+iface); err != nil {
			return err
		}
		delete(h.exempt, iface)
	case "nft load agentos_ap":
		iface := regexp.MustCompile(`iifname "([^"]+)" drop\n`).FindStringSubmatch(script)[1]
		if err := h.step(ctx, step+" "+iface); err != nil {
			return err
		}
		h.apFor = iface
	case "nft unload agentos_ap":
		if err := h.step(ctx, step); err != nil {
			return err
		}
		h.apFor = ""
	default:
		return h.step(ctx, step)
	}
	return nil
}

func (h *netHost) StartUnit(ctx context.Context, unit string) error {
	if err := h.step(ctx, "start "+unit); err != nil {
		return err
	}
	h.exempt[unitRe.FindStringSubmatch(unit)[1]] = true
	return nil
}

func (h *netHost) StopUnit(ctx context.Context, unit string) error {
	if err := h.step(ctx, "stop "+unit); err != nil {
		return err
	}
	delete(h.exempt, unitRe.FindStringSubmatch(unit)[1])
	return nil
}

// open says whether some interface is exempt with no agentos_ap holding it
// to the page, DHCP and DNS: every box port is open to that network (A14).
func (h *netHost) open() []string {
	var out []string
	for i := range h.exempt {
		if h.apFor != i {
			out = append(out, i)
		}
	}
	return out
}

func apCfg(iface string) APConfig {
	c := testAP()
	c.Iface = iface
	return c
}

func newLoader(h *netHost) (*APLoader, *[]string) {
	var log []string
	return &APLoader{AP: &fakeAP{log: &log}, Host: h}, &log
}

func noJoin(t *testing.T) func(context.Context) error {
	return func(context.Context) error {
		t.Fatal("a station join ran")
		return nil
	}
}

// DEV-net-h (a): a loader that died with the access point up left wlan0
// exempt and agentos_ap loaded. The next loader's Start brings it down
// before anything else, and refuses a station join or a bring-up until it
// has.
func TestLoaderStartClearsAStaleExemption(t *testing.T) {
	h := newNetHost()
	dead, _ := newLoader(h)
	if err := dead.Start(context.Background(), "wlan0"); err != nil {
		t.Fatal(err)
	}
	if err := dead.Up(context.Background(), apCfg("wlan0")); err != nil {
		t.Fatal(err)
	}
	// The loader dies here: no Down runs.
	n := len(h.log)
	if !h.exempt["wlan0"] || h.apFor != "wlan0" {
		t.Fatalf("setup: exempt %v, agentos_ap for %q", h.exempt, h.apFor)
	}

	l, _ := newLoader(h)
	if err := l.Station(context.Background(), "wlan0", noJoin(t)); err == nil {
		t.Fatal("a station join ran before the loader's Start")
	}
	if err := l.Up(context.Background(), apCfg("wlan0")); err == nil {
		t.Fatal("a bring-up ran before the loader's Start")
	}
	if len(h.log) != n {
		t.Fatalf("the host was touched before Start: %q", h.log[n:])
	}
	if err := l.Start(context.Background(), "wlan0"); err != nil {
		t.Fatal(err)
	}
	if h.exempt["wlan0"] || h.apFor != "" {
		t.Fatalf("after Start: exempt %v, agentos_ap for %q", h.exempt, h.apFor)
	}
	joined := false
	if err := l.Station(context.Background(), "wlan0", func(context.Context) error { joined = true; return nil }); err != nil || !joined {
		t.Fatalf("station join after a clean Start: %v", err)
	}
}

// DEV-net-h (a), (b): BringDown failing at Start (a fault in the removal)
// leaves wlan0 refused for a station join; a later Down that succeeds lets
// it join.
func TestLoaderStartFailureBlocksTheStationJoin(t *testing.T) {
	h := newNetHost()
	h.exempt["wlan0"], h.apFor = true, "wlan0" // a dead loader's leftovers
	h.fail["nft unexempt wlan0"] = true
	h.fail["stop agentos-ap-exempt@wlan0.service"] = true
	l, _ := newLoader(h)
	if err := l.Start(context.Background(), "wlan0"); err == nil {
		t.Fatal("Start hid a failed BringDown")
	}
	if !h.exempt["wlan0"] || h.apFor != "wlan0" {
		t.Fatalf("agentos_ap went while wlan0 may be exempt: exempt %v, agentos_ap for %q", h.exempt, h.apFor)
	}
	if err := l.Station(context.Background(), "wlan0", noJoin(t)); err == nil {
		t.Fatal("wlan0 joined as a station while its BringDown had failed")
	}
	// The fault clears; Down retries and the join is allowed again.
	h.fail = map[string]bool{}
	if err := l.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := l.Station(context.Background(), "wlan0", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(h.open()) != 0 || h.exempt["wlan0"] {
		t.Fatalf("exempt %v after Down", h.exempt)
	}
}

// DEV-net-h (b): a BringDown that fails after the access point ran keeps
// its interface out of station mode, and so does the interface that is
// still up.
func TestLoaderNeverJoinsAStationOnAnExemptInterface(t *testing.T) {
	h := newNetHost()
	l, _ := newLoader(h)
	if err := l.Start(context.Background(), "wlan0", "wlan1"); err != nil {
		t.Fatal(err)
	}
	if err := l.Up(context.Background(), apCfg("wlan0")); err != nil {
		t.Fatal(err)
	}
	if err := l.Station(context.Background(), "wlan0", noJoin(t)); err == nil {
		t.Fatal("wlan0 joined as a station while it ran the access point")
	}
	h.fail["nft unexempt wlan0"] = true
	if err := l.Down(context.Background()); err == nil {
		t.Fatal("Down hid a failed BringDown")
	}
	if err := l.Station(context.Background(), "wlan0", noJoin(t)); err == nil {
		t.Fatal("wlan0 joined as a station while its BringDown had failed")
	}
	// Another interface is not held back by wlan0's state.
	if err := l.Station(context.Background(), "wlan1", func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	// A bring-up that fails and whose own teardown fails holds its interface
	// back too.
	h2 := newNetHost()
	l2, _ := newLoader(h2)
	if err := l2.Start(context.Background(), "wlan0"); err != nil {
		t.Fatal(err)
	}
	h2.fail["start agentos-ap-exempt@wlan0.service"] = true
	h2.fail["nft unexempt wlan0"] = true
	if err := l2.Up(context.Background(), apCfg("wlan0")); err == nil {
		t.Fatal("a failed bring-up returned nil")
	}
	if err := l2.Station(context.Background(), "wlan0", noJoin(t)); err == nil {
		t.Fatal("wlan0 joined as a station after a bring-up whose teardown failed")
	}
}

// DEV-net-h (c): with wlan0 up, BringUp(wlan1) would replace agentos_ap
// and leave wlan0 exempt with no table. The loader refuses it, and refuses
// it too while wlan0's BringDown has failed; once wlan0 is down, wlan1
// comes up.
func TestLoaderRefusesASecondAccessPoint(t *testing.T) {
	h := newNetHost()
	l, _ := newLoader(h)
	if err := l.Start(context.Background(), "wlan0", "wlan1"); err != nil {
		t.Fatal(err)
	}
	if err := l.Up(context.Background(), apCfg("wlan0")); err != nil {
		t.Fatal(err)
	}
	n := len(h.log)
	for _, iface := range []string{"wlan1", "wlan0"} {
		if err := l.Up(context.Background(), apCfg(iface)); err == nil {
			t.Fatalf("BringUp(%s) ran while wlan0 was up", iface)
		}
	}
	if len(h.log) != n || len(h.open()) != 0 {
		t.Fatalf("the refused bring-up touched the host: %q, open %v", h.log[n:], h.open())
	}
	h.fail["nft unexempt wlan0"] = true
	if err := l.Down(context.Background()); err == nil {
		t.Fatal("Down hid a failed BringDown")
	}
	if err := l.Up(context.Background(), apCfg("wlan1")); err == nil {
		t.Fatal("BringUp(wlan1) ran while wlan0's BringDown had failed")
	}
	if len(h.open()) != 0 {
		t.Fatalf("open interfaces %v", h.open())
	}
	delete(h.fail, "nft unexempt wlan0")
	if err := l.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := l.Up(context.Background(), apCfg("wlan1")); err != nil {
		t.Fatal(err)
	}
	if h.apFor != "wlan1" || h.exempt["wlan0"] || !h.exempt["wlan1"] || len(h.open()) != 0 {
		t.Fatalf("exempt %v, agentos_ap for %q", h.exempt, h.apFor)
	}
}

// DEV-net-h (d): the caller's context is cancelled (the loader is shutting
// down) as the access point fails, or before BringDown: the teardown still
// runs to the end, so the interface is not left exempt.
func TestTeardownOutlivesTheCallersContext(t *testing.T) {
	h := newNetHost()
	h.ctxBound = true
	ctx, cancel := context.WithCancel(context.Background())
	var log []string
	ap := &cancelAP{fakeAP: fakeAP{log: &log, startErr: errors.New("hostapd: radio busy")}, cancel: cancel}
	if err := BringUp(ctx, ap, apCfg("wlan0"), h); err == nil {
		t.Fatal("the failed access point was not reported")
	}
	if len(h.exempt) != 0 || h.apFor != "" {
		t.Fatalf("a cancelled bring-up left exempt %v, agentos_ap for %q (log %q)", h.exempt, h.apFor, h.log)
	}

	h = newNetHost()
	h.ctxBound = true
	if err := BringUp(context.Background(), &fakeAP{log: &log}, apCfg("wlan0"), h); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if err := BringDown(ctx, &fakeAP{log: &log}, "wlan0", h); err != nil {
		t.Fatalf("BringDown under a cancelled context: %v", err)
	}
	if len(h.exempt) != 0 || h.apFor != "" {
		t.Fatalf("a cancelled bring-down left exempt %v, agentos_ap for %q", h.exempt, h.apFor)
	}

	// The loader's own teardowns run the same way.
	h = newNetHost()
	h.ctxBound = true
	h.exempt["wlan0"], h.apFor = true, "wlan0"
	l, _ := newLoader(h)
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if err := l.Start(ctx, "wlan0"); err != nil || len(h.exempt) != 0 {
		t.Fatalf("Start under a cancelled context: %v, exempt %v", err, h.exempt)
	}
}

// cancelAP cancels the caller's context as its start fails.
type cancelAP struct {
	fakeAP
	cancel context.CancelFunc
}

func (a *cancelAP) Start(ctx context.Context, cfg APConfig) error {
	a.cancel()
	return a.fakeAP.Start(ctx, cfg)
}

// Start needs an interface, and a name BringDown refuses is reported.
func TestLoaderStartChecksItsInterfaces(t *testing.T) {
	l, _ := newLoader(newNetHost())
	if err := l.Start(context.Background()); err == nil {
		t.Fatal("Start with no interface")
	}
	if err := l.Start(context.Background(), "wl;x"); err == nil || !strings.Contains(err.Error(), "wl;x") {
		t.Fatalf("Start(wl;x): %v", err)
	}
}

// DEV-net-h (a), (b): an interface Start did not name has an unknown
// exemption state. A loader that died with the access point up on wlan2
// left it exempt; Start("wlan0") never brings wlan2 down, so Station and
// Up refuse wlan2 and touch neither the host nor the join.
func TestLoaderRefusesAnInterfaceStartDidNotName(t *testing.T) {
	h := newNetHost()
	dead, _ := newLoader(h)
	if err := dead.Start(context.Background(), "wlan2"); err != nil {
		t.Fatal(err)
	}
	if err := dead.Up(context.Background(), apCfg("wlan2")); err != nil {
		t.Fatal(err)
	}

	l, _ := newLoader(h)
	if err := l.Start(context.Background(), "wlan0"); err != nil {
		t.Fatal(err)
	}
	n := len(h.log)
	if err := l.Station(context.Background(), "wlan2", noJoin(t)); err == nil || !strings.Contains(err.Error(), "wlan2") {
		t.Fatalf("station join on wlan2 after Start(wlan0): %v", err)
	}
	if err := l.Up(context.Background(), apCfg("wlan2")); err == nil || !strings.Contains(err.Error(), "wlan2") {
		t.Fatalf("bring-up on wlan2 after Start(wlan0): %v", err)
	}
	if len(h.log) != n {
		t.Fatalf("the host was touched for an unnamed interface: %q", h.log[n:])
	}

	// A later Start that names wlan2 brings it down, and it may then join.
	if err := l.Start(context.Background(), "wlan2"); err != nil {
		t.Fatal(err)
	}
	if h.exempt["wlan2"] {
		t.Fatalf("after Start(wlan2): exempt %v", h.exempt)
	}
	joined := false
	if err := l.Station(context.Background(), "wlan2", func(context.Context) error { joined = true; return nil }); err != nil || !joined {
		t.Fatalf("station join on wlan2 after Start(wlan2): %v", err)
	}
	if err := l.Station(context.Background(), "wlan0", func(context.Context) error { return nil }); err != nil {
		t.Fatalf("wlan0 lost its Start: %v", err)
	}
}
