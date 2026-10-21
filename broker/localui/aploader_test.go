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

func (h *netHost) APTableIface(ctx context.Context) (string, error) {
	if err := h.step(ctx, "nft list agentos_ap"); err != nil {
		return "", err
	}
	return h.apFor, nil
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

// DEV-net-h (a): a loader that died with the access point up left wlan0
// exempt and agentos_ap loaded. The next loader's Start brings it down
// before anything else, and refuses a bring-up until it
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
}

// DEV-net-h (a), (b): BringDown failing at Start (a fault in the removal)
// leaves wlan0 exempt with agentos_ap still loaded; a later Down that
// succeeds clears it.
func TestLoaderStartFailureKeepsTheTable(t *testing.T) {
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
	// The fault clears; Down retries and clears the exemption.
	h.fail = map[string]bool{}
	if err := l.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.open()) != 0 || h.exempt["wlan0"] {
		t.Fatalf("exempt %v after Down", h.exempt)
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
// left it exempt; Start("wlan0") brings wlan2 down (DEV-net-i) but does
// not name it, so Up refuses wlan2 and touches nothing for it.
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
	if err := l.Up(context.Background(), apCfg("wlan2")); err == nil || !strings.Contains(err.Error(), "wlan2") {
		t.Fatalf("bring-up on wlan2 after Start(wlan0): %v", err)
	}
	if len(h.log) != n {
		t.Fatalf("the host was touched for an unnamed interface: %q", h.log[n:])
	}

	// A later Start that names wlan2 brings it down.
	if err := l.Start(context.Background(), "wlan2"); err != nil {
		t.Fatal(err)
	}
	if h.exempt["wlan2"] {
		t.Fatalf("after Start(wlan2): exempt %v", h.exempt)
	}
}

// REQ: DEV-net-i

// deadOn leaves h as a loader that died with the access point up on iface
// leaves it: iface exempt and agentos_ap loaded for it.
func deadOn(t *testing.T, h *netHost, iface string) {
	t.Helper()
	dead, _ := newLoader(h)
	if err := dead.Start(context.Background(), iface); err != nil {
		t.Fatal(err)
	}
	if err := dead.Up(context.Background(), apCfg(iface)); err != nil {
		t.Fatal(err)
	}
	if !h.exempt[iface] || h.apFor != iface {
		t.Fatalf("setup: exempt %v, agentos_ap for %q", h.exempt, h.apFor)
	}
}

// DEV-net-i, A14: a loader that died with the access point up on wlan2
// restarts with Start("wlan0"). No interface may be left exempt without
// agentos_ap: before DEV-net-i, BringDown(wlan0) unloaded wlan2's table
// and left wlan2 exempt, every box port open to its network.
func TestLoaderStartLeavesNoUnnamedRadioExemptWithoutItsTable(t *testing.T) {
	h := newNetHost()
	deadOn(t, h, "wlan2")
	l, _ := newLoader(h)
	if err := l.Start(context.Background(), "wlan0"); err != nil {
		t.Fatal(err)
	}
	if open := h.open(); len(open) != 0 {
		t.Fatalf("after Start(wlan0): %v exempt with no agentos_ap (log %q)", open, h.log)
	}
	if h.exempt["wlan2"] || h.apFor != "" {
		t.Fatalf("after Start(wlan0): exempt %v, agentos_ap for %q", h.exempt, h.apFor)
	}
	// wlan0 can now run the access point, and wlan2 is still not the
	// loader's: it was brought down, not named.
	if err := l.Up(context.Background(), apCfg("wlan0")); err != nil {
		t.Fatal(err)
	}
	if open := h.open(); len(open) != 0 {
		t.Fatalf("after Up(wlan0): %v exempt with no agentos_ap", open)
	}
}

// DEV-net-i: BringDown unloads agentos_ap only when its drop names the
// interface being brought down (or nothing is loaded); otherwise the
// table stays with the interface it holds.
func TestBringDownKeepsAnotherInterfacesTable(t *testing.T) {
	h := newNetHost()
	deadOn(t, h, "wlan2")
	var log []string
	if err := BringDown(context.Background(), &fakeAP{log: &log}, "wlan0", h); err != nil {
		t.Fatal(err)
	}
	if !h.exempt["wlan2"] || h.apFor != "wlan2" {
		t.Fatalf("BringDown(wlan0) touched wlan2: exempt %v, agentos_ap for %q", h.exempt, h.apFor)
	}
	if err := BringDown(context.Background(), &fakeAP{log: &log}, "wlan2", h); err != nil {
		t.Fatal(err)
	}
	if len(h.exempt) != 0 || h.apFor != "" {
		t.Fatalf("BringDown(wlan2): exempt %v, agentos_ap for %q", h.exempt, h.apFor)
	}
}

// DEV-net-i: if the stale radio cannot be brought down, Start says so,
// agentos_ap stays with it, and no other interface may run the access
// point (its BringUp would replace wlan2's table). Down retries it.
func TestLoaderStartFailureOnAnUnnamedRadioBlocksBringUp(t *testing.T) {
	h := newNetHost()
	deadOn(t, h, "wlan2")
	h.fail["nft unexempt wlan2"] = true
	h.fail["stop agentos-ap-exempt@wlan2.service"] = true
	l, _ := newLoader(h)
	if err := l.Start(context.Background(), "wlan0"); err == nil || !strings.Contains(err.Error(), "wlan2") {
		t.Fatalf("Start hid wlan2's failed BringDown: %v", err)
	}
	if open := h.open(); len(open) != 0 {
		t.Fatalf("%v exempt with no agentos_ap (agentos_ap for %q)", open, h.apFor)
	}
	if err := l.Up(context.Background(), apCfg("wlan0")); err == nil {
		t.Fatal("wlan0 ran the access point while wlan2 may be exempt")
	}
	if len(h.open()) != 0 {
		t.Fatalf("refused bring-up opened %v", h.open())
	}
	delete(h.fail, "nft unexempt wlan2")
	delete(h.fail, "stop agentos-ap-exempt@wlan2.service")
	if err := l.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.exempt) != 0 || h.apFor != "" {
		t.Fatalf("after Down: exempt %v, agentos_ap for %q", h.exempt, h.apFor)
	}
	if err := l.Up(context.Background(), apCfg("wlan0")); err != nil {
		t.Fatal(err)
	}
}

// DEV-net-i: when the host cannot say which interface agentos_ap holds,
// nothing unloads it, and the interfaces stay refused.
func TestUnreadableAPTableIsKept(t *testing.T) {
	h := newNetHost()
	deadOn(t, h, "wlan2")
	h.fail["nft list agentos_ap"] = true
	l, _ := newLoader(h)
	if err := l.Start(context.Background(), "wlan0"); err == nil {
		t.Fatal("Start hid an unreadable agentos_ap")
	}
	if h.apFor != "wlan2" || len(h.open()) != 0 {
		t.Fatalf("agentos_ap went while unreadable: exempt %v, agentos_ap for %q", h.exempt, h.apFor)
	}
	if err := l.Up(context.Background(), apCfg("wlan0")); err == nil {
		t.Fatal("wlan0 ran the access point though agentos_ap could not be read")
	}
	// The read works again, but wlan0's BringDown has not finished and
	// agentos_ap still holds wlan2: Up refuses until a Start brings both
	// down.
	delete(h.fail, "nft list agentos_ap")
	if err := l.Up(context.Background(), apCfg("wlan0")); err == nil || !strings.Contains(err.Error(), "wlan0 did not come down") {
		t.Fatalf("wlan0 ran the access point before its BringDown finished: %v (open %v)", err, h.open())
	}
	if err := l.Start(context.Background(), "wlan0"); err != nil {
		t.Fatal(err)
	}
	if err := l.Up(context.Background(), apCfg("wlan0")); err != nil || len(h.open()) != 0 {
		t.Fatalf("Up(wlan0) after a clean Start: %v, open %v", err, h.open())
	}
}
