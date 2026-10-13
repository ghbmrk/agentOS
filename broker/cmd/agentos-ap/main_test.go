package main

// REQ: DEV-net-h, CH-7, HW-10

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/localui"
)

// fakeHost records the loader's host calls; agentos_ap holds held.
type fakeHost struct {
	mu    sync.Mutex
	calls []string
	held  string
}

func (h *fakeHost) log(s string) { h.mu.Lock(); h.calls = append(h.calls, s); h.mu.Unlock() }
func (h *fakeHost) Nft(_ context.Context, script string) error {
	h.log("nft " + strings.SplitN(script, "\n", 2)[0])
	return nil
}
func (h *fakeHost) StartUnit(_ context.Context, u string) error  { h.log("start " + u); return nil }
func (h *fakeHost) StopUnit(_ context.Context, u string) error   { h.log("stop " + u); return nil }
func (h *fakeHost) APTableIface(context.Context) (string, error) { return h.held, nil }

// fakeAP is an access point whose child can be made to exit.
type fakeAP struct {
	mu      sync.Mutex
	started []localui.APConfig
	stops   int
	exited  chan struct{}
}

func (a *fakeAP) Start(_ context.Context, c localui.APConfig) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.started = append(a.started, c)
	a.exited = make(chan struct{})
	return nil
}
func (a *fakeAP) SetPassthrough(bool, string) error { return errors.New("no") }
func (a *fakeAP) Stop() error                       { a.mu.Lock(); a.stops++; a.mu.Unlock(); return nil }
func (a *fakeAP) Exited() <-chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.exited
}

// sysNet makes a /sys/class/net with the given wireless and wired
// interfaces.
func sysNet(t *testing.T, wireless, wired []string) string {
	t.Helper()
	d := t.TempDir()
	for _, w := range wireless {
		if err := os.MkdirAll(filepath.Join(d, w, "phy80211"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, w := range wired {
		if err := os.MkdirAll(filepath.Join(d, w), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

type box struct {
	cfg  config
	host *fakeHost
	ap   *fakeAP
	net  claim.SetupNet
}

func newBox(t *testing.T, wireless ...string) *box {
	t.Helper()
	d := t.TempDir()
	n, err := claim.NewSetupNet(nil)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := n.Marshal()
	setup := filepath.Join(d, "setup-net.json")
	if err := (change.FileStore{Path: setup}).Save(m); err != nil {
		t.Fatal(err)
	}
	return &box{cfg: config{Iface: "wlan0", Addr: netip.MustParsePrefix("10.42.0.1/24"),
		Latch: filepath.Join(d, "card-latch.json"), Setup: setup, OwnerState: filepath.Join(d, "owner.json"),
		SysClassNet: sysNet(t, wireless, []string{"lo", "eth0"})}, host: &fakeHost{}, ap: &fakeAP{}, net: n}
}

func (b *box) run(ctx context.Context) error {
	return run(ctx, b.cfg, &localui.APLoader{AP: b.ap, Host: b.host}, b.ap.Exited)
}

func (b *box) runAsync(t *testing.T) (context.CancelFunc, chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.run(ctx) }()
	return cancel, done
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func (b *box) startedCount() int { b.ap.mu.Lock(); defer b.ap.mu.Unlock(); return len(b.ap.started) }

// The loader starts with every access point interface brought down
// before any bring-up (DEV-net-h a), then serves the sticker's setup
// network on -iface (§8.1 step 4), and brings it down at shutdown.
func TestServesTheSetupNetworkAfterBringingEveryRadioDown(t *testing.T) {
	b := newBox(t, "wlan0", "wlan1")
	cancel, done := b.runAsync(t)
	waitFor(t, func() bool { return b.startedCount() == 1 })
	b.host.mu.Lock()
	calls := slices.Clone(b.host.calls)
	b.host.mu.Unlock()
	firstStart := slices.IndexFunc(calls, func(s string) bool { return strings.HasPrefix(s, "start ") })
	for _, w := range []string{"stop agentos-ap-exempt@wlan0.service", "stop agentos-ap-exempt@wlan1.service"} {
		i := slices.Index(calls, w)
		if i < 0 || i > firstStart {
			t.Fatalf("%q not before the first bring-up: %v", w, calls)
		}
	}
	got := b.ap.started[0]
	if got.Iface != "wlan0" || got.SSID != b.net.SSID || got.Password != b.net.Password || got.Addr != b.cfg.Addr {
		t.Fatalf("the access point started with %+v", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run at shutdown = %v", err)
	}
	if b.ap.stops < 3 {
		t.Fatalf("the access point was not brought down at shutdown (%d stops)", b.ap.stops)
	}
}

// A box with no wireless interface (the CI image's QEMU boot) runs no
// access point and does not fail.
func TestNoWirelessInterfaceIdles(t *testing.T) {
	b := newBox(t)
	cancel, done := b.runAsync(t)
	time.Sleep(100 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if b.startedCount() != 0 || len(b.host.calls) != 0 {
		t.Fatalf("with no radio: started %d, host calls %v", b.startedCount(), b.host.calls)
	}
}

// A radio whose name is not -iface is still brought down but serves
// nothing.
func TestOtherRadioIsBroughtDownOnly(t *testing.T) {
	b := newBox(t, "wlp1s0")
	cancel, done := b.runAsync(t)
	waitFor(t, func() bool { b.host.mu.Lock(); defer b.host.mu.Unlock(); return len(b.host.calls) > 0 })
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if b.startedCount() != 0 {
		t.Fatal("an access point started on a radio -iface does not name")
	}
	if !slices.Contains(b.host.calls, "stop agentos-ap-exempt@wlp1s0.service") {
		t.Fatalf("wlp1s0 not brought down: %v", b.host.calls)
	}
}

// Once the card is confirmed, or the box is owned, the setup network is
// burned and not served (CTRL-claim-ap).
func TestConfirmedOrOwnedBoxServesNoSetupNetwork(t *testing.T) {
	for name, prep := range map[string]func(b *box){
		"confirmed": func(b *box) { os.WriteFile(b.cfg.Latch, []byte(`{"card_confirmed":true}`), 0o600) },
		"owned":     func(b *box) { os.WriteFile(b.cfg.OwnerState, []byte(`{}`), 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			b := newBox(t, "wlan0")
			prep(b)
			cancel, done := b.runAsync(t)
			waitFor(t, func() bool {
				fi, err := os.Stat(b.cfg.Setup)
				return err == nil && fi.Size() == 0
			})
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if b.startedCount() != 0 {
				t.Fatal("served the setup network on a confirmed box")
			}
		})
	}
}

// A child that dies takes the access point down and fails the run, so
// its unit restarts it.
func TestAChildExitBringsTheAccessPointDown(t *testing.T) {
	b := newBox(t, "wlan0")
	_, done := b.runAsync(t)
	waitFor(t, func() bool { return b.startedCount() == 1 })
	stops := func() int { b.ap.mu.Lock(); defer b.ap.mu.Unlock(); return b.ap.stops }
	before := stops()
	b.ap.mu.Lock()
	close(b.ap.exited)
	b.ap.mu.Unlock()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("run returned nil after a child exit")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after a child exit")
	}
	if stops() <= before {
		t.Fatal("the access point was not brought down")
	}
}

// The latch is the page's file: the root loader reads it without
// following a link, without blocking on a FIFO, and only so far.
func TestReadLatchIsCareful(t *testing.T) {
	d := t.TempDir()
	if b, err := readLatch(filepath.Join(d, "absent")); err != nil || b != nil {
		t.Fatalf("absent latch: %q, %v", b, err)
	}
	target := filepath.Join(d, "target")
	os.WriteFile(target, []byte(`{"card_confirmed":false}`), 0o600)
	link := filepath.Join(d, "link")
	os.Symlink(target, link)
	if _, err := readLatch(link); err == nil {
		t.Error("followed a symlink")
	}
	fifo := filepath.Join(d, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLatch(fifo); err == nil {
		t.Error("read a FIFO")
	}
	big := filepath.Join(d, "big")
	os.WriteFile(big, make([]byte, maxLatch+1), 0o600)
	if _, err := readLatch(big); err == nil {
		t.Error("read an oversized latch")
	}
	if b, err := readLatch(target); err != nil || string(b) != `{"card_confirmed":false}` {
		t.Errorf("regular latch: %q, %v", b, err)
	}
}
