package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
)

func boot(t *testing.T) time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		t.Fatal(err)
	}
	return time.Duration(ts.Nano())
}

// TestChannelElapsedIsBootTime: the channel's rate clock is
// CLOCK_BOOTTIME, which counts through a suspend, so an honest core does
// not trip after the enforcer sleeps (#4507, Security point 4 on #4536).
// Catches a daemon that leaves Elapsed nil (Go's monotonic clock) or wires
// the wall clock.
func TestChannelElapsedIsBootTime(t *testing.T) {
	x := newBox(t, true)
	// run wires bootTime as deps.Elapsed; open hands it to the channel.
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "Elapsed: bootTime,") {
		t.Fatal("run does not wire bootTime as the channel's rate clock")
	}
	if reflect.ValueOf(x.d.chCfg.Elapsed).Pointer() != reflect.ValueOf(x.d.dp.Elapsed).Pointer() {
		t.Fatal("the channel's Elapsed is not the daemon's rate clock")
	}
	b1 := boot(t)
	e := bootTime()
	b2 := boot(t)
	if e < b1 || e > b2 {
		t.Fatalf("bootTime %v outside CLOCK_BOOTTIME's [%v, %v]", e, b1, b2)
	}
	if w := time.Duration(time.Now().UnixNano()); e > w/2 {
		t.Fatal("bootTime reads the wall clock")
	}
}

// TestDepsRequired: the daemon refuses to start with any piece missing,
// so production never runs a channel on Go's monotonic clock or with no
// firewall, light or radio host.
func TestDepsRequired(t *testing.T) {
	x := newBox(t, false)
	full := x.deps()
	full.Elapsed = bootTime
	for name, f := range map[string]func(*deps){
		"Elapsed": func(d *deps) { d.Elapsed = nil },
		"Fire":    func(d *deps) { d.Fire = nil },
		"Network": func(d *deps) { d.Network = nil },
		"Light":   func(d *deps) { d.Light = nil },
		"Radio":   func(d *deps) { d.Radio = nil },
		"Logf":    func(d *deps) { d.Logf = nil },
		"DNS":     func(d *deps) { d.DNS = nil },
		"MDNS":    func(d *deps) { d.MDNS = nil },
		"Wake":    func(d *deps) { d.Wake = nil },
		"Boot":    func(d *deps) { d.Boot = nil },
	} {
		d := full
		f(&d)
		if _, err := open(x.cfg, x.dir, d); err == nil {
			t.Errorf("open without %s started", name)
		}
	}
}

// TestStateDirChecked: a state directory others can read, or a symlink
// to one, is refused before anything is read from it.
func TestStateDirChecked(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if checkStateDir(dir) == nil {
		t.Fatal("a group-readable state directory was taken")
	}
	os.Chmod(dir, 0o700)
	if err := checkStateDir(dir); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if checkStateDir(link) == nil {
		t.Fatal("a symlinked state directory was taken")
	}
}

// TestConfigRefused: a configuration that would bind the page or the
// channel off its network, or carry an unknown key, is refused.
func TestConfigRefused(t *testing.T) {
	good := testConfig(t)
	for name, f := range map[string]func(*Config){
		"no zone":            func(c *Config) { c.Zone = "" },
		"local zone":         func(c *Config) { c.Zone = "Local" },
		"catch-all core":     func(c *Config) { c.CoreAllow = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} },
		"unspecified chan":   func(c *Config) { c.Channel = netip.MustParseAddrPort("0.0.0.0:7443") },
		"chan port mismatch": func(c *Config) { c.Channel = netip.MustParseAddrPort("10.50.0.1:7444") },
		"page port mismatch": func(c *Config) { c.Page = []netip.AddrPort{netip.MustParseAddrPort("10.10.0.1:8443")} },
		"relative nft":       func(c *Config) { c.Nft = "nft" },
	} {
		c := good
		f(&c)
		if c.check() == nil {
			t.Errorf("%s: taken", name)
		}
	}
	b, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseConfig(b); err != nil {
		t.Fatalf("the good configuration was refused: %v", err)
	}
	// A good configuration plus one unknown key: only the key can refuse it.
	if _, err := parseConfig(append(b[:len(b)-1], `,"extra":1}`...)); err == nil {
		t.Error("an unknown key was taken")
	}
}

// countLight counts every time the alerts show the light.
type countLight struct {
	mu sync.Mutex
	n  int
}

func (l *countLight) Show(alert.Colour) error { l.mu.Lock(); l.n++; l.mu.Unlock(); return nil }

// TestIdleTickQuiet: an idle daemon re-shows the light only on a change
// and at the minute's Refresh, never on every tick, and logLight logs
// only a change of colour (L3 fix-list item 1 on #4754: 121 light lines
// a minute buried the channel's record, P6). Catches a Tick that tells
// the alerts the core's or the recovery's state when it has not changed.
func TestIdleTickQuiet(t *testing.T) {
	x := newBox(t, true)
	x.d.Close()
	cl := &countLight{}
	var buf bytes.Buffer
	ll := newLogLight(log.New(&buf, "", 0))
	for _, light := range []alert.Light{cl, ll} {
		dp := x.deps()
		dp.Light = light
		d, err := open(x.cfg, x.dir, dp)
		if err != nil {
			t.Fatal(err)
		}
		x.d = d
		cl.mu.Lock()
		cl.n = 0 // the shows at open are not idle ones
		cl.mu.Unlock()
		buf.Reset()
		for range 60 {
			x.advance(time.Second)
		}
		d.Close()
		if light == alert.Light(cl) && cl.n > 1 {
			t.Fatalf("an idle minute showed the light %d times; only the minute's Refresh should", cl.n)
		}
	}
	if n := strings.Count(buf.String(), "light:"); n != 0 {
		t.Fatalf("an idle minute logged the light %d times with no change of colour", n)
	}
	ll.Show(alert.Red)
	ll.Show(alert.Red)
	if n := strings.Count(buf.String(), "light:"); n != 1 {
		t.Fatalf("a change of colour logged %d lines, want 1", n)
	}
}
