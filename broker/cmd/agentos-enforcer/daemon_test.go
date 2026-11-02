package main

// REQ: NET-2, KRN-12

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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
	full := deps{Elapsed: bootTime, Fire: x.fire, Network: x.net, Light: x.light, Radio: noRadio{}, Logf: func(string) {}}
	for name, f := range map[string]func(*deps){
		"Elapsed": func(d *deps) { d.Elapsed = nil },
		"Fire":    func(d *deps) { d.Fire = nil },
		"Network": func(d *deps) { d.Network = nil },
		"Light":   func(d *deps) { d.Light = nil },
		"Radio":   func(d *deps) { d.Radio = nil },
		"Logf":    func(d *deps) { d.Logf = nil },
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
	if _, err := parseConfig([]byte(`{"name":"x","zone":"UTC","extra":1}`)); err == nil {
		t.Error("an unknown key was taken")
	}
}
