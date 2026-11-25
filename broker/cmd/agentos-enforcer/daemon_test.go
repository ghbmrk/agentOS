package main

// REQ: NET-2, KRN-12

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/channel"
	"github.com/ghbmrk/agentos/broker/enforcer/page"
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

// TestBootTimeNeverStepsBack: a reading below one already returned
// gives the larger one again, so the channel's rates never see time run
// backwards (#4507); each call takes and gives back the clock's lock.
func TestBootTimeNeverStepsBack(t *testing.T) {
	bootMu.Lock()
	saved := lastBoot
	ahead := boot(t) + 1000*time.Hour
	lastBoot = ahead
	bootMu.Unlock()
	t.Cleanup(func() { bootMu.Lock(); lastBoot = saved; bootMu.Unlock() })
	for range 2 {
		if e := bootTime(); e != ahead {
			t.Fatalf("bootTime %v after %v was returned", e, ahead)
		}
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
		"AP":      func(d *deps) { d.AP = nil },
		"Light":   func(d *deps) { d.Light = nil },
		"Radio":   func(d *deps) { d.Radio = nil },
		"Logf":    func(d *deps) { d.Logf = nil },
		"DNS":     func(d *deps) { d.DNS = nil },
		"MDNS":    func(d *deps) { d.MDNS = nil },
		"Wake":    func(d *deps) { d.Wake = nil },
		"Boot":    func(d *deps) { d.Boot = nil },
		"Offload": func(d *deps) { d.Offload = nil },
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
		"relative dnsmasq":   func(c *Config) { c.Dnsmasq = "dnsmasq" },
		"dns misses a net":   func(c *Config) { c.DNS.Nets = slices.Clone(c.DNS.Nets[1:]) },
		"wake on no network": func(c *Config) { c.Wake = []WakeMachine{{MAC: "02:00:00:00:00:01", Iface: "eth9"}} },
	} {
		c := good
		f(&c)
		if c.check() == nil {
			t.Errorf("%s: taken", name)
		}
	}
	// Each of these is refused by its own check, which the error names.
	for _, c := range []struct {
		want string
		f    func(*Config)
	}{
		{"name is required", func(c *Config) { c.Name = "" }},
		{"config: layout: ", func(c *Config) { c.Layout.ISP = nil }},
		{"page and page_allow are required", func(c *Config) { c.Page = nil }},
		{"page and page_allow are required", func(c *Config) { c.PageAllow = nil }},
	} {
		cfg := good
		c.f(&cfg)
		if err := cfg.check(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("want %q: %v", c.want, err)
		}
	}
	// A hardware address that does not parse is named as it was written.
	bad := good
	bad.Wake = []WakeMachine{{MAC: "zz", Iface: "hh0"}}
	if err := bad.check(); err == nil || !strings.Contains(err.Error(), `wake: hardware address "zz"`) {
		t.Errorf("an unparsable wake address: %v", err)
	}
	ok := good
	ok.Wake = []WakeMachine{{MAC: "02:00:00:00:00:01", Iface: "hh0"}}
	if err := ok.check(); err != nil {
		t.Errorf("a good wake machine was refused: %v", err)
	}
	b, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseConfig(b); err != nil {
		t.Fatalf("the good configuration was refused: %v", err)
	}
	// A second document after the first is refused, not dropped.
	if _, err := parseConfig(append(slices.Clone(b), "{}"...)); err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Errorf("trailing data: %v", err)
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
// the alerts the core's state when it has not changed.
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
		if light == alert.Light(cl) && cl.n != 1 {
			t.Fatalf("an idle minute showed the light %d times; only the minute's Refresh should, once", cl.n)
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

// colour is the light as the bulb and the alert log both show it; a
// mismatch fails the test.
func (x *box) colour() alert.Colour {
	x.t.Helper()
	x.light.mu.Lock()
	c := x.light.c
	x.light.mu.Unlock()
	if s := x.d.alerts.Status().Colour; s != c {
		x.t.Fatalf("the bulb shows %v, the alert log %v", c, s)
	}
	return c
}

// openTrips counts the open trips and missing records from device.
func (x *box) openTrips(device string) int {
	n := 0
	for _, r := range x.d.alerts.Status().Open {
		if r.Kind.Lights() && r.Device == device {
			n++
		}
	}
	return n
}

// failAlertSync makes every fsync of the alert journal fail while fail is
// set, so its appends fail; it is called before the box opens so the
// seam is in place before any goroutine reads it.
func failAlertSync(t *testing.T) *atomic.Bool {
	var fail atomic.Bool
	saved := syncFile
	syncFile = func(f *os.File) error {
		if fail.Load() && filepath.Base(f.Name()) == fileAlerts {
			return errors.New("disk: no space left")
		}
		return saved(f)
	}
	t.Cleanup(func() { syncFile = saved })
	return &fail
}

// TestTripCardOffersNoClear (KRN-12 Response, #4305 item 1): a core trip's
// open alert is Fixed on the page, so it shows no clear, and a clear drawn
// on it anyway is refused with errFixed before any passkey; the light
// stays red. Catches the page path that turned the light off while the
// cut stood.
func TestTripCardOffersNoClear(t *testing.T) {
	x, _ := enrolled(t, true)
	x.d.cut.Trip("test trip")
	var trip *page.Alert
	for _, r := range (pageAlerts{x.d.alerts}).Status().Open {
		if r.Text != "" && strings.Contains(r.Text, "touched a decoy") {
			trip = &r
		}
	}
	if trip == nil || !trip.Fixed {
		t.Fatalf("the trip's card: %+v", trip)
	}
	w := x.b.do(http.MethodPost, "/challenge", map[string]string{"action": page.ActClear, "target": strconv.FormatUint(trip.ID, 10)})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "this alert clears when") {
		t.Fatalf("a clear drawn on the trip: %d %s", w.Code, w.Body)
	}
	if err := (pageAlerts{x.d.alerts}).Resolve(trip.ID); !errors.Is(err, alert.ErrResolved) {
		t.Fatalf("the trip resolved past the page: %v", err)
	}
	if x.colour() != alert.Red || x.openTrips(coreDevice) != 1 {
		t.Fatal("the trip's light went off with the core cut")
	}
	home := x.b.do(http.MethodGet, "/", nil).Body.String()
	if strings.Contains(home, `data-action="clear" data-target="`+strconv.FormatUint(trip.ID, 10)+`"`) {
		t.Fatal("home offers a clear on the trip")
	}
}

// TestLiftedOnlyOnFullLift (KRN-12 Response, #4305 items 2 and 4): a core
// trip keeps the light red through every step short of the full lift: the
// ticks, a refused clear, a resume whose save fails, and a restart; only a
// resume whose lift is saved turns it off. DECOY-d's two-step lift must
// keep this: Lifted runs only once the cut has lifted in full. Catches an
// early Lifted.
func TestLiftedOnlyOnFullLift(t *testing.T) {
	x, a := enrolled(t, true)
	x.d.cut.Trip("test trip")
	red := func(what string) {
		t.Helper()
		if x.colour() != alert.Red || x.openTrips(coreDevice) != 1 || x.d.cut.Stage() != channel.Tripped {
			t.Fatalf("%s: light %v, %d trips open, stage %v", what, x.colour(), x.openTrips(coreDevice), x.d.cut.Stage())
		}
	}
	red("tripped")
	x.advance(time.Second)
	red("a tick")
	x.fail(fileCut, true)
	if w := x.b.act(a, page.ActResume, ""); w.Code == http.StatusOK {
		t.Fatalf("a resume whose lift was not saved answered %d %s", w.Code, w.Body)
	}
	red("a resume whose save failed")
	x.advance(time.Second)
	red("a tick after the failed resume")
	x.d.Close()
	x.fail(fileCut, false)
	x.start()
	red("a restart")
	if w := x.b.act(a, page.ActResume, ""); w.Code != http.StatusOK {
		t.Fatalf("resume: %d %s", w.Code, w.Body)
	}
	if x.colour() != alert.Off || x.openTrips(coreDevice) != 0 || x.d.cut.Stage() != channel.Open {
		t.Fatal("the full lift left the light red")
	}
}

// TestFailedLiftAlertRetried (KRN-12 Response, #4305 item 2): a lift
// whose cut is saved but whose alerts the journal refuses returns the
// error and leaves the box open with the light red; a second Resume or
// Lift on the open box closes them, and so do the next tick and the next
// start. For the core and the edge alike. Catches a light that stays red
// for good once Lifted is the only close (the L3 repro on #5999).
func TestFailedLiftAlertRetried(t *testing.T) {
	fail := failAlertSync(t)
	x, _ := enrolled(t, true)
	type box struct {
		name   string
		device string
		trip   func()
		lift   func() error
		open   func() bool
	}
	day := uint32(1)
	for _, b := range []box{
		{"core", coreDevice, func() { x.d.cut.Trip("test trip") }, func() error { return x.d.cut.Resume() },
			func() bool { return x.d.cut.Stage() == channel.Open }},
		// Each edge trip is on a new day: a lift holds the rest of its own.
		{"edge", edgeDevice, func() { day++; x.d.edge.Trip(day, "test trip") }, func() error { return x.d.edge.Lift(day, false) },
			func() bool { cut, _ := x.d.edge.Cut(); return !cut }},
	} {
		// failed reports a lift whose alerts the journal refused.
		failed := func(what string) {
			t.Helper()
			b.trip()
			if x.colour() != alert.Red {
				t.Fatalf("%s %s: the trip left the light off", b.name, what)
			}
			fail.Store(true)
			if err := b.lift(); err == nil {
				t.Fatalf("%s %s: a lift whose alerts were not saved answered nil", b.name, what)
			}
			if !b.open() || x.colour() != alert.Red || x.openTrips(b.device) != 1 {
				t.Fatalf("%s %s: open %v, light %v, %d trips open", b.name, what, b.open(), x.colour(), x.openTrips(b.device))
			}
		}
		closed := func(what string) {
			t.Helper()
			if !b.open() || x.colour() != alert.Off || x.openTrips(b.device) != 0 {
				t.Fatalf("%s %s: open %v, light %v, %d trips open", b.name, what, b.open(), x.colour(), x.openTrips(b.device))
			}
		}

		failed("lift")
		fail.Store(false)
		if err := b.lift(); err != nil {
			t.Fatalf("%s: a second lift on the open box: %v", b.name, err)
		}
		closed("second lift")

		failed("lift before a tick")
		fail.Store(false)
		x.advance(time.Second)
		closed("tick")

		// The tick and Close retry too, so the journal keeps failing
		// until the box is shut, and the next start closes them.
		failed("lift before a restart")
		x.d.Close()
		fail.Store(false)
		x.start()
		closed("restart")
	}
}

// TestOwedCloseLogged (KRN-12 Response, #4305 item 2: "each call's error
// is returned or logged"): a lift whose alerts the journal refused leaves
// a close owed, and each failed retry is logged, at start-up and on each
// tick, until a retry lands and that is logged too. The core and the edge
// each get a fresh box, so one box's owed close never shows in the
// other's log. Catches a dropped log line on any of those paths.
func TestOwedCloseLogged(t *testing.T) {
	fail := failAlertSync(t)
	for _, b := range []struct {
		name, owed, closed string
		trip               func(x *box)
		lift               func(x *box) error
	}{
		{"core", "cut: the core is not cut but its alerts did not close", "cut: the core's alerts closed",
			func(x *box) { x.d.cut.Trip("test trip") }, func(x *box) error { return x.d.cut.Resume() }},
		{"edge", "edge cut: the edge is not cut but its alerts did not close", "edge cut: the edge's alerts closed",
			func(x *box) { x.d.edge.Trip(1, "test trip") }, func(x *box) error { return x.d.edge.Lift(1, false) }},
	} {
		fail.Store(false)
		x, _ := enrolled(t, true)
		b.trip(x)
		fail.Store(true)
		if err := b.lift(x); err == nil {
			t.Fatalf("%s: a lift whose alerts were not saved answered nil", b.name)
		}
		n := x.logs(b.owed)
		x.advance(time.Second)
		if got := x.logs(b.owed); got != n+1 {
			t.Fatalf("%s: a failed retry on a tick logged %d lines, want %d", b.name, got-n, 1)
		}
		x.d.Close()
		n = x.logs(b.owed)
		x.start()
		if got := x.logs(b.owed); got != n+1 {
			t.Fatalf("%s: a failed close at start-up logged %d lines, want 1", b.name, got-n)
		}
		if x.logs(b.closed) != 0 || x.colour() != alert.Red {
			t.Fatalf("%s: the close was logged before it landed, light %v", b.name, x.colour())
		}
		fail.Store(false)
		x.advance(time.Second)
		if x.logs(b.closed) != 1 || x.colour() != alert.Off {
			t.Fatalf("%s: the landed close logged %d lines, light %v", b.name, x.logs(b.closed), x.colour())
		}
	}
}

// TestTrippedRestartKeepsPause (KRN-12 Response, #4305 item 2): a core
// that restarts cut keeps its channel-paused alert open, the same record,
// since only the owner's resume closes it. Catches a start-up close run on
// a cut core, which the lift's close path would do.
func TestTrippedRestartKeepsPause(t *testing.T) {
	x, _ := enrolled(t, true)
	x.d.cut.Trip("test trip")
	paused := func() []uint64 {
		var ids []uint64
		for _, r := range x.d.alerts.Log() {
			if r.Kind == alert.ChannelPaused {
				if !r.Open {
					t.Fatalf("the channel-paused alert closed while the core stayed cut: %+v", r)
				}
				ids = append(ids, r.ID)
			}
		}
		return ids
	}
	before := paused()
	x.restart()
	if after := paused(); len(before) != 1 || !slices.Equal(before, after) || x.d.cut.Stage() != channel.Tripped {
		t.Fatalf("channel-paused alerts %v before the restart, %v after, stage %v", before, after, x.d.cut.Stage())
	}
}

// TestTripFailuresLogged (KRN-12 Response, ENF-l-5): a trip whose alert
// the journal refuses is logged, on the core and on the edge, and an edge
// trip still unsaved at close is logged there. Catches a refusal that
// leaves no trace but the light.
func TestTripFailuresLogged(t *testing.T) {
	fail := failAlertSync(t)
	x, _ := enrolled(t, true)
	fail.Store(true)
	x.fail(fileEdgeCut, true)
	x.d.cut.Trip("test trip")
	x.d.edge.Trip(1, "test trip")
	for _, line := range []string{"cut: " + alert.Trip.String() + " alert for core: ", "edge cut: " + alert.Trip.String() + " alert for edge: "} {
		if n := x.logs(line); n != 1 {
			t.Fatalf("%q logged %d times, want once", line, n)
		}
	}
	fail.Store(false)
	x.d.Close()
	if n := x.logs("edge cut: trip not saved at close: "); n != 1 {
		t.Fatalf("a close that could not save the edge's trip logged it %d times, want once", n)
	}
	x.fail(fileEdgeCut, false)
}

// TestTripDeviceNamesAreTheBoxConstants (KRN-12 Response, #4305 item 3):
// every trip, missing record and lift in the daemon names its box by
// coreDevice or edgeDevice, never a literal or a computed name, so Lifted
// always matches what Raise used. Catches a trip or missing record raised
// under a name Lifted never matches, which would keep the light red.
func TestTripDeviceNamesAreTheBoxConstants(t *testing.T) {
	if coreDevice != "core" || edgeDevice != "edge" {
		t.Fatalf("box names %q %q: alert.Words names the boxes by these", coreDevice, edgeDevice)
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	counts := map[string]int{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var site string
				var dev ast.Expr
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					if fun.Name == "recordMissing" && len(call.Args) == 3 {
						site, dev = "recordMissing", call.Args[1]
					}
				case *ast.SelectorExpr:
					switch {
					case (fun.Sel.Name == "Lifted" || fun.Sel.Name == "LiftedCovered" || fun.Sel.Name == "Cover") && len(call.Args) >= 1:
						site, dev = "Lifted", call.Args[0]
					case fun.Sel.Name == "Raise" && len(call.Args) == 2 && isAlertKind(call.Args[0], "Trip", "RecordMissing"):
						// recordMissing's own body passes its parameter on:
						// its callers are the sites checked.
						if fn.Name.Name == "recordMissing" {
							return true
						}
						site, dev = "Raise "+call.Args[0].(*ast.SelectorExpr).Sel.Name, call.Args[1]
					}
				}
				if site == "" {
					return true
				}
				counts[site]++
				if id, ok := dev.(*ast.Ident); !ok || id.Name != "coreDevice" && id.Name != "edgeDevice" {
					t.Errorf("%s: %s names its box by %s, not coreDevice or edgeDevice", fset.Position(call.Pos()), site, types.ExprString(dev))
				}
				return true
			})
		}
	}
	// At least the sites there are today, so the check cannot pass on none.
	for site, n := range map[string]int{"Raise Trip": 2, "recordMissing": 3, "Lifted": 2} {
		if counts[site] < n {
			t.Errorf("%d %s sites found, want at least %d: %v", counts[site], site, n, counts)
		}
	}
	if counts["Raise RecordMissing"] != 0 {
		t.Errorf("RecordMissing raised outside recordMissing: %v", counts)
	}
}

// isAlertKind reports whether e is alert.<one of names>.
func isAlertKind(e ast.Expr, names ...string) bool {
	s, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := s.X.(*ast.Ident)
	return ok && pkg.Name == "alert" && slices.Contains(names, s.Sel.Name)
}

// TestUnsavedTripStaysRedAfterRestart (KRN-12 Response, NET-2 Texts and
// calls, #4305 item 2, L3 point 1 on #6012): a trip whose cut record write
// was refused, then a restart, finds the box open, but its trip stays open
// and the light red: the start-up close covers only the alerts the last
// saved lift recorded (Covers), so it cannot tell the owner all is clear
// when they never lifted anything. Checked with no lift before and after
// a lift. Catches a start-up close that resolves every open trip.
func TestUnsavedTripStaysRedAfterRestart(t *testing.T) {
	x, _ := enrolled(t, true)
	day := uint32(4)
	for _, b := range []struct {
		name, device, file string
		trip               func()
		lift               func() error
	}{
		{"core", coreDevice, fileCut, func() { x.d.cut.Trip("test trip") }, func() error { return x.d.cut.Resume() }},
		{"edge", edgeDevice, fileEdgeCut, func() { day++; x.d.edge.Trip(day, "test trip") }, func() error { return x.d.edge.Lift(day, false) }},
	} {
		for _, lifted := range []bool{false, true} {
			if lifted {
				b.trip()
				if err := b.lift(); err != nil {
					t.Fatal(err)
				}
			}
			x.fail(b.file, true)
			b.trip()
			x.advance(time.Second)
			x.d.Close()
			x.fail(b.file, false)
			x.start()
			if x.colour() != alert.Red || x.openTrips(b.device) != 1 {
				t.Fatalf("%s (lifted before %v): an unsaved trip closed at the restart: light %v, %d open", b.name, lifted, x.colour(), x.openTrips(b.device))
			}
			// The owner's lift of the open box closes it.
			if b.name == "core" {
				x.d.cut.Trip("again") // the page offers a resume only on a cut core
			} else {
				day++
				x.d.edge.Trip(day, "again")
			}
			if err := b.lift(); err != nil || x.colour() != alert.Off || x.openTrips(b.device) != 0 {
				t.Fatalf("%s: the lift after: %v, light %v", b.name, err, x.colour())
			}
		}
	}
}

// liftBoxes is the core and the edge as the lift tests trip and lift them;
// each edge trip is on a new day, since a lift holds the rest of its own.
func liftBoxes(x *box) []struct {
	name, device, file string
	trip               func()
	lift               func() error
} {
	day := uint32(40)
	return []struct {
		name, device, file string
		trip               func()
		lift               func() error
	}{
		{"core", coreDevice, fileCut, func() { x.d.cut.Trip("test trip") }, func() error { return x.d.cut.Resume() }},
		{"edge", edgeDevice, fileEdgeCut, func() { day++; x.d.edge.Trip(day, "test trip") }, func() error { return x.d.edge.Lift(day, false) }},
	}
}

// TestTripCountedOnOwedCloseStaysRed (KRN-12 Response, NET-2, #4305 item
// 2; L3 and Security repro on #6012 at c2026dc): a lift is saved but its
// close is refused, the journal heals, and a new trip counts on the trip
// alert still open, while its own cut write is refused. A restart finds
// the box open: the saved lift covered that alert at its earlier count, so
// it stays open and the light red. Catches a lift's cover that closes a
// trip counted on it after the lift.
func TestTripCountedOnOwedCloseStaysRed(t *testing.T) {
	fail := failAlertSync(t)
	x, _ := enrolled(t, true)
	for _, b := range liftBoxes(x) {
		b.trip()
		fail.Store(true)
		if err := b.lift(); err == nil {
			t.Fatalf("%s: a lift whose close was refused answered nil", b.name)
		}
		fail.Store(false)
		x.fail(b.file, true)
		b.trip() // counts on the covered alert, still open
		x.advance(time.Second)
		x.d.Close()
		x.fail(b.file, false)
		x.start()
		if x.colour() != alert.Red || x.openTrips(b.device) != 1 {
			t.Fatalf("%s: a trip after the lift closed at the restart: light %v, %d open", b.name, x.colour(), x.openTrips(b.device))
		}
		b.trip()
		if err := b.lift(); err != nil || x.colour() != alert.Off {
			t.Fatalf("%s: the next lift: %v, light %v", b.name, err, x.colour())
		}
	}
}

// TestReusedTripIDStaysRed (KRN-12 Response, NET-2, #4305 item 2; L3 and
// Security repro on #6012 at c2026dc): a trip whose alert append is lost
// is lifted, so the saved lift covers an ID the journal never held. After
// a restart a new trip, whose cut write is refused, must not take that ID,
// so the next restart leaves it open and red. Catches a cover matched by
// a reused ID.
func TestReusedTripIDStaysRed(t *testing.T) {
	fail := failAlertSync(t)
	x, _ := enrolled(t, true)
	for _, b := range liftBoxes(x) {
		fail.Store(true)
		b.trip() // the cut is saved, its alert is not
		_ = b.lift()
		x.d.Close()
		fail.Store(false)
		x.start()
		x.fail(b.file, true)
		b.trip()
		x.advance(time.Second)
		x.d.Close()
		x.fail(b.file, false)
		x.start()
		if x.colour() != alert.Red || x.openTrips(b.device) != 1 {
			t.Fatalf("%s: a trip with a reused ID closed at the restart: light %v, %d open", b.name, x.colour(), x.openTrips(b.device))
		}
		b.trip()
		if err := b.lift(); err != nil || x.colour() != alert.Off {
			t.Fatalf("%s: the next lift: %v, light %v", b.name, err, x.colour())
		}
	}
}

// TestLostCountCoverStaysRed (KRN-12 Response, NET-2, #4305 item 2; L3 and
// Security repro on #6012 at 59cdc46): a lift is saved but its close is
// refused; a trip and a second lift follow while the journal still
// refuses, and a restart rebuilds the alerts from what the journal kept.
// A trip after that, whose cut write is refused, must stay open and red at
// the next restart. A covered alert is sealed, so the trip opens a new
// alert rather than counting back up to a covered one. Catches a cover
// matched through a count the journal lost.
func TestLostCountCoverStaysRed(t *testing.T) {
	fail := failAlertSync(t)
	x, _ := enrolled(t, true)
	for _, b := range liftBoxes(x) {
		b.trip()
		fail.Store(true)
		_ = b.lift()
		b.trip()
		_ = b.lift()
		x.d.Close()
		x.start()
		fail.Store(false)
		x.fail(b.file, true)
		b.trip()
		x.advance(time.Second)
		x.d.Close()
		x.fail(b.file, false)
		x.start()
		if x.colour() != alert.Red || x.openTrips(b.device) != 1 {
			t.Fatalf("%s: a trip after the lift closed at the restart: light %v, %d open", b.name, x.colour(), x.openTrips(b.device))
		}
		b.trip()
		if err := b.lift(); err != nil || x.colour() != alert.Off {
			t.Fatalf("%s: the next lift: %v, light %v", b.name, err, x.colour())
		}
	}
}
