package netjoin

// REQ: ONB-3, CRED-1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/apnet"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// fakeScan is NetworkManager's devices and access points, read only.
type fakeScan struct {
	mu      sync.Mutex
	devErr  error
	devs    []string
	types   map[string]uint32
	aps     map[string][]string
	ssids   map[string][]byte
	strong  map[string]uint8
	fail    map[string]bool // a device or access point whose reads fail
	block   chan struct{}   // when set, Devices waits for it or ctx
	reads   int
	reached bool
}

func newScan() *fakeScan {
	return &fakeScan{types: map[string]uint32{}, aps: map[string][]string{}, ssids: map[string][]byte{}, strong: map[string]uint8{}, fail: map[string]bool{}}
}

// wifi adds a Wi-Fi device with the given access points (ssid, strength).
func (f *fakeScan) wifi(dev string, aps ...any) {
	f.devs = append(f.devs, dev)
	f.types[dev] = DeviceWifi
	for i := 0; i < len(aps); i += 2 {
		p := fmt.Sprintf("%s/ap/%d", dev, i/2)
		f.aps[dev] = append(f.aps[dev], p)
		switch s := aps[i].(type) {
		case string:
			f.ssids[p] = []byte(s)
		case []byte:
			f.ssids[p] = s
		}
		f.strong[p] = uint8(aps[i+1].(int))
	}
}

func (f *fakeScan) read(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	f.reached = true
	if f.fail[p] {
		return errors.New("no such object")
	}
	return nil
}

func (f *fakeScan) Devices(ctx context.Context) ([]string, error) {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err := f.read(""); err != nil {
		return nil, err
	}
	return f.devs, f.devErr
}

func (f *fakeScan) DeviceType(_ context.Context, dev string) (uint32, error) {
	return f.types[dev], f.read(dev)
}

func (f *fakeScan) AccessPoints(_ context.Context, dev string) ([]string, error) {
	return f.aps[dev], f.read(dev + "#aps")
}

func (f *fakeScan) APSsid(_ context.Context, ap string) ([]byte, error) {
	return f.ssids[ap], f.read(ap)
}

func (f *fakeScan) APStrength(_ context.Context, ap string) (uint8, error) {
	return f.strong[ap], f.read(ap + "#strength")
}

// Test 1: Wi-Fi devices only; odd names dropped; each name once at its
// best strength; strongest first, then by name; read failures skipped.
func TestTheScanListsShowableNamesStrongestFirst(t *testing.T) {
	f := newScan()
	f.wifi("/d/1",
		"Home Net", 40,
		"Neighbor", 70,
		"", 90, // hidden
		[]byte{0, 0, 0}, 90, // hidden, as NUL bytes
		[]byte{0xff, 0xfe}, 90, // not UTF-8
		"bad\nname", 90, // a control character
		"bidi‮name", 90, // a format character
		strings.Repeat("x", 33), 90, // over 32 bytes
		"Home Net", 80, // the same name, stronger
		"Cafe", 70,
		"Gone", 99,
	)
	f.fail["/d/1/ap/10"] = true // Gone's reads fail
	f.devs = append(f.devs, "/d/eth")
	f.types["/d/eth"] = 1 // ethernet: its access points are never asked for
	f.aps["/d/eth"] = []string{"/d/eth/ap/0"}
	f.ssids["/d/eth/ap/0"] = []byte("Wired?")
	f.wifi("/d/2", "Upstairs", 30)
	f.devs = append(f.devs, "/d/3")
	f.fail["/d/3"] = true // a device whose type cannot be read

	got := NewScanner(f).Scan(context.Background())
	want := []string{"Home Net", "Cafe", "Neighbor", "Upstairs"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Scan = %q, want %q", got, want)
	}
}

func TestTheScanIsCappedAndAFailedDeviceListIsEmpty(t *testing.T) {
	f := newScan()
	var aps []any
	for i := range MaxNetworks + 5 {
		aps = append(aps, fmt.Sprintf("Net %02d", i), i)
	}
	f.wifi("/d/1", aps...)
	got := NewScanner(f).Scan(context.Background())
	if len(got) != MaxNetworks || got[0] != fmt.Sprintf("Net %02d", MaxNetworks+4) {
		t.Fatalf("Scan gave %d names starting %q", len(got), got[0])
	}

	f = newScan()
	f.wifi("/d/1", "Home Net", 50)
	f.devErr = errors.New("NetworkManager is not running")
	if got := NewScanner(f).Scan(context.Background()); len(got) != 0 {
		t.Fatalf("a failed device list gave %q", got)
	}
}

// The scan's reads are bounded by ScanWait.
func TestTheScanIsBoundedByItsWait(t *testing.T) {
	f := newScan()
	f.wifi("/d/1", "Home Net", 50)
	f.block = make(chan struct{})
	s := NewScanner(f)
	s.wait = 20 * time.Millisecond
	start := time.Now()
	if got := s.Scan(context.Background()); len(got) != 0 {
		t.Fatalf("a stuck scan gave %q", got)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the scan waited %v", d)
	}
	if ScanWait >= ScanTimeout || ScanTimeout >= 10*time.Second {
		t.Fatalf("ScanWait %v must be inside ScanTimeout %v, inside the page's 10s", ScanWait, ScanTimeout)
	}
}

func TestShowable(t *testing.T) {
	for _, c := range []struct {
		ssid string
		ok   bool
	}{
		{"Home Net", true}, {"Café ☕", true}, {strings.Repeat("x", 32), true},
		{"", false}, {strings.Repeat("x", 33), false}, {"\x00", false},
		{"tab\there", false}, {"del\x7f", false}, {"\xc3", false}, {"rtl‮", false},
	} {
		if got := Showable([]byte(c.ssid)); got != c.ok {
			t.Errorf("Showable(%q) = %v", c.ssid, got)
		}
	}
}

// serveScan starts the helper's socket for uid with a scanner over f.
func serveScan(t *testing.T, f *fakeScan, uid int) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "run")
	s := &sockets.Server{Dir: dir}
	ctx, cancel := context.WithCancel(context.Background())
	j, _ := joiner(newFake())
	if err := s.Start(ctx, Endpoint(j, NewScanner(f), uid)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); s.Wait() })
	return filepath.Join(dir, Socket)
}

func networks(t *testing.T, r sockets.Response) []string {
	t.Helper()
	var n Networks
	if !r.OK || json.Unmarshal(r.Result, &n) != nil {
		t.Fatalf("not a list: %+v", r)
	}
	return n.SSIDs
}

// Test 2: the socket's scan op serves agentosd's uid alone, before any
// read, and takes no arguments.
func TestTheSocketScansForAgentosdOnly(t *testing.T) {
	f := newScan()
	f.wifi("/d/1", "Home Net", 50)
	path := serveScan(t, f, os.Getuid()+1)
	if r := raw(t, path, []byte(`{"op":"scan"}`)); r.OK || r.Error != string(sockets.ErrPeer) {
		t.Fatalf("another uid was served: %+v", r)
	}
	if f.reached {
		t.Fatal("another uid's scan reached NetworkManager")
	}

	f = newScan()
	f.wifi("/d/1", "Home Net", 50)
	path = serveScan(t, f, os.Getuid())
	for _, bad := range []string{`{"op":"scan","args":{"ssid":"x"}}`, `{"op":"scan","args":[]}`, `{"op":"scan","args":"x"}`, `{"op":"scan","args":{}{}}`} {
		if r := raw(t, path, []byte(bad)); r.OK {
			t.Fatalf("%s was answered: %+v", bad, r)
		}
	}
	if f.reached {
		t.Fatal("a refused scan reached NetworkManager")
	}
	for _, good := range []string{`{"op":"scan"}`, `{"op":"scan","args":{}}`, `{"op":"scan","args":null}`} {
		if got := networks(t, raw(t, path, []byte(good))); !reflect.DeepEqual(got, []string{"Home Net"}) {
			t.Fatalf("%s answered %q", good, got)
		}
	}
	// No network in range is an empty list, not null.
	f2 := newScan()
	path = serveScan(t, f2, os.Getuid())
	r := raw(t, path, []byte(`{"op":"scan"}`))
	if !r.OK || string(r.Result) != `{"ssids":[]}` {
		t.Fatalf("an empty scan answered %+v", r)
	}
}

// Test 4: Client.Networks returns a good answer and re-checks it.
func TestClientListsTheHelpersNetworks(t *testing.T) {
	f := newScan()
	f.wifi("/d/1", "Home Net", 50, "Cafe", 60)
	path := serveScan(t, f, os.Getuid())
	got, err := Client{Path: path}.Networks(context.Background())
	if err != nil || !reflect.DeepEqual(got, []string{"Cafe", "Home Net"}) {
		t.Fatalf("Networks = %q, %v", got, err)
	}
	if _, err := (Client{Path: filepath.Join(t.TempDir(), "none.sock")}).Networks(context.Background()); err == nil {
		t.Fatal("a missing helper gave no error")
	}
	many := make([]string, MaxNetworks+1)
	for i := range many {
		many[i] = fmt.Sprintf("n%d", i)
	}
	tooMany, _ := json.Marshal(Networks{SSIDs: many})
	for _, reply := range []string{
		`{"ok":true,"result":` + string(tooMany) + `}`,
		`{"ok":true,"result":{"ssids":["ok",""]}}`,
		`{"ok":true,"result":{"ssids":["bad\nname"]}}`,
		`{"ok":true,"result":{"ssids":["` + strings.Repeat("x", 33) + `"]}}`,
		`{"ok":true,"result":{"code":"joined"}}`,
		`{"ok":false,"error":"request failed"}`,
		`not json`,
	} {
		p := fakeHelper(t, reply)
		if got, err := (Client{Path: p}).Networks(context.Background()); err == nil {
			t.Fatalf("reply %s gave %q", reply, got)
		}
	}
	p := fakeHelper(t, `{"ok":true,"result":{"ssids":[]}}`)
	if got, err := (Client{Path: p}).Networks(context.Background()); err != nil || len(got) != 0 {
		t.Fatalf("an empty list gave %q, %v", got, err)
	}
}

// The longest answer a helper can give still fits the client's reader.
func TestTheLongestListFitsTheClient(t *testing.T) {
	f := newScan()
	var aps []any
	for i := range MaxNetworks {
		aps = append(aps, fmt.Sprintf("%02d", i)+strings.Repeat("<", 30), i)
	}
	f.wifi("/d/1", aps...)
	path := serveScan(t, f, os.Getuid())
	got, err := Client{Path: path}.Networks(context.Background())
	if err != nil || len(got) != MaxNetworks {
		t.Fatalf("Networks gave %d, %v", len(got), err)
	}
}

// REQ: ONB-3
// #1281: the box's own networks, the setup network and the card's (both
// apnet.Prefix), are never offered as the home Wi-Fi, however strong.
func TestTheScanLeavesOutTheBoxsOwnNetworks(t *testing.T) {
	// The scan filters on apnet.Prefix, so the setup network's name must
	// start with it or the box offers its own setup network as home Wi-Fi.
	if !strings.HasPrefix(claim.SetupSSIDPrefix, apnet.Prefix) {
		t.Fatalf("setup prefix %q does not start with %q", claim.SetupSSIDPrefix, apnet.Prefix)
	}
	f := newScan()
	f.wifi("/d/1",
		"AgentOS-Setup-K7Q2", 99,
		"AgentOS-ABCD", 95,
		"Home Net", 40,
	)
	got := NewScanner(f).Scan(context.Background())
	if want := []string{"Home Net"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Scan = %q, want %q", got, want)
	}
}
