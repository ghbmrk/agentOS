package drone

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// REQ: NET-2, NET-4
// TestPolicyLoadFailsClosed (brief acceptance test 4): every malformed,
// unsigned, wrongly signed, older or out-of-bounds policy is refused, and a
// refused policy derives nothing: the key-holder sends the aircraft no frame
// and records no policy.
func TestPolicyLoadFailsClosed(t *testing.T) {
	owner := testOwner(t, 1)
	other := testOwner(t, 2)
	pub := owner.Public().(ed25519.PublicKey)
	loaded, err := LoadPolicy(signPolicy(t, testPolicy(), owner), pub, nil)
	if err != nil {
		t.Fatalf("the fixture policy is refused: %v", err)
	}
	mut := func(f func(*Policy)) []byte {
		p := testPolicy()
		f(&p)
		return signPolicy(t, p, owner)
	}
	withRaw := func(f func(string) string) []byte {
		return signRaw(t, []byte(f(string(record(t, testPolicy())))), owner)
	}
	cases := []struct {
		name   string
		env    []byte
		loaded *Policy
		want   string
	}{
		{"unsigned", []byte(`{"policy":` + string(record(t, testPolicy())) + `,"sig":""}`), nil, "signature"},
		{"no signature field", []byte(`{"policy":` + string(record(t, testPolicy())) + `}`), nil, "signature"},
		{"wrong key", signPolicy(t, testPolicy(), other), nil, "does not verify"},
		{"signature over other bytes", func() []byte {
			env := signPolicy(t, testPolicy(), owner)
			return bytes.Replace(env, []byte(`"ceiling_m":60`), []byte(`"ceiling_m":90`), 1)
		}(), nil, "does not verify"},
		{"older version", mut(func(p *Policy) { p.Version = 2 }), loaded, "older"},
		{"same version, other content", mut(func(p *Policy) { p.LowBatteryV = 11 }), loaded, "same version"},
		{"version zero", mut(func(p *Policy) { p.Version = 0 }), nil, "version"},
		{"waypoint outside the boundary", mut(func(p *Policy) { p.Routes[0].Waypoints[1] = wp(250, 150, 30) }), nil, "boundary"},
		{"leg crossing the boundary", mut(func(p *Policy) {
			p.Routes[0].Waypoints = []Waypoint{wp(150, -100, 30), wp(150, 100, 30)}
		}), nil, "boundary"},
		{"waypoint inside the margin", mut(func(p *Policy) { p.Routes[0].Waypoints[1] = wp(199, 150, 30) }), nil, "margin"},
		{"waypoint in a no-fly zone", mut(func(p *Policy) { p.Routes[0].Waypoints[1] = wp(-125, 125, 30) }), nil, "no-fly"},
		{"leg through a no-fly zone", mut(func(p *Policy) { p.Routes[0].Waypoints = []Waypoint{wp(-125, 180, 30)} }), nil, "no-fly"},
		{"dock in a no-fly zone", mut(func(p *Policy) {
			p.NoFly = append(p.NoFly, []Point{at(-5, -5), at(5, -5), at(5, 5), at(-5, 5)})
		}), nil, "dock"},
		{"waypoint above the ceiling", mut(func(p *Policy) { p.Routes[1].Waypoints[0].AltM = 70 }), nil, "altitude"},
		{"waypoint within the margin of the ceiling", mut(func(p *Policy) { p.Routes[1].Waypoints[0].AltM = 59 }), nil, "altitude"},
		{"zero ceiling", mut(func(p *Policy) { p.CeilingM = 0 }), nil, "ceiling"},
		{"ceiling above 400 ft", mut(func(p *Policy) { p.CeilingM = 130 }), nil, "ceiling"},
		{"zero fence margin", mut(func(p *Policy) { p.FenceMarginM = 0 }), nil, "margin"},
		{"zero low-battery threshold", mut(func(p *Policy) { p.LowBatteryV = 0 }), nil, "low-battery"},
		{"negative low-battery threshold", mut(func(p *Policy) { p.LowBatteryV = -1 }), nil, "low-battery"},
		{"zero lost-link timeout", mut(func(p *Policy) { p.LostLinkS = 0 }), nil, "lost-link"},
		{"negative lost-link timeout", mut(func(p *Policy) { p.LostLinkS = -5 }), nil, "lost-link"},
		{"zero GPS/camera bound", mut(func(p *Policy) { p.GPSCameraBoundM = 0 }), nil, "GPS/camera"},
		{"zero dock radius", mut(func(p *Policy) { p.Dock.RadiusM = 0 }), nil, "dock radius"},
		{"missing threshold", withRaw(func(s string) string { return strings.Replace(s, `"low_battery_v":10.5,`, "", 1) }), nil, "canonical"},
		{"unknown field", withRaw(func(s string) string { return strings.Replace(s, `{"version"`, `{"extra":1,"version"`, 1) }), nil, "unknown field"},
		{"not canonical (whitespace)", withRaw(func(s string) string { return strings.Replace(s, `,"ceiling_m"`, `, "ceiling_m"`, 1) }), nil, "canonical"},
		{"malformed record", signRaw(t, []byte(`{"version":3,`), owner), nil, "malformed"},
		{"malformed envelope", []byte(`{"policy":`), nil, "malformed"},
		{"trailing data", append(signPolicy(t, testPolicy(), owner), []byte(`{}`)...), nil, "trailing"},
		{"no routes", mut(func(p *Policy) { p.Routes = nil }), nil, "routes"},
		{"routes out of order", mut(func(p *Policy) { p.Routes[0], p.Routes[1] = p.Routes[1], p.Routes[0] }), nil, "sorted"},
		{"repeated route name", mut(func(p *Policy) { p.Routes[1].Name = "north" }), nil, "sorted"},
		{"route name not plain", mut(func(p *Policy) { p.Routes[0].Name = "North Pond" }), nil, "name"},
		{"self-crossing boundary", mut(func(p *Policy) {
			p.Boundary = []Point{at(-200, -200), at(200, 200), at(200, -200), at(-200, 200)}
		}), nil, "crosses itself"},
		{"self-crossing boundary with area (a pentagram)", mut(func(p *Policy) {
			p.Boundary = []Point{at(0, 200), at(-118, -162), at(190, 62), at(-190, 62), at(118, -162)}
		}), nil, "crosses itself"},
		{"no return altitude below the ceiling", mut(func(p *Policy) { p.CeilingM, p.FenceMarginM = 8, 2 }), nil, "return altitude"},
		{"two-vertex boundary", mut(func(p *Policy) { p.Boundary = p.Boundary[:2] }), nil, "vertices"},
		{"invalid latitude", mut(func(p *Policy) { p.Boundary[0].Lat = 91 }), nil, "latitude"},
		{"boundary far from the dock", mut(func(p *Policy) { p.Boundary[0] = at(-20000, -200) }), nil, "from the dock"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := LoadPolicy(c.env, pub, c.loaded)
			if err == nil || p != nil {
				t.Fatalf("loaded (%v, %v); want a refusal", p != nil, err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not name %q", err, c.want)
			}
			// Nothing is derived: a holder refusing it writes no frame and records nothing.
			h, sent, dir := fakeHolder(t, pub)
			if c.loaded != nil {
				h.policy = c.loaded
			}
			if err := h.Load(c.env); err == nil {
				t.Fatal("the holder loaded it")
			}
			time.Sleep(20 * time.Millisecond)
			if n := sent.Load(); n != 0 {
				t.Errorf("the holder sent the aircraft %d bytes for a refused policy", n)
			}
			if _, err := os.Stat(filepath.Join(dir, policyFile)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a refused policy was recorded: %v", err)
			}
		})
	}
	// The byte count can see a frame: one heartbeat moves it.
	h, sent, _ := fakeHolder(t, pub)
	if err := h.link.SendHeartbeat(); err != nil || sent.Load() == 0 {
		t.Fatalf("a sent frame is not counted (%v); the nothing-sent check would be vacuous", err)
	}
	// The same bytes again reload (a boot re-reads the record in force).
	if _, err := LoadPolicy(signPolicy(t, testPolicy(), owner), pub, loaded); err != nil {
		t.Errorf("reloading the policy in force: %v", err)
	}
	// A newer version, adding a route, loads (NET-4: a loosening is a new signed version).
	if _, err := LoadPolicy(mut(func(p *Policy) {
		p.Version = 4
		p.Routes = append(p.Routes, Route{Name: "west", Waypoints: []Waypoint{wp(-150, 0, 20)}})
	}), pub, loaded); err != nil {
		t.Errorf("a newer version: %v", err)
	}
}

// fakeHolder is a holder whose aircraft is the far end of a pipe that counts
// every byte the holder writes.
func fakeHolder(t *testing.T, pub ed25519.PublicKey) (*Holder, *atomic.Int64, string) {
	t.Helper()
	near, far := net.Pipe()
	t.Cleanup(func() { near.Close(); far.Close() })
	var sent atomic.Int64
	k, err := NewKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Dial(countingConn{near, &sent}, k)
	if err != nil {
		t.Fatal(err)
	}
	sent.Store(0) // Dial's own heartbeat
	dir := t.TempDir()
	h, err := NewHolder(l, pub, dir, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	return h, &sent, dir
}

type countingConn struct {
	net.Conn
	n *atomic.Int64
}

func (c countingConn) Write(b []byte) (int, error) {
	c.n.Add(int64(len(b)))
	return len(b), nil // the frame is counted, never delivered
}

// REQ: NET-2
// TestDeriveIsTheSignedLimits: the derived plan carries the policy's limits
// as the aircraft's own parameters, fence and dock rally point.
func TestDeriveIsTheSignedLimits(t *testing.T) {
	owner := testOwner(t, 1)
	p, err := LoadPolicy(signPolicy(t, testPolicy(), owner), owner.Public().(ed25519.PublicKey), nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := Derive(p)
	want := map[string]float32{"FENCE_ENABLE": 1, "FENCE_TYPE": 5, "FENCE_ACTION": 1, "FENCE_ALT_MAX": 60,
		"FENCE_MARGIN": 2, "BATT_LOW_VOLT": 10.5, "BATT_FS_LOW_ACT": 2, "FS_GCS_ENABLE": 1, "FS_GCS_TIMEOUT": 5,
		"SCR_ENABLE": 0, "RC_PROTOCOLS": 0, "RTL_ALT_M": 56, "RALLY_INCL_HOME": 0,
		"FS_OPTIONS": 0, "BATT_MONITOR": 4, "BATT_LOW_TIMER": 10, "AUTO_OPTIONS": 3, "AVOID_ENABLE": 0, "FENCE_OPTIONS": 1}
	got := map[string]float32{}
	for _, pr := range plan.Params {
		got[pr.Name] = pr.Value
	}
	for n, v := range want {
		if g, ok := got[n]; !ok || g != v {
			t.Errorf("%s = %v (present %v), want %v", n, g, ok, v)
		}
	}
	if len(plan.Fence) != 8+4 || plan.Fence[0].Command != cmdFenceInclusion || plan.Fence[0].Param1 != 8 ||
		plan.Fence[8].Command != cmdFenceExclusion || plan.Fence[8].Param1 != 4 {
		t.Errorf("fence = %+v", plan.Fence)
	}
	if len(plan.Rally) != 1 || plan.Rally[0].Lat != e7(testDock.Lat) || plan.Rally[0].Lon != e7(testDock.Lon) {
		t.Errorf("rally = %+v", plan.Rally)
	}
	again := Derive(p)
	if len(again.Params) != len(plan.Params) {
		t.Fatal("Derive is not deterministic")
	}
	for i := range again.Params {
		if again.Params[i] != plan.Params[i] {
			t.Fatalf("Derive is not deterministic at %d", i)
		}
	}
}

// REQ: NET-4
// TestStoredPolicyReloads: the policy in force is recorded before its upload
// and a key-holder restarted on the same state directory loads it, so the
// version rule survives a restart; a tampered record stops the holder.
func TestStoredPolicyReloads(t *testing.T) {
	owner := testOwner(t, 1)
	pub := owner.Public().(ed25519.PublicKey)
	h, _, dir := fakeHolder(t, pub)
	if err := h.Load(signPolicy(t, testPolicy(), owner)); err == nil {
		t.Fatal("a load with no aircraft answering succeeded")
	}
	k, _ := NewKey(nil)
	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()
	go io.Copy(io.Discard, far)
	l, err := Dial(near, k)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := NewHolder(l, pub, dir, nil)
	if err != nil {
		t.Fatalf("restarting on the recorded policy: %v", err)
	}
	if p := h2.Policy(); p == nil || p.Version != 3 {
		t.Fatalf("restarted holder's policy = %+v", p)
	}
	older := testPolicy()
	older.Version = 2
	if err := h2.Load(signPolicy(t, older, owner)); err == nil || !strings.Contains(err.Error(), "older") {
		t.Errorf("an older version after a restart: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, policyFile))
	os.WriteFile(filepath.Join(dir, policyFile), bytes.Replace(b, []byte(`"ceiling_m":60`), []byte(`"ceiling_m":90`), 1), 0o600)
	if _, err := NewHolder(l, pub, dir, nil); err == nil {
		t.Error("a tampered stored policy was accepted")
	}
}
