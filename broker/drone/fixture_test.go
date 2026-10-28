package drone

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"testing"
)

// The test site is ArduPilot's own SITL default (CMAC, Canberra): synthetic,
// public, nobody's house. Local offsets are metres east (x) and north (y) of
// the dock.
var testDock = Point{Lat: -35.363261, Lon: 149.165230}

func at(x, y float64) Point {
	ky := earthRadiusM * math.Pi / 180
	kx := ky * math.Cos(testDock.Lat*math.Pi/180)
	return Point{Lat: round7(testDock.Lat + y/ky), Lon: round7(testDock.Lon + x/kx)}
}

func wp(x, y, alt float64) Waypoint {
	q := at(x, y)
	return Waypoint{Lat: q.Lat, Lon: q.Lon, AltM: alt}
}

func round7(v float64) float64 { return math.Round(v*1e7) / 1e7 }

// testPolicy is a valid policy: a 400 m square with a notch cut into its east
// side (so a leg between two inside points can still leave it), one no-fly
// square in the north-west, and two routes.
func testPolicy() Policy {
	return Policy{
		Version: 3,
		Boundary: []Point{at(-200, -200), at(200, -200), at(200, -20), at(60, -20), at(60, 20),
			at(200, 20), at(200, 200), at(-200, 200)},
		CeilingM:     60,
		FenceMarginM: 2,
		NoFly:        [][]Point{{at(-150, 100), at(-100, 100), at(-100, 150), at(-150, 150)}},
		Routes: []Route{
			{Name: "north", Waypoints: []Waypoint{wp(0, 150, 30), wp(100, 150, 30)}},
			{Name: "south", Waypoints: []Waypoint{wp(0, -150, 40), wp(-150, -150, 40)}},
		},
		Dock:            Dock{Lat: testDock.Lat, Lon: testDock.Lon, RadiusM: 3},
		LowBatteryV:     10.5,
		LostLinkS:       5,
		GPSCameraBoundM: 8,
	}
}

func testOwner(t testing.TB, seed byte) ed25519.PrivateKey {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	return ed25519.NewKeyFromSeed(s)
}

func record(t testing.TB, p Policy) []byte {
	t.Helper()
	b, err := json.Marshal(&p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// signRaw wraps raw record bytes in a signed envelope, whatever they hold.
func signRaw(t testing.TB, raw []byte, priv ed25519.PrivateKey) []byte {
	t.Helper()
	sig := ed25519.Sign(priv, policyMessage(raw))
	env := []byte(`{"policy":`)
	env = append(env, raw...)
	env = append(env, `,"sig":"`+base64.StdEncoding.EncodeToString(sig)+`"}`...)
	return env
}

func signPolicy(t testing.TB, p Policy, priv ed25519.PrivateKey) []byte {
	return signRaw(t, record(t, p), priv)
}
