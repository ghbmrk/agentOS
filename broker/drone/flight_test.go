package drone

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// REQ: NET-6
// TestFlightRecordFailsClosed: a flight record is refused unless the owner
// signed exactly it, in canonical form, for a route the policy names, with a
// plain id and animal list, not expired and not signed for a later day; the
// valid record loads, so the refusals are not vacuous.
func TestFlightRecordFailsClosed(t *testing.T) {
	owner := testOwner(t, 1)
	pub := owner.Public().(ed25519.PublicKey)
	p := testPolicy()
	now := time.Now()
	mut := func(f func(*Flight)) []byte {
		r := testFlight(now)
		f(&r)
		return signFlight(t, r, owner)
	}
	raw, _ := json.Marshal(testFlight(now))
	cases := []struct {
		name   string
		env    []byte
		policy *Policy
	}{
		{"wrong key", signFlight(t, testFlight(now), testOwner(t, 2)), &p},
		{"signature in the policy domain", []byte(`{"flight":` + string(raw) + `,"sig":"` +
			base64.StdEncoding.EncodeToString(ed25519.Sign(owner, policyMessage(raw))) + `"}`), &p},
		{"bad signature", bytes.Replace(signFlight(t, testFlight(now), owner), []byte(`"sig":"`), []byte(`"sig":"A`), 1), &p},
		{"no signature", []byte(`{"flight":` + string(raw) + `,"sig":""}`), &p},
		{"not canonical", signFlightRaw(t, append([]byte(" "), raw...), owner), &p},
		{"unknown field", signFlightRaw(t, []byte(strings.Replace(string(raw), `{`, `{"zone":"all",`, 1)), owner), &p},
		{"no policy loaded", signFlight(t, testFlight(now), owner), nil},
		{"route the policy lacks", mut(func(f *Flight) { f.Route = "west" }), &p},
		{"expired", mut(func(f *Flight) { f.NotAfter = now.Add(-time.Second).Unix() }), &p},
		{"signed for a later day", mut(func(f *Flight) { f.NotAfter = now.Add(25 * time.Hour).Unix() }), &p},
		{"id not hex", mut(func(f *Flight) { f.ID = strings.Repeat("g", 32) }), &p},
		{"id short", mut(func(f *Flight) { f.ID = "0123" }), &p},
		{"animals missing", mut(func(f *Flight) { f.Animals = nil }), &p},
		{"too many animals", mut(func(f *Flight) { f.Animals = strings.Split("a b c d e f g h i", " ") }), &p},
		{"animal not plain", mut(func(f *Flight) { f.Animals = []string{"deer\nreturn_to_dock"} }), &p},
		{"too large", append(signFlight(t, testFlight(now), owner), bytes.Repeat([]byte(" "), maxFlightEnv)...), &p},
		{"malformed", []byte(`{"flight":`), &p},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if f, err := LoadFlight(c.env, pub, c.policy, now); err == nil {
				t.Fatalf("loaded %+v", f)
			}
		})
	}
	if _, err := LoadFlight(signFlight(t, testFlight(now), owner), pub, &p, now); err != nil {
		t.Fatalf("the valid record: %v", err)
	}
	if _, err := LoadFlight(mut(func(f *Flight) { f.Animals = []string{"deer", "wild-boar"} }), pub, &p, now); err != nil {
		t.Fatalf("a record that follows animals: %v", err)
	}
}

// REQ: NET-6
// TestFlightIsUsedOnce: a record already in the used set is refused before
// anything reaches the aircraft, the used set survives a restart, an expired
// entry is dropped from it, and a corrupt set refuses every flight.
func TestFlightIsUsedOnce(t *testing.T) {
	owner := testOwner(t, 1)
	pub := owner.Public().(ed25519.PublicKey)
	now := time.Now()
	h, sent, dir := fakeHolder(t, pub)
	p := testPolicy()
	plan := Derive(&p)
	h.policy, h.plan = &p, &plan
	f := testFlight(now)
	env := signFlight(t, f, owner)

	old := "fedcba9876543210fedcba9876543210"
	if err := h.writeUsed(map[string]int64{f.ID: f.NotAfter, old: now.Add(-time.Minute).Unix()}); err != nil {
		t.Fatal(err)
	}
	if err := h.Fly(env); err == nil || !strings.Contains(err.Error(), "already flown") {
		t.Fatalf("a used record: %v", err)
	}
	if n := sent.Load(); n != 0 {
		t.Fatalf("a used record sent %d bytes to the aircraft", n)
	}
	used, err := h.readUsed(now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := used[old]; ok || used[f.ID] != f.NotAfter {
		t.Fatalf("used set after reading = %v", used)
	}

	// An unused record gets as far as the read-back (no aircraft answers
	// here) and is not marked used when it fails there.
	g := testFlight(now)
	g.ID = "11111111111111111111111111111111"
	if err := h.Fly(signFlight(t, g, owner)); err == nil || strings.Contains(err.Error(), "already flown") {
		t.Fatalf("an unused record with no aircraft: %v", err)
	}
	if used, _ := h.readUsed(now); used[g.ID] != 0 {
		t.Fatal("a record refused at the read-back was marked used")
	}

	for _, bad := range []string{"not-an-id 1\n", f.ID + "\n", f.ID + " soon\n"} {
		if err := os.WriteFile(filepath.Join(dir, usedFile), []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := h.Fly(env); err == nil || !strings.Contains(err.Error(), "corrupt") {
			t.Fatalf("used set %q: %v", bad, err)
		}
	}
}
