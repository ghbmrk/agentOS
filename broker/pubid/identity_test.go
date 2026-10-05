package pubid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// REQ: OSS-6

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Every installation rotates at the same instants: epochs are fixed UTC
// periods from one public reference, so a key change says nothing about
// which installation changed (OSS-6).
func TestOSS6EpochsAreGlobalAndFixed(t *testing.T) {
	if got := EpochOf(Reference); got != 0 {
		t.Fatalf("EpochOf(Reference) = %d", got)
	}
	if got := EpochOf(Reference.Add(EpochLength - time.Nanosecond)); got != 0 {
		t.Fatalf("last instant of epoch 0 = %d", got)
	}
	if got := EpochOf(Reference.Add(EpochLength)); got != 1 {
		t.Fatalf("first instant of epoch 1 = %d", got)
	}
	// Time zones do not matter: the same instant is the same epoch.
	ny := time.FixedZone("x", -4*3600)
	if EpochOf(Reference.Add(3*EpochLength).In(ny)) != 3 {
		t.Fatal("epoch depends on the zone")
	}
	if EpochOf(Reference.Add(-time.Hour)) != -1 || EpochOf(Reference.Add(-EpochLength)) != -1 || EpochOf(Reference.Add(-EpochLength-1)) != -2 {
		t.Fatal("epochs before the reference are off by one")
	}
	if EpochLength != 28*24*time.Hour || Reference.Weekday() != time.Sunday || Reference.Location() != time.UTC {
		t.Fatalf("epoch schedule changed: %v from %v", EpochLength, Reference)
	}
}

// The key is random, kept for its epoch across restarts, replaced at the
// next epoch with a fresh one that nothing links to the old, and the old
// one is gone from disk.
func TestOSS6KeyIsRandomPerEpochAndRotates(t *testing.T) {
	dir := t.TempDir()
	c := &clock{Reference.Add(10 * 24 * time.Hour)}
	path := filepath.Join(dir, "pubid.json")
	id, err := Open(path, c.now)
	must(t, err)
	k1, e1, err := id.Key()
	must(t, err)
	if e1 != 0 {
		t.Fatalf("epoch %d", e1)
	}
	old, err := os.ReadFile(path)
	must(t, err)

	// Same epoch, after a restart: same key.
	id2, err := Open(path, c.now)
	must(t, err)
	k2, _, err := id2.Key()
	must(t, err)
	if !k1.Equal(k2) {
		t.Fatal("key changed within its epoch")
	}
	// Another installation at the same instant: another key.
	other, err := Open(filepath.Join(t.TempDir(), "pubid.json"), c.now)
	must(t, err)
	k3, _, err := other.Key()
	must(t, err)
	if k1.Equal(k3) {
		t.Fatal("two installations share a key")
	}

	// Next epoch: a new key, and the old seed is no longer on disk.
	c.t = Reference.Add(EpochLength + time.Hour)
	k4, e4, err := id2.Key()
	must(t, err)
	if e4 != 1 || k4.Equal(k1) {
		t.Fatalf("no rotation: epoch %d", e4)
	}
	now, err := os.ReadFile(path)
	must(t, err)
	if bytes.Contains(now, seedField(t, old)) {
		t.Fatal("the old epoch's seed is still on disk")
	}

	// A clock in another epoch, earlier or later, gets a fresh key for
	// that epoch: an old key never comes back, and no key outlives the
	// global boundary (L3 MUST 1 on #163).
	c.t = Reference.Add(time.Hour)
	k5, e5, err := id2.Key()
	must(t, err)
	if e5 != 0 || k5.Equal(k4) || k5.Equal(k1) {
		t.Fatalf("clock stepped back: epoch %d, an old key %v", e5, k5.Equal(k1))
	}
	// A clock far ahead and then corrected: a fresh key each time, never
	// one kept from the wrong clock.
	c.t = Reference.Add(100 * 365 * 24 * time.Hour)
	far, ef, err := id2.Key()
	must(t, err)
	c.t = Reference.Add(3*EpochLength + time.Hour)
	k6, e6, err := id2.Key()
	must(t, err)
	if ef <= 3 || e6 != 3 || k6.Equal(far) {
		t.Fatalf("after a forward step and its correction: epochs %d, %d, same key %v", ef, e6, k6.Equal(far))
	}
	// Key hands out a copy: changing it changes nothing inside.
	k6[0] ^= 0xff
	k7, _, err := id2.Key()
	must(t, err)
	if k7.Equal(k6) {
		t.Fatal("Key exposed the identity's own key")
	}
	// No file in the directory holds an earlier seed.
	cur, err := os.ReadFile(path)
	must(t, err)
	ents, err := os.ReadDir(dir)
	must(t, err)
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		must(t, err)
		if bytes.Contains(b, seedField(t, old)) || (e.Name() != "pubid.json" && bytes.Contains(b, seedField(t, cur))) {
			t.Fatalf("%s holds a seed", e.Name())
		}
	}
	if len(ents) != 1 {
		t.Fatalf("%d files beside the identity", len(ents)-1)
	}
	if id2.rand != rand.Reader {
		t.Fatal("the key is not drawn from crypto/rand")
	}
}

// An identity file others could read gets a fresh key at once, written
// 0600: the old key may have been copied (L3 SHOULD 8 on #163).
func TestOSS6LooseIdentityFileGetsAFreshKey(t *testing.T) {
	c := &clock{Reference.Add(time.Hour)}
	path := filepath.Join(t.TempDir(), "pubid.json")
	id, err := Open(path, c.now)
	must(t, err)
	k1, _, err := id.Key()
	must(t, err)
	must(t, os.Chmod(path, 0o640))
	id, err = Open(path, c.now)
	must(t, err)
	k2, e, err := id.Key()
	must(t, err)
	fi, err := os.Stat(path)
	must(t, err)
	if k2.Equal(k1) || e != 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("loose file kept its key (%v) or mode %v", k2.Equal(k1), fi.Mode().Perm())
	}
}

func seedField(t *testing.T, b []byte) []byte {
	t.Helper()
	var s struct{ Seed string }
	must(t, json.Unmarshal(b, &s))
	if s.Seed == "" {
		t.Fatal("no seed")
	}
	return []byte(s.Seed)
}

// The identity file holds the epoch and the seed and nothing else: no
// name, number, account or host detail can ride along (OSS-6). It is
// readable only by the broker.
func TestOSS6IdentityFileHoldsOnlyEpochAndSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pubid.json")
	id, err := Open(path, (&clock{Reference}).now)
	must(t, err)
	_, _, err = id.Key()
	must(t, err)
	fi, err := os.Stat(path)
	must(t, err)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	must(t, err)
	var m map[string]json.RawMessage
	must(t, json.Unmarshal(b, &m))
	if len(m) != 2 || m["epoch"] == nil || m["seed"] == nil {
		t.Fatalf("identity file fields: %s", b)
	}
}

// A damaged identity file is never repaired silently into a key that
// could be someone else's: Open refuses it, and the caller publishes
// nothing until it is fixed.
func TestOSS6DamagedIdentityFileIsRefused(t *testing.T) {
	for _, bad := range []string{
		`{`,
		`{"epoch":0}`,
		`{"epoch":0,"seed":"AAAA"}`,
		`{"epoch":0,"seed":"` + b64(make([]byte, ed25519.SeedSize)) + `","name":"x"}`,
		`{"epoch":0,"seed":"` + b64(make([]byte, ed25519.SeedSize)) + `","epoch":1}`,
	} {
		path := filepath.Join(t.TempDir(), "pubid.json")
		must(t, os.WriteFile(path, []byte(bad), 0o600))
		if _, err := Open(path, (&clock{Reference}).now); err == nil {
			t.Errorf("Open accepted %s", bad)
		}
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
