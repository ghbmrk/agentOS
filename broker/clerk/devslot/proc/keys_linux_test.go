package proc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
)

// REQ: CLK-1, DEV-3

// The key's and the device file's descriptors come only from systemd's
// variables for this process, after the connection on 3, each named once;
// anything else is refused, and none set means no key. Fails if a
// descriptor is read as the key that the template did not name as one.
func TestKeyFDs(t *testing.T) {
	env := func(kv ...string) func(string) string {
		m := map[string]string{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	for name, c := range map[string]struct {
		env      func(string) string
		key, dev int
		refused  bool
	}{
		"none":         {env(), -1, -1, false},
		"both":         {env("LISTEN_PID", "7", "LISTEN_FDS", "3", "LISTEN_FDNAMES", "connection:clerk-key:device"), 4, 5, false},
		"swapped":      {env("LISTEN_PID", "7", "LISTEN_FDS", "3", "LISTEN_FDNAMES", "connection:device:clerk-key"), 5, 4, false},
		"key skipped":  {env("LISTEN_PID", "7", "LISTEN_FDS", "2", "LISTEN_FDNAMES", "connection:device"), -1, 4, false},
		"conn only":    {env("LISTEN_PID", "7", "LISTEN_FDS", "1", "LISTEN_FDNAMES", "connection"), -1, -1, false},
		"other pid":    {env("LISTEN_PID", "8", "LISTEN_FDS", "3", "LISTEN_FDNAMES", "connection:clerk-key:device"), -1, -1, true},
		"no pid":       {env("LISTEN_FDS", "3", "LISTEN_FDNAMES", "connection:clerk-key:device"), -1, -1, true},
		"twice":        {env("LISTEN_PID", "7", "LISTEN_FDS", "3", "LISTEN_FDNAMES", "connection:clerk-key:clerk-key"), -1, -1, true},
		"unknown name": {env("LISTEN_PID", "7", "LISTEN_FDS", "2", "LISTEN_FDNAMES", "connection:passwd"), -1, -1, true},
		"count off":    {env("LISTEN_PID", "7", "LISTEN_FDS", "2", "LISTEN_FDNAMES", "connection:clerk-key:device"), -1, -1, true},
		"too many":     {env("LISTEN_PID", "7", "LISTEN_FDS", "4", "LISTEN_FDNAMES", "connection:clerk-key:device:device"), -1, -1, true},
		"no conn":      {env("LISTEN_PID", "7", "LISTEN_FDS", "2", "LISTEN_FDNAMES", "clerk-key:device"), -1, -1, true},
	} {
		k, d, err := keyFDs(c.env, 7)
		if (err != nil) != c.refused || k != c.key || d != c.dev {
			t.Errorf("%s: key %d, device %d, %v", name, k, d, err)
		}
	}
}

// lendFrom lends only the static slot device/<name>, under the clerk
// driver-<name>'s key, and refuses at start a name off the alphabet, a
// hand-off for another clerk, a file that is not regular or is too large,
// a missing slot, a grant in the slot's place and a slot sealed under
// another name. Fails if a driver's process could be lent another slot
// or another driver's key.
func TestLendFromRefuses(t *testing.T) {
	var root [clerkkey.Len]byte
	root[0] = 1
	key := func(name string) *os.File {
		k, _ := clerkkey.Derive(&root, name)
		b, _ := clerkkey.Marshal(k)
		r, w, _ := os.Pipe()
		w.Write(b)
		w.Close()
		return r
	}
	store := func(clerkName string, put func(*clerk.Secrets)) []byte {
		k, _ := clerkkey.Derive(&root, clerkName)
		sk, _ := k.Sealer()
		sl, _ := clerk.NewAESSealer(sk)
		s := clerk.NewSecrets(sl, nil)
		put(s)
		b, _ := s.MarshalBinary()
		return b
	}
	file := func(b []byte) *os.File {
		p := filepath.Join(t.TempDir(), "device")
		os.WriteFile(p, b, 0o400)
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	good := store("driver-scale", func(s *clerk.Secrets) {
		s.Put("device/scale", clerk.KindStatic, []byte("canary-kl-0001"))
		s.Put("device/hue", clerk.KindStatic, []byte("canary-kl-0002"))
	})
	lend, err := lendFrom("scale", key("driver-scale"), file(good))
	if err != nil {
		t.Fatal(err)
	}
	var got string
	if err := lend(func(k []byte) error { got = string(k); return nil }); err != nil || got != "canary-kl-0001" {
		t.Fatalf("lent %q, %v", got, err)
	}

	// A slot sealed as device/hue, renamed device/scale in the file.
	var swapped map[string]json.RawMessage
	json.Unmarshal(good, &swapped)
	swapped["device/scale"] = swapped["device/hue"]
	sw, _ := json.Marshal(swapped)
	dir := t.TempDir()
	for name, c := range map[string]struct {
		name   string
		key    *os.File
		device func() *os.File
	}{
		"name off the alphabet": {"Scale", key("driver-Scale"), func() *os.File { return file(good) }},
		"another clerk's key":   {"scale", key("driver-hue"), func() *os.File { return file(good) }},
		"not a regular file":    {"scale", key("driver-scale"), func() *os.File { f, _ := os.Open(dir); return f }},
		"too large":             {"scale", key("driver-scale"), func() *os.File { return file(make([]byte, maxDeviceFile+1)) }},
		"no slot":               {"scale", key("driver-scale"), func() *os.File { return file(store("driver-scale", func(*clerk.Secrets) {})) }},
		"a grant": {"scale", key("driver-scale"), func() *os.File {
			return file(store("driver-scale", func(s *clerk.Secrets) { s.Put("device/scale", clerk.KindGrant, []byte("canary-g")) }))
		}},
		"a swapped slot": {"scale", key("driver-scale"), func() *os.File { return file(sw) }},
	} {
		if l, err := lendFrom(c.name, c.key, c.device()); err == nil || l != nil {
			t.Errorf("%s: lent", name)
		}
	}
}
