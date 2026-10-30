package main

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
)

// REQ: CH-4, CLK-1, STO-2

func TestParseNeedsEachPath(t *testing.T) {
	ok := []string{"-dir", "/run/x", "-state", "/var/x", "-seed", "/run/s", "-verify-uid", "2"}
	if c, err := parse(ok, io.Discard); err != nil || c.verifyUID != 2 {
		t.Fatalf("%+v %v", c, err)
	}
	for name, args := range map[string][]string{
		"no seed":       {"-dir", "/run/x", "-state", "/var/x", "-verify-uid", "2"},
		"relative seed": {"-dir", "/run/x", "-state", "/var/x", "-seed", "s", "-verify-uid", "2"},
		"no verify uid": {"-dir", "/run/x", "-state", "/var/x", "-seed", "/run/s"},
		"old hand uid":  {"-dir", "/run/x", "-state", "/var/x", "-seed", "/run/s", "-verify-uid", "2", "-hand-uid", "1"},
	} {
		if _, err := parse(args, io.Discard); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The checker never runs as its peer (SIM-split R3).
func TestRunRefusesItsPeerUID(t *testing.T) {
	dir := t.TempDir()
	args := []string{"-dir", filepath.Join(dir, "run"), "-state", filepath.Join(dir, "state.json"),
		"-seed", filepath.Join(dir, "seed"), "-verify-uid", strconv.Itoa(os.Getuid())}
	if err := run(args, io.Discard, keyPipe(t, testKey(t))); err == nil || !strings.Contains(err.Error(), "peer uid") {
		t.Fatalf("%v", err)
	}
}

func testKey(t *testing.T) clerkkey.Key {
	t.Helper()
	var root [clerkkey.Len]byte
	for i := range root {
		root[i] = byte(0x50 + i)
	}
	k, err := clerkkey.Derive(&root, handoff.CheckerName)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func keyPipe(t *testing.T, k clerkkey.Key) *os.File {
	t.Helper()
	b, err := clerkkey.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Write(b)
	w.Close()
	return r
}

// The process gets its seed only from the unlock step's file opened under
// the kernel's key: no key starts nothing, a key for another clerk starts
// nothing, no file starts a checker that holds no seed, and the file under
// the right key gives it the seed. Fails if a checker could start holding a
// seed from anywhere else.
func TestStartTakesTheSeedOnlyUnderItsKey(t *testing.T) {
	dir := t.TempDir()
	c := config{dir: filepath.Join(dir, "run"), state: filepath.Join(dir, "state.json"), seed: filepath.Join(dir, "seed")}
	f, _ := os.CreateTemp(dir, "key")
	if _, err := start(c, io.Discard, f); err == nil {
		t.Fatal("a key from a file on the drive started the checker")
	}
	k := testKey(t)
	other := k
	other.Name = "mail"
	if _, err := start(c, io.Discard, keyPipe(t, other)); err == nil {
		t.Fatal("another clerk's key started the checker")
	}
	chk, err := start(c, io.Discard, keyPipe(t, k))
	if err != nil || chk.Held() {
		t.Fatalf("no seed file: held %v, %v", chk != nil && chk.Held(), err)
	}
	sealer, _ := k.Sealer()
	blob, err := handoff.SealCodeSeed(sealer, handoff.CodeSeed{Seed: []byte("synthetic-seed-0123"), Step: 3})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.seed, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	chk, err = start(c, io.Discard, keyPipe(t, k))
	if err != nil || !chk.Held() {
		t.Fatalf("the unlock step's file: %v", err)
	}
	sign, _ := k.Signer()
	if !chk.Public().Equal(sign.Public()) {
		t.Fatal("the checker signs under a key the kernel would not pin")
	}
	os.Remove(c.seed)
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), c.seed); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "elsewhere"), blob, 0o600)
	if _, err := start(c, io.Discard, keyPipe(t, k)); err == nil {
		t.Fatal("the seed was read through a link")
	}
}
