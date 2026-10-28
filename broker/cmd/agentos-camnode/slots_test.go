package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/camwire/camwiretest"
)

// REQ: NET-7, DEV-3

// TestSlotsStageArmAndMarkGood: staging drops the inactive slot's
// manifest before its device is written, so a cut during the write leaves
// no manifest over a half image; Arm stores the manifest and keeps the
// running slot the default with the staged one as the one-shot; the trial
// boot reads the staged manifest and hashes its slot; MarkGood makes it
// the default. An image larger than the slot is refused. Revert mutant:
// Stage without the manifest removal.
func TestSlotsStageArmAndMarkGood(t *testing.T) {
	dir := t.TempDir()
	dev := [2]string{filepath.Join(dir, "a"), filepath.Join(dir, "b")}
	for _, d := range dev {
		os.WriteFile(d, make([]byte, 4096), 0o600)
	}
	auto := filepath.Join(dir, "autoboot.txt")
	s, err := newSlots(auto, dir, dev, [2]int{2, 3}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if m, _, err := s.running(); m != nil || err != nil {
		t.Fatalf("factory image: %v %v", m, err)
	}
	os.WriteFile(s.manifest(1), []byte("stale"), 0o600)
	if _, err := s.Stage(4097); err == nil {
		t.Fatal("an image larger than the slot was staged")
	}
	img := make([]byte, 3000)
	rand.Read(img)
	st, err := s.Stage(uint64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.manifest(1)); !os.IsNotExist(err) {
		t.Fatal("the inactive slot kept its manifest while being written")
	}
	st.Write(img)
	p := signedManifest(t, img)
	if err := st.Arm(p); err != nil {
		t.Fatal(err)
	}
	want := "[all]\ntryboot_a_b=1\nboot_partition=2\n[tryboot]\nboot_partition=3\n"
	if got, _ := os.ReadFile(auto); string(got) != want {
		t.Fatalf("autoboot.txt after Arm:\n%s", got)
	}

	// The trial boot runs from partition 3.
	trial, err := newSlots(auto, dir, dev, [2]int{2, 3}, 3)
	if err != nil {
		t.Fatal(err)
	}
	m, sum, err := trial.running()
	if err != nil || !bytes.Equal(m, p) || sum != sha256.Sum256(img) {
		t.Fatalf("trial slot: %v, hash ok %v", err, sum == sha256.Sum256(img))
	}
	if err := trial.MarkGood(); err != nil {
		t.Fatal(err)
	}
	want = "[all]\ntryboot_a_b=1\nboot_partition=3\n[tryboot]\nboot_partition=2\n"
	if got, _ := os.ReadFile(auto); string(got) != want {
		t.Fatalf("autoboot.txt after MarkGood:\n%s", got)
	}

	// Aborting a staging leaves the other slot without a manifest.
	st, _ = trial.Stage(10)
	st.Abort()
	if _, err := os.Stat(trial.manifest(0)); !os.IsNotExist(err) {
		t.Fatal("aborted staging left a manifest")
	}
	if _, err := newSlots(auto, dir, dev, [2]int{2, 3}, 4); err == nil {
		t.Fatal("a partition that is neither slot was taken")
	}
	// A slot shorter than its manifest is refused.
	os.WriteFile(dev[1], img[:100], 0o600)
	if _, _, err := trial.running(); err == nil {
		t.Fatal("a short slot hashed")
	}
}

func signedManifest(t *testing.T, img []byte) []byte {
	_, rel, _ := ed25519.GenerateKey(rand.Reader)
	m := camwire.Manifest{Image: sha256.Sum256(img), Size: uint64(len(img)), Version: 1, Counter: 1, Nodes: [][32]byte{{1}}}
	enc, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sm := camwire.SignedManifest{Manifest: enc, Assertion: camwiretest.NewPasskey(t).Assert(t, enc)}
	copy(sm.Release[:], ed25519.Sign(rel, enc))
	out, err := sm.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestFlags: the release key must be a base64 Ed25519 key, and the ranges
// must parse and be ordered.
func TestFlags(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"short": "AAAA", "text": "not base64!"} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o600)
		if _, err := readRelease(p); err == nil {
			t.Errorf("%s release key taken", name)
		}
	}
	if r, err := parseRanges("1920x1080,1280x720", 30, 500, 8000); err != nil || len(r.Resolutions) != 2 {
		t.Fatalf("ranges: %v", err)
	}
	for _, c := range []struct {
		res         string
		fps, lo, hi uint
	}{{"1920", 30, 500, 8000}, {"0x720", 30, 500, 8000}, {"1280x720", 0, 500, 8000}, {"1280x720", 30, 9000, 8000}, {"1280x720", 300, 500, 8000}} {
		if _, err := parseRanges(c.res, c.fps, c.lo, c.hi); err == nil {
			t.Errorf("ranges %+v taken", c)
		}
	}
}
