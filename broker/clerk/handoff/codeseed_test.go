package handoff

import (
	"bytes"
	"errors"
	"testing"
)

// REQ: CH-4, CLK-1, STO-2

// The code seed's store form reads back as written, and anything off its
// shape (no tag, no seed, an oversized seed, a negative step) is refused.
func TestCodeSeedRoundTrip(t *testing.T) {
	s := CodeSeed{Seed: bytes.Repeat([]byte{7}, 20), Step: 59000123}
	b, err := EncodeCodeSeed(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseCodeSeed(b)
	if err != nil || !bytes.Equal(got.Seed, s.Seed) || got.Step != s.Step {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	for name, v := range map[string]CodeSeed{
		"no seed":       {Step: 1},
		"too long":      {Seed: make([]byte, MaxCodeSeed+1)},
		"negative step": {Seed: []byte{1}, Step: -1},
	} {
		if _, err := EncodeCodeSeed(v); !errors.Is(err, ErrCodeSeed) {
			t.Errorf("%s: encoded", name)
		}
	}
	for name, v := range map[string][]byte{
		"no tag":   b[1:],
		"no seed":  b[:len(codeSeedTag)+8],
		"too long": append(bytes.Clone(b), make([]byte, MaxCodeSeed)...),
	} {
		if _, err := ParseCodeSeed(v); !errors.Is(err, ErrCodeSeed) {
			t.Errorf("%s: parsed", name)
		}
	}
}

// The sealed file opens only under the key it was sealed under, holds no
// run of the seed in the clear, and refuses any changed byte. Fails if the
// root-only file alone gives the seed to whoever reads it.
func TestSealedCodeSeedOpensOnlyUnderTheCheckersKey(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	other := bytes.Repeat([]byte{2}, 32)
	seed := []byte("canary-seed-0123456789")
	blob, err := SealCodeSeed(key, CodeSeed{Seed: seed, Step: 9})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, seed[:8]) {
		t.Fatal("the sealed file holds the seed in the clear")
	}
	got, err := OpenCodeSeed(key, blob)
	if err != nil || !bytes.Equal(got.Seed, seed) || got.Step != 9 {
		t.Fatalf("open: %+v %v", got, err)
	}
	if _, err := OpenCodeSeed(other, blob); !errors.Is(err, ErrCodeSeed) {
		t.Fatalf("another key opened it: %v", err)
	}
	for i := range blob {
		b := bytes.Clone(blob)
		b[i] ^= 1
		if _, err := OpenCodeSeed(key, b); err == nil {
			t.Fatalf("a change at byte %d opened", i)
		}
	}
	if _, err := OpenCodeSeed(key, blob[:len(blob)-1]); err == nil {
		t.Fatal("a cut file opened")
	}
}
