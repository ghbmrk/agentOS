package handoff

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// The CH-4 code-generator seed's way from setup to the checker
// (MIG-4-exit-c2, D-226). Enrollment keeps the owner's confirmed seed in the
// store at CheckerSeedEntry, with the step its confirming code spent. At
// each boot the unlock step seals that value under the checker's sealer
// (clerkkey.Derive(root, "checker").Sealer()) and writes it to a file only
// root reads; the kernel hands the checker that key at each start of its
// unit, as it hands every clerk its key. So the kernel never holds the seed
// (CLK-1), and the file alone opens nothing.

// CheckerSeedEntry is the sealed store's entry holding the code seed, in
// EncodeCodeSeed's form. Only enrollment writes it (STO-2).
const CheckerSeedEntry = "checker/seed"

// CheckerName is the checker's name as a clerk: its key's derivation.
const CheckerName = "checker"

// MaxCodeSeed bounds the seed: a code generator's is 20 bytes.
const MaxCodeSeed = 64

const codeSeedTag = "agentos-checker-seed/v1\n"

// sealedSeedTag starts the sealed file the checker reads, and is its AEAD's
// associated data, so no other sealed value under the checker's key opens
// as a seed.
const sealedSeedTag = "agentos-checker-seed-sealed/v1\n"

// MaxSealedSeed bounds the sealed file.
const MaxSealedSeed = len(sealedSeedTag) + 12 + len(codeSeedTag) + 8 + MaxCodeSeed + 16

var ErrCodeSeed = errors.New("handoff: the code seed is damaged or missing")

// CodeSeed is the seed and the last step a code spent on it.
type CodeSeed struct {
	Seed []byte
	Step int64
}

// Wipe clears the seed.
func (s *CodeSeed) Wipe() { clear(s.Seed) }

// EncodeCodeSeed is CheckerSeedEntry's value: the tag, the step as a
// big-endian uint64, then the seed.
func EncodeCodeSeed(s CodeSeed) ([]byte, error) {
	if len(s.Seed) == 0 || len(s.Seed) > MaxCodeSeed || s.Step < 0 {
		return nil, ErrCodeSeed
	}
	b := append([]byte(codeSeedTag), make([]byte, 8)...)
	binary.BigEndian.PutUint64(b[len(codeSeedTag):], uint64(s.Step))
	return append(b, s.Seed...), nil
}

// ParseCodeSeed reads EncodeCodeSeed's form. The seed is a copy of b's.
func ParseCodeSeed(b []byte) (CodeSeed, error) {
	rest, ok := bytes.CutPrefix(b, []byte(codeSeedTag))
	if !ok || len(rest) <= 8 || len(rest) > 8+MaxCodeSeed {
		return CodeSeed{}, ErrCodeSeed
	}
	step := binary.BigEndian.Uint64(rest)
	if step > 1<<62 {
		return CodeSeed{}, ErrCodeSeed
	}
	return CodeSeed{Seed: bytes.Clone(rest[8:]), Step: int64(step)}, nil
}

func seedAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrCodeSeed
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// SealCodeSeed seals s under key, the checker's sealer: the tag, a random
// nonce, then AES-256-GCM over EncodeCodeSeed's form.
func SealCodeSeed(key []byte, s CodeSeed) ([]byte, error) {
	plain, err := EncodeCodeSeed(s)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	g, err := seedAEAD(key)
	if err != nil {
		return nil, err
	}
	out := append([]byte(sealedSeedTag), make([]byte, g.NonceSize())...)
	if _, err := rand.Read(out[len(sealedSeedTag):]); err != nil {
		return nil, err
	}
	return g.Seal(out, out[len(sealedSeedTag):], plain, []byte(sealedSeedTag)), nil
}

// OpenCodeSeed opens SealCodeSeed's form under key. Any other key, or a
// changed byte, opens nothing.
func OpenCodeSeed(key, blob []byte) (CodeSeed, error) {
	g, err := seedAEAD(key)
	if err != nil {
		return CodeSeed{}, err
	}
	rest, ok := bytes.CutPrefix(blob, []byte(sealedSeedTag))
	if !ok || len(blob) > MaxSealedSeed || len(rest) < g.NonceSize()+g.Overhead() {
		return CodeSeed{}, ErrCodeSeed
	}
	plain, err := g.Open(nil, rest[:g.NonceSize()], rest[g.NonceSize():], []byte(sealedSeedTag))
	if err != nil {
		return CodeSeed{}, ErrCodeSeed
	}
	defer clear(plain)
	return ParseCodeSeed(plain)
}
