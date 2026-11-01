// Package words is the Owner Card's passphrase wordlist, EFF's large list,
// and the passphrase of a card the box makes on the lost-card route
// (D-201 route B, MIG-4-recovery-r4d). That passphrase derives from a
// random seed the made card carries beside its recovery key's bits, never
// from those bits, so a recovery key the owner later replaces derives
// nothing that still opens the store. The unlock step, which puts the
// passphrase in the store's passphrase slot, and the owner's page, which
// prints it, derive it alike from the seed the kernel holds.
package words

import (
	"crypto/hkdf"
	"crypto/sha256"
	_ "embed"
	"errors"
	"strings"
)

// effLarge is EFF's large wordlist (7,776 words, five dice per word),
// byte-identical to eff_large_wordlist.txt as EFF publishes it; a test pins
// its SHA-256. Licensed CC BY 3.0 US by the Electronic Frontier Foundation:
// https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases
//
//go:embed eff_large_wordlist.txt
var effLarge []byte

const (
	// Count is the list's length.
	Count = 7776
	// PerPassphrase is a card passphrase's length in words: 90 bits, above
	// STO-2's 80.
	PerPassphrase = 7
	// seedLen is a made card's passphrase seed (handoff.PassSeedLen).
	seedLen = 16
)

var (
	list    []string
	index   = map[string]int{}
	longest int
)

func init() {
	for _, line := range strings.Split(strings.TrimSpace(string(effLarge)), "\n") {
		if _, w, ok := strings.Cut(line, "\t"); ok {
			index[w] = len(list)
			list = append(list, w)
			longest = max(longest, len(w))
		}
	}
}

// Word is the list's word i, for 0 <= i < Count.
func Word(i int) string { return list[i] }

// Index is w's place in the list, if it is on it.
func Index(w string) (int, bool) {
	i, ok := index[w]
	return i, ok
}

// ErrSeed: the bytes are not a passphrase seed.
var ErrSeed = errors.New("words: not a passphrase seed")

// FromSeed is the passphrase of the card the box made with passphrase seed
// seed: PerPassphrase words, lower case, one space apart (the form the
// passphrase slot takes), drawn without bias from HKDF-SHA256 of the seed,
// two bytes a word, a value at or past 8*Count skipped. The caller owns and
// clears the result.
func FromSeed(seed []byte) ([]byte, error) {
	if len(seed) != seedLen {
		return nil, ErrSeed
	}
	// 32 draws: fewer than seven of them below 8*Count has odds under 2^-90.
	s, err := hkdf.Key(sha256.New, seed, nil, "agentos.card.lost-passphrase.v1", 64)
	defer clear(s)
	if err != nil {
		return nil, err
	}
	out, ok := phrase(s)
	if !ok {
		return nil, ErrSeed
	}
	return out, nil
}

// phrase draws PerPassphrase words from s, two bytes a word, skipping a
// value at or past 8*Count; ok is false if s runs out first.
func phrase(s []byte) (out []byte, ok bool) {
	// Sized for the longest phrase, so no partial copy is left behind.
	out = make([]byte, 0, PerPassphrase*(longest+1))
	n := 0
	for i := 0; i+1 < len(s) && n < PerPassphrase; i += 2 {
		v := int(s[i])<<8 | int(s[i+1])
		if v >= 8*Count {
			continue
		}
		if n > 0 {
			out = append(out, ' ')
		}
		out = append(out, list[v%Count]...)
		n++
	}
	if n < PerPassphrase {
		clear(out)
		return nil, false
	}
	return out, true
}
