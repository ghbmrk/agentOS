package words

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// REQ: STO-2, REC-4

func TestWordlistIsEFFLarge(t *testing.T) {
	// SHA-256 of eff_large_wordlist.txt as EFF publishes it.
	sum := sha256.Sum256(effLarge)
	if got := hex.EncodeToString(sum[:]); got != "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e" {
		t.Fatalf("wordlist hash %s", got)
	}
	if len(list) != Count || Word(0) != "abacus" || Word(Count-1) != "zoom" {
		t.Fatalf("wordlist parse: %d words", len(list))
	}
	if i, ok := Index("zoom"); !ok || i != Count-1 {
		t.Fatalf("Index(zoom) = %d, %v", i, ok)
	}
	if _, ok := Index("notaword"); ok {
		t.Fatal("a word off the list has an index")
	}
}

// The lost-card passphrase (MIG-4-recovery-r4d): seven listed words in the
// slot's form, the same for the same seed, unrelated for another seed,
// and none for bytes that are not a seed.
// Catches a draw that differs between the unlock step and the page, or
// one that maps two cards to one passphrase.
func TestFromSeed(t *testing.T) {
	seed := bytes.Repeat([]byte{0x5a}, seedLen)
	a, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	ws := strings.Split(string(a), " ")
	if len(ws) != PerPassphrase {
		t.Fatalf("%d words", len(ws))
	}
	for _, w := range ws {
		if _, ok := Index(w); !ok {
			t.Fatalf("word %q is not on the list", w)
		}
	}
	if b, _ := FromSeed(bytes.Clone(seed)); !bytes.Equal(a, b) {
		t.Fatal("the same seed gave two passphrases")
	}
	// A fixed vector, so a change to the draw cannot pass both sides.
	if got := string(a); got != vector {
		t.Fatalf("passphrase for the 0x5a seed = %q", got)
	}
	other := bytes.Clone(seed)
	other[seedLen-1] ^= 1
	if c, _ := FromSeed(other); bytes.Equal(a, c) {
		t.Fatal("two seeds gave one passphrase")
	}
	for _, n := range []int{0, seedLen - 1, seedLen + 1, 32} {
		if _, err := FromSeed(make([]byte, n)); err != ErrSeed {
			t.Fatalf("%d bytes: %v", n, err)
		}
	}
}

// vector is FromSeed of sixteen 0x5a bytes, computed apart from this code
// (RFC 5869 HKDF-SHA256 in Python's hmac, the same draw).
const vector = "pried unmoved vending cabdriver stopwatch equivocal ankle"

// The draw itself, on streams made to hit its edges: a value of exactly
// 8*Count is skipped and the one below it is kept; a stream that runs out,
// even mid-pair, gives no phrase; the phrase is built in one allocation
// sized for the longest seven words, so no partial copy is left behind.
// Catches a boundary off by one (a biased word, or a read past the stream)
// and an undersized buffer that reallocates and leaves a copy.
func TestPhraseDraw(t *testing.T) {
	pair := func(v int) []byte { return []byte{byte(v >> 8), byte(v)} }
	var s []byte
	s = append(s, pair(8*Count)...)   // skipped
	s = append(s, pair(8*Count-1)...) // kept: word Count-1
	for i := range PerPassphrase - 1 {
		s = append(s, pair(i)...)
	}
	out, ok := phrase(s)
	ws := strings.Split(string(out), " ")
	if !ok || len(ws) != PerPassphrase || ws[0] != Word(Count-1) || ws[1] != Word(0) || ws[PerPassphrase-1] != Word(PerPassphrase-2) {
		t.Fatalf("phrase = %q, %v", out, ok)
	}
	if longest != 9 || cap(out) != PerPassphrase*(longest+1) {
		t.Fatalf("longest word %d, buffer %d", longest, cap(out))
	}
	// Every value rejected, with an odd byte left over: no phrase.
	if out, ok := phrase(bytes.Repeat([]byte{0xff}, 15)); ok || out != nil {
		t.Fatalf("a rejected stream gave %q", out)
	}
	// Six words and half a pair: no phrase.
	if out, ok := phrase(append(s[2:2+2*(PerPassphrase-1)], 0)); ok || out != nil {
		t.Fatalf("a short stream gave %q", out)
	}
}
