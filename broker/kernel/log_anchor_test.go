package kernel_test

// REQ: KRN-7

import (
	"math/rand/v2"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// A widening entry that the anchor covers is kept at reopen, and one past
// the anchor is dropped (KRN-7). Catches a restart that drops an
// owner-confirmed widening, or keeps an unconfirmed one.
func TestOpenKeepsAnchoredWidening(t *testing.T) {
	head := gen(3)
	cfg := kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: head.pub, Sign: head.priv, Key: logKey,
		Rand: rand.NewChaCha8([32]byte{4})}
	l, err := kernel.Open(cfg)
	must(t, err)
	for i, anchor := range []bool{true, true, false} {
		_, err := l.Append(int64(i), kernel.TResume, 1, struct{}{})
		must(t, err)
		if anchor {
			must(t, l.Anchor())
		}
	}
	for range 2 { // the cut tail stays cut
		l, err = kernel.Open(cfg)
		must(t, err)
		if l.Len() != 2 {
			t.Fatalf("reopen kept %d entries, want the 2 anchored", l.Len())
		}
	}
}
