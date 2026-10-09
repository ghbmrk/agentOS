package pubid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"
)

// REQ: OSS-6

// testSigners are the Signer kinds these tests register; detached adds an
// ed25519 signature and its key, as a real attestation signer would.
var testSigners = map[string]Signer{
	"prefix": signer,
	"detached": func(priv ed25519.PrivateKey, payload []byte) ([]byte, error) {
		out := append(append([]byte(nil), priv.Public().(ed25519.PublicKey)...), ed25519.Sign(priv, payload)...)
		return append(out, payload...), nil
	},
}

// OSS-6s-a3 Bound: the batch envelope and its signature are exactly
// BatchOverhead bytes, each item adds its signed bytes plus the item
// header, and every registered Signer kind stays within ItemOverhead.
func TestOSS6sA3OverheadBound(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	empty, err := SealBatch(priv, "2026-01-08", nil)
	must(t, err)
	if len(empty) != BatchOverhead {
		t.Fatalf("empty batch %d bytes, BatchOverhead %d", len(empty), BatchOverhead)
	}
	for kind, s := range testSigners {
		for _, n := range []int{1, 100, MaxPayload} {
			payload := bytes.Repeat([]byte{'x'}, n)
			b, err := s(priv, payload)
			must(t, err)
			if len(b)-n > SignerOverhead {
				t.Errorf("%s adds %d bytes, over SignerOverhead %d", kind, len(b)-n, SignerOverhead)
			}
			sealed, err := SealBatch(priv, "2026-01-08", [][]byte{b})
			must(t, err)
			if len(sealed) > BatchOverhead+n+ItemOverhead {
				t.Errorf("%s: %d-byte item takes %d bytes", kind, n, len(sealed)-BatchOverhead)
			}
		}
	}
	// One maximum-size item fits an empty batch, and m ≤ C.
	if BatchOverhead+ItemSlots(MaxPayload+SignerOverhead)*SlotSize > Slots*SlotSize {
		t.Fatal("a MaxPayload item does not fit an empty batch")
	}
	if MaxItemSlots != ItemSlots(MaxPayload+SignerOverhead) || MaxItemSlots > UsableSlots {
		t.Fatalf("m %d, slots of a MaxPayload item %d, C %d", MaxItemSlots, ItemSlots(MaxPayload+SignerOverhead), UsableSlots)
	}
	if UsableSlots != Slots-(BatchOverhead+SlotSize-1)/SlotSize {
		t.Fatalf("C %d", UsableSlots)
	}
}

// OSS-6s-a2: a batch, cover or not, is signed over its day, key, count and
// items, so it opens only intact; trailing padding is not part of it.
func TestOSS6sA2BatchOpensOnlyIntact(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	for _, items := range [][][]byte{nil, {[]byte("one"), []byte("two")}} {
		b, err := SealBatch(priv, "2026-01-08", items)
		must(t, err)
		got, err := OpenBatch(append(append([]byte(nil), b...), make([]byte, 99)...))
		must(t, err)
		if got.Day != "2026-01-08" || !got.Key.Equal(pub) || len(got.Items) != len(items) || got.Len != len(b) {
			t.Fatalf("opened %+v", got)
		}
		for i := range b {
			bad := append([]byte(nil), b...)
			bad[i] ^= 1
			if _, err := OpenBatch(bad); err == nil {
				t.Fatalf("byte %d flipped, still opens", i)
			}
		}
	}
	if _, err := SealBatch(priv, "8 Jan", nil); err == nil {
		t.Error("sealed a bad day")
	}
}

// OSS-6s-a3 Bound: an item over MaxPayload is refused at Queue; one at
// MaxPayload, signed with the most a Signer may add, leaves alone in an
// otherwise empty batch; a signer that adds more is refused at release.
func TestOSS6sA3MaxPayloadFitsAnEmptyBatch(t *testing.T) {
	g := newRig(t, 0)
	fat := func(priv ed25519.PrivateKey, payload []byte) ([]byte, error) {
		return append(make([]byte, SignerOverhead), payload...), nil
	}
	fatter := func(priv ed25519.PrivateKey, payload []byte) ([]byte, error) {
		return append(make([]byte, SignerOverhead+1), payload...), nil
	}
	p, err := NewPublisher(Config{Path: filepath.Join(g.dir, "o2.json"), Identity: g.id, Sender: g.out, Now: g.c.now,
		Signers: map[string]Signer{"fat": fat, "fatter": fatter}, Rand: g.rand, Mono: g.mono})
	must(t, err)
	g.warm(t, p)
	if err := p.Queue("fat", make([]byte, MaxPayload+1)); err == nil {
		t.Fatal("an item over MaxPayload was queued")
	}
	must(t, p.Queue("fat", make([]byte, MaxPayload)))
	must(t, p.Queue("fatter", []byte("x")))
	g.day(1, 12*time.Hour)
	if err := p.Release(); err == nil {
		t.Fatal("an item over the signer bound was not reported")
	}
	if len(g.out.got) != 1 || len(g.out.got[0].batch) != 1 || len(g.out.got[0].batch[0]) != MaxPayload+SignerOverhead || p.Len() != 0 {
		t.Fatalf("published %d batches, left %d", len(g.out.got), p.Len())
	}
	if len(g.out.all[len(g.out.all)-1].raw) > Slots*SlotSize {
		t.Fatal("batch over the frame")
	}
}

// OSS-6s-a2: the batch hash differs by day, so two cover days are two
// ledger keys.
func TestOSS6sA2CoverBatchesDifferByDay(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	a, _ := SealBatch(priv, "2026-01-08", nil)
	b, _ := SealBatch(priv, "2026-01-09", nil)
	if sha256.Sum256(a) == sha256.Sum256(b) {
		t.Fatal("two days' cover batches are the same bytes")
	}
}
