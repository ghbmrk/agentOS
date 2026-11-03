package kernel

// REQ: KRN-1, KRN-6

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"math/rand/v2"
	"testing"
)

var errNoForm = errors.New("no logged form")

type refusesDecode struct{ A string }

func (*refusesDecode) UnmarshalJSON([]byte) error { return errNoForm }

// asLogged says why a value has no logged form: JSON refused to write it or
// to read it back, each with its own error, never ErrNotText, which is kept
// for text the log rewrites; such text round-trips as U+FFFD with no error,
// for Append to refuse (#4760). Catches Submit and the owner calls reporting
// every encoding failure as text that is not UTF-8.
func TestAsLoggedReturnsTheEncodingsError(t *testing.T) {
	var uv *json.UnsupportedValueError
	if _, err := asLogged(math.NaN()); !errors.As(err, &uv) || errors.Is(err, ErrNotText) {
		t.Fatalf("a value JSON cannot write: %v", err)
	}
	if _, err := asLogged(refusesDecode{"a"}); !errors.Is(err, errNoForm) || errors.Is(err, ErrNotText) {
		t.Fatalf("a value JSON cannot read back: %v", err)
	}
	p, err := asLogged(Plan{ID: "p\xff"})
	if err != nil || p.ID != "p�" {
		t.Fatalf("text the log rewrites: %q, %v", p.ID, err)
	}
}

// Append refuses an entry whose JSON is not UTF-8, which only a body that
// writes its own bytes (a json.RawMessage) can make, and logs nothing: the
// guard's second branch (#4720, #4760). Catches a guard that checks only for
// the � escape.
func TestAppendRefusesBytesThatAreNotUTF8(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	l, err := Open(Config{Store: &MemStore{}, Anchor: &MemAnchor{}, Pub: priv.Public().(ed25519.PublicKey), Sign: priv,
		Rand: rand.NewChaCha8([32]byte{4})})
	if err != nil {
		t.Fatal(err)
	}
	n := len(l.Entries())
	if _, err := l.Append(1, TPlanCancel, schema[TPlanCancel], json.RawMessage("{\"plan\":\"p\xff\"}")); !errors.Is(err, ErrNotText) {
		t.Fatalf("raw bytes that are not UTF-8: %v", err)
	}
	if len(l.Entries()) != n {
		t.Fatal("a refused entry was logged")
	}
	if _, err := l.Append(1, TPlanCancel, schema[TPlanCancel], json.RawMessage("{\"plan\":\"p�\"}")); err != nil {
		t.Fatalf("raw valid text: %v", err)
	}
}
