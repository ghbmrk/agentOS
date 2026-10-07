package changesource

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestqueue"
)

func receiptFixture(t testing.TB) (*change.Pipeline, *Source, *digestqueue.Snapshot) {
	t.Helper()
	p, err := change.New(change.Config{Store: &change.MemStore{}, Evaluator: noEvaluation{}, Rand: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Notice("original", "Original fixed notice."); err != nil {
		t.Fatal(err)
	}
	s, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	original, err := s.Peek(context.Background())
	if err != nil || original == nil {
		t.Fatal(original, err)
	}
	if err = p.Notice("later", "Later fixed notice."); err != nil {
		t.Fatal(err)
	}
	return p, s, original
}

// REQ: OP-1, OP-2
// Rehashing the outer queue snapshot must not turn arbitrary receipt bytes
// into source authority. Even accepted equivalent encodings may consume only
// the original generation; a later persisted notice must always survive.
func FuzzReceiptAckPreservesSourceAssociations(f *testing.F) {
	_, _, original := receiptFixture(f)
	f.Add(original.Receipt)
	f.Add("")
	f.Add("null")
	f.Add("{}")
	f.Add(original.Receipt + " {}")
	f.Add("{\"generation\":18446744073709551615,\"hash\":\"synthetic\"}")
	var decoded change.DigestSnapshot
	if err := json.Unmarshal([]byte(original.Receipt), &decoded); err != nil {
		f.Fatal(err)
	}
	decoded.Lines = []string{"Forged fixed notice."}
	forged, err := json.Marshal(decoded)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(forged))
	f.Fuzz(func(t *testing.T, receipt string) {
		if len(receipt) > 128<<10 {
			t.Skip("outside admitted receipt size bound")
		}
		p, source, original := receiptFixture(t)
		snap, err := digestqueue.NewSnapshotWithReceipt(ID, original.Generation, original.Lines, original.References, receipt)
		if err != nil {
			pending, peekErr := p.PeekDigest()
			if peekErr != nil || pending == nil || pending.Hash == "" || pending.Lines[0] != "Original fixed notice." {
				t.Fatal("constructor refusal changed source", pending, peekErr)
			}
			return
		}
		ackErr := source.Ack(context.Background(), snap)
		pending, peekErr := p.PeekDigest()
		if peekErr != nil || pending == nil {
			t.Fatal("source missing after acknowledgment", pending, peekErr)
		}
		if ackErr != nil {
			// Original queue hash binds receipt bytes, while pipeline Hash binds
			// its own typed source receipt. Compare the actual pending lines/gen.
			if pending.Generation != 1 || len(pending.Lines) != 1 || pending.Lines[0] != "Original fixed notice." {
				t.Fatal("rejected receipt consumed source", pending, ackErr)
			}
			if err = source.Ack(context.Background(), *original); err != nil {
				t.Fatal("rejected mutation damaged authentic receipt", err)
			}
			pending, peekErr = p.PeekDigest()
		} else {
			// Equivalent accepted JSON must not repeat consumption of newer data.
			if err = source.Ack(context.Background(), snap); err != nil {
				t.Fatal("accepted receipt not idempotent", err)
			}
		}
		if peekErr != nil || pending == nil || pending.Generation != 2 || len(pending.Lines) != 1 || pending.Lines[0] != "Later fixed notice." {
			t.Fatal("later persisted event lost or mixed", pending, peekErr)
		}
		if err = source.Ack(context.Background(), *original); err != nil {
			t.Fatal("authentic old receipt not idempotent", err)
		}
		again, err := p.PeekDigest()
		if err != nil || again == nil || again.Hash != pending.Hash {
			t.Fatal("old receipt consumed later generation", again, err)
		}
	})
}
