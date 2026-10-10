package journal

// REQ: OP-4

import "testing"

// The tail a projection replays after its snapshot is exactly the records
// after the snapshot's sequence number, and it survives a restart.
func TestRecordsAfterIsTheTailAfterASequenceNumber(t *testing.T) {
	st := &MemStore{}
	e := mustOpen(t, st, newPolicy(), newService())
	for _, id := range []string{"a", "b", "c"} {
		must(e.Submit(intent(id, "mail")))
	}
	all := e.Trail()
	if len(all) != 3 {
		t.Fatalf("trail has %d records, want 3", len(all))
	}
	for seq := uint64(0); seq <= 4; seq++ {
		got := e.RecordsAfter(seq)
		want := 3 - int(min(seq, 3))
		if len(got) != want {
			t.Fatalf("RecordsAfter(%d) has %d records, want %d", seq, len(got), want)
		}
		for i, r := range got {
			if r.Seq != seq+uint64(i)+1 {
				t.Fatalf("RecordsAfter(%d)[%d].Seq = %d", seq, i, r.Seq)
			}
		}
	}
	// The caller's copy is its own.
	got := e.RecordsAfter(0)
	got[0].ID = "changed"
	if e.RecordsAfter(0)[0].ID != "a" {
		t.Fatal("RecordsAfter shares the engine's records")
	}
	e2 := mustOpen(t, st, newPolicy(), newService())
	if r := e2.RecordsAfter(2); len(r) != 1 || r[0].ID != "c" {
		t.Fatalf("after restart RecordsAfter(2) = %+v", r)
	}
}
