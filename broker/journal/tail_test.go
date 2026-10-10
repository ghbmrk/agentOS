package journal

// REQ: OP-4

import (
	"context"
	"testing"
)

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

// A caller that changes the intent in a returned record, in place, does not
// change what the engine dispatches: projections and Trail readers get deep
// copies (L3 on PR #722).
func TestReturnedRecordsDoNotAliasTheDispatchedIntent(t *testing.T) {
	for name, read := range map[string]func(*Engine) []Record{
		"RecordsAfter": func(e *Engine) []Record { return e.RecordsAfter(0) },
		"Trail":        (*Engine).Trail,
	} {
		t.Run(name, func(t *testing.T) {
			svc := newService()
			var seen Intent
			svc.onExecute = func(in Intent, _ int) { seen = in }
			e := mustOpen(t, &MemStore{}, newPolicy(), svc)
			in := intent("a", "mail")
			in.Params["meta"] = map[string]any{"tag": "kept"}
			in.Preconditions = []string{"pre-1"}
			in.Reservation = &Reservation{Amount: 5, Unit: "usd"}
			must(e.Submit(in))

			r := read(e)[0].Intent
			r.Params["subject"] = "X"
			r.Params["meta"].(map[string]any)["tag"] = "X"
			r.Recipients[0] = "mallory@example.test"
			r.Preconditions[0] = "X"
			r.Reservation.Amount = 999

			must(e.Authorize(context.Background(), "a"))
			must(e.Dispatch(context.Background(), "a"))
			if seen.Params["subject"] != "hello" || seen.Params["meta"].(map[string]any)["tag"] != "kept" ||
				seen.Recipients[0] != "alice@example.test" || seen.Preconditions[0] != "pre-1" ||
				seen.Reservation.Amount != 5 {
				t.Fatalf("executor saw a changed intent: %+v", seen)
			}
			if got := read(e)[0].Intent; got.Params["subject"] != "hello" || got.Recipients[0] != "alice@example.test" {
				t.Fatalf("journal record changed: %+v", got)
			}
		})
	}
}
