package journal

import (
	"errors"
	"testing"
)

// REQ: CH-12, CH12-mms-c

// A picture texted to the box is journaled as a fixed record naming only
// whether the owner sent it: kept across a restart, changing no intent,
// and written while STOP holds dispatch.
func TestPictureNote(t *testing.T) {
	st := &MemStore{}
	e := mustOpen(t, st, newPolicy(), newService())
	must(e.Submit(intent("a", "acct")))
	if _, err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	notes := []PictureNote{{From: PictureOwner}, {From: PictureOther}}
	for _, n := range notes {
		if err := e.RecordPicture(n); err != nil {
			t.Fatalf("record %+v: %v", n, err)
		}
	}
	for _, bad := range []PictureNote{{}, {From: "+15550000777"}} {
		if err := e.RecordPicture(bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v, want ErrInvalid", bad, err)
		}
	}
	e2 := mustOpen(t, st, newPolicy(), newService())
	var got []PictureNote
	for _, r := range e2.Trail() {
		if r.Type == RecPicture {
			got = append(got, *r.Picture)
		}
	}
	if len(got) != 2 || got[0] != notes[0] || got[1] != notes[1] {
		t.Fatalf("after a restart: %+v", got)
	}
	if s, err := e2.Get("a"); err != nil || s.State != Pending {
		t.Fatalf("an intent changed: %+v %v", s, err)
	}
}
