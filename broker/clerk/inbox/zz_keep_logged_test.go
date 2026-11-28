package inbox

// REQ: VRB-2 (assumption MIG-4-mail-reader-5)

import (
	"encoding/hex"
	"testing"
)

// A full read that meets a mail the log already holds keeps that entry as
// it is: keep logs nothing over it and charges nothing. Driven on the state
// directly, so no server's folder order decides whether a full read meets a
// logged mail (mailbox.go keep's first return; TestAFullReadKeepsTheNewestReadMail
// reaches it only in some folder orders).
func TestAFullReadLeavesALoggedMailAsItIs(t *testing.T) {
	id := [16]byte{7}
	log := SeenLog{Since: "2026-10-01", Seen: []Seen{
		{From: "pat@example.test", ID: hex.EncodeToString(id[:]), Date: "2026-10-18"},
	}}
	o, err := newOpened("2026-10-19", log)
	if err != nil {
		t.Fatal(err)
	}
	was, ok := o.log[id]
	if !ok {
		t.Fatalf("newOpened did not log the recent entry: %+v", o.log)
	}
	o.full = true
	kept, fresh := o.kept, len(o.fresh)
	o.keep(id, "other@x.test", 5)
	if o.log[id] != was || o.kept != kept || len(o.fresh) != fresh {
		t.Fatalf("keep of a logged mail: entry %+v (was %+v), charged %d, fresh %d (was %d); want nothing",
			o.log[id], was, o.kept-kept, len(o.fresh), fresh)
	}
}
