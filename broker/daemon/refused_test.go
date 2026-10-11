package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// LOOP-7 bullet 2 (P3-4b-3): a frame a guest socket refuses is journaled
// under the machine, coalesced as egress denials are, so a probe's
// malformed and unknown frames leave an audit trail a looping guest
// cannot flood; the socket still answers after them.
// REQ: LOOP-7
func TestGuestSocketRefusalsAreJournaled(t *testing.T) {
	dir, err := os.MkdirTemp("", "bk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	cancel, d := start(t, dir)
	defer func() { cancel(); d.Wait() }()
	g := filepath.Join(dir, "run", GuestSocket("m1"))
	for i := 0; i < 3; i++ {
		if r := send(t, g, "nope", nil); r.Error != string(sockets.ErrUnknownOp) {
			t.Fatalf("unknown op: %+v", r)
		}
	}
	if r := send(t, g, "whoami", nil); !r.OK {
		t.Fatalf("whoami after refusals: %+v", r)
	}
	var notes []journal.EgressNote
	for _, rec := range d.Engine().Trail() {
		if rec.Type == journal.RecEgress && rec.Egress.Adapter == sockets.RefusalNote {
			notes = append(notes, *rec.Egress)
		}
	}
	if len(notes) != 1 || notes[0].Machine != "m1" || notes[0].Operation != "unknown-op" {
		t.Fatalf("journaled %+v, want one coalesced unknown-op note for m1", notes)
	}
}
