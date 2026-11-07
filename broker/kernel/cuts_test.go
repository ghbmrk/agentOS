package kernel

import (
	"encoding/json"
	"testing"
)

// The predicates the D-310 cut on #5006 rewrote as one expression each:
// every operand decides on its own.
func TestCutPredicatesEachOperandDecides(t *testing.T) {
	e := Entry{Seq: 1, Type: "a", Body: json.RawMessage(`{}`)}
	seq, ws := e, e
	seq.Seq = 2
	ws.Body = json.RawMessage(`{ }`) // compacts to the same hash, different bytes
	if !Same([]Entry{e}, []Entry{e}) || Same([]Entry{e}, nil) || Same([]Entry{e}, []Entry{seq}) || Same([]Entry{e}, []Entry{ws}) {
		t.Error("Same: equal logs only")
	}
	cands := []derived{{typ: "a", body: []byte(`{}`)}}
	other := e
	other.Type = "b"
	if !matches(cands, e) || matches(cands, other) || matches(cands, ws) {
		t.Error("matches: type and body both")
	}
	for name, want := range map[string]bool{"usb.1": true, "usb_1-A": true, "usb/1": false, "usb 1": false} {
		if got := (BackupTarget{Name: name, Kind: KindDir, Locator: "/mnt/usb"}).shape(); got != want {
			t.Errorf("shape(%q) = %v", name, got)
		}
	}
}
