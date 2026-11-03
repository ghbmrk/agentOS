package policy

import "testing"

// REQ: NET-2

// TestNormalCopiesTheCaps (#4561 L3 release item): normal copies the byte
// caps, never shares them, so a caller that changes the caps of a
// document it was handed (Engine.Current) changes neither the policy in
// force nor the document it came from. Mutant: normal keeping d.Caps.
func TestNormalCopiesTheCaps(t *testing.T) {
	d := Document{Version: 1, Destinations: []string{"a.example"}, Caps: map[string]uint64{"a.example": 5}}
	n := d.normal()
	n.Caps["a.example"] = 9
	if d.Caps["a.example"] != 5 {
		t.Fatalf("normal shares the caps map: the original now holds %d", d.Caps["a.example"])
	}
}
