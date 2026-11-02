package plan

// REQ: PLN-5

import "testing"

// check reads a value as a map only under a map shape. A JSON shape reaches
// check's default case when send passes it nothing, and a shape that skipped
// valid can reach it from inside the package; neither is read as a map
// (#4678, #4660 Security M5).
func TestCheckReadsOnlyAMapAsAMap(t *testing.T) {
	each := &Value{Kind: KindBool}
	x := map[string]any{"a": true}
	if !(Value{Kind: KindMap, Max: 8, Each: each}).check(x) {
		t.Fatal("a map shape refused a map")
	}
	for _, kind := range []string{KindJSON, "undeclared"} {
		if (Value{Kind: kind, Max: 8, Each: each}).check(x) {
			t.Errorf("a %q shape read a map as a map", kind)
		}
	}
}
