package plan

// REQ: PLN-5

import "testing"

// check reads a value as a map only under a map shape. send never brings a
// JSON shape to check's default case: given nothing it returns before the
// switch, and given a JSON text it checks the text's Each shape. Only a
// direct call from inside the package reaches the default case with a JSON
// shape or one that skipped valid, and neither is read as a map (#4678,
// #4660 Security M5).
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

// A drop shape is valid only as an object's field and only bare: at the
// top, as a map entry or a JSON text's value it would have nothing to
// delete from, and a cap or list on it would claim a check it never makes
// (#4632).
func TestDropIsOnlyABareField(t *testing.T) {
	drop := Value{Kind: KindDrop}
	if !(Value{Kind: KindObject, Fields: map[string]Value{"w": drop}}).valid(0) {
		t.Fatal("an object refused a bare drop field")
	}
	for name, v := range map[string]Value{
		"top":        drop,
		"map entry":  {Kind: KindMap, Max: 8, Each: &drop},
		"JSON value": {Kind: KindJSON, Max: 8, Each: &drop},
		"capped":     {Kind: KindObject, Fields: map[string]Value{"w": {Kind: KindDrop, Max: 8}}},
		"listed":     {Kind: KindObject, Fields: map[string]Value{"w": {Kind: KindDrop, Only: []string{"a"}}}},
		"nullable":   {Kind: KindObject, Fields: map[string]Value{"w": {Kind: KindDrop, Null: true}}},
		"shaped":     {Kind: KindObject, Fields: map[string]Value{"w": {Kind: KindDrop, Each: &drop}}},
	} {
		if v.valid(0) {
			t.Errorf("%s: a drop shape was valid", name)
		}
	}
}
