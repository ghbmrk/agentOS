package plan

// REQ: PLN-5

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

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

// readAs reads an event-stream answer through the meter in reads of the
// given sizes, then to its end, and returns how the call settled.
func readAs(t *testing.T, body string, sizes ...int) Used {
	t.Helper()
	var got []Used
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}},
		Body: io.NopCloser(strings.NewReader(body))}
	m := newMeterReader(resp, func(u Used) { got = append(got, u) }, nil)
	for _, n := range sizes {
		if k, err := io.ReadFull(m, make([]byte, n)); err != nil {
			t.Fatalf("read %d of %d: %v", k, n, err)
		}
	}
	if _, err := io.Copy(io.Discard, m); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("settled %d times", len(got))
	}
	return got[0]
}

// The meter reads a stream line by line: an event is its own line and no
// more, a line that is not an event is no usage, and a line past maxEvent
// is passed on unread, however it arrives (LOG-7).
func TestMeterReadsEachEventOnItsOwn(t *testing.T) {
	const done = `{"type":"response.completed","response":{"usage":{"input_tokens":3,"output_tokens":4}}}`
	if u := readAs(t, "data: "+done+"\n\ndata: [DONE]\n\n"); !u.Reported || u.In != 3 || u.Out != 4 || !u.Done {
		t.Fatalf("an event with more lines behind it in the same read: %+v", u)
	}
	if u := readAs(t, done+"\n\n"); u.Reported {
		t.Fatalf("a line with no data: field reported %+v", u)
	}
	head := `data: {"type":"response.completed","pad":"`
	tail := `","response":{"usage":{"input_tokens":3,"output_tokens":4}}}` + "\n\n"
	if u := readAs(t, head+strings.Repeat("x", maxEvent)+tail, len(head), maxEvent); u.Reported || !u.Done {
		t.Fatalf("an event past maxEvent was read: %+v", u)
	}
}
