package route

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ghbmrk/agentos/broker/meter"
)

// REQ: LOG-7

// TestAttemptWireUnchanged: route.Attempt replaced meter.Attempt on the
// egress usage trailer (MIG-4-spend-m, #2585) with the same fields and
// JSON tags, so a trailer written by either side reads the same on the
// other. Go ignores tags in a conversion, so they are compared here.
func TestAttemptWireUnchanged(t *testing.T) {
	r, m := reflect.TypeFor[Attempt](), reflect.TypeFor[meter.Attempt]()
	if r.NumField() != m.NumField() {
		t.Fatalf("route.Attempt has %d fields, meter.Attempt %d", r.NumField(), m.NumField())
	}
	for i := range r.NumField() {
		rf, mf := r.Field(i), m.Field(i)
		if rf.Name != mf.Name || rf.Type != mf.Type || rf.Tag != mf.Tag {
			t.Errorf("field %d: route %s %s %q, meter %s %s %q", i, rf.Name, rf.Type, rf.Tag, mf.Name, mf.Type, mf.Tag)
		}
	}
	a := Attempt{Provider: "anthropic", Status: 529, Full: true, Reported: true, Input: 1, Output: 2, CacheRead: 3, CacheWrite: 4, OutputChars: 5}
	rb, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	mb, err := json.Marshal(meter.Attempt(a))
	if err != nil {
		t.Fatal(err)
	}
	if string(rb) != string(mb) {
		t.Fatalf("wire form changed:\nroute %s\nmeter %s", rb, mb)
	}
	var back Attempt
	if err := json.Unmarshal(mb, &back); err != nil || back != a {
		t.Fatalf("meter trailer read back as %+v (%v), want %+v", back, err, a)
	}
}
