package main

import (
	"context"
	"testing"
)

// REQ: CAP-5

// G15: the guest socket lists the question tools, and each name goes to
// its own set. managed_tree is no longer served (MIG-4-untrusted-learn).
func TestToolSetServesEachSet(t *testing.T) {
	q := &questions{}
	set := toolSet{nil, q}
	names := map[string]bool{}
	for _, tl := range set.List() {
		names[tl["name"].(string)] = true
	}
	if names["managed_tree"] || !names["owner_question"] {
		t.Fatalf("listed %v", names)
	}
	if _, ok, _ := set.Call(context.Background(), "agent", "lin", "managed_tree", nil); ok {
		t.Fatal("managed_tree is still served")
	}
	if _, ok, err := set.Call(context.Background(), "agent", "lin", "owner_question", nil); !ok || err == nil {
		t.Fatalf("question tool with no book: %v %v", ok, err)
	}
	if _, ok, _ := set.Call(context.Background(), "agent", "lin", "effect_request", nil); ok {
		t.Fatal("handled a tool no set serves")
	}
}
