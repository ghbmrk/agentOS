package main

import (
	"testing"
)

// The image's default routing rule (#1249 P-3) loads as serve loads it and
// routes the guest's model class, broker-default, to both providers.
// REQ: ARC-6, CAP-9
func TestTheImageRuleLoads(t *testing.T) {
	rule, err := readRule("../../../image/mkosi/mkosi.extra/usr/lib/agentos/egress/rule.json")
	if err != nil {
		t.Fatal(err)
	}
	routes, ok := rule["broker-default"]
	if !ok || len(rule) != 1 {
		t.Fatalf("rule classes %v, want only broker-default", rule)
	}
	got := map[string]bool{}
	for _, r := range routes {
		got[r.Provider] = true
	}
	for _, p := range modelProviders() {
		if !got[p.Name()] {
			t.Errorf("no route to %s", p.Name())
		}
	}
	if _, _, err := modelRouting(rule, grants{"agent": {"anthropic", "openai"}}, nil, nil, "", ""); err != nil {
		t.Fatal(err)
	}
}
