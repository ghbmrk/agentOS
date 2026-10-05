package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/route"
)

// REQ: ADP-4, CAP-9, LOOP-5

var (
	ra = route.Route{Provider: "openai", Model: "gpt-test"}
	rb = route.Route{Provider: "anthropic", Model: "claude-test"}
	rc = route.Route{Provider: "openai", Model: "gpt-dear"}
)

// W3 (potency PW4 on #90): agentosd reads and sets the active routing
// rule over the routing socket. Only a reordering of the owner's -rule is
// taken; it is saved, applied to the router and to the evaluation price
// ceiling, and survives a restart. Anything else is refused and changes
// nothing.
func TestRoutingAdoptionsOnlyReorderTheOwnersRoutes(t *testing.T) {
	base := route.Rule{"chat": {ra, rb}}
	rt, err := newRouter(base, map[string][]string{"agent": {"openai", "anthropic"}}, map[string]bool{"openai": true})
	if err != nil {
		t.Fatal(err)
	}
	ev := &evalRoute{From: "agent", Active: base}
	path := filepath.Join(t.TempDir(), "routing.json")
	ro := &routing{base: base, rt: rt, ev: ev, path: path}
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, &custody{notify: func(string) {}}, rt, ev, ro, os.Getuid(), os.Getuid()+1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, s := range srvs {
			s.Close()
		}
	}()
	cl := modelroute.NewRouting(filepath.Join(run, RoutingSocket))
	ctx := context.Background()

	st, err := cl.State(ctx)
	if err != nil || st.Rule["chat"][0] != ra || len(st.Candidate["chat"]) != 2 {
		t.Fatalf("state %+v %v", st, err)
	}
	for name, bad := range map[string]route.Rule{
		"adds a route":    {"chat": {ra, rb, rc}},
		"swaps a model":   {"chat": {rc, rb}},
		"drops a route":   {"chat": {rb}},
		"adds a class":    {"chat": {rb, ra}, "code": {ra}},
		"repeats a route": {"chat": {ra, ra}},
	} {
		if err := cl.Set(ctx, bad); !errors.Is(err, modelroute.ErrRoutingRefused) || !strings.Contains(err.Error(), "refused") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a refused rule was saved")
	}
	if rt.Rule()["chat"][0] != ra || ev.active()["chat"][0] != ra {
		t.Fatal("a refused rule was applied")
	}

	swapped := route.Rule{"chat": {rb, ra}}
	if err := cl.Set(ctx, swapped); err != nil {
		t.Fatal(err)
	}
	if rt.Rule()["chat"][0] != rb || ev.active()["chat"][0] != rb {
		t.Fatalf("router %v, ceiling %v", rt.Rule(), ev.active())
	}
	// A restart starts from the adopted rule, and from -rule when the
	// saved one no longer reorders it (the owner changed -rule).
	if r, err := startRule(base, path); err != nil || r["chat"][0] != rb {
		t.Fatalf("restart: %v %v", r, err)
	}
	if r, err := startRule(route.Rule{"chat": {ra, rc}}, path); err == nil || r["chat"][1] != rc {
		t.Fatalf("restart after -rule changed: %v %v", r, err)
	}
	if r, err := startRule(base, filepath.Join(t.TempDir(), "none.json")); err != nil || r["chat"][0] != ra {
		t.Fatalf("no adoption yet: %v %v", r, err)
	}
	// An empty rule is the owner's -rule: the change pipeline's record
	// before any routing adoption (security R1, potency PW6 on PW4).
	if err := cl.Set(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if rt.Rule()["chat"][0] != ra || ev.active()["chat"][0] != ra {
		t.Fatalf("reset: router %v, ceiling %v", rt.Rule(), ev.active())
	}
	if r, err := startRule(base, path); err != nil || r["chat"][0] != ra {
		t.Fatalf("restart after reset: %v %v", r, err)
	}
}
