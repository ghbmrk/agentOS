package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/durable"
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

// L3 M1 and S2 on #96: only a rule that is not a reordering is refused
// (409, which the broker reads as permanent). A failed save is the vault
// process's own error (500): it applies nothing and is not a refusal, so
// the broker retries it rather than giving up on the rule. A body over
// 16 KiB is 413. GET also names the owner's rule, which the broker checks
// the router against (L3 S1).
func TestRoutingErrorsAreNotRefusals(t *testing.T) {
	base := route.Rule{"chat": {ra, rb}}
	rt, err := newRouter(base, map[string][]string{"agent": {"openai", "anthropic"}}, map[string]bool{"openai": true})
	if err != nil {
		t.Fatal(err)
	}
	ev := &evalRoute{From: "agent", Active: base}
	ro := &routing{base: base, rt: rt, ev: ev, path: filepath.Join(t.TempDir(), "gone", "routing.json")}
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
	if st, err := cl.State(ctx); err != nil || st.Owner["chat"][0] != ra {
		t.Fatalf("state %+v %v", st, err)
	}
	err = cl.Set(ctx, route.Rule{"chat": {rb, ra}})
	if err == nil || errors.Is(err, modelroute.ErrRoutingRefused) {
		t.Fatalf("a failed save: %v", err)
	}
	if rt.Rule()["chat"][0] != ra || ev.active()["chat"][0] != ra {
		t.Fatal("a rule that was not saved was applied")
	}
	big := route.Rule{"chat": {ra, rb}}
	for i := 0; len(big) < 600; i++ {
		big[fmt.Sprintf("class-%03d", i)] = []route.Route{ra, rb}
	}
	req, _ := json.Marshal(big)
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(run, RoutingSocket))
	}}}
	put, _ := http.NewRequest(http.MethodPut, "http://x"+modelroute.RoutingPath, bytes.NewReader(req))
	resp, err := c.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(req) <= modelroute.MaxRule || resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("a %d-byte rule: %d", len(req), resp.StatusCode)
	}
}

// L3 MUST-1 on #96: an owner's -rule with a repeated route is refused
// even when a saved adoption exists, so no reordering check is fooled
// into taking a route the owner never configured, and the router refuses
// to start on it.
func TestARepeatInTheOwnersRuleIsNeverABase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routing.json")
	if err := durable.WriteFile(path, []byte(`{"chat":[{"provider":"anthropic","model":"claude-test"},{"provider":"openai","model":"gpt-test"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := route.Rule{"chat": {ra, ra}}
	if r, err := startRule(bad, path); err == nil || r["chat"][1] != ra {
		t.Fatalf("a repeated -rule with a saved adoption: %v %v", r, err)
	}
	if _, err := newRouter(bad, map[string][]string{"agent": {"openai", "anthropic"}}, nil); err == nil {
		t.Fatal("the router started on a repeated -rule")
	}
	if err := reorders(bad, route.Rule{"chat": {ra, rc}}); err == nil {
		t.Fatal("a route the owner never configured passed as a reordering")
	}
	if err := reorders(route.Rule{"chat": {}}, route.Rule{"chat": {}}); err == nil {
		t.Fatal("an empty class passed as a base")
	}
}
