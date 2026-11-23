package main

import (
	"context"
	"flag"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/route"
)

// REQ: LOOP-5, CAP-9

// The replay model route is gone (#2797): a replay machine's call on the
// model socket fails closed with 503 before any provider, and neither the
// rule header nor a granted agent machine gives it a route.
func TestReplayMachineHasNoModelRoute(t *testing.T) {
	var hits atomic.Int32
	sock := serveModel(t, testRouter(t), func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{"ok":true}`))
	})
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	for _, rule := range []string{"", "eyJndWVzdCI6MX0="} {
		req, _ := http.NewRequest("POST", "http://agentos-egress/v1/chat/completions", strings.NewReader(`{"model":"default","messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set(modelroute.HeaderMachine, modelroute.EvalPrefix+"0a1b")
		req.Header.Set(modelroute.HeaderLabel, "private")
		if rule != "" {
			req.Header.Set("Agentos-Rule", rule)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("rule %q: status %d, want 503", rule, resp.StatusCode)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("a replay machine's call reached the provider %d times", hits.Load())
	}
}

// No -grant gives a replay machine model access.
func TestReplayMachineTakesNoGrant(t *testing.T) {
	rule := route.Rule{"default": {{Provider: "openai", Model: "gpt-test"}}}
	if _, _, err := modelRouting(rule, grants{"agent": {"openai"}, modelroute.EvalPrefix + "x": {"openai"}}, nil, nil, nil, ""); err == nil {
		t.Fatal("-grant gave a replay machine model access")
	}
}

// Neither -eval-from nor -prices is a flag any more: a start script still
// passing them fails to start rather than silently granting nothing.
func TestReplayFlagsAreGone(t *testing.T) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	declareModelFlags(fs, "")
	for _, name := range []string{"eval-from", "prices"} {
		if fs.Lookup(name) != nil {
			t.Errorf("-%s is still declared", name)
		}
	}
}
