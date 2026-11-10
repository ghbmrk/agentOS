package header_test

// REQ: CLK-3, CLK-7

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/header"
	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// The old core's egress uses this package's list and value check (#5278),
// so the corpora run through it here, outside the old core it must not
// grow: a plan route takes only header.PassHeaders, byte for byte, on its
// request, sign-in and response lists, and only header.PassPrefixes; a key
// check's declared value refuses the value corpus and says why. Catches the
// old denylist, which took X-Original-Url, X-Api-Key and Forwarded.
func TestEgressRefusesTheCorpus(t *testing.T) {
	takes := func(edit func(*egress.PlanRoute)) error {
		r := egress.Codex()
		edit(&r)
		// A route that validates fails next on the empty config.
		if _, err := egress.NewWorkerRoute(egress.WorkerRouteConfig{Route: r}); strings.HasPrefix(err.Error(), "plan route ") {
			return err
		}
		return nil
	}
	for name, set := range map[string]func(r *egress.PlanRoute, h string){
		"request":  func(r *egress.PlanRoute, h string) { r.RequestHeaders = []string{h} },
		"sign-in":  func(r *egress.PlanRoute, h string) { r.SignInHeaders = []string{h} },
		"response": func(r *egress.PlanRoute, h string) { r.ResponseHeaders = []string{h} },
	} {
		t.Run(name, func(t *testing.T) {
			hostiletext.RunHeaders(t, func(h string) bool {
				return takes(func(r *egress.PlanRoute) { set(r, h) }) == nil
			}, header.PassHeaders...)
		})
	}
	if err := takes(func(r *egress.PlanRoute) { r.RequestHeaders = []string{"X-Original-Url"} }); err == nil || err.Error() != `plan route codex: may not forward header "X-Original-Url"` {
		t.Errorf("X-Original-Url: got %v", err)
	}
	if err := takes(func(r *egress.PlanRoute) { r.ResponsePrefixes = []string{"X-Codex-"} }); err != nil {
		t.Errorf(`the prefix "X-Codex-" was refused: %v`, err)
	}
	for _, pre := range []string{"X-", "x-codex-", "X-Codex", "Set-", "Proxy-Auth", ""} {
		if err := takes(func(r *egress.PlanRoute) { r.ResponsePrefixes = []string{pre} }); err == nil || err.Error() != `plan route codex: response prefix "`+pre+`"` {
			t.Errorf("the prefix %q: got %v", pre, err)
		}
	}
	declare := func(v string) error {
		a := egress.Anthropic("anthropic")
		a.KeyCheck.Headers = map[string]string{"Anthropic-Version": v}
		return a.Validate()
	}
	hostiletext.RunHeaderValues(t, func(v string) bool { return declare(v) == nil })
	for _, v := range []string{"", " v", "v ", "v\t"} {
		if err := declare(v); err == nil || err.Error() != "adapter anthropic: key check header Anthropic-Version: "+header.Value(v).Error() {
			t.Errorf("the key check value %q: got %v", v, err)
		}
	}
}
