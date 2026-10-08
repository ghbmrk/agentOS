package route

import (
	"strings"
	"testing"
	"time"
)

// REQ: CRED-5, CAP-9
//
// CRED-5's fallback when no API key is granted: the provider's broker-held
// plan route is withdrawn by a release while the owner's grant stands, and
// the owner granted no API key route for that provider. The call goes to
// another granted route, the withdrawn route is never contacted, and the
// owner is told, at most once per provider a day. Plan routes are not yet
// a provider kind (R1), so the class's first route stands in for one.
func TestWithdrawnPlanRouteWithoutAPIKeyGoesToAnotherGrantedRoute(t *testing.T) {
	r := newRig(t, rigOpts{rule: Rule{"default": {{Provider: "anthropic", Model: "claude-plan-fixture"}, {Provider: "openai", Model: "gpt-fixture"}}}})
	var told []string
	r.router.cfg.Withdrawn = func(p string) bool { return p == "anthropic" }
	r.router.cfg.RouteWithdrawn = func(p string) { told = append(told, p) }
	r.up.set(hostAnthropic, serveFixture(200, "application/json", fixture(t, "anthropic_message.json")))
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))

	for i := 0; i < 2; i++ {
		w := r.do(t, "m1", simpleChat)
		if w.Code != 200 || completionText(t, w) != "Hello from the fixture." {
			t.Fatalf("call %d: %d %s", i, w.Code, w.Body)
		}
	}
	if n := r.up.count(hostAnthropic); n != 0 {
		t.Fatalf("withdrawn route contacted %d times", n)
	}
	if d := r.decisions[len(r.decisions)-1]; d.Outcome != Served || d.Route != "openai/gpt-fixture" {
		t.Fatalf("decision %+v", d)
	}
	if len(told) != 1 || told[0] != "anthropic" {
		t.Fatalf("owner told %v, want once for anthropic", told)
	}
	r.advance(24 * time.Hour)
	if w := r.do(t, "m1", simpleChat); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if len(told) != 2 {
		t.Fatalf("owner told %v, want a second notice after a day", told)
	}
}

// REQ: CRED-5, CAP-9
//
// With no other granted route, the call is declined with the reason, never
// sent to the withdrawn route, and the owner is still told.
func TestWithdrawnPlanRouteWithNoOtherRouteIsDeclinedAndTold(t *testing.T) {
	r := newRig(t, rigOpts{
		rule:   Rule{"default": {{Provider: "anthropic", Model: "claude-plan-fixture"}, {Provider: "openai", Model: "gpt-fixture"}}},
		grants: map[string][]string{"m1": {"anthropic"}},
	})
	var told []string
	r.router.cfg.Withdrawn = func(p string) bool { return p == "anthropic" }
	r.router.cfg.RouteWithdrawn = func(p string) { told = append(told, p) }
	r.up.set(hostAnthropic, serveFixture(200, "application/json", fixture(t, "anthropic_message.json")))

	w := r.do(t, "m1", simpleChat)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "no_route") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if n := r.up.count(hostAnthropic) + r.up.count(hostOpenAI); n != 0 {
		t.Fatalf("%d calls sent", n)
	}
	if len(told) != 1 || told[0] != "anthropic" {
		t.Fatalf("owner told %v", told)
	}
}
