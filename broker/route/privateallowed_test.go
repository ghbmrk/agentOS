package route

import (
	"sync/atomic"
	"testing"
)

// REQ: CAP-9

// P2-2w c4e: the owner's private-data answer given at setup lives in the
// vault, so the router asks for it on each call. With PrivateOK empty, a
// private call goes only to a provider PrivateAllowed names, and stops
// going there as soon as it no longer does (the vault locked).
func TestPrivateAllowedHookGatesPrivateCalls(t *testing.T) {
	var allowAnthropic atomic.Bool
	allowAnthropic.Store(true)
	r := newRig(t, rigOpts{
		rule:   Rule{"default": {{Provider: "openai", Model: "gpt-fixture"}, {Provider: "anthropic", Model: "claude-fixture"}}},
		labels: map[string]string{"m1": "private"},
		privateAllowed: func(p string) bool {
			return p == "anthropic" && allowAnthropic.Load()
		},
	})
	r.up.set(hostAnthropic, serveFixture(200, "application/json", fixture(t, "anthropic_message.json")))
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))

	if w := r.do(t, "m1", simpleChat); w.Code != 200 || completionText(t, w) != "Checking the weather." || r.up.count(hostOpenAI) != 0 {
		t.Fatalf("allowed: %d openai=%d", w.Code, r.up.count(hostOpenAI))
	}
	allowAnthropic.Store(false)
	if w := r.do(t, "m1", simpleChat); w.Code != 403 || r.up.count(hostOpenAI) != 0 || r.up.count(hostAnthropic) != 1 {
		t.Fatalf("withdrawn: %d openai=%d anthropic=%d", w.Code, r.up.count(hostOpenAI), r.up.count(hostAnthropic))
	}
}

// The static map still allows on its own; a nil hook keeps the old
// behaviour, and a hook never narrows what the map allows.
func TestPrivateAllowedHookAddsToTheStaticMap(t *testing.T) {
	r := newRig(t, rigOpts{
		rule:           Rule{"default": {{Provider: "openai", Model: "gpt-fixture"}}},
		labels:         map[string]string{"m1": "private"},
		privateOK:      map[string]bool{"openai": true},
		privateAllowed: func(string) bool { return false },
	})
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))
	if w := r.do(t, "m1", simpleChat); w.Code != 200 {
		t.Fatalf("static map: %d", w.Code)
	}
	r2 := newRig(t, rigOpts{labels: map[string]string{"m1": "private"}})
	if w := r2.do(t, "m1", simpleChat); w.Code != 403 {
		t.Fatalf("nil hook: %d", w.Code)
	}
}
