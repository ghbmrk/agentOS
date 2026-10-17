package localui

import (
	"html"
	"net/url"
	"strings"
	"testing"
)

// REQ: CAP-9, OWN-7

// #1608: a provider the vault process's configuration allows private
// content shows its box ticked and fixed, with the providers page's
// wording, and a post without the box (a disabled box is never sent, or
// a forged untick) records no answer for it. An unconfigured provider
// keeps D-115's defaults.
func TestSetupAIStepShowsConfiguredProviderFixed(t *testing.T) {
	const fixed = "My configuration allows it, so it can't be withdrawn here."
	r := newRig(t)
	r.hooks.mu.Lock()
	r.hooks.byConfig = map[string]bool{"anthropic": true}
	r.hooks.mu.Unlock()
	r.runSetupToAI()
	page := html.UnescapeString(r.get("/setup"))
	forms := setupForms(t, page)
	for _, k := range []string{"ai-device anthropic", "ai-key anthropic"} {
		f, ok := forms[k]
		if !ok || !strings.Contains(f, `<input type="checkbox" checked disabled>`) || !strings.Contains(f, fixed) || strings.Contains(f, `name="private"`) {
			t.Fatalf("%s: box not shown fixed:\n%s", k, page)
		}
	}
	// Control (D-115): the unconfigured provider is asked, unticked.
	if f := forms["ai-key openai"]; !strings.Contains(f, `name="private" value="1">`) || strings.Contains(f, "checked") || strings.Contains(f, fixed) {
		t.Fatalf("unconfigured provider changed:\n%s", f)
	}

	r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}})
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}})
	r.hooks.mu.Lock()
	_, recorded := r.hooks.private["anthropic"]
	_, owed := r.hooks.owed["anthropic"]
	n := r.hooks.privates
	r.hooks.mu.Unlock()
	if recorded || owed || n != 0 {
		t.Fatalf("an answer was recorded for a configured provider: private %v, owed %v, %d calls", recorded, owed, n)
	}
}
