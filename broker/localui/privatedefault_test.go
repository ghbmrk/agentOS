package localui

import (
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// REQ: CAP-9, REV-6

// setupForms returns each Connect AI form on the page, keyed by its
// action and provider ("ai-device anthropic").
func setupForms(t *testing.T, page string) map[string]string {
	t.Helper()
	forms := map[string]string{}
	for _, m := range regexp.MustCompile(`(?s)<form method="post" action="/setup/(ai-[a-z]+)"><input type="hidden" name="provider" value="([a-z]+)">(.*?)</form>`).FindAllStringSubmatch(page, -1) {
		forms[m[1]+" "+m[2]] = m[3]
	}
	return forms
}

// #1403 (D-115, §8.1 step 6): the private-content question is ticked by
// default on a plan sign-in and unticked on an API key, and it names the
// provider whose servers the content goes to.
func TestThePlanSignInPreTicksPrivateContent(t *testing.T) {
	r := newRig(t)
	r.runSetupToAI()
	page := html.UnescapeString(r.get("/setup"))
	forms := setupForms(t, page)
	plan, ok := forms["ai-device anthropic"]
	if !ok || !strings.Contains(plan, `name="private" value="1" checked>`) {
		t.Fatalf("plan sign-in not ticked by default:\n%s", page)
	}
	for _, k := range []string{"ai-key anthropic", "ai-key openai"} {
		f, ok := forms[k]
		if !ok || !strings.Contains(f, `name="private" value="1">`) || strings.Contains(f, "checked") {
			t.Fatalf("%s: not asked, or ticked by default:\n%s", k, page)
		}
	}
	for _, want := range []string{
		"Let Anthropic see your private content: mail, documents, chats, and anything made from them.",
		"Let OpenAI see your private content",
		"Your passwords and keys are never shown to it.",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("page lacks %q:\n%s", want, page)
		}
	}
	// Left as it is, the plan sign-in records yes.
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}, "private": {"1"}})
	if !r.hooks.private["anthropic"] {
		t.Fatal("plan default not recorded as yes")
	}
}

// U-4 (#1422 item 4): a refused key records no answer, and the box comes
// back as the owner left it, so a retry does not quietly flip it.
func TestARefusedKeyKeepsTheOwnersPrivateAnswer(t *testing.T) {
	r := newRig(t)
	r.runSetupToAI()
	r.hooks.mu.Lock()
	r.hooks.keyErr = ErrKeyRefused
	r.hooks.mu.Unlock()
	r.post("/setup/ai-key", url.Values{"provider": {"openai"}, "key": {apiCanary}, "private": {"1"}})
	if _, ok := r.hooks.private["openai"]; ok {
		t.Fatal("answer recorded before the key was stored")
	}
	if f := setupForms(t, r.get("/setup"))["ai-key openai"]; !strings.Contains(f, `name="private" value="1" checked>`) {
		t.Fatalf("box not as the owner left it:\n%s", f)
	}
	r.hooks.mu.Lock()
	r.hooks.keyErr = nil
	r.hooks.mu.Unlock()
	r.post("/setup/ai-key", url.Values{"provider": {"openai"}, "key": {apiCanary}, "private": {"1"}})
	if !r.hooks.private["openai"] {
		t.Fatal("answer not recorded once the key was stored")
	}
}

// U-5 (#1422 item 5): the providers page says tasks can't run only while
// no connected provider may see private content.
func TestTheProvidersIntroShowsOnlyWhenNoneIsAllowed(t *testing.T) {
	const intro = "Tasks that need your mail or files can't run until you allow a provider that is connected."
	r, _, fp := providerRig(t)
	r.signIn()
	if p := html.UnescapeString(r.get("/providers/")); !strings.Contains(p, intro) {
		t.Fatalf("no connected provider allowed, intro missing:\n%s", p)
	}
	fp.mu.Lock()
	fp.ps[0].PrivateOK = true // OpenAI, connected
	fp.mu.Unlock()
	if p := html.UnescapeString(r.get("/providers/")); strings.Contains(p, intro) {
		t.Fatalf("a connected provider is allowed, intro still shown:\n%s", p)
	}
	fp.mu.Lock()
	fp.ps[0].PrivateOK, fp.ps[1].PrivateOK = false, true // only the unconnected one
	fp.mu.Unlock()
	if p := html.UnescapeString(r.get("/providers/")); !strings.Contains(p, intro) {
		t.Fatalf("only an unconnected provider allowed, intro missing:\n%s", p)
	}
}
