package localui

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

// REQ: CAP-9, ONB-3, CRED-5

// holdFails is a setup store that saves everything but a hold: the
// unsaved.json write fails (HeldStore, L55).
type holdFails struct{ SetupStore }

func (h holdFails) Save(s SetupState) error {
	if len(s.Unsaved) > 0 {
		return errors.New("unsaved.json: read-only file system")
	}
	return h.SetupStore.Save(s)
}

// #1888 Security R1: when the vault does not record the owner's private
// answer and the page cannot hold it on disk either, the owner hears that
// the answer will not outlive a restart, not the vault-failure text; the
// hold still keeps setup open while the page runs.
func TestAnAnswerThePageCannotKeepSaysSo(t *testing.T) {
	r := newRig(t)
	r.srv = r.open(holdFails{&MemStore{}})
	r.runSetupToAI()
	r.failPrivate(true)
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}})
	page := r.get("/setup")
	if !strings.Contains(page, errUnkept.Error()) || strings.Contains(page, errUnsaved.Error()) {
		t.Fatalf("an answer the page could not keep reads as the vault's failure:\n%s", page)
	}
	if _, ok := setupForms(t, page)["ai-private anthropic"]; !ok || r.srv.setup.done() {
		t.Fatalf("the hold does not keep setup open in memory:\n%s", page)
	}

	// A hold that is kept on disk keeps the vault-failure text.
	k := newRig(t)
	k.srv = k.open(&MemStore{})
	k.runSetupToAI()
	k.failPrivate(true)
	k.post("/setup/ai-device", url.Values{"provider": {"anthropic"}})
	if page := k.get("/setup"); !strings.Contains(page, errUnsaved.Error()) || strings.Contains(page, errUnkept.Error()) {
		t.Fatalf("a kept hold reads as unkept:\n%s", page)
	}
}

// #1888 PUX L1: a sign-in started while the private answer did not save
// shows no link (#1467), but it still waits for the owner; once the answer
// saves, by the hold's own form or by signing in again, its link comes
// back instead of a busy refusal for the code's whole life.
func TestAParkedSignInLinkComesBackOnceTheAnswerSaves(t *testing.T) {
	for _, via := range []string{"ai-private", "ai-device"} {
		t.Run(via, func(t *testing.T) {
			r := newRig(t)
			r.runSetupToAI()
			r.failPrivate(true)
			r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}})
			if page := r.get("/setup"); devicePrompt.MatchString(page) {
				t.Fatalf("link shown with the answer unsaved:\n%s", page)
			}
			r.hooks.mu.Lock()
			r.hooks.deviceErr = ErrSignInBusy // the sign-in still waits
			r.hooks.mu.Unlock()
			r.failPrivate(false)
			r.post("/setup/"+via, url.Values{"provider": {"anthropic"}})
			page := r.get("/setup")
			if m := devicePrompt.FindStringSubmatch(page); m == nil || m[2] != "WXYZ-1234" || strings.Contains(page, "still waiting") {
				t.Fatalf("the waiting sign-in's link did not come back:\n%s", page)
			}
			if p, ok := r.hooks.private["anthropic"]; !ok || p {
				t.Fatalf("the owner's no was not saved: %v %v", p, ok)
			}
		})
	}
}

// gateClosed lists a plan route the box cannot sign in to yet: the vault
// lists it, but neither a key nor a sign-in is offered (#1888 PUX R1).
type gateClosed struct{ *fakeHooks }

func (g gateClosed) Providers() []Provider {
	return append(g.fakeHooks.Providers(), Provider{ID: "codex", Name: "ChatGPT plan"})
}

// #1888 PUX R1: a plan row with no way in says so in the box's voice
// rather than standing as a bare heading, and offers no sign-in form, so
// #1867's step-7 driver still reads it as not offered.
func TestAPlanTheBoxCannotSignInToSaysSo(t *testing.T) {
	r := newRig(t)
	r.via = gateClosed{r.hooks}
	r.srv = r.open(&MemStore{})
	r.runSetupToAI()
	page := r.get("/setup")
	if !strings.Contains(page, "<h3>ChatGPT plan</h3>") || !strings.Contains(page, "<p>I can't sign in to your ChatGPT plan yet. Use another provider for now.</p>") {
		t.Fatalf("the closed plan row:\n%s", page)
	}
	if strings.Contains(page, `name="provider" value="codex"`) {
		t.Fatalf("the closed plan row offers a form:\n%s", page)
	}
	if strings.Count(page, "I can't sign in to your") != 1 {
		t.Fatalf("the line shows on a provider with a way in:\n%s", page)
	}
}
