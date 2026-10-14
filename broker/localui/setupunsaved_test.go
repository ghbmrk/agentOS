package localui

import (
	"errors"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

// REQ: CAP-9, REV-6, ONB-3

// #1467 (#1436 Security S1): a key stored whose private-content answer
// then fails to save holds setup open, shows the error and a box-only
// retry, and the retry records the owner's answer. The path the review
// probed: a plan sign-in records yes (D-115), the owner unticks the key
// box, the save fails; setup must not finish with the provider keeping
// yes.
func TestAnUnsavedAnswerHoldsSetupOpen(t *testing.T) {
	r := newRig(t)
	st := &MemStore{}
	r.srv = r.open(st)
	r.runSetupToAI()
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}, "private": {"1"}})
	if !r.hooks.private["anthropic"] {
		t.Fatal("plan default not recorded as yes")
	}
	r.hooks.mu.Lock()
	r.hooks.privateErr = errors.New("vault busy")
	r.hooks.mu.Unlock()
	r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}})
	if r.hooks.keys["anthropic"] != apiCanary {
		t.Fatal("key not stored")
	}
	if r.srv.setup.done() || r.hooks.finishes != 0 {
		t.Fatal("setup finished with the owner's answer unsaved")
	}
	page := r.get("/setup")
	if !strings.Contains(page, "Could not save. Try again.") {
		t.Fatalf("error not shown:\n%s", page)
	}
	// Each later load holds too, and keeps the retry with the box as the
	// owner left it (unticked).
	f, ok := setupForms(t, r.get("/setup"))["ai-private anthropic"]
	if !ok || !strings.Contains(f, `name="private" value="1">`) || strings.Contains(f, "checked") {
		t.Fatalf("no retry, or the owner's unticked box came back ticked:\n%s", f)
	}
	if strings.Contains(f, `name="key"`) {
		t.Fatalf("the retry asks for the key again:\n%s", f)
	}
	if r.srv.setup.done() || !r.hooks.private["anthropic"] {
		t.Fatal("page load finished setup, or the old yes changed")
	}
	// A restart keeps the hold: it is part of the saved setup state.
	r.srv = r.open(st)
	if f, ok := setupForms(t, r.get("/setup"))["ai-private anthropic"]; !ok || strings.Contains(f, "checked") || r.srv.setup.done() {
		t.Fatalf("restart dropped the hold:\n%s", f)
	}
	// A failed retry keeps holding.
	r.post("/setup/ai-private", url.Values{"provider": {"anthropic"}})
	if r.srv.setup.done() || !strings.Contains(r.setupErr(), "Could not save") {
		t.Fatal("failed retry finished setup or showed no error")
	}
	r.hooks.mu.Lock()
	r.hooks.privateErr = nil
	r.hooks.mu.Unlock()
	r.post("/setup/ai-private", url.Values{"provider": {"anthropic"}})
	if ok, set := r.hooks.private["anthropic"]; !set || ok {
		t.Fatal("retry did not record the owner's no")
	}
	if !r.srv.setup.done() || r.hooks.finishes != 1 {
		t.Fatal("setup did not finish once the answer was saved")
	}
}

// The hold is set before the key is stored, so a page load racing the
// save cannot finish setup between the two (#1467).
func TestTheHoldCoversTheSaveInFlight(t *testing.T) {
	r := newRig(t)
	h := &holdingHooks{fakeHooks: r.hooks, r: r}
	r.via = h
	r.srv = r.open(&MemStore{})
	r.runSetupToAI()
	r.post("/setup/ai-key", url.Values{"provider": {"openai"}, "key": {apiCanary}})
	if !h.ran {
		t.Fatal("SetPrivateOK not called")
	}
	if h.doneMid {
		t.Fatal("a page load finished setup while the answer was being saved")
	}
	if !r.srv.setup.done() {
		t.Fatal("setup did not finish after the save")
	}
}

// holdingHooks loads the setup page while SetPrivateOK runs.
type holdingHooks struct {
	*fakeHooks
	r       *rig
	ran     bool
	doneMid bool
}

func (h *holdingHooks) SetPrivateOK(id string, ok bool) error {
	h.ran = true
	h.r.srv.setup.maybeFinish()
	h.doneMid = h.r.srv.setup.done()
	return h.fakeHooks.SetPrivateOK(id, ok)
}

// A key that the vault refuses releases the hold it set, so setup is not
// held for an answer that was never owed (#1467).
func TestARefusedKeyLeavesNoHold(t *testing.T) {
	r := newRig(t)
	r.runSetupToAI()
	r.hooks.mu.Lock()
	r.hooks.keyErr = ErrKeyRefused
	r.hooks.mu.Unlock()
	r.post("/setup/ai-key", url.Values{"provider": {"openai"}, "key": {apiCanary}})
	if _, ok := setupForms(t, r.get("/setup"))["ai-private openai"]; ok {
		t.Fatal("refused key left a retry")
	}
	r.hooks.mu.Lock()
	r.hooks.keyErr = nil
	r.hooks.mu.Unlock()
	r.post("/setup/ai-key", url.Values{"provider": {"openai"}, "key": {apiCanary}})
	if !r.srv.setup.done() {
		t.Fatal("setup did not finish")
	}
}

// #1467 test 2: SetPrivateOK failing in aiDevice shows no link, shows the
// error, and keeps the box as the owner left it.
func TestAnUnsavedPlanAnswerShowsNoLink(t *testing.T) {
	r := newRig(t)
	r.runSetupToAI()
	r.hooks.mu.Lock()
	r.hooks.privateErr = errors.New("vault busy")
	r.hooks.mu.Unlock()
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}})
	page := r.get("/setup")
	if strings.Contains(page, "example.invalid/device") || strings.Contains(page, "WXYZ-1234") {
		t.Fatalf("link shown with the answer unsaved:\n%s", page)
	}
	if !strings.Contains(page, "Could not save. Try again.") {
		t.Fatalf("error not shown:\n%s", page)
	}
	if f := setupForms(t, r.get("/setup"))["ai-device anthropic"]; !strings.Contains(f, `name="private" value="1">`) || strings.Contains(f, "checked") {
		t.Fatalf("the owner's unticked box came back ticked:\n%s", f)
	}
}

// #1467 test 3: an unknown provider id, or one without that route, on
// any AI post records nothing, connects nothing and keeps no answer.
func TestUnknownProvidersRecordNothing(t *testing.T) {
	for _, c := range []struct{ path, id string }{
		{"/setup/ai-key", "mistral"},
		{"/setup/ai-key", ""},
		{"/setup/ai-device", "mistral"},
		{"/setup/ai-device", "openai"}, // no device code
		{"/setup/ai-private", "mistral"},
		{"/setup/ai-private", "openai"}, // nothing unsaved
	} {
		t.Run(c.path+" "+c.id, func(t *testing.T) {
			r := newRig(t)
			r.runSetupToAI()
			r.post(c.path, url.Values{"provider": {c.id}, "key": {apiCanary}, "private": {"1"}})
			if r.hooks.keys != nil || r.hooks.privates != 0 || r.hooks.connected {
				t.Fatalf("recorded: keys %v, %d answers", r.hooks.keys, r.hooks.privates)
			}
			if r.setupErr() == "" {
				t.Fatal("no error shown")
			}
			page := r.get("/setup")
			if strings.Contains(page, "example.invalid/device") || strings.Contains(page, "ai-private") {
				t.Fatalf("link or retry shown:\n%s", page)
			}
			if f := setupForms(t, page)["ai-key openai"]; strings.Contains(f, "checked") {
				t.Fatalf("an answer was kept:\n%s", f)
			}
		})
	}
}

// #1467 test 4: before the host step, the AI posts record nothing. Before
// an owner exists any phone may post setup steps, so this gate keeps a
// stranger off the AI step.
func TestAIStepNeedsTheHostStep(t *testing.T) {
	for _, path := range []string{"/setup/ai-key", "/setup/ai-device", "/setup/ai-private"} {
		t.Run(path, func(t *testing.T) {
			r := newRig(t)
			r.hooks.mu.Lock()
			r.hooks.progress = Progress{Phase: "ready", Updated: true, Online: true}
			r.hooks.mu.Unlock()
			for i := 0; i < 2; i++ { // the setup phone, then a stranger
				r.jar, _ = cookiejar.New(nil)
				r.get("/setup")
				r.post(path, url.Values{"provider": {"anthropic"}, "key": {apiCanary}, "private": {"1"}})
				if r.hooks.keys != nil || r.hooks.privates != 0 || r.hooks.connected {
					t.Fatalf("AI post before the host step recorded: keys %v, %d answers", r.hooks.keys, r.hooks.privates)
				}
				if !strings.Contains(r.setupErr(), "Finish the earlier steps first.") {
					t.Fatal("no error shown")
				}
			}
		})
	}
}
