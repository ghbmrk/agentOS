package localui

import (
	"errors"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// REQ: CAP-9, REV-6, ONB-3

// failPrivate makes SetPrivateOK fail, or succeed again.
func (r *rig) failPrivate(fail bool) {
	r.hooks.mu.Lock()
	r.hooks.privateErr = nil
	if fail {
		r.hooks.privateErr = errors.New("vault busy")
	}
	r.hooks.mu.Unlock()
}

// #1467 (#1436 Security S1): the path the review probed. A plan sign-in
// records yes (D-115), then the owner unticks the box with an API key and
// the save of that no fails. The no is saved before the key, so no key is
// stored; the error shows once, then a box-only retry holds setup open.
func TestAnUnsavedAnswerHoldsSetupOpen(t *testing.T) {
	r := newRig(t)
	r.runSetupToAI()
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}, "private": {"1"}})
	if !r.hooks.private["anthropic"] {
		t.Fatal("plan default not recorded as yes")
	}
	r.failPrivate(true)
	r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}})
	if r.hooks.keys != nil || r.hooks.connected {
		t.Fatal("a key was stored with the owner's no unsaved")
	}
	if r.srv.setup.done() || r.hooks.finishes != 0 {
		t.Fatal("setup finished with the owner's answer unsaved")
	}
	if page := r.get("/setup"); !strings.Contains(page, "Could not save. Try again.") {
		t.Fatalf("error not shown:\n%s", page)
	}
	// Later loads show the note and the retry, with the box as the owner
	// left it (unticked) and no key field; the error showed once.
	page := r.get("/setup")
	if strings.Contains(page, "Could not save. Try again.") || !strings.Contains(page, "was not saved yet") {
		t.Fatalf("error shown again, or no note:\n%s", page)
	}
	f, ok := setupForms(t, page)["ai-private anthropic"]
	if !ok || !strings.Contains(f, `name="private" value="1">`) || strings.Contains(f, "checked") {
		t.Fatalf("no retry, or the owner's unticked box came back ticked:\n%s", f)
	}
	if strings.Contains(f, `name="key"`) {
		t.Fatalf("the retry asks for the key again:\n%s", f)
	}
	if r.srv.setup.done() || !r.hooks.private["anthropic"] {
		t.Fatal("page load finished setup, or the old yes changed")
	}
	// A failed retry keeps holding and keeps the retry's own answer, so a
	// held yes renders ticked (#1534 M9, M11).
	r.post("/setup/ai-private", url.Values{"provider": {"anthropic"}, "private": {"1"}})
	if r.srv.setup.done() || !strings.Contains(r.setupErr(), "Could not save") {
		t.Fatal("failed retry finished setup or showed no error")
	}
	if f := setupForms(t, r.get("/setup"))["ai-private anthropic"]; !strings.Contains(f, "checked") {
		t.Fatalf("the failed retry's yes came back unticked:\n%s", f)
	}
	// A saved retry releases the hold; nothing is connected, so setup
	// stays open until a key is.
	r.failPrivate(false)
	r.post("/setup/ai-private", url.Values{"provider": {"anthropic"}})
	if ok, set := r.hooks.private["anthropic"]; !set || ok {
		t.Fatal("retry did not record the owner's no")
	}
	if _, held := setupForms(t, r.get("/setup"))["ai-private anthropic"]; held || r.srv.setup.done() {
		t.Fatal("hold kept after a saved answer, or setup finished unconnected")
	}
	r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}})
	if !r.srv.setup.done() || r.hooks.finishes != 1 || r.hooks.private["anthropic"] {
		t.Fatal("setup did not finish with the owner's no")
	}
}

// #1534 Security S1: the hold lasts only as long as the SetupStore, and
// agentos-localui's store is in memory. A restart that loses the hold,
// even one keeping every other step, finds nothing connected after the
// failed no above, so setup does not finish on the old yes.
func TestARestartAfterAFailedNoFinishesNothing(t *testing.T) {
	r := newRig(t)
	st := &MemStore{}
	r.srv = r.open(st)
	r.runSetupToAI()
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}, "private": {"1"}})
	r.failPrivate(true)
	r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}})
	kept, _ := st.Load()
	if len(kept.Unsaved) != 1 || !kept.Host {
		t.Fatalf("no hold saved: %+v", kept.Unsaved)
	}
	kept.Unsaved = nil
	r.srv = r.open(&MemStore{s: kept})
	r.get("/setup")
	if r.srv.setup.done() || r.hooks.finishes != 0 || r.hooks.keys != nil {
		t.Fatal("restart finished setup on the unsaved answer")
	}
}

// A yes is saved after the key: a yes that fails leaves the key stored
// without the yes, so the vault is never wider than the owner's answer,
// and holds setup open with the box ticked.
func TestAnUnsavedYesHoldsWithTheKeyStored(t *testing.T) {
	r := newRig(t)
	r.runSetupToAI()
	r.failPrivate(true)
	r.post("/setup/ai-key", url.Values{"provider": {"openai"}, "key": {apiCanary}, "private": {"1"}})
	if r.hooks.keys["openai"] != apiCanary || r.hooks.private["openai"] {
		t.Fatal("key not stored, or the yes recorded")
	}
	if f := setupForms(t, r.get("/setup"))["ai-private openai"]; !strings.Contains(f, "checked") || r.srv.setup.done() {
		t.Fatalf("setup finished, or the retry lost the owner's yes:\n%s", f)
	}
}

// orderHooks records the vault calls and loads setup inside each, so a
// page load racing a save cannot finish setup (#1534 L-1).
type orderHooks struct {
	*fakeHooks
	r       *rig
	calls   []string
	doneMid bool
}

func (h *orderHooks) mid(call string) {
	h.calls = append(h.calls, call)
	h.r.srv.setup.maybeFinish()
	h.doneMid = h.doneMid || h.r.srv.setup.done()
}

func (h *orderHooks) SetPrivateOK(id string, ok bool) error {
	if ok {
		h.mid("yes")
	} else {
		h.mid("no")
	}
	return h.fakeHooks.SetPrivateOK(id, ok)
}

func (h *orderHooks) ConnectAPIKey(id, key string) error {
	h.mid("key")
	return h.fakeHooks.ConnectAPIKey(id, key)
}

// A no is saved before the key and a yes after it, and setup finishes
// only after both, never from a load while either is in flight.
func TestTheAnswerAndKeyOrder(t *testing.T) {
	for _, c := range []struct {
		private string
		want    string
	}{{"", "no key"}, {"1", "key yes"}} {
		r := newRig(t)
		h := &orderHooks{fakeHooks: r.hooks, r: r}
		r.via = h
		r.srv = r.open(&MemStore{})
		r.runSetupToAI()
		r.post("/setup/ai-key", url.Values{"provider": {"openai"}, "key": {apiCanary}, "private": {c.private}})
		if got := strings.Join(h.calls, " "); got != c.want {
			t.Fatalf("private=%q: calls %q, want %q", c.private, got, c.want)
		}
		if h.doneMid || !r.srv.setup.done() {
			t.Fatalf("private=%q: finished mid-save, or not after", c.private)
		}
	}
}

// failStore fails every Save while fail is set.
type failStore struct {
	MemStore
	mu   sync.Mutex
	fail bool
}

func (f *failStore) Save(s SetupState) error {
	f.mu.Lock()
	fail := f.fail
	f.mu.Unlock()
	if fail {
		return errors.New("disk full")
	}
	return f.MemStore.Save(s)
}

// #1534 M8/M13: a hold the setup store fails to save still holds in
// memory, so setup does not finish with the answer unsaved.
func TestAHoldTheStoreFailsStillHolds(t *testing.T) {
	r := newRig(t)
	st := &failStore{}
	r.srv = r.open(st)
	r.runSetupToAI()
	st.mu.Lock()
	st.fail = true
	st.mu.Unlock()
	r.failPrivate(true)
	r.post("/setup/ai-key", url.Values{"provider": {"openai"}, "key": {apiCanary}, "private": {"1"}})
	if r.srv.setup.done() || r.hooks.finishes != 0 {
		t.Fatal("setup finished with the answer unsaved")
	}
	if _, ok := setupForms(t, r.get("/setup"))["ai-private openai"]; !ok {
		t.Fatal("no retry")
	}
}

// #1534 M5: a key the vault refuses leaves an earlier hold as it was.
func TestARefusedKeyKeepsAnEarlierHold(t *testing.T) {
	r := newRig(t)
	r.runSetupToAI()
	r.failPrivate(true)
	r.post("/setup/ai-key", url.Values{"provider": {"openai"}, "key": {apiCanary}})
	r.failPrivate(false)
	r.hooks.mu.Lock()
	r.hooks.keyErr = ErrKeyRefused
	r.hooks.mu.Unlock()
	r.post("/setup/ai-key", url.Values{"provider": {"openai"}, "key": {apiCanary}, "private": {"1"}})
	f, ok := setupForms(t, r.get("/setup"))["ai-private openai"]
	if !ok || strings.Contains(f, "checked") {
		t.Fatalf("refused key dropped or changed the earlier hold:\n%s", f)
	}
}

// A key that the vault refuses sets no hold, so setup is not held for an
// answer that was never owed (#1467). This passes on main too: it guards
// the hold from being set before the key.
func TestARefusedKeyLeavesNoHold(t *testing.T) {
	r := newRig(t)
	r.runSetupToAI()
	r.hooks.mu.Lock()
	r.hooks.keyErr = ErrKeyRefused
	r.hooks.mu.Unlock()
	r.post("/setup/ai-key", url.Values{"provider": {"openai"}, "key": {apiCanary}, "private": {"1"}})
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
// error, and keeps the box as the owner left it; a failed re-post drops
// the link an earlier sign-in showed (#1534 M7).
func TestAnUnsavedPlanAnswerShowsNoLink(t *testing.T) {
	r := newRig(t)
	r.runSetupToAI()
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}, "private": {"1"}})
	if !strings.Contains(r.get("/setup"), "WXYZ-1234") {
		t.Fatal("no link after a saved sign-in")
	}
	r.failPrivate(true)
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

// postInside posts one AI form from inside a vault call, once.
type postInside struct {
	*fakeHooks
	r      *rig
	inKey  url.Values
	inDone url.Values
	path   string // inKey's route; "" is /setup/ai-key
	inErr  string // the setup error inKey's post left
}

func (h *postInside) ConnectAPIKey(id, key string) error {
	if f := h.inKey; f != nil {
		h.inKey = nil
		path := h.path
		if path == "" {
			path = "/setup/ai-key"
		}
		h.r.post(path, f)
		h.inErr = h.r.setupErr()
	}
	return h.fakeHooks.ConnectAPIKey(id, key)
}

func (h *postInside) Finish(n string) error {
	if f := h.inDone; f != nil {
		h.inDone = nil
		h.r.post("/setup/ai-key", f)
	}
	return h.fakeHooks.Finish(n)
}

// #1534 S3/P-1: one AI post per provider at a time, and none while Finish
// runs, so a second post cannot record an answer the first one overrides.
func TestAIPostsWaitTheirTurn(t *testing.T) {
	r := newRig(t)
	h := &postInside{fakeHooks: r.hooks, r: r,
		inKey: url.Values{"provider": {"openai"}, "key": {"sk-second"}, "private": {"1"}}}
	r.via = h
	r.srv = r.open(&MemStore{})
	r.runSetupToAI()
	r.post("/setup/ai-key", url.Values{"provider": {"openai"}, "key": {apiCanary}})
	if r.hooks.keys["openai"] != apiCanary || r.hooks.private["openai"] || r.hooks.privates != 1 {
		t.Fatalf("a post during another for the provider went through: %d answers", r.hooks.privates)
	}

	r = newRig(t)
	h = &postInside{fakeHooks: r.hooks, r: r,
		inDone: url.Values{"provider": {"openai"}, "key": {apiCanary}, "private": {"1"}}}
	r.via = h
	r.srv = r.open(&MemStore{})
	r.runSetupToAI()
	r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}})
	if !r.srv.setup.done() || r.hooks.keys["openai"] != "" || r.hooks.private["openai"] {
		t.Fatal("a post while Finish ran stored a key or an answer")
	}
}

// #1534 M16: the hold survives a FileStore round trip.
func TestFileStoreKeepsTheHold(t *testing.T) {
	st := FileStore{Path: filepath.Join(t.TempDir(), "setup.json")}
	if err := st.Save(SetupState{Unsaved: map[string]bool{"openai": true, "anthropic": false}}); err != nil {
		t.Fatal(err)
	}
	s, err := st.Load()
	if err != nil || len(s.Unsaved) != 2 || !s.Unsaved["openai"] || s.Unsaved["anthropic"] {
		t.Fatalf("Unsaved %v, %v", s.Unsaved, err)
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

// #1545 (#1534 R-L1): the retry route and the device route take their
// turn too. Each posts while an ai-key post for the same provider is in
// flight; the second post is refused and records nothing, so it cannot
// record an answer the first one then overrides.
func TestRetryAndDevicePostsWaitTheirTurn(t *testing.T) {
	t.Run("ai-private", func(t *testing.T) {
		r := newRig(t)
		h := &postInside{fakeHooks: r.hooks, r: r, path: "/setup/ai-private",
			inKey: url.Values{"provider": {"anthropic"}}}
		r.via = h
		r.srv = r.open(&MemStore{})
		r.runSetupToAI()
		r.failPrivate(true) // hold anthropic, so the retry route is open
		r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}})
		r.failPrivate(false)
		n := r.hooks.privates
		r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}, "private": {"1"}})
		if r.hooks.privates != n+1 || !r.hooks.private["anthropic"] {
			t.Fatalf("the retry during a key post went through: %d answers", r.hooks.privates-n)
		}
		if !strings.Contains(h.inErr, "still saving") {
			t.Fatalf("the retry was not refused: %q", h.inErr)
		}
	})
	t.Run("ai-device", func(t *testing.T) {
		r := newRig(t)
		h := &postInside{fakeHooks: r.hooks, r: r, path: "/setup/ai-device",
			inKey: url.Values{"provider": {"anthropic"}, "private": {"1"}}}
		r.via = h
		r.srv = r.open(&MemStore{})
		r.runSetupToAI()
		r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}})
		if r.hooks.privates != 1 || r.hooks.private["anthropic"] {
			t.Fatalf("the sign-in during a key post went through: %d answers", r.hooks.privates)
		}
		if !strings.Contains(h.inErr, "still saving") {
			t.Fatalf("the sign-in was not refused: %q", h.inErr)
		}
		r.srv.setup.mu.Lock()
		_, link := r.srv.setup.device["anthropic"]
		r.srv.setup.mu.Unlock()
		if link {
			t.Fatal("the refused sign-in kept a link")
		}
	})
}

// #1544 (#1534 S2): a plan sign-in connects the provider with yes, then
// the owner's no fails to save, then the page restarts and loses its
// hold. agentosd still owes the no, so the restarted page holds setup
// open with the owner's unticked box, and finishes only once a retry
// saves the no. The restarted page keeps the walked SetupState minus
// Unsaved, not a fresh MemStore and a re-walk as in #1544; the localsrv
// restart test and adoption on the host step cover that path (#1623).
func TestARestartKeepsAnOwedNo(t *testing.T) {
	r := newRig(t)
	st := &MemStore{}
	r.srv = r.open(st)
	r.runSetupToAI()
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}, "private": {"1"}})
	r.failPrivate(true)
	r.hooks.mu.Lock()
	r.hooks.connected = true // the owner finishes signing in on the provider's site
	r.hooks.mu.Unlock()
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}})
	kept, _ := st.Load()
	kept.Unsaved = nil // the page's store did not survive
	r.srv = r.open(&MemStore{s: kept})
	page := r.get("/setup")
	if r.srv.setup.done() || r.hooks.finishes != 0 || !r.hooks.private["anthropic"] {
		t.Fatal("restart finished setup on the old yes")
	}
	f, ok := setupForms(t, page)["ai-private anthropic"]
	if !ok || strings.Contains(f, "checked") {
		t.Fatalf("no retry after the restart, or the owner's no came back ticked:\n%s", page)
	}
	r.failPrivate(false)
	r.post("/setup/ai-private", url.Values{"provider": {"anthropic"}})
	if !r.srv.setup.done() || r.hooks.finishes != 1 || r.hooks.private["anthropic"] {
		t.Fatal("setup did not finish with the owner's no")
	}
}

// #1554 Potency R4 (M13): an owed answer the page adopts holds setup
// before Finish is called at all, not only by agentosd's refusal.
func TestAnAdoptedOwedAnswerCallsNoFinish(t *testing.T) {
	r := newRig(t)
	r.srv = r.open(&MemStore{})
	r.runSetupToAI()
	r.hooks.mu.Lock()
	r.hooks.owed = map[string]bool{"openai": false} // owed before this page ran
	r.hooks.mu.Unlock()
	r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}, "private": {"1"}})
	r.get("/setup")
	r.hooks.mu.Lock()
	calls := r.hooks.finishCalls
	r.hooks.mu.Unlock()
	if calls != 0 || r.srv.setup.done() {
		t.Fatalf("Finish called %d times while an adopted answer was owed", calls)
	}
	r.srv.setup.mu.Lock()
	_, held := r.srv.setup.st.Unsaved["openai"]
	r.srv.setup.mu.Unlock()
	if !held {
		t.Fatal("the owed answer was not adopted")
	}
}
