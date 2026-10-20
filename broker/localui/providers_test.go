package localui

import (
	"context"
	"html"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: CAP-9, CH-3, CH-7, CRED-1, CRED-5, ONB-3, OWN-7

// fakeProviders stands in for the vault process's provider routes
// (#1266): allowing needs the right code, which works once; withdrawing
// needs none.
type fakeProviders struct {
	mu    sync.Mutex
	ps    []ProviderStatus
	code  string
	used  bool
	calls int
	// failList, when set, is what ProviderList returns instead.
	failList error
	// keys is what AddProviderKey stored (id to key); refuseKey, when set,
	// is what it returns instead of storing, as the vault process does
	// when its provider refuses a key or cannot be asked (ONB-3).
	keys      map[string]string
	refuseKey error
}

func (f *fakeProviders) AddProviderKey(ctx context.Context, id, key, code string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if code != f.code || f.used {
		return &VaultError{403, "wrong code: check your code generator and try again"}
	}
	if f.refuseKey != nil {
		return f.refuseKey
	}
	f.used = true
	if f.keys == nil {
		f.keys = map[string]string{}
	}
	f.keys[id] = key
	for i := range f.ps {
		if f.ps[i].ID == id {
			f.ps[i].Connected = true
		}
	}
	return nil
}

func (f *fakeProviders) ProviderList(ctx context.Context) ([]ProviderStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList != nil {
		return nil, f.failList
	}
	return append([]ProviderStatus(nil), f.ps...), nil
}

func (f *fakeProviders) SetProviderPrivate(ctx context.Context, id string, ok bool, code string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	i := -1
	for j, p := range f.ps {
		if p.ID == id {
			i = j
		}
	}
	if i < 0 {
		return &VaultError{400, ""}
	}
	if ok {
		if code != f.code || f.used {
			return &VaultError{403, "wrong code: check your code generator and try again"}
		}
		f.used = true
	}
	f.ps[i].PrivateOK = ok
	return nil
}

func (f *fakeProviders) allowed(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.ps {
		if p.ID == id {
			return p.PrivateOK
		}
	}
	return false
}

// providerRig is a set-up box, signed in on this phone, whose vault is
// open and whose local UI serves the AI providers page.
func providerRig(t *testing.T) (*rig, *fakeVault, *fakeProviders) {
	t.Helper()
	r := newRig(t)
	fv := newFakeVault(r.card.VaultPassphrase)
	fv.state = "open"
	fp := &fakeProviders{code: "246810", ps: []ProviderStatus{
		{ID: "openai", Name: "OpenAI", Connected: true}, {ID: "anthropic", Name: "Anthropic"}}}
	s, err := New(Config{AP: testAP(), Hooks: r.hooks, SetupSecret: r.card.SetupSecret, Store: &MemStore{},
		Defaults: "spend cap $20 a day; payments need approval.", Vault: fv, Providers: fp, Now: r.clock, Rand: rand.New(rand.NewSource(9))})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = s
	r.runSetup()
	r.startChannel(modem.NewCarrier().Line(boxNum))
	return r, fv, fp
}

// #1266 (CAP-9, CH-3): after setup the owner changes a provider's
// private-data answer on the local page, behind sign-in. Allowing takes
// a code from the code generator; withdrawing asks first and needs none.
func TestTheOwnerChangesAProvidersPrivateAnswerOnTheLocalPage(t *testing.T) {
	r, _, fp := providerRig(t)
	if w := r.do("GET", "/providers/", nil); w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/unlock?next=") {
		t.Fatalf("without sign-in: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := r.post("/providers/", url.Values{"step": {"allow"}, "provider": {"openai"}, "code": {fp.code}}); w.Code != http.StatusSeeOther || fp.calls != 0 {
		t.Fatalf("a post without sign-in reached the vault process: %d, %d calls", w.Code, fp.calls)
	}
	r.signIn()
	if !strings.Contains(r.get("/home"), `href="/providers/"`) {
		t.Fatal("home does not list the AI providers")
	}
	p := html.UnescapeString(r.get("/providers/"))
	for _, want := range []string{"OpenAI: connected", "OpenAI may not see your private data", "Anthropic: not connected",
		`name="code"`, "Tasks that need your mail or files can't run until you allow a provider that is connected."} {
		if !strings.Contains(p, want) {
			t.Fatalf("page lacks %q:\n%s", want, p)
		}
	}

	w := r.post("/providers/", url.Values{"step": {"allow"}, "provider": {"openai"}, "code": {"000000"}})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "wrong code") || fp.allowed("openai") {
		t.Fatalf("wrong code: %d %s", w.Code, w.Body.String())
	}
	w = r.post("/providers/", url.Values{"step": {"allow"}, "provider": {"openai"}, "code": {fp.code}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/providers/" || !fp.allowed("openai") {
		t.Fatalf("allow: %d %s", w.Code, w.Body.String())
	}
	if p := html.UnescapeString(r.get("/providers/")); !strings.Contains(p, "OpenAI may see your private data") {
		t.Fatalf("allowed page:\n%s", p)
	}

	w = r.post("/providers/", url.Values{"step": {"withdraw"}, "provider": {"openai"}})
	b := html.UnescapeString(w.Body.String())
	if w.Code != http.StatusOK || !fp.allowed("openai") {
		t.Fatalf("withdrawn without confirmation: %d", w.Code)
	}
	for _, want := range []string{"Stop OpenAI seeing your private data? Tasks that need your mail or files can't run until you allow a provider again.",
		`name="confirm" value="1"`, `name="provider" value="openai"`, `href="/providers/">Cancel</a>`} {
		if !strings.Contains(b, want) {
			t.Fatalf("confirmation lacks %q:\n%s", want, b)
		}
	}
	w = r.post("/providers/", url.Values{"step": {"withdraw"}, "provider": {"openai"}, "confirm": {"1"}})
	if w.Code != http.StatusSeeOther || fp.allowed("openai") {
		t.Fatalf("confirmed withdraw: %d %s", w.Code, w.Body.String())
	}
	if w := r.post("/providers/", url.Values{"step": {"other"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown step: %d", w.Code)
	}
}

// The page says when the vault is locked or the vault process is not
// answering, and a refusal without the vault process's own wording reads
// as a plain retry, never an internal reason.
func TestTheProvidersPageWhenTheVaultIsLockedOrDown(t *testing.T) {
	r, fv, fp := providerRig(t)
	r.signIn()
	fv.mu.Lock()
	fv.state = "locked"
	fv.mu.Unlock()
	if p := r.get("/providers/"); !strings.Contains(p, "I am locked") || strings.Contains(p, `name="code"`) {
		t.Fatalf("locked:\n%s", p)
	}
	fv.mu.Lock()
	fv.state, fv.down = "open", true
	fv.mu.Unlock()
	if p := r.get("/providers/"); !strings.Contains(p, "I am still starting") || !strings.Contains(p, `http-equiv="refresh"`) {
		t.Fatalf("down:\n%s", p)
	}
	fv.mu.Lock()
	fv.down = false
	fv.mu.Unlock()
	fp.failList = &VaultError{500, "internal detail"}
	if p := r.get("/providers/"); !strings.Contains(p, "I am locked") || strings.Contains(p, "internal detail") {
		t.Fatalf("list refused:\n%s", p)
	}
	fp.failList = nil
	w := r.post("/providers/", url.Values{"step": {"allow"}, "provider": {"nope"}, "code": {fp.code}})
	if !strings.Contains(html.UnescapeString(w.Body.String()), "That didn't go through. Try again.") {
		t.Fatalf("refusal: %s", w.Body.String())
	}
}

// Without the unlock socket there is no providers page, and the page
// needs the vault socket.
func TestNoProvidersPageWithoutItsSocket(t *testing.T) {
	r := newRig(t)
	r.runSetup()
	r.startChannel(modem.NewCarrier().Line(boxNum))
	r.signIn()
	if strings.Contains(r.get("/home"), "/providers/") {
		t.Fatal("home lists the providers page")
	}
	if w := r.do("GET", "/providers/", nil); w.Code != http.StatusNotFound {
		t.Fatalf("page served: %d", w.Code)
	}
	if _, err := New(Config{AP: testAP(), Hooks: r.hooks, Store: &MemStore{}, Providers: &fakeProviders{}, Now: time.Now}); err == nil {
		t.Fatal("a providers page without the vault socket")
	}
}

// #1266 (REV-6): the setup box says what leaving it unticked means, and
// is unticked by default (CAP-9: the default is no).
func TestTheSetupPrivateBoxSaysWhatUntickedMeans(t *testing.T) {
	for _, checked := range []bool{false, true} {
		var b strings.Builder
		if err := pagesFor("box.local").ExecuteTemplate(&b, "private", privateBox{Name: "OpenAI", Checked: checked}); err != nil {
			t.Fatal(err)
		}
		p := html.UnescapeString(b.String())
		if !strings.Contains(p, "Unticked, tasks that need your mail or files can't run until you allow a provider on the AI providers page.") {
			t.Fatalf("box line:\n%s", p)
		}
		if strings.Contains(p, "checked") != checked {
			t.Fatalf("checked=%v not rendered as such:\n%s", checked, p)
		}
	}
}

// #1420 (Security S-1 on #1367; CAP-9, OWN-7): a provider this box's
// configuration allows private data shows as allowed, says why, and
// offers no withdraw, since the page cannot stop it.
func TestTheProvidersPageShowsAProviderTheBoxsConfigurationAllows(t *testing.T) {
	r, _, fp := providerRig(t)
	fp.mu.Lock()
	fp.ps[0].PrivateOK, fp.ps[0].PrivateByConfig = true, true
	fp.mu.Unlock()
	r.signIn()
	p := html.UnescapeString(r.get("/providers/"))
	if !strings.Contains(p, "OpenAI may see your private data (mail, files) to do tasks. My configuration allows it, so it can't be withdrawn here.") {
		t.Fatalf("page lacks the configuration line:\n%s", p)
	}
	if strings.Contains(p, "Stop OpenAI seeing it") || strings.Contains(p, "OpenAI may not see") || strings.Contains(p, "Allow OpenAI") {
		t.Fatalf("page offers a change the flag overrides:\n%s", p)
	}
	if strings.Contains(p, "can't run until you allow a provider that is connected") {
		t.Fatalf("page says no connected provider is allowed:\n%s", p)
	}
	w := r.post("/providers/", url.Values{"step": {"withdraw"}, "provider": {"openai"}})
	if strings.Contains(html.UnescapeString(w.Body.String()), "Stop OpenAI seeing your private data?") {
		t.Fatalf("withdraw confirmation for a flag-allowed provider:\n%s", w.Body.String())
	}
}

// CRED-5f-mr-addkey-1: past setup the owner adds a provider's key on the
// providers page. It goes to the vault process with the code, which asks
// the provider before it stores anything (ONB-3); the page never keeps
// the key, shows it back or puts it in the address (CRED-1).
func TestAddKeyPastSetupStoresThroughTheVault(t *testing.T) {
	r, _, fp := providerRig(t)
	r.signIn()
	p := html.UnescapeString(r.get("/providers/"))
	for _, want := range []string{`name="step" value="addkey"`, `name="key"`, `type="password"`, `autocomplete="off"`} {
		if !strings.Contains(p, want) {
			t.Fatalf("page lacks %q:\n%s", want, p)
		}
	}
	form := func(code string) url.Values {
		return url.Values{"step": {"addkey"}, "provider": {"anthropic"}, "key": {apiCanary}, "code": {code}}
	}
	// A refused key or no answer from the provider stores nothing, and
	// says so in the owner's words, never the vault's internals.
	for _, c := range []struct {
		err  error
		want string
	}{
		{&VaultError{403, "the provider did not accept the key"}, "the provider did not accept the key"},
		{&VaultError{502, "internal detail"}, "couldn't be checked"},
	} {
		fp.refuseKey = c.err
		w := r.post("/providers/", form(fp.code))
		b := html.UnescapeString(w.Body.String())
		if w.Code != http.StatusOK || !strings.Contains(b, c.want) || strings.Contains(b, "internal detail") || strings.Contains(b, apiCanary) || len(fp.keys) != 0 {
			t.Fatalf("refusal %v: %d %s", c.err, w.Code, b)
		}
	}
	fp.refuseKey = nil
	if w := r.post("/providers/", form("000000")); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "wrong code") || len(fp.keys) != 0 || strings.Contains(w.Body.String(), apiCanary) {
		t.Fatalf("wrong code: %d %s", w.Code, w.Body.String())
	}
	w := r.post("/providers/", form(fp.code))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/providers/" || strings.Contains(w.Header().Get("Location"), apiCanary) {
		t.Fatalf("add: %d %s", w.Code, w.Body.String())
	}
	if fp.keys["anthropic"] != apiCanary {
		t.Fatalf("the vault process got %v", fp.keys)
	}
	if p := html.UnescapeString(r.get("/providers/")); !strings.Contains(p, "Anthropic: connected") || strings.Contains(p, apiCanary) {
		t.Fatalf("after the add:\n%s", p)
	}
	if strings.Contains(r.get("/home"), apiCanary) || strings.Contains(r.get("/status"), apiCanary) {
		t.Fatal("the key shows on another page")
	}
}

// CRED-5f-mr-addkey-3: only the signed-in owner reaches the step; a post
// without sign-in never reaches the vault process, and setup's own key
// route stays closed once setup is finished.
func TestAddKeyPastSetupNeedsTheOwner(t *testing.T) {
	r, _, fp := providerRig(t)
	w := r.post("/providers/", url.Values{"step": {"addkey"}, "provider": {"anthropic"}, "key": {apiCanary}, "code": {fp.code}})
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/unlock?next=") || fp.calls != 0 || len(fp.keys) != 0 {
		t.Fatalf("a post without sign-in: %d %s, %d calls", w.Code, w.Header().Get("Location"), fp.calls)
	}
	if strings.Contains(w.Body.String(), apiCanary) {
		t.Fatal("the refusal showed the key back")
	}
	r.signIn()
	was := len(r.hooks.keys)
	if w := r.post("/setup/ai-key", url.Values{"provider": {"openai"}, "key": {apiCanary + "2"}}); len(r.hooks.keys) != was || r.hooks.keys["openai"] != "" || fp.calls != 0 {
		t.Fatalf("setup's key route took a key after finish: %d", w.Code)
	}
}

// CRED-5f-mr-addkey-1: the ChatGPT plan row signs in with a login, so it
// gets no add-key form; a key row does. Stray spaces around a pasted key
// are dropped before it goes to the vault.
func TestAddKeyFormSkipsThePlanRowAndTrimsTheKey(t *testing.T) {
	r, _, fp := providerRig(t)
	fp.ps = append(fp.ps, ProviderStatus{ID: "codex", Name: "ChatGPT plan", Plan: true})
	r.signIn()
	p := html.UnescapeString(r.get("/providers/"))
	if n := strings.Count(p, `name="step" value="addkey"`); n != 2 {
		t.Fatalf("want an add-key form on the two key rows only, got %d:\n%s", n, p)
	}
	if strings.Contains(p, `value="addkey"><input type="hidden" name="provider" value="codex"`) {
		t.Fatalf("the plan row has an add-key form:\n%s", p)
	}
	w := r.post("/providers/", url.Values{"step": {"addkey"}, "provider": {"anthropic"}, "key": {" " + apiCanary + "\n"}, "code": {fp.code}})
	if w.Code != http.StatusSeeOther || fp.keys["anthropic"] != apiCanary {
		t.Fatalf("add: %d keys %v", w.Code, fp.keys)
	}
}
