package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/route"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CAP-9, CH-3, REV-6, OP-9, CRED-1, OWN-7

func privateBody(provider string, ok bool, code string) map[string]any {
	return map[string]any{"provider": provider, "ok": ok, "code": code}
}

// #1266: after setup the owner lists the providers on the unlock socket
// and changes a provider's private-data answer there. Allowing is a
// tier-4 change, approved with a code that works once; withdrawing
// narrows what leaves the box, as STOP and revoke do, so it needs none.
// The owner is told of each change, and of a wrong code.
func TestTheOwnerChangesAProvidersPrivateAnswerAfterSetup(t *testing.T) {
	r := newFastRig(t, true)
	call := handlerCall(t, r.c)
	if st, _ := call("GET", "/providers", nil); st != http.StatusConflict {
		t.Fatalf("locked list: %d", st)
	}
	if st, _ := call("POST", "/providers/private", privateBody("openai", false, "")); st != http.StatusConflict {
		t.Fatalf("locked withdraw: %d", st)
	}
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	list := func() map[string]modelroute.SetupProvider {
		t.Helper()
		w := httptest.NewRecorder()
		unlockHandler(r.c).ServeHTTP(w, httptest.NewRequest("GET", "/providers", nil))
		if strings.Contains(w.Body.String(), "sk-canary-") {
			t.Fatal("the list carries a key")
		}
		return listed(t, w)
	}
	ps := list()
	if p := ps["openai"]; !p.Connected || p.PrivateOK || p.Name != "OpenAI" {
		t.Fatalf("openai: %+v", p)
	}
	if p := ps["anthropic"]; p.Connected || p.PrivateOK {
		t.Fatalf("anthropic: %+v", p)
	}

	st, out := call("POST", "/providers/private", privateBody("openai", true, "000000"))
	if st == http.StatusNoContent || !strings.HasPrefix(out["error"].(string), "wrong code") {
		t.Fatalf("wrong code: %d %v", st, out)
	}
	if r.c.privateAllowed("openai") || !hasNote(r.notes, "wrong code for allowing a provider private data") {
		t.Fatalf("wrong code allowed it, or the owner was not told: %v", r.notes)
	}
	if st, out := call("POST", "/providers/private", privateBody("openai", true, "")); st == http.StatusNoContent {
		t.Fatalf("no code: %d %v", st, out)
	}

	code := r.next()
	if st, out := call("POST", "/providers/private", privateBody("openai", true, code)); st != http.StatusNoContent {
		t.Fatalf("allow: %d %v", st, out)
	}
	if !r.c.privateAllowed("openai") || !list()["openai"].PrivateOK || !hasNote(r.notes, "private data allowed for OpenAI") {
		t.Fatalf("not allowed, or the owner was not told: %v", r.notes)
	}
	if st, _ := call("POST", "/providers/private", privateBody("anthropic", true, code)); st == http.StatusNoContent || r.c.privateAllowed("anthropic") {
		t.Fatalf("a used code allowed another provider: %d", st)
	}

	if st, out := call("POST", "/providers/private", privateBody("openai", false, "")); st != http.StatusNoContent {
		t.Fatalf("withdraw: %d %v", st, out)
	}
	if r.c.privateAllowed("openai") || list()["openai"].PrivateOK || !hasNote(r.notes, "private data withdrawn for OpenAI") {
		t.Fatalf("not withdrawn, or the owner was not told: %v", r.notes)
	}
	// Withdrawing again changes nothing and still succeeds.
	if st, out := call("POST", "/providers/private", privateBody("openai", false, "")); st != http.StatusNoContent {
		t.Fatalf("withdraw again: %d %v", st, out)
	}
}

// Only a built-in provider has an answer, and a vault entry of another
// kind under the marker's name is never overwritten or removed.
func TestThePrivateAnswerIsOnlyABuiltInProvidersMarker(t *testing.T) {
	r := openRig(t)
	call := handlerCall(t, r.c)
	if st, _ := call("POST", "/providers/private", privateBody("acme", true, r.next())); st != http.StatusBadRequest {
		t.Fatalf("unknown provider: %d", st)
	}
	if st, _ := call("POST", "/providers/private", privateBody("acme", false, "")); st != http.StatusBadRequest {
		t.Fatalf("unknown provider withdraw: %d", st)
	}
	if err := r.c.v.Put(PrivateOKPrefix+"anthropic", vault.KindAPIKey, []byte(synthetic(t, "other-"))); err != nil {
		t.Fatal(err)
	}
	for _, ok := range []bool{true, false} {
		if st, _ := call("POST", "/providers/private", privateBody("anthropic", ok, r.next())); st != http.StatusBadRequest {
			t.Fatalf("other kind, ok=%v: %d", ok, st)
		}
	}
	if !hasKind(r.c.v, PrivateOKPrefix+"anthropic", vault.KindAPIKey) {
		t.Fatal("the other entry was changed")
	}
	if st, _ := call("GET", "/providers/private", nil); st != http.StatusMethodNotAllowed {
		t.Fatalf("GET change: %d", st)
	}
}

// #1266 (P-2 on #1280): the model state says whether any granted
// provider may receive private data, so agentosd's STATUS can say the
// agent cannot do most tasks until the owner allows one. The answer is a
// flag, never a key or a marker's bytes (CRED-1).
func TestTheModelStateSaysWhetherAGrantedProviderMayGetPrivateData(t *testing.T) {
	ctx := context.Background()
	r := newFastRig(t, true)
	agentKeyed(r, nil)
	probe := modelroute.NewStateProbe(serveState(t, r.c))
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	if got := probe(ctx); got != (modelroute.ModelState{Reachable: true, Granted: true, Open: true}) {
		t.Fatalf("granted, not allowed: %+v", got)
	}
	// A marker for a provider the agent has no key for grants nothing private.
	if err := r.c.putPrivate("anthropic", true, r.next()); err != nil {
		t.Fatal(err)
	}
	if got := probe(ctx); got.Private {
		t.Fatalf("allowed only for an ungranted provider: %+v", got)
	}
	if err := r.c.putPrivate("openai", true, r.next()); err != nil {
		t.Fatal(err)
	}
	if got := probe(ctx); got != (modelroute.ModelState{Reachable: true, Granted: true, Open: true, Private: true}) {
		t.Fatalf("granted and allowed: %+v", got)
	}
	r.c.lock()
	if got := probe(ctx); got.Private {
		t.Fatalf("locked: %+v", got)
	}

	// A -grant flag with a -private-ok flag allows private data too.
	f := newFastRig(t, true)
	withGrants(f.c, grants{"agent": {"openai"}}, "")
	f.c.privateFlags = map[string]bool{"openai": true}
	if err := f.c.confirm(f.unlock(t), f.code()); err != nil {
		t.Fatal(err)
	}
	if !f.c.privateGrantedNow() {
		t.Fatal("flags: not private")
	}
	f.c.privateFlags = map[string]bool{"anthropic": true}
	if f.c.privateGrantedNow() {
		t.Fatal("flags: allowed only an ungranted provider")
	}
}

// The model state's JSON names the answer "private" and drops it when
// false, so an older reader sees what it saw before.
func TestTheModelStatePrivateField(t *testing.T) {
	b, err := json.Marshal(modelroute.ModelState{Granted: true, Open: true, Private: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"granted":true,"open":true,"private":true}` {
		t.Fatalf("%s", b)
	}
}

// bind gives custody the -private-ok flags, which the model state reads.
func TestBindCarriesThePrivateFlags(t *testing.T) {
	mw, err := wireModel(route.Rule{"default": {{Provider: "openai", Model: "gpt-test"}}}, grants{"agent": {"openai"}}, map[string]bool{"openai": true}, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := mw.bind(&custody{statePath: filepath.Join(t.TempDir(), "unlock.json")})
	if err != nil {
		t.Fatal(err)
	}
	if !c.privateFlags["openai"] || !c.flagGrants["openai"] {
		t.Fatalf("flags %v, grants %v", c.privateFlags, c.flagGrants)
	}
}

// #1420 (Security S-1 on #1367; CAP-9, OWN-7): a provider that this
// box's -private-ok flag allows does get private data (route.go asks the
// flag before the marker), so the list says it is allowed and that the
// box's configuration allows it. Withdrawing there removes any marker
// but cannot stop the flag, so it is refused and the owner is not told
// it was withdrawn.
func TestTheListSaysWhenThisBoxsConfigurationAllowsPrivateData(t *testing.T) {
	r := openRig(t)
	r.c.privateFlags = map[string]bool{"anthropic": true}
	call := handlerCall(t, r.c)
	list := func() map[string]modelroute.SetupProvider {
		t.Helper()
		w := httptest.NewRecorder()
		unlockHandler(r.c).ServeHTTP(w, httptest.NewRequest("GET", "/providers", nil))
		return listed(t, w)
	}
	if p := list()["anthropic"]; !p.PrivateOK || !p.PrivateByConfig {
		t.Fatalf("flag-allowed: %+v", p)
	}
	if p := list()["openai"]; p.PrivateOK || p.PrivateByConfig {
		t.Fatalf("not allowed: %+v", p)
	}
	if err := r.c.putPrivate("anthropic", true, r.next()); err != nil {
		t.Fatal(err)
	}
	st, out := call("POST", "/providers/private", privateBody("anthropic", false, ""))
	if st != http.StatusConflict || !strings.Contains(out["error"].(string), "configuration") {
		t.Fatalf("withdraw of a flag-allowed provider: %d %v", st, out)
	}
	if hasKind(r.c.v, PrivateOKPrefix+"anthropic", KindPrivateOK) {
		t.Fatal("the marker was kept")
	}
	if hasNote(r.notes, "private data withdrawn for Anthropic") {
		t.Fatalf("the owner was told it was withdrawn: %v", r.notes)
	}
	if p := list()["anthropic"]; !p.PrivateOK || !p.PrivateByConfig {
		t.Fatalf("after the refused withdraw: %+v", p)
	}
}

// Security S1 on #1588 (CAP-9, REV-6; D-115): setup's list reports the
// owner's saved answer as PrivateOK, never the -private-ok flag, since
// setup's box defaults to it and saving the box records a lasting owner
// yes. The flag reaches setup only as PrivateByConfig, so its box shows
// the provider as fixed (#1608).
func TestSetupsListIgnoresThePrivateFlag(t *testing.T) {
	r := providerRig(t)
	r.c.privateFlags = map[string]bool{"anthropic": true}
	r.c.confirm(r.unlock(t), r.code())
	ps := listed(t, setupCall(t, r.c, "GET", "/setup/providers", ""))
	if p := ps["anthropic"]; p.PrivateOK || !p.PrivateByConfig {
		t.Fatalf("setup's list with only the flag: %+v", p)
	}
	if p := ps["openai"]; p.PrivateOK || p.PrivateByConfig {
		t.Fatalf("setup's list for an unflagged provider: %+v", p)
	}
	if w := setupCall(t, r.c, "POST", "/setup/providers/private", `{"provider":"anthropic","ok":true}`); w.Code != http.StatusOK {
		t.Fatalf("private: %d %s", w.Code, w.Body)
	}
	if p := listed(t, setupCall(t, r.c, "GET", "/setup/providers", ""))["anthropic"]; !p.PrivateOK || !p.PrivateByConfig {
		t.Fatalf("setup's list with the owner's yes: %+v", p)
	}
}

// The flag's mark is dropped from the JSON when false, so a reader that
// predates it sees what it saw before.
func TestThePrivateByConfigField(t *testing.T) {
	b, err := json.Marshal(modelroute.SetupProvider{ID: "openai", PrivateOK: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "config") {
		t.Fatalf("%s", b)
	}
}
