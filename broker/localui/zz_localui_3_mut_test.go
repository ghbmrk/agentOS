package localui

import (
	"context"
	"errors"
	"io/fs"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: CH-7, CH-8, CH-19, ONB-3, ONB-6

// localui3Kills runs, as subtests of TestHeldStoreKeepsOnlyTheHold, the
// checks that kill MUT-kill-localui-3's (#6767) mutgate survivors in
// setup.go and held.go. Each drives the handler or method itself on a
// bare Server, so the lines it runs stay those two files' own; they are
// subtests because a new top-level localui test widens mutgate's targets
// to the whole package (#6000).
func localui3Kills(t *testing.T) {
	t.Run("HeldStoreLoadNamesEachFailure", l3HeldStoreLoadNamesEachFailure)
	t.Run("HeldPageRefusals", l3HeldPageRefusals)
	t.Run("HeldPageKindsAndHeaders", l3HeldPageKindsAndHeaders)
	t.Run("DoneSetupStepPostGoesToStatus", l3DoneSetupStepPostGoesToStatus)
	t.Run("DoneSetupPageOnlyRedirects", l3DoneSetupPageOnlyRedirects)
	t.Run("FinishingSetupPageOnlyRedirects", l3FinishingSetupPageOnlyRedirects)
	t.Run("NumberCodeRefusals", l3NumberCodeRefusals)
	t.Run("NumberCodePairsAndForgets", l3NumberCodePairsAndForgets)
	t.Run("NumberCodeUnsavedPairingSendsNothing", l3NumberCodeUnsavedPairingSendsNothing)
	t.Run("ClaimBeforePairingPasses", l3ClaimBeforePairingPasses)
	t.Run("ClaimForgetsItsCode", l3ClaimForgetsItsCode)
	t.Run("ClaimCountsTextsInTheHour", l3ClaimCountsTextsInTheHour)
	t.Run("ClaimNamesARandFailure", l3ClaimNamesARandFailure)
	t.Run("NameBeforePairing", l3NameBeforePairing)
	t.Run("CodesNewAndEnrolled", l3CodesNewAndEnrolled)
	t.Run("ConfiguredPrivateClearsItsHold", l3ConfiguredPrivateClearsItsHold)
	t.Run("RefusedSignInDropsItsParkedLink", l3RefusedSignInDropsItsParkedLink)
	t.Run("RetryDropsOrReplacesTheOldLink", l3RetryDropsOrReplacesTheOldLink)
	t.Run("FinishWaitsForTheCard", l3FinishWaitsForTheCard)
}

// l3Store is a SetupStore whose Load or Save fails when its error is set.
type l3Store struct {
	MemStore
	loadErr, saveErr error
}

func (s *l3Store) Load() (SetupState, error) {
	if s.loadErr != nil {
		return SetupState{}, s.loadErr
	}
	return s.MemStore.Load()
}

func (s *l3Store) Save(st SetupState) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	return s.MemStore.Save(st)
}

// l3Owner answers OpHeld with list, or err, and counts its calls.
type l3Owner struct {
	list  localapi.HeldList
	err   error
	calls int
}

func (o *l3Owner) Call(_ context.Context, op string, _, out any) error {
	o.calls++
	if o.err != nil {
		return o.err
	}
	if l, ok := out.(*localapi.HeldList); ok && op == localapi.OpHeld {
		*l = o.list
	}
	return nil
}

// l3Card is an OwnerCard whose Hold refuses until the card is confirmed.
type l3Card struct{}

func (l3Card) Display() *card.Display { return nil }
func (l3Card) Hold() error            { return errors.New("not confirmed") }

// l3Failing is a Rand that always fails.
type l3Failing struct{ err error }

func (f l3Failing) Read([]byte) (int, error) { return 0, f.err }

// l3When is the bare Server's clock.
func l3When() time.Time { return time.Date(2026, 11, 28, 9, 0, 0, 0, time.UTC) }

// l3Setup is a setup on a bare Server with hooks h, state st and store
// store (a MemStore when nil).
func l3Setup(h *fakeHooks, st SetupState, store SetupStore) *setup {
	if store == nil {
		store = &MemStore{}
	}
	cfg := Config{Page: testPage(), Hooks: h, Store: store, Now: l3When, Rand: rand.New(rand.NewSource(3))}
	s := &Server{cfg: cfg, pages: pagesFor(cfg.Page.pageName())}
	s.setup = newSetup(s, st)
	return s.setup
}

func l3Form(path string, form url.Values) *http.Request {
	q := httptest.NewRequest(http.MethodPost, "http://10.42.0.1"+path, strings.NewReader(form.Encode()))
	q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return q
}

// l3Redirected fails unless w is a See Other to loc whose body is only
// http.Redirect's own.
func l3Redirected(t *testing.T, w *httptest.ResponseRecorder, method, loc string) {
	t.Helper()
	want := httptest.NewRecorder()
	http.Redirect(want, httptest.NewRequest(method, "http://10.42.0.1/", nil), loc, http.StatusSeeOther)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != loc || w.Body.String() != want.Body.String() {
		t.Fatalf("%d %q, want a See Other to %s alone:\n%s", w.Code, w.Header().Get("Location"), loc, w.Body.String())
	}
}

// HeldStore's Load fails with Inner's own failure, and with the read's
// own failure for a hold file it cannot read, not as a hold it misread.
func l3HeldStoreLoadNamesEachFailure(t *testing.T) {
	inner := errors.New("inner unreadable")
	if _, err := (HeldStore{Inner: &l3Store{loadErr: inner}, Path: t.TempDir() + "/none.json"}).Load(); !errors.Is(err, inner) {
		t.Fatalf("Inner's failure: %v", err)
	}
	var pe *fs.PathError
	if _, err := (HeldStore{Inner: &MemStore{}, Path: t.TempDir()}).Load(); !errors.As(err, &pe) || strings.Contains(err.Error(), "held answers") {
		t.Fatalf("an unreadable hold file: %v", err)
	}
}

func l3Held(s *Server, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.held(w, httptest.NewRequest(method, "http://10.42.0.1"+path, nil))
	return w
}

func l3HeldServer(o Owner) *Server {
	cfg := Config{Page: testPage()}
	return &Server{cfg: cfg, pages: pagesFor(cfg.Page.pageName()), owner: o}
}

// The Held page answers only its own path and GET or HEAD, sends a box
// with no owner channel to the status page, and a session agentosd
// refuses to sign-in, each without showing the page.
func l3HeldPageRefusals(t *testing.T) {
	o := &l3Owner{}
	s := l3HeldServer(o)
	if w := l3Held(s, http.MethodGet, "/x"); w.Code != http.StatusNotFound || o.calls != 0 {
		t.Fatalf("another path: %d, %d calls", w.Code, o.calls)
	}
	if w := l3Held(s, http.MethodPost, "/"); w.Code != http.StatusMethodNotAllowed || o.calls != 0 {
		t.Fatalf("a POST: %d, %d calls", w.Code, o.calls)
	}
	l3Redirected(t, l3Held(l3HeldServer(nil), http.MethodGet, "/"), http.MethodGet, "/status")
	l3Redirected(t, l3Held(l3HeldServer(&l3Owner{err: Refused(localapi.ErrUnauthorized)}), http.MethodGet, "/"), http.MethodGet, "/unlock?next=/held/")
}

// An expired message shows only as expired, a message of no recorded kind
// as an agent reply, and the page is never cached.
func l3HeldPageKindsAndHeaders(t *testing.T) {
	at := time.Date(2026, 10, 3, 9, 30, 0, 0, time.Local)
	s := l3HeldServer(&l3Owner{list: localapi.HeldList{Items: []localapi.HeldItem{
		{ID: "a1", At: at, Text: "kept reply"},
		{ID: "a0", Kind: localapi.HeldSecret, At: at, Expired: true},
	}}})
	w := l3Held(s, http.MethodGet, "/")
	b := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(b, "Agent reply") || strings.Contains(b, "Held back") || !strings.Contains(b, "A held message from 3 Oct has expired.") {
		t.Fatalf("%d\n%s", w.Code, b)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control %q", cc)
	}
}

// A step posted once setup is done goes to the status page and runs
// nothing.
func l3DoneSetupStepPostGoesToStatus(t *testing.T) {
	h := &fakeHooks{}
	u := l3Setup(h, SetupState{Done: true}, nil)
	mux := http.NewServeMux()
	u.routes(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, l3Form("/setup/number", url.Values{"number": {"+15550100"}}))
	l3Redirected(t, w, http.MethodPost, "/status")
	if len(h.sent) != 0 {
		t.Fatalf("sent %v", h.sent)
	}
}

// The setup page once setup is done is only a redirect to status.
func l3DoneSetupPageOnlyRedirects(t *testing.T) {
	u := l3Setup(&fakeHooks{}, SetupState{Done: true}, nil)
	w := httptest.NewRecorder()
	u.page(w, httptest.NewRequest(http.MethodGet, "http://10.42.0.1/setup", nil))
	l3Redirected(t, w, http.MethodGet, "/status")
	if len(w.Result().Cookies()) != 0 {
		t.Fatalf("cookies %v", w.Result().Cookies())
	}
}

// The setup page that finishes setup as it shows the AI step is only a
// redirect to status.
func l3FinishingSetupPageOnlyRedirects(t *testing.T) {
	const tok = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	h := &fakeHooks{connected: true, progress: Progress{Phase: "ready", Updated: true, Online: true}}
	u := l3Setup(h, SetupState{Owner: "+15550100", Device: tokenKey(tok), Codes: true, Recovery: true, Host: true}, nil)
	q := httptest.NewRequest(http.MethodGet, "http://10.42.0.1/setup", nil)
	q.AddCookie(&http.Cookie{Name: setupCookie, Value: tok})
	w := httptest.NewRecorder()
	u.page(w, q)
	l3Redirected(t, w, http.MethodGet, "/status")
	if !u.done() || h.finishes != 1 {
		t.Fatalf("done %v, %d finishes", u.done(), h.finishes)
	}
}

// The texted number code is refused once paired, before one was sent,
// and when it does not match; none of these pairs.
func l3NumberCodeRefusals(t *testing.T) {
	code := func(form string) *http.Request { return l3Form("/setup/number-code", url.Values{"code": {form}}) }
	u := l3Setup(&fakeHooks{}, SetupState{Owner: "+15550100", Device: "k"}, nil)
	if err := u.numberCode(code(""), "k"); !errors.Is(err, errElsewhere) {
		t.Fatalf("once paired: %v", err)
	}
	u = l3Setup(&fakeHooks{}, SetupState{}, nil)
	if err := u.numberCode(code(""), "k"); err == nil || err.Error() != "That code has expired. Send a new one." || u.st.Owner != "" {
		t.Fatalf("no code sent: %v, owner %q", err, u.st.Owner)
	}
	u.numCode, u.numTo, u.numDevice, u.numExpires = "123456", "+15550100", "k", l3When().Add(time.Minute)
	if err := u.numberCode(code("000000"), "k"); err == nil || err.Error() != "That code did not match." || u.st.Owner != "" {
		t.Fatalf("a wrong code: %v, owner %q", err, u.st.Owner)
	}
}

// The right number code pairs, then forgets the code and every phone's
// pairing code.
func l3NumberCodePairsAndForgets(t *testing.T) {
	h := &fakeHooks{}
	u := l3Setup(h, SetupState{}, nil)
	u.pair, u.pairOrder = map[string]string{"j": "ABCDEFGH"}, []string{"j"}
	u.numCode, u.numTo, u.numDevice, u.numExpires = "123456", "+15550100", "k", l3When().Add(time.Minute)
	if err := u.numberCode(l3Form("/setup/number-code", url.Values{"code": {"123456"}}), "k"); err != nil {
		t.Fatal(err)
	}
	if u.st.Owner != "+15550100" || u.st.Device != "k" || u.numCode != "" || u.numTo != "" || u.numDevice != "" || len(u.pair) != 0 || u.pairOrder != nil {
		t.Fatalf("state %+v, code %q to %q device %q, pair %v %v", u.st, u.numCode, u.numTo, u.numDevice, u.pair, u.pairOrder)
	}
	if len(h.sent) != 1 || h.sent[0].To != "+15550100" {
		t.Fatalf("sent %v", h.sent)
	}
}

// A pairing the store does not save fails with the store's error and
// texts nothing.
func l3NumberCodeUnsavedPairingSendsNothing(t *testing.T) {
	h := &fakeHooks{}
	bad := errors.New("disk full")
	u := l3Setup(h, SetupState{}, &l3Store{saveErr: bad})
	u.pair = map[string]string{"j": "ABCDEFGH"}
	u.numCode, u.numTo, u.numDevice, u.numExpires = "123456", "+15550100", "k", l3When().Add(time.Minute)
	if err := u.numberCode(l3Form("/setup/number-code", url.Values{"code": {"123456"}}), "k"); !errors.Is(err, bad) {
		t.Fatalf("unsaved pairing: %v", err)
	}
	if len(h.sent) != 0 || u.st.Owner != "" || len(u.pair) != 1 {
		t.Fatalf("sent %v, owner %q, pair %v", h.sent, u.st.Owner, u.pair)
	}
}

func l3Claim(code string) *http.Request {
	return l3Form("/setup/claim", url.Values{"code": {code}})
}

// Before pairing, any phone's claim passes and texts nothing.
func l3ClaimBeforePairingPasses(t *testing.T) {
	h := &fakeHooks{}
	u := l3Setup(h, SetupState{}, nil)
	if err := u.claim(l3Claim("123456"), "k"); err != nil || len(h.sent) != 0 || len(u.texts) != 0 {
		t.Fatalf("claim before pairing: %v, sent %v", err, h.sent)
	}
}

// The right page code claims setup for the phone and is then forgotten.
func l3ClaimForgetsItsCode(t *testing.T) {
	u := l3Setup(&fakeHooks{}, SetupState{Owner: "+15550100"}, nil)
	u.claimCode, u.claimExpires = "123456", l3When().Add(time.Minute)
	if err := u.claim(l3Claim("123456"), "k"); err != nil || u.st.Device != "k" || u.claimCode != "" {
		t.Fatalf("claim: %v, device %q, code %q", err, u.st.Device, u.claimCode)
	}
}

// A claim texts a new page code and counts it; texts older than an hour
// no longer count, and NumberTextsPerHour in the hour stop the next.
func l3ClaimCountsTextsInTheHour(t *testing.T) {
	const texted = "That code did not match. I texted you a new page code."
	h := &fakeHooks{}
	u := l3Setup(h, SetupState{Owner: "+15550100"}, nil)
	for i := 0; i < NumberTextsPerHour; i++ {
		u.texts = append(u.texts, l3When().Add(-2*time.Hour))
	}
	if err := u.claim(l3Claim("000000"), "k"); err == nil || err.Error() != texted || len(u.texts) != 1 || len(h.sent) != 1 {
		t.Fatalf("after an hour: %v, %d texts counted, sent %v", err, len(u.texts), h.sent)
	}
	for len(u.texts) < NumberTextsPerHour {
		u.texts = append(u.texts, l3When())
	}
	u.claimCode = ""
	if err := u.claim(l3Claim("000000"), "k"); err == nil || err.Error() != "Too many tries. Try again in an hour." || len(h.sent) != 1 {
		t.Fatalf("over the limit: %v, sent %v", err, h.sent)
	}
}

// A page code the box cannot draw fails with the draw's error, texting
// nothing.
func l3ClaimNamesARandFailure(t *testing.T) {
	h := &fakeHooks{}
	u := l3Setup(h, SetupState{Owner: "+15550100"}, nil)
	bad := errors.New("no entropy")
	u.s.cfg.Rand = l3Failing{bad}
	if err := u.claim(l3Claim("000000"), "k"); !errors.Is(err, bad) || len(h.sent) != 0 || len(u.texts) != 0 {
		t.Fatalf("a failed draw: %v, sent %v, texts %d", err, h.sent, len(u.texts))
	}
}

// Before pairing the names form says to text the box first.
func l3NameBeforePairing(t *testing.T) {
	u := l3Setup(&fakeHooks{}, SetupState{}, nil)
	err := u.name(l3Form("/setup/name", url.Values{"name": {"Juniper"}}), "k")
	if err == nil || err.Error() != "Text your box first; then you can name it." {
		t.Fatalf("name before pairing: %v", err)
	}
}

// "new" asks for a new link and passes; "enrolled" with no sealed seed
// in the vault says to start the step again.
func l3CodesNewAndEnrolled(t *testing.T) {
	u := l3Setup(&fakeHooks{now: l3When}, SetupState{Owner: "+15550100", Device: "k"}, nil)
	u.shown = true
	if err := u.codes(l3Form("/setup/codes", url.Values{"new": {"1"}}), "k"); err != nil || u.shown {
		t.Fatalf("new: %v, shown %v", err, u.shown)
	}
	if err := u.codes(l3Form("/setup/codes", url.Values{"enrolled": {"1"}}), "k"); err == nil || err.Error() != "Start this step again." {
		t.Fatalf("enrolled with no sealed seed: %v", err)
	}
}

// A provider the configuration allows drops the form's kept answer and
// clears its hold, leaving no hold map at all.
func l3ConfiguredPrivateClearsItsHold(t *testing.T) {
	store := &MemStore{}
	u := l3Setup(&fakeHooks{byConfig: map[string]bool{"openai": true}}, SetupState{Unsaved: map[string]bool{"openai": true}}, store)
	u.answer["ai-key openai"] = true
	if err := u.privateOK(l3Form("/setup/ai-key", url.Values{"private": {"1"}}), "ai-key", "openai"); err != nil {
		t.Fatal(err)
	}
	saved, _ := store.Load()
	if _, kept := u.answer["ai-key openai"]; kept || u.st.Unsaved != nil || saved.Unsaved != nil {
		t.Fatalf("answer kept %v, hold %v, saved hold %v", kept, u.st.Unsaved, saved.Unsaved)
	}
}

func l3AIState() SetupState {
	return SetupState{Owner: "+15550100", Device: "k", Codes: true, Recovery: true, Host: true}
}

func l3AIHooks(link string) *fakeHooks {
	return &fakeHooks{deviceLink: link, progress: Progress{Phase: "ready", Updated: true, Online: true}}
}

// A sign-in the page refuses drops a link parked for that provider.
func l3RefusedSignInDropsItsParkedLink(t *testing.T) {
	u := l3Setup(l3AIHooks("http://example.invalid/device"), l3AIState(), nil)
	u.parked["anthropic"] = [3]string{"https://example.invalid/old", "OLD-CODE", "Example"}
	if err := u.aiDevice(l3Form("/setup/ai-device", url.Values{"provider": {"anthropic"}}), "k"); err == nil {
		t.Fatal("a refused sign-in passed")
	}
	if _, parked := u.parked["anthropic"]; parked {
		t.Fatalf("parked %v", u.parked)
	}
}

// A new code the page refuses drops the parked and lapsed links too; a
// new code it shows drops the lapsed one.
func l3RetryDropsOrReplacesTheOldLink(t *testing.T) {
	old := [3]string{"https://example.invalid/old", "OLD-CODE", "Example"}
	retry := l3Form("/setup/ai-retry", url.Values{"provider": {"anthropic"}})
	u := l3Setup(l3AIHooks("http://example.invalid/device"), l3AIState(), nil)
	u.device["anthropic"], u.parked["anthropic"], u.lapsed["anthropic"] = old, old, old
	if err := u.aiRetry(retry, "k"); err == nil || len(u.device)+len(u.parked)+len(u.lapsed) != 0 {
		t.Fatalf("refused: %v, device %v parked %v lapsed %v", err, u.device, u.parked, u.lapsed)
	}
	u = l3Setup(l3AIHooks(""), l3AIState(), nil)
	u.device["anthropic"], u.lapsed["anthropic"] = old, old
	if err := u.aiRetry(l3Form("/setup/ai-retry", url.Values{"provider": {"anthropic"}}), "k"); err != nil || len(u.lapsed) != 0 || u.device["anthropic"][1] != "WXYZ-1234" {
		t.Fatalf("shown: %v, device %v lapsed %v", err, u.device, u.lapsed)
	}
}

// Setup does not finish while the Owner Card is unconfirmed, and tells
// the paired phone why.
func l3FinishWaitsForTheCard(t *testing.T) {
	h := &fakeHooks{connected: true}
	u := l3Setup(h, l3AIState(), nil)
	u.s.cfg.Card = l3Card{}
	u.maybeFinish()
	if u.done() || h.finishCalls != 0 || u.err["k"] != errCardFirst.Error() {
		t.Fatalf("done %v, %d finish calls, err %q", u.done(), h.finishCalls, u.err["k"])
	}
}
