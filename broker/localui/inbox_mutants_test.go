package localui

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-14
// showHeld's exact output: a line break shows and ends the character a
// mark may sit on, "[" is escaped and carries a mark, one variation
// selector shows on a symbol and the next is flagged, and a mark after a
// flagged character is flagged too (mutgate on #5194).
func TestShowHeldExactForms(t *testing.T) {
	for _, c := range []struct {
		in, want string
		odd      bool
	}{
		{"a\nb", "a\nb", false},
		{"a\ń", "a\n[U+0301]", true},
		{"[x", "[U+005B]x", false},
		{"\n[́", "\n[U+005B]́", false},
		{"★️️", "★️[U+FE0F]", true},
		{"a​́", "a[U+200B][U+0301]", true},
		{"aㅤb", "a[U+3164]b", true},
		{"\u2605\ufe0f\u0301", "\u2605\ufe0f[U+0301]", true}, // a mark after a shown selector (#5783)
	} {
		if got, odd := showHeld(c.in); got != c.want || odd != c.odd {
			t.Errorf("showHeld(%q) = %q, %v; want %q, %v", c.in, got, odd, c.want, c.odd)
		}
	}
}

// failSaves is a store whose saves fail once fail is set.
type failSaves struct {
	owner.MemStore
	fail bool
}

func (f *failSaves) Save(s owner.State) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.MemStore.Save(s)
}

// The Inbox page refuses other paths, methods and over-long forms, waits
// for the owner channel, is never cached, counts dropped messages, and
// refuses a tap marking an unshown message, a list longer than a page, or
// one the channel could not run (mutgate on #5194).
func TestTheInboxPageRefusesBadRequestsAndShowsCounts(t *testing.T) {
	r := newRig(t)
	r.runSetup()
	st := &failSaves{}
	ch, err := owner.New(owner.Config{Owner: ownerNum, Engine: r.eng, Store: st,
		Secrets: owner.Secrets{TOTPSeed: r.hooks.seed, GridSeed: r.card.GridSeed}, Now: r.clock, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	r.ch = ch
	r.srv.SetOwner(r.page(ch))
	ch.Handle(context.Background(), ownerNum, "keep me")
	ch.Handle(context.Background(), ownerNum, strings.Repeat("x", 160*owner.DefaultHoldSegments))
	// The handler itself, as reached in the moment the channel is gone.
	r.srv.SetOwner(nil)
	w0, want0 := httptest.NewRecorder(), httptest.NewRecorder()
	r.srv.inbox(w0, httptest.NewRequest("GET", "/", nil))
	http.Redirect(want0, httptest.NewRequest("GET", "/", nil), "/status", http.StatusSeeOther)
	if w0.Code != http.StatusSeeOther || w0.Header().Get("Location") != "/status" || w0.Body.String() != want0.Body.String() {
		t.Fatalf("no channel: %d %q %q", w0.Code, w0.Header().Get("Location"), w0.Body.String())
	}
	r.srv.SetOwner(r.page(ch))
	if w := r.post("/unlock", url.Values{"code": {r.code()}}); w.Code != http.StatusSeeOther {
		t.Fatalf("unlock: %d %s", w.Code, w.Body.String())
	}
	var cookie string
	r.do("GET", "/inbox/", nil, func(q *http.Request) { cookie = q.Header.Get("Cookie") })
	// Signed in, so a refusal that went on to draw the page would show it.
	direct := func(method, path, body string) *httptest.ResponseRecorder {
		q := httptest.NewRequest(method, path, strings.NewReader(body))
		q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		q.Header.Set("Cookie", cookie)
		w := httptest.NewRecorder()
		r.srv.inbox(w, q)
		return w
	}
	for _, c := range []struct {
		method, path, body string
		code               int
		want               string
	}{
		{"GET", "/x", "", http.StatusNotFound, "404 page not found\n"},
		{"PUT", "/", "", http.StatusMethodNotAllowed, "Method not allowed\n"},
		{"POST", "/", "shown=" + strings.Repeat("1", 17<<10), http.StatusBadRequest, "Bad request\n"},
	} {
		if w := direct(c.method, c.path, c.body); w.Code != c.code || w.Body.String() != c.want {
			t.Fatalf("%s %s: %d %q", c.method, c.path, w.Code, w.Body.String())
		}
	}
	// The handler marks its own page uncacheable, not only the server.
	if w := direct("GET", "/", ""); w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("direct page: %d, Cache-Control %q", w.Code, w.Header().Get("Cache-Control"))
	}
	w := r.do("GET", "/inbox/", nil)
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q", w.Header().Get("Cache-Control"))
	}
	page := w.Body.String()
	if !strings.Contains(page, "1 more were dropped unread") {
		t.Fatalf("dropped count missing: %s", page)
	}
	shown := regexp.MustCompile(`name="shown" value="([^"]*)"`).FindStringSubmatch(page)
	tok := regexp.MustCompile(`name="tok" value="([^"]*)"`).FindStringSubmatch(page)
	if shown == nil || tok == nil {
		t.Fatalf("form fields missing: %s", page)
	}
	// An empty mark is no shown message: the page refuses it as stale
	// before agentosd, which would refuse it as a bad argument.
	for _, run := range []string{"9", ""} {
		if w := r.post("/inbox/", url.Values{"shown": {shown[1]}, "tok": {tok[1]}, "run": {run}}); !strings.Contains(w.Body.String(), stalePage) {
			t.Fatalf("unshown mark %q: %s", run, w.Body.String())
		}
	}
	// A list longer than a page, signed as the page would sign it.
	var sess string
	r.do("GET", "/inbox/", nil, func(q *http.Request) { sess = tokenKey(cookieToken(q)) })
	ids := make([]string, 65)
	for i := range ids {
		ids[i] = strconv.Itoa(i + 1)
	}
	long := strings.Join(ids, ",")
	if w := r.post("/inbox/", url.Values{"shown": {long}, "tok": {r.srv.formToken(sess, "inbox", long)}}); !strings.Contains(w.Body.String(), stalePage) {
		t.Fatalf("over a page: %s", w.Body.String())
	}
	// The unlock's sign-in text saves from the channel's own goroutine;
	// wait for it so setting fail does not race that save (#5768).
	ch.WaitSends()
	st.fail = true
	if w := r.post("/inbox/", url.Values{"shown": {shown[1]}, "tok": {tok[1]}, "run": {shown[1]}}); !strings.Contains(w.Body.String(), html.EscapeString(inboxUnreachable)) {
		t.Fatalf("failed run: %s", w.Body.String())
	}
}

// When the setup store cannot save the host step's suggested name, the
// step still offers it and keeps it in memory, so the names form is never
// blank (CH-21; mutgate on #5783).
func TestAFailedSaveStillOffersTheSuggestedName(t *testing.T) {
	r, _ := newNamedRig(t)
	st := &failStore{}
	r.srv = r.open(st)
	r.toNames()
	st.mu.Lock()
	st.fail = true
	st.mu.Unlock()
	// As before the host step's first drawing, which suggests the name.
	r.srv.setup.mu.Lock()
	r.srv.setup.st.Name = ""
	r.srv.setup.mu.Unlock()
	box := func() string {
		if m := boxNameRe.FindStringSubmatch(html.UnescapeString(r.get("/setup"))); m != nil {
			return m[1]
		}
		return ""
	}
	first := box()
	if strings.Count(first, " ") != 1 {
		t.Fatalf("suggested %q with the store failing", first)
	}
	if again := box(); again != first {
		t.Errorf("reload suggested %q, then %q", first, again)
	}
}

// An API key of up to 512 characters is taken; a longer one is refused
// before the vault sees it (ONB-3; mutgate on #5783). Synthetic keys only.
func TestAnAPIKeyOfUpTo512CharactersIsTaken(t *testing.T) {
	r := newRig(t)
	r.runSetupToAI()
	long := strings.Repeat("k", 513)
	r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {long}, "private": {"1"}})
	if got := html.UnescapeString(r.setupErr()); !strings.Contains(got, "Paste the API key") || len(r.hooks.keys) != 0 {
		t.Fatalf("513 characters: page says %q, keys %d", got, len(r.hooks.keys))
	}
	r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {long[1:]}, "private": {"1"}})
	if r.hooks.keys["anthropic"] != long[1:] {
		t.Fatalf("512 characters not taken: page says %q", r.setupErr())
	}
}
