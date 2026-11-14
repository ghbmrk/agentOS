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
	"sync/atomic"
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
	} {
		if got, odd := showHeld(c.in); got != c.want || odd != c.odd {
			t.Errorf("showHeld(%q) = %q, %v; want %q, %v", c.in, got, odd, c.want, c.odd)
		}
	}
}

// failSaves is a store whose saves fail once fail is set. fail is atomic
// because the channel saves from its own goroutines.
type failSaves struct {
	owner.MemStore
	fail atomic.Bool
}

func (f *failSaves) Save(s owner.State) error {
	if f.fail.Load() {
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
	w0 := httptest.NewRecorder()
	r.srv.inbox(w0, httptest.NewRequest("GET", "/", nil))
	if w0.Code != http.StatusSeeOther || w0.Header().Get("Location") != "/status" {
		t.Fatalf("no channel: %d %q", w0.Code, w0.Header().Get("Location"))
	}
	r.srv.SetOwner(r.page(ch))
	if w := r.post("/unlock", url.Values{"code": {r.code()}}); w.Code != http.StatusSeeOther {
		t.Fatalf("unlock: %d %s", w.Code, w.Body.String())
	}
	direct := func(method, path, body string) *httptest.ResponseRecorder {
		q := httptest.NewRequest(method, path, strings.NewReader(body))
		q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.srv.inbox(w, q)
		return w
	}
	if w := direct("GET", "/x", ""); w.Code != http.StatusNotFound {
		t.Fatalf("other path: %d", w.Code)
	}
	if w := direct("PUT", "/", ""); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT: %d", w.Code)
	}
	if w := direct("POST", "/", "shown="+strings.Repeat("1", 17<<10)); w.Code != http.StatusBadRequest {
		t.Fatalf("over-long form: %d", w.Code)
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
	if w := r.post("/inbox/", url.Values{"shown": {shown[1]}, "tok": {tok[1]}, "run": {"9"}}); !strings.Contains(w.Body.String(), stalePage) {
		t.Fatalf("unshown mark: %s", w.Body.String())
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
	st.fail.Store(true)
	if w := r.post("/inbox/", url.Values{"shown": {shown[1]}, "tok": {tok[1]}, "run": {shown[1]}}); !strings.Contains(w.Body.String(), html.EscapeString(inboxUnreachable)) {
		t.Fatalf("failed run: %s", w.Body.String())
	}
}
