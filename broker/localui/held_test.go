package localui

// REQ: CH-19, CH-21, CH-8

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
)

// TestHeldPageShowsAndKeeps (HELD-3): a signed-in phone sees each kept
// text verbatim and escaped, with no link made live, sees it again on a
// second read, and an expired one says it has expired. Signed out, the
// page sends the phone to sign in and shows nothing.
func TestHeldPageShowsAndKeeps(t *testing.T) {
	a := newApprovalRig(t)
	at := time.Date(2026, 10, 3, 9, 30, 0, 0, time.Local)
	list := localapi.HeldList{Items: []localapi.HeldItem{
		{ID: "a1", Kind: localapi.HeldCode, At: at.Add(time.Hour), Text: "I fixed the code <script>alert('CANARY')</script> see https://evil.example/x"},
		{ID: "a0", Kind: localapi.HeldSecret, At: at, Expired: true},
	}}
	reads := 0
	a.srv.SetOwner(a.pageWith(a.ch, localsrv.Config{Held: func() localapi.HeldList { reads++; return list }}))
	a.signIn()
	if !strings.Contains(a.get("/home"), `href="/held/"`) {
		t.Fatal("home does not link the held messages")
	}
	for range 2 {
		p := a.get("/held/")
		if !strings.Contains(p, "I fixed the code &lt;script&gt;alert(&#39;CANARY&#39;)&lt;/script&gt;") || strings.Contains(p, "<script>alert") ||
			strings.Contains(p, `href="https://evil`) || !strings.Contains(p, "Held back: it mentioned a code") || !strings.Contains(p, "3 Oct 2026, 10:30") {
			t.Fatalf("page:\n%s", p)
		}
		if !strings.Contains(p, "A held message from 3 Oct has expired.") {
			t.Fatalf("no expired line:\n%s", p)
		}
	}
	if reads < 2 {
		t.Fatalf("read %d times", reads)
	}
	a.post("/signout", nil)
	if w := a.do("GET", "/held/", nil); w.Code != http.StatusSeeOther || strings.Contains(w.Body.String(), "CANARY") {
		t.Fatalf("signed out: %d", w.Code)
	}
}

// TestHeldPageEmptyAndUnreachable: with nothing kept the page says so;
// with no held op it says it cannot show them, never that nothing is
// held.
func TestHeldPageEmptyAndUnreachable(t *testing.T) {
	a := newApprovalRig(t)
	if p := a.get("/held/"); !strings.Contains(p, "show held messages right now") || strings.Contains(p, "Nothing is held.") {
		t.Fatalf("no op:\n%s", p)
	}
	a.srv.SetOwner(a.pageWith(a.ch, localsrv.Config{Held: func() localapi.HeldList { return localapi.HeldList{} }}))
	a.signIn()
	if p := a.get("/held/"); !strings.Contains(p, "Nothing is held.") {
		t.Fatalf("empty:\n%s", p)
	}
}
