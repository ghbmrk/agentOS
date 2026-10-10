package localui

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: CH-3, CH-10, CH-7

var resumeFormRe = regexp.MustCompile(`name="grant" value="([^"]+)"><input type="hidden" name="pause" value="([^"]+)"><input type="hidden" name="tok" value="([^"]+)"`)

// resumeForm returns the page's resume form for grant id.
func (a *approvalRig) resumeForm(id string) url.Values {
	a.t.Helper()
	for _, m := range resumeFormRe.FindAllStringSubmatch(a.get("/paused/"), -1) {
		if m[1] == id {
			return url.Values{"grant": {m[1]}, "pause": {m[2]}, "tok": {m[3]}}
		}
	}
	a.t.Fatalf("no resume form for %s", id)
	return nil
}

// W5a-resume: a signed-in phone sees each paused grant, what resuming lets
// run again and who paused it, and asks to resume it; the ask is then
// approved under Approvals with a fresh code (the gate's tests).
func TestThePausedPageAsksToResumeAGrant(t *testing.T) {
	a := newApprovalRig(t)
	if !strings.Contains(a.get("/home"), `href="/paused/"`) {
		t.Fatal("home does not link the paused grants")
	}
	if !strings.Contains(a.get("/paused/"), "Nothing is paused.") {
		t.Fatal("empty page")
	}
	a.paused.grants = []localapi.PausedGrant{
		{ID: "G2", What: "Read mail as <b>CANARY</b>.", By: "Loop 2", Pause: "loop2/pause/0a1b"},
		{ID: "G3", What: "Pay up to $5.", By: "you", Pause: "owner/pause/7"},
	}
	p := a.get("/paused/")
	if !strings.Contains(p, "G2") || !strings.Contains(p, "Read mail as &lt;b&gt;CANARY&lt;/b&gt;.") || strings.Contains(p, "<b>CANARY") ||
		!strings.Contains(p, "Paused by Loop 2.") || !strings.Contains(p, "Paused by you.") {
		t.Fatalf("page:\n%s", p)
	}
	f := a.resumeForm("G2")
	if w := a.post("/paused/", f); !strings.Contains(w.Body.String(), `<p class="ok">Asked to resume G2.</p>`) {
		t.Fatalf("ask: %s", w.Body.String())
	}
	// The form names the grant and the pause as shown; any other is stale.
	for _, k := range []string{"grant", "pause"} {
		g := url.Values{"grant": f["grant"], "pause": f["pause"], "tok": f["tok"]}
		g.Set(k, "G3")
		if w := a.post("/paused/", g); !strings.Contains(w.Body.String(), "This page is out of date") {
			t.Fatalf("%s changed: %s", k, w.Body.String())
		}
	}
	a.asOther(func() {
		a.signIn()
		if w := a.post("/paused/", f); !strings.Contains(w.Body.String(), "This page is out of date") {
			t.Fatalf("other phone: %s", w.Body.String())
		}
	})
	if w := a.do("POST", "/paused/", f, func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") }); w.Code != http.StatusForbidden {
		t.Fatalf("cross-site: %d", w.Code)
	}
	if len(a.paused.asked) != 1 {
		t.Fatalf("asked %v", a.paused.asked)
	}
	// A grant resumed or paused again since gets the gate's fixed words;
	// a failure gets the page's own, never the error.
	a.paused.grants[1].Pause = "owner/pause/8"
	g := a.resumeForm("G3")
	a.paused.grants[1].Pause = "owner/pause/9"
	if w := a.post("/paused/", g); !strings.Contains(w.Body.String(), "no longer paused as this page showed it") {
		t.Fatalf("re-paused: %s", w.Body.String())
	}
	a.paused.grants = append(a.paused.grants, localapi.PausedGrant{ID: "G9", What: "x", By: "you", Pause: "p9"})
	g = a.resumeForm("G9")
	a.paused.grants = a.paused.grants[:2]
	if w := a.post("/paused/", g).Body.String(); !strings.Contains(w, "Nothing was asked") || strings.Contains(w, "/var/lib") {
		t.Fatalf("failure: %s", w)
	}
	a.post("/signout", url.Values{})
	if w := a.do("GET", "/paused/", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("signed out: %d", w.Code)
	}
	if w := a.do("POST", "/paused/", f); w.Code != http.StatusSeeOther || len(a.paused.asked) != 1 {
		t.Fatalf("signed out ask: %d %v", w.Code, a.paused.asked)
	}
}
