package localui

import (
	"bytes"
	"context"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CAP-3, CH-7, CH-8

// forgetRig is a set-up, signed-in phone whose socket serves FORGET's
// page ops as agentosd does: tasks listed only while the session is
// unlocked, an ask only for a listed task.
type forgetRig struct {
	*rig
	mu    sync.Mutex
	tasks []localapi.ForgetTask
	asked []string
	reply string
}

const forgetCanary = "CANARY-forget"

func newForgetPageRig(t *testing.T) *forgetRig {
	t.Helper()
	f := &forgetRig{rig: newRig(t), reply: "Asked. Nothing is forgotten until you approve the request with a code."}
	f.runSetup()
	ch, err := owner.New(owner.Config{Owner: ownerNum, Modem: modem.NewCarrier().Line(boxNum), Engine: f.eng, Store: &owner.MemStore{},
		Secrets: owner.Secrets{TOTPSeed: f.hooks.seed, GridSeed: f.card.GridSeed}, Now: f.clock, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	f.ch = ch
	f.tasks = []localapi.ForgetTask{
		{ID: "owner:b", Date: "Mon 5 Oct 08:40", Label: `"<b>pay</b> ` + forgetCanary + `" (today 08:40)`},
		{ID: "owner:a", Date: "Sun 4 Oct 18:00", Label: "(a task, yesterday 18:00)"},
	}
	f.srv.SetOwner(f.pageWith(ch, localsrv.Config{
		ForgetTasks: func(unlocked bool) localapi.ForgetTasks {
			f.mu.Lock()
			defer f.mu.Unlock()
			if !unlocked {
				return localapi.ForgetTasks{Locked: true}
			}
			return localapi.ForgetTasks{Tasks: append([]localapi.ForgetTask(nil), f.tasks...)}
		},
		Forget: func(_ context.Context, goal string, unlocked bool) string {
			f.mu.Lock()
			defer f.mu.Unlock()
			if !unlocked {
				return "Your session is locked, so nothing was asked."
			}
			for _, x := range f.tasks {
				if x.ID == goal {
					f.asked = append(f.asked, goal)
					return f.reply
				}
			}
			return "That task isn't in your recent tasks, so nothing was asked."
		},
	}))
	f.signIn()
	return f
}

func (f *forgetRig) askedN() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.asked) }

var forgetFormRe = regexp.MustCompile(`action="/forget/ask"><input type="hidden" name="task" value="([^"]+)"><input type="hidden" name="tok" value="([^"]+)">`)

// forgetForm returns the page's form for task id.
func (f *forgetRig) forgetForm(id string) url.Values {
	f.t.Helper()
	for _, m := range forgetFormRe.FindAllStringSubmatch(f.get("/forget/"), -1) {
		if m[1] == id {
			return url.Values{"task": {m[1]}, "tok": {m[2]}}
		}
	}
	f.t.Fatalf("no forget form for %s", id)
	return nil
}

// W3-forget-b3r (potency R2): a signed-in phone sees the recent tasks by
// FORGET's labels and asks to forget one; the page says it asked, never
// that the task is forgotten, and the ask is FORGET's own (CAP-3).
func TestTheForgetPageListsRecentTasksAndAsksToForgetOne(t *testing.T) {
	f := newForgetPageRig(t)
	if !strings.Contains(f.get("/home"), `href="/forget/"`) {
		t.Fatal("home does not link the forget page")
	}
	p := f.get("/forget/")
	if !strings.Contains(p, `<bdi>&#34;&lt;b&gt;pay&lt;/b&gt; `+forgetCanary+`&#34; (today 08:40)</bdi>`) || strings.Contains(p, "<b>pay") ||
		!strings.Contains(p, "<bdi>(a task, yesterday 18:00)</bdi>") {
		t.Fatalf("page:\n%s", p)
	}
	if strings.Index(p, "today 08:40") > strings.Index(p, "yesterday 18:00") {
		t.Fatal("not in the listed order")
	}
	w := f.post("/forget/ask", f.forgetForm("owner:a"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `<p class="ok">`+f.reply+`</p>`) {
		t.Fatalf("ask: %d %s", w.Code, w.Body.String())
	}
	if strings.Join(f.asked, ",") != "owner:a" {
		t.Fatalf("asked %v", f.asked)
	}
	// The page's own words never say a task is forgotten.
	for _, b := range f.seen {
		if strings.Contains(b, "Forgotten") || strings.Contains(strings.ReplaceAll(b, f.reply, ""), "forgotten") {
			t.Fatalf("page says forgotten:\n%s", b)
		}
	}
	// A task that agentosd no longer lists gets its fixed words.
	g := f.forgetForm("owner:b")
	f.mu.Lock()
	f.tasks = f.tasks[1:]
	f.mu.Unlock()
	if w := f.post("/forget/ask", g); !strings.Contains(w.Body.String(), "isn&#39;t in your recent tasks") {
		t.Fatalf("unlisted: %s", w.Body.String())
	}
	if f.askedN() != 1 {
		t.Fatalf("asked %v", f.asked)
	}
	f.mu.Lock()
	f.tasks = nil
	f.mu.Unlock()
	if !strings.Contains(f.get("/forget/"), "No recent tasks to forget.") {
		t.Fatal("empty page")
	}
}

// CH-7, CH-8: signed out, the page neither lists nor asks; a GET never
// asks; a cross-site POST is refused before it reaches the page.
func TestTheForgetPageRefusesSignedOutGetAndCrossSite(t *testing.T) {
	f := newForgetPageRig(t)
	form := f.forgetForm("owner:a")
	f.asOther(func() {
		for _, m := range []string{"GET", "POST"} {
			for _, path := range []string{"/forget/", "/forget/ask"} {
				w := f.do(m, path, form)
				if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/unlock?next=") ||
					strings.Contains(w.Body.String(), forgetCanary) {
					t.Fatalf("signed out %s %s: %d %s", m, path, w.Code, w.Header().Get("Location"))
				}
			}
		}
	})
	if w := f.do("GET", "/forget/ask?"+form.Encode(), nil); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "POST" {
		t.Fatalf("GET ask: %d", w.Code)
	}
	if w := f.do("GET", "/forget/?"+form.Encode(), nil); w.Code != http.StatusOK {
		t.Fatalf("GET list: %d", w.Code)
	}
	if w := f.do("POST", "/forget/", form); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST list: %d", w.Code)
	}
	if w := f.do("GET", "/forget/other", nil); w.Code != http.StatusNotFound {
		t.Fatalf("other path: %d", w.Code)
	}
	for _, mod := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") },
		func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") },
	} {
		if w := f.do("POST", "/forget/ask", form, mod); w.Code != http.StatusForbidden {
			t.Fatalf("cross-site: %d", w.Code)
		}
	}
	if f.askedN() != 0 {
		t.Fatalf("asked %v", f.asked)
	}
}

// The form is bound to this phone's sign-in and the task shown: another
// phone's replay, a changed task or a missing token ask nothing.
func TestAForgetFormIsBoundToThePhoneAndTheTask(t *testing.T) {
	f := newForgetPageRig(t)
	form := f.forgetForm("owner:a")
	for _, g := range []url.Values{
		{"task": {"owner:b"}, "tok": form["tok"]},
		{"task": form["task"]},
		{"task": form["task"], "tok": {form.Get("tok") + "0"}},
		{"task": {"owner:a", "owner:b"}, "tok": form["tok"]},
		{},
	} {
		if w := f.post("/forget/ask", g); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), forgetStaleText) {
			t.Fatalf("%v: %d %s", g, w.Code, w.Body.String())
		}
	}
	f.asOther(func() {
		f.signIn()
		if w := f.post("/forget/ask", form); !strings.Contains(w.Body.String(), forgetStaleText) {
			t.Fatalf("other phone: %s", w.Body.String())
		}
	})
	if f.askedN() != 0 {
		t.Fatalf("asked %v", f.asked)
	}
}

// Locked (CH-21): the page lists nothing and an ask asks nothing, with
// fixed words; signed back in, the page lists again.
func TestALockedSessionShowsNoTasks(t *testing.T) {
	f := newForgetPageRig(t)
	form := f.forgetForm("owner:a")
	if err := f.ch.RequireUnlock(); err != nil {
		t.Fatal(err)
	}
	w := f.do("GET", "/forget/", nil)
	if strings.Contains(w.Body.String(), forgetCanary) || strings.Contains(w.Body.String(), "a task, yesterday") ||
		(w.Code != http.StatusSeeOther && !strings.Contains(w.Body.String(), "Your session is locked")) {
		t.Fatalf("locked list: %d %s", w.Code, w.Body.String())
	}
	f.post("/forget/ask", form)
	if f.askedN() != 0 {
		t.Fatalf("asked %v", f.asked)
	}
}

// The page logs nothing of a task (no canary in the logs) and fails
// closed when the box does not answer.
func TestTheForgetPageLogsNoTaskWords(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	f := newForgetPageRig(t)
	f.post("/forget/ask", f.forgetForm("owner:b"))
	f.srv.SetOwner(f.pageWith(f.ch, localsrv.Config{}))
	f.signIn()
	if p := f.get("/forget/"); !strings.Contains(p, template.HTMLEscapeString(pausedUnreachable)) || strings.Contains(p, forgetCanary) {
		t.Fatalf("no hook: %s", p)
	}
	if strings.Contains(buf.String(), forgetCanary) {
		t.Fatalf("logged %q", buf.String())
	}
}
