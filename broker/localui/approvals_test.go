package localui

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-10, CH-7

// approvalRig is a set-up box whose owner channel records its decisions,
// with this phone signed in.
type approvalRig struct {
	*rig
	mu        sync.Mutex
	decisions []owner.Decision
	carrier   *modem.Carrier
}

func newApprovalRig(t *testing.T) *approvalRig {
	t.Helper()
	a := &approvalRig{rig: newRig(t)}
	a.runSetup()
	a.carrier = modem.NewCarrier()
	ch, err := owner.New(owner.Config{Owner: ownerNum, Modem: a.carrier.Line(boxNum), Engine: a.eng, Store: &owner.MemStore{},
		Secrets: owner.Secrets{TOTPSeed: a.hooks.seed, GridSeed: a.card.GridSeed}, Now: a.clock, Location: time.UTC,
		Decide: func(d owner.Decision) { a.mu.Lock(); a.decisions = append(a.decisions, d); a.mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	a.ch = ch
	a.srv.SetOwner(a.page(ch))
	a.signIn()
	return a
}

func (a *approvalRig) decided() []owner.Decision {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]owner.Decision(nil), a.decisions...)
}

// pageItem is an action whose recipients cannot be texted: a Cyrillic
// look-alike, a right-to-left override, and markup.
func pageItem(ref string) owner.Item {
	return owner.Item{Ref: ref, Object: "invoice 1042", Recipient: "bіlling@acme.example, \u202eelpmaxe.emca@sllib, <b>CANARY</b>@acme.example",
		Facts: owner.Facts{Verb: "send", RecipientChecked: true, RecipientExists: true, RecipientByOwner: true}}
}

var formRe = regexp.MustCompile(`name="id" value="([^"]+)"><input type="hidden" name="tok" value="([^"]+)"><input type="hidden" name="sum" value="([^"]+)"`)

// form returns the id and token of the page's form for request id.
func (a *approvalRig) form(id string) url.Values {
	a.t.Helper()
	for _, m := range formRe.FindAllStringSubmatch(a.get("/approvals/"), -1) {
		if m[1] == id {
			return url.Values{"id": {m[1]}, "tok": {m[2]}, "sum": {m[3]}}
		}
	}
	a.t.Fatalf("no form for %s", id)
	return nil
}

func answer(f url.Values, word, code string) url.Values {
	g := url.Values{}
	for k, v := range f {
		g[k] = v
	}
	g.Set("answer", word)
	if code != "" {
		g.Set("code", code)
	}
	return g
}

// P2-2a: the page lists each open request with every recipient in full,
// one per line, escaped, and any character outside plain ASCII shown as
// its code point, so a look-alike or a reversed address is visible
// rather than rendered (SR2-1).
func TestTheApprovalsPageShowsEveryRecipientAsItIs(t *testing.T) {
	a := newApprovalRig(t)
	if !strings.Contains(a.get("/home"), `href="/approvals/"`) {
		t.Fatal("home does not list approvals")
	}
	if !strings.Contains(a.get("/approvals/"), "Nothing is waiting for you.") || strings.Contains(a.get("/home"), "waiting for you") {
		t.Fatal("empty page")
	}
	id, err := a.ch.RequestLocal(pageItem("i1"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.get("/home"), `<a href="/approvals/">1 waiting for you</a>`) {
		t.Fatal("home does not count it (UX A4)")
	}
	p := a.get("/approvals/")
	for _, want := range []string{id, "invoice 1042", "b[U+0456]lling@acme.example", "[U+202E]elpmaxe.emca@sllib",
		"<b>CANARY</b>@acme.example", "unusual character", "3 recipients", "Answer before", "Can't be shown in a text"} {
		if !strings.Contains(html.UnescapeString(p), want) {
			t.Fatalf("page lacks %q:\n%s", want, p)
		}
	}
	for _, bad := range []string{"bіlling", "\u202e", "<b>CANARY"} {
		if strings.Contains(p, bad) {
			t.Fatalf("page renders %q", bad)
		}
	}
	// A literal "[U+...]" in an address cannot pass for an escape.
	if got, odd := showField("a[U+0041]"); got != "a[U+005B]U+0041]" || !odd {
		t.Fatalf("showField: %q %v", got, odd)
	}
	if got, odd := showField("billing@acme.example"); got != "billing@acme.example" || odd {
		t.Fatalf("plain: %q %v", got, odd)
	}
	// One recipient per line.
	if n := strings.Count(p, `<li class="mono">`); n != 3 {
		t.Fatalf("%d recipient lines", n)
	}

	// Without sign-in the page and its answers are closed (CH-7).
	a.post("/signout", url.Values{})
	if w := a.do("GET", "/approvals/", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("signed out: %d", w.Code)
	}
}

// Approving on the page takes a fresh code every time, even signed in;
// denying needs none. Both reach the broker as decisions and are texted to
// the owner.
func TestThePageApprovesOnlyWithACode(t *testing.T) {
	a := newApprovalRig(t)
	id, _ := a.ch.RequestLocal(pageItem("i1"), 0)
	f := a.form(id)
	if w := a.post("/approvals/", answer(f, "approve", "")); w.Code != 200 || !strings.Contains(w.Body.String(), "Enter a code") {
		t.Fatalf("no code: %d %s", w.Code, w.Body.String())
	}
	if w := a.post("/approvals/", answer(f, "approve", "000000")); !strings.Contains(w.Body.String(), "Wrong code for "+id+". 2 tries left.") {
		t.Fatalf("wrong code: %s", w.Body.String())
	}
	if len(a.decided()) != 0 {
		t.Fatal("decided without a code")
	}
	// The wrong code voids nothing yet (WrongPerRequest is 3); a good one approves.
	f = a.form(id)
	w := a.post("/approvals/", answer(f, "approve", a.code()))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Approved "+id+". Your agent can go ahead.") {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
	if d := a.decided(); len(d) != 1 || !d[0].Approved || d[0].Ref != "i1" {
		t.Fatalf("decisions %+v", d)
	}
	if strings.Contains(a.get("/approvals/"), id) {
		t.Fatal("still listed")
	}

	id2, _ := a.ch.RequestLocal(pageItem("i2"), 0)
	if w := a.post("/approvals/", answer(a.form(id2), "deny", "")); !strings.Contains(w.Body.String(), `<p class="ok">Denied `+id2+`.</p>`) {
		t.Fatalf("deny: %s", w.Body.String())
	}
	if d := a.decided(); len(d) != 2 || d[1].Approved || d[1].Ref != "i2" {
		t.Fatalf("decisions %+v", d)
	}
	// Told to the owner, coalesced with the sign-in an hour ago (UX A6).
	a.advance(owner.SignInAlertEvery)
	a.ch.FlushLocal()
	var told []string
	for _, m := range a.carrier.Log() {
		if m.To == ownerNum {
			told = append(told, m.Text)
		}
	}
	all := strings.Join(told, "\n")
	if !strings.Contains(all, "On my Wi-Fi page: Approved "+id+" at ") || !strings.Contains(all, "Denied "+id2+" at ") {
		t.Fatalf("owner told %q", all)
	}
}

// A form only answers the request it was shown for, on the phone it was
// shown to, until that request's expiry: a forged, foreign or stale form
// is refused, and cross-site posts never reach the handler.
func TestOnlyTheFormShownAnswersItsRequest(t *testing.T) {
	a := newApprovalRig(t)
	id, _ := a.ch.RequestLocal(pageItem("i1"), 0)
	f := a.form(id)
	for name, g := range map[string]url.Values{
		"forged":    {"id": {id}, "tok": {strings.Repeat("0", 64)}},
		"no token":  {"id": {id}},
		"other id":  {"id": {"Q9"}, "tok": f["tok"], "sum": f["sum"]},
		"other sum": {"id": {id}, "tok": f["tok"], "sum": {strings.Repeat("1", 64)}},
	} {
		if w := a.post("/approvals/", answer(g, "deny", "")); !strings.Contains(w.Body.String(), "This page is out of date") {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	// Another signed-in phone cannot replay this phone's form.
	a.asOther(func() {
		a.signIn()
		if w := a.post("/approvals/", answer(f, "deny", "")); !strings.Contains(w.Body.String(), "This page is out of date") {
			t.Fatalf("other phone: %s", w.Body.String())
		}
	})
	if w := a.do("POST", "/approvals/", answer(f, "deny", ""), func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") }); w.Code != http.StatusForbidden {
		t.Fatalf("cross-site: %d", w.Code)
	}
	if len(a.decided()) != 0 {
		t.Fatal("a refused form decided")
	}
	// Once the request closes, its form is stale.
	if _, err := a.ch.LocalAnswer(id, f.Get("sum"), false, ""); err != nil {
		t.Fatal(err)
	}
	if w := a.post("/approvals/", answer(f, "deny", "")); !strings.Contains(w.Body.String(), "This page is out of date") {
		t.Fatalf("closed: %s", w.Body.String())
	}
	if len(a.decided()) != 1 {
		t.Fatalf("decisions %+v", a.decided())
	}
	// A request that changed since the page showed it is refused too.
	tid, err := a.ch.Request([]owner.Item{pageItemText("t1"), pageItemText("t2")}, 0)
	if err != nil {
		t.Fatal(err)
	}
	g := a.form(tid)
	a.ch.Handle(context.Background(), ownerNum, "NO "+tid+" 2")
	if w := a.post("/approvals/", answer(g, "deny", "")); !strings.Contains(w.Body.String(), "This page is out of date") {
		t.Fatalf("changed: %s", w.Body.String())
	}
	if d := a.decided(); len(d) != 2 || d[1].Ref != "t2" {
		t.Fatalf("decisions %+v", d)
	}
}

func pageItemText(ref string) owner.Item {
	return owner.Item{Ref: ref, Object: "invoice 8", Recipient: "ops@acme.example",
		Facts: owner.Facts{Verb: "send", RecipientChecked: true, RecipientExists: true, RecipientByOwner: true}}
}

// Security D5: one phone gets PageWrongPerMinute wrong approval codes a
// minute across requests; denying still works meanwhile.
func TestWrongCodesFromOnePhoneAreBounded(t *testing.T) {
	a := newApprovalRig(t)
	var ids []string
	for i := 0; i < 3; i++ {
		id, _ := a.ch.RequestLocal(pageItem(fmt.Sprint("i", i)), 0)
		ids = append(ids, id)
	}
	for n := 0; n < PageWrongPerMinute; n++ {
		id := ids[n/2]
		if w := a.post("/approvals/", answer(a.form(id), "approve", "000000")); !strings.Contains(w.Body.String(), "Wrong code") {
			t.Fatalf("wrong %d: %s", n, w.Body.String())
		}
	}
	if w := a.post("/approvals/", answer(a.form(ids[2]), "approve", a.code())); !strings.Contains(w.Body.String(), "Wait a minute") {
		t.Fatalf("over the bound: %s", w.Body.String())
	}
	if w := a.post("/approvals/", answer(a.form(ids[2]), "deny", "")); !strings.Contains(w.Body.String(), "Denied "+ids[2]+".") {
		t.Fatalf("deny: %s", w.Body.String())
	}
	a.advance(time.Minute)
	// Security R2: with the per-phone table full, an unknown phone's
	// approval is refused rather than unbounded.
	a.srv.mu.Lock()
	for i := 0; i < MaxSessions*2; i++ {
		a.srv.pageWrong[fmt.Sprint("other", i)] = []time.Time{a.clock()}
	}
	a.srv.mu.Unlock()
	full, _ := a.ch.RequestLocal(pageItem("k"), 0)
	if w := a.post("/approvals/", answer(a.form(full), "approve", a.code())); !strings.Contains(w.Body.String(), "Wait a minute") {
		t.Fatalf("full table: %s", w.Body.String())
	}
	a.srv.mu.Lock()
	a.srv.pageWrong = nil
	a.srv.mu.Unlock()
	id, _ := a.ch.RequestLocal(pageItem("j"), 0)
	if w := a.post("/approvals/", answer(a.form(id), "approve", a.code())); !strings.Contains(w.Body.String(), "Approved "+id+".") {
		t.Fatalf("after a minute: %s", w.Body.String())
	}
}

// L3 S-b on #165: parallel approvals cannot pass the per-phone bound
// together. With one slot left, of several wrong codes posted at once only
// one reaches the owner channel.
func TestParallelPostsKeepThePerPhoneBound(t *testing.T) {
	a := newApprovalRig(t)
	for i := 0; i < PageWrongPerMinute-1; i++ {
		if i%2 == 0 {
			a.ch.RequestLocal(pageItem(fmt.Sprint("w", i)), 0)
		}
		open := a.ch.LocalRequests()
		id := open[len(open)-1].ID
		a.post("/approvals/", answer(a.form(id), "approve", fmt.Sprintf("%06d", i)))
	}
	id, _ := a.ch.RequestLocal(pageItem("p"), 0)
	f := a.form(id)
	// Each answer takes a while, so the posts overlap in the channel if
	// the bound lets them through together.
	a.served.Owner = slowOwner{a.ch}
	var mu sync.Mutex
	var wrong, held int
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := a.post("/approvals/", answer(f, "approve", fmt.Sprintf("1%05d", i))).Body.String()
			mu.Lock()
			defer mu.Unlock()
			switch {
			case strings.Contains(body, "Wrong code"):
				wrong++
			case strings.Contains(body, "Wait a minute"):
				held++
			}
		}(i)
	}
	wg.Wait()
	if wrong != 1 || held != 4 {
		t.Fatalf("%d reached the channel as wrong, %d held back", wrong, held)
	}
}

type slowOwner struct{ *owner.Channel }

func (o slowOwner) LocalAnswer(id, sum string, approve bool, code string) (string, error) {
	time.Sleep(50 * time.Millisecond)
	return o.Channel.LocalAnswer(id, sum, approve, code)
}

// Security F1 on #171: the texted code offered on the page gets its hint
// and counts against the phone's page bound, so the page is no uncounted
// oracle for it; the channel's own bounds still do not count it.
func TestTheTextedCodeOnThePageCountsForThePhone(t *testing.T) {
	a := newApprovalRig(t)
	id, err := a.ch.Request([]owner.Item{pageItemText("t1")}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var texted string
	for _, m := range a.carrier.Log() {
		if s := regexp.MustCompile(`Reply YES ` + id + ` (\d+) `).FindStringSubmatch(m.Text); s != nil {
			texted = s[1]
		}
	}
	if texted == "" {
		t.Fatal("no texted code")
	}
	for i := 0; i < PageWrongPerMinute; i++ {
		if w := a.post("/approvals/", answer(a.form(id), "approve", texted)); !strings.Contains(w.Body.String(), "That&#39;s the code I texted.") {
			t.Fatalf("try %d: %s", i, w.Body.String())
		}
	}
	if w := a.post("/approvals/", answer(a.form(id), "approve", texted)); !strings.Contains(w.Body.String(), "Too many wrong codes from this phone.") {
		t.Fatalf("sixth: %s", w.Body.String())
	}
	if len(a.decided()) != 0 || len(a.ch.LocalRequests()) != 1 {
		t.Fatal("decided or voided")
	}
}

// L3 SHOULD on #171: a try that was not wrong gives its slot back, so
// after 4 wrong codes and a right one, a 5th wrong code still reaches the
// channel rather than the phone's bound.
func TestARightCodeGivesItsSlotBack(t *testing.T) {
	a := newApprovalRig(t)
	var ids []string
	for i := 0; i < 4; i++ {
		id, _ := a.ch.RequestLocal(pageItem(fmt.Sprint("s", i)), 0)
		ids = append(ids, id)
	}
	for n := 0; n < PageWrongPerMinute-1; n++ {
		if w := a.post("/approvals/", answer(a.form(ids[n/2]), "approve", "000000")); !strings.Contains(w.Body.String(), "Wrong code") {
			t.Fatalf("wrong %d: %s", n, w.Body.String())
		}
	}
	if w := a.post("/approvals/", answer(a.form(ids[2]), "approve", a.code())); !strings.Contains(w.Body.String(), "Approved "+ids[2]+".") {
		t.Fatalf("right: %s", w.Body.String())
	}
	if w := a.post("/approvals/", answer(a.form(ids[3]), "approve", "000000")); !strings.Contains(w.Body.String(), "Wrong code") {
		t.Fatalf("5th wrong: %s", w.Body.String())
	}
}

// L3 nit on #171: an unlock proof offered as an approval code counts
// against the phone's bound like any wrong code.
func TestAnUnlockProofCountsForThePhone(t *testing.T) {
	a := newApprovalRig(t)
	id, _ := a.ch.RequestLocal(pageItem("u1"), 0)
	for i := 0; i < PageWrongPerMinute; i++ {
		if w := a.post("/approvals/", answer(a.form(id), "approve", owner.UnlockProofPrefix+"CANARY")); !strings.Contains(w.Body.String(), "That code did not work.") {
			t.Fatalf("try %d: %s", i, w.Body.String())
		}
	}
	if w := a.post("/approvals/", answer(a.form(id), "approve", a.code())); !strings.Contains(w.Body.String(), "Too many wrong codes from this phone.") {
		t.Fatalf("sixth: %s", w.Body.String())
	}
}

// UX U-2A-1 on P2-2a part 2: next to the buttons, the card says what
// approving lets the agent do, in the broker's own fields.
func TestTheCardSaysWhatApprovingLetsTheAgentDo(t *testing.T) {
	a := newApprovalRig(t)
	id, _ := a.ch.RequestLocal(owner.Item{Ref: "g4", Object: "mail.read for <i>CANARY</i>", Facts: owner.Facts{Kind: owner.GrantChange, Verb: "grant", NoRecipient: true}}, 0)
	p := a.get("/approvals/")
	want := `<p>Approving lets your agent grant mail.read for &lt;i&gt;CANARY&lt;/i&gt;.</p>`
	if i, j := strings.Index(p, "<h2>"+id), strings.Index(p, want); i < 0 || j < i || j > strings.Index(p, `value="approve"`) {
		t.Fatalf("card:\n%s", p)
	}
}
