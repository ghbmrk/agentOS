package browser

// REQ: CLK-3, KRN-5, VRB-1

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// A two-page checkout: "Continue" on the cart, then "Place order".
const (
	contPage  = "- main [ref=e1]:\n  - button \"Continue\" [ref=e6]"
	orderPage = "- main [ref=e1]:\n  - button \"Place order\" [ref=e9]"
	doneShot  = "- main [ref=e1]:\n  - heading \"Thanks\" [ref=e2]"
	pressCont = `{"v":0,"verb":"click","ref":"e6"}`
	pressBuy  = `{"v":0,"verb":"click","ref":"e9"}`
)

func shopReply(path, snapshot string) map[string]any {
	return map[string]any{"ok": true, "url": "https://shop.example.test" + path, "snapshot": snapshot}
}

// newCheckout is a rig on the cart page with task id open and a plan key
// that serves it.
func newCheckout(t *testing.T, id string) (*clerkRig, key.Key) {
	t.Helper()
	r := newClerkRig(t, newHarness(t, map[string]any{
		"snapshot": shopReply("/cart", contPage),
		"click":    []any{shopReply("/checkout", orderPage), shopReply("/done", doneShot)},
	}, "", 0))
	if err := r.k.OpenTask(0, id); err != nil {
		t.Fatal(err)
	}
	k := r.taskKey(t, id)
	r.run(t, 1, "look", k, read(`{"v":0,"verb":"snapshot"}`))
	return r, k
}

// taskKey is the home clerk's key bound to task id, as the kernel binds
// each plan's key (KRN-5).
func (r *clerkRig) taskKey(t *testing.T, id string) key.Key {
	t.Helper()
	hpub, hpriv := seedKey(2)
	k, err := key.Derive(r.root, hpriv, hpub, key.LimitTask(id))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// tapTask is the owner's one tap for task id over the held request a: the
// phone passkey co-signs the task, its place in the task, the site and the
// request (CLK-3).
func (r *clerkRig) tapTask(t *testing.T, now int64, id string, a Approval) {
	t.Helper()
	task, ok := r.k.State().Task(id, now)
	if !ok {
		t.Fatalf("task %s is not live", id)
	}
	by := key.Approve(r.phone, kernel.TaskHash(id, task.Taps, a.Site, a.Print))
	if err := r.k.ApproveTask(now, id, kernel.TaskApproval{Site: a.Site, First: a.Print, By: by, N: task.Taps}); err != nil {
		t.Fatal(err)
	}
}

func (r *clerkRig) result(t *testing.T, id string) Result {
	t.Helper()
	var res Result
	if err := json.Unmarshal([]byte(r.step(id).Detail), &res); err != nil {
		t.Fatalf("%s: detail %q: %v", id, r.step(id).Detail, err)
	}
	return res
}

// One tap covers the task's later submit on the same site: Continue, then
// Place order, each sent once, each with its STATUS line. Neither price can
// be read, and neither asks again for it (D-148).
func TestOneTapCoversTheTasksSubmits(t *testing.T) {
	r, k := newCheckout(t, "t1")
	r.run(t, 2, "ask", k, read(pressCont))
	a1 := r.stepApproval(t, "ask")
	if a1.Site != "example.test" {
		t.Fatalf("site %q", a1.Site)
	}
	r.tapTask(t, 3, "t1", a1)
	r.run(t, 4, "cont", k, submitStep(a1, pressCont))
	if s := r.step("cont"); s.Phase != kernel.PDone {
		t.Fatalf("continue: phase %s (%s)", s.Phase, s.Detail)
	}
	if c := r.result(t, "cont").Covered; !strings.HasPrefix(c, `Sent on example.test: "Continue", `) {
		t.Fatalf("covered %q", c)
	}
	// The read of Place order says the task's tap covers it, so the
	// planner posts it without asking the owner.
	r.run(t, 5, "ask2", k, read(pressBuy))
	a2 := r.stepApproval(t, "ask2")
	if res := r.result(t, "ask2"); res.Error != "task_approved" || !strings.Contains(res.Detail, "covers this request on example.test") {
		t.Fatalf("read under the tap: %+v", res)
	}
	r.run(t, 6, "buy", k, submitStep(a2, pressBuy))
	if s := r.step("buy"); s.Phase != kernel.PDone {
		t.Fatalf("place order: phase %s (%s)", s.Phase, s.Detail)
	}
	if c := r.result(t, "buy").Covered; !strings.HasPrefix(c, `Sent on example.test: "Place order", `) {
		t.Fatalf("covered %q", c)
	}
	if got := forwarded(t, r.h, "click"); len(got) != 2 {
		t.Fatalf("clicks %q", got)
	}
	// STATUS lists both, from the clerk's lines (#2705).
	if cs := r.k.State().Covered(6); len(cs) != 2 || cs[0].Line != r.result(t, "cont").Covered || cs[1].Line != r.result(t, "buy").Covered {
		t.Fatalf("STATUS covered %+v", cs)
	}
	// Sent once: the same submit again sends nothing.
	r.run(t, 7, "again", k, submitStep(a2, pressBuy))
	if p := r.k.State().Plans["again"]; len(p.Steps) > 0 && p.Steps[0].Phase == kernel.PDone || len(forwarded(t, r.h, "click")) != 2 {
		t.Fatal("the same submit ran twice")
	}
}

// The tap covers only the task it was given in: the same flow in another
// task, or after the task ends, sends nothing.
func TestTaskApprovalStaysInItsTask(t *testing.T) {
	r, k := newCheckout(t, "t1")
	r.run(t, 2, "ask", k, read(pressCont))
	a1 := r.stepApproval(t, "ask")
	r.tapTask(t, 3, "t1", a1)
	if err := r.k.OpenTask(4, "t2"); err != nil {
		t.Fatal(err)
	}
	// A tap for a site this gate never built an approval for covers
	// nothing and names no site a card could offer (a site split the
	// gate saw is TestASiteSplitAsksForTheOtherSitesTap).
	if err := r.k.OpenTask(4, "t3"); err != nil {
		t.Fatal(err)
	}
	elsewhere := a1
	elsewhere.Site = "example.com"
	r.tapTask(t, 4, "t3", elsewhere)
	r.run(t, 5, "elsewhere", r.taskKey(t, "t3"), submitStep(a1, pressCont))
	if s := r.step("elsewhere"); s.Phase != kernel.PFailed || s.Detail != "unapproved" {
		t.Fatalf("other site: phase %s (%s)", s.Phase, s.Detail)
	}
	r.run(t, 5, "other", r.taskKey(t, "t2"), submitStep(a1, pressCont))
	if s := r.step("other"); s.Phase != kernel.PFailed || s.Detail != "unapproved" {
		t.Fatalf("other task: phase %s (%s)", s.Phase, s.Detail)
	}
	if err := r.k.EndTask(6, "t1"); err != nil {
		t.Fatal(err)
	}
	_ = r.k.Submit(7, plan("ended", k, submitStep(a1, pressCont)))
	_ = r.k.Tick(7)
	if p := r.k.State().Plans["ended"]; p != nil && len(p.Steps) > 0 && p.Steps[0].Phase == kernel.PDone {
		t.Fatal("a plan for an ended task ran")
	}
	r.run(t, 8, "none", r.root, submitStep(a1, pressCont))
	if s := r.step("none"); s.Phase != kernel.PFailed || s.Detail != "unapproved" {
		t.Fatalf("no task: phase %s (%s)", s.Phase, s.Detail)
	}
	if got := forwarded(t, r.h, "click"); len(got) != 0 {
		t.Fatalf("clicks %q", got)
	}
}

// What asks again, at the gate: another site, and a screen that may
// reveal or create a secret (VRB-1). The held request itself is covered.
func TestCoveredSubmitAsksAgain(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		page, line string
		tc         func(Approval) cover
		want       string
	}{
		"held":       {orderPage, pressBuy, func(a Approval) cover { return cover{a.Site} }, ""},
		"other site": {orderPage, pressBuy, func(a Approval) cover { return cover{"example.com"} }, "another site"},
		"no site":    {orderPage, pressBuy, func(a Approval) cover { return cover{""} }, "another site"},
		// A request on a secret screen never rides a task approval, even
		// the held one: it is approved per step (VRB-1).
		"held secret": {strings.Replace(orderPage, "Place order", "Change password", 1), pressBuy, func(a Approval) cover { return cover{a.Site} }, `(VRB-1: "password")`},
		"secret checkbox": {"- main [ref=e1]:\n  - checkbox \"I saved my recovery codes\" [ref=e4]\n  - button \"Done\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site} }, `(VRB-1: "recovery")`},
		"secret radio": {"- main [ref=e1]:\n  - radio \"Text me a passcode\" [ref=e4]\n  - button \"Done\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site} }, `(VRB-1: "passcode")`},
		"secret option": {"- main [ref=e1]:\n  - option \"Export all data\" [ref=e4]\n  - button \"Done\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site} }, `(VRB-1: "export")`},
		"secret listbox": {"- main [ref=e1]:\n  - listbox \"Recovery options\" [ref=e4]\n  - button \"Done\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site} }, `(VRB-1: "recovery")`},
		"secret menuitemcheckbox": {"- main [ref=e1]:\n  - menuitemcheckbox \"Show passwords\" [ref=e4]\n  - button \"Done\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site} }, `(VRB-1: "passwords")`},
		"secret menuitemradio": {"- main [ref=e1]:\n  - menuitemradio \"Use an authenticator\" [ref=e4]\n  - button \"Done\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site} }, `(VRB-1: "authenticator")`},
		"secret slider": {"- main [ref=e1]:\n  - slider \"PIN length\" [ref=e4]\n  - button \"Done\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site} }, `(VRB-1: "pin")`},
		"exempt beside secret": {"- main [ref=e1]:\n  - textbox \"Security code\" [ref=e4]\n  - heading \"Backup codes\" [ref=e2]\n  - button \"Done\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site} }, `(VRB-1: "backup")`},
		"secret switch": {"- main [ref=e1]:\n  - switch \"Two-step sign-in\" [ref=e4]\n  - button \"Done\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site} }, `(VRB-1: "two step")`},
		"script link": {"- main [ref=e1]:\n  - link \"Place order\" [ref=e9]:\n    - /url: javascript:void(0)", pressBuy,
			func(a Approval) cover { return cover{"example.test"} }, ""},
		"cross-site link": {"- main [ref=e1]:\n  - link \"Pay\" [ref=e9]:\n    - /url: https://pay.other.test/confirm?step=2", pressBuy,
			func(a Approval) cover { return cover{"example.test"} }, "another site"},
		"unparsed target": {"- main [ref=e1]:\n  - link \"Pay\" [ref=e9]:\n    - /url: https://pay.other.test\\confirm?go=1", pressBuy,
			func(a Approval) cover { return cover{"example.test"} }, "another site"},
		"secret url": {orderPage, pressBuy, func(a Approval) cover { return cover{a.Site} }, "secret"},
		"secret target": {"- main [ref=e1]:\n  - link \"Continue\" [ref=e9]:\n    - /url: /confirm/recovery-codes?step=2", pressBuy,
			func(a Approval) cover { return cover{a.Site} }, "secret"},
		"secret heading": {"- main [ref=e1]:\n  - heading \"Recovery codes\" [ref=e2]\n  - button \"Generate\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site} }, "secret"},
		"secret name": {strings.Replace(orderPage, "Place order", "Change password", 1), pressBuy, func(a Approval) cover { return cover{a.Site} }, "secret"},
		"secret field": {orderPage + "\n  - textbox \"Backup codes\" [ref=e4]", pressBuy,
			func(a Approval) cover { return cover{a.Site} }, `(VRB-1: "backup")`},
		"add a device": {"- main [ref=e1]:\n  - heading \"Trusted devices\" [ref=e2]\n  - button \"Add a device\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site} }, `(VRB-1: "device")`},
		"export": {"- main [ref=e1]:\n  - button \"Export\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site} }, `(VRB-1: "export")`},
		"create token": {"- main [ref=e1]:\n  - textbox \"Token name\" [ref=e4]\n  - button \"Create\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site} }, `(VRB-1: "token")`},
	} {
		path := "/checkout"
		if name == "secret url" {
			path = "/settings/recovery"
		}
		h := newHarness(t, map[string]any{"snapshot": shopReply(path, c.page), "click": shopReply("/done", doneShot)}, "", 0)
		h.do(t, `{"v":0,"verb":"snapshot"}`)
		a := approvalOf(t, h.do(t, c.line))
		tc := c.tc(a)
		res, written, _ := h.g.submit(ctx, []byte(c.line), a.To, a.Print, false, fixed(tc))
		if c.want == "" {
			if !res.OK || !written || res.Approval == nil || res.Approval.Print != a.Print {
				t.Fatalf("%s: %+v", name, res)
			}
			continue
		}
		if written || res.Error != "approval_required" || !strings.Contains(res.Detail, c.want) ||
			res.Approval == nil || res.Approval.Print != a.Print {
			t.Fatalf("%s: %+v", name, res)
		}
	}
}

// A page with no http(s) site, such as about:blank, has no site, so no task
// approval covers a submit there, even one given over site "".
func TestSitelessPageIsNeverCovered(t *testing.T) {
	blank := map[string]any{"ok": true, "url": "about:blank", "snapshot": orderPage}
	h := newHarness(t, map[string]any{"snapshot": blank}, "", 0)
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	a := approvalOf(t, h.do(t, pressBuy))
	tc := cover{""}
	if res, written, _ := h.g.submit(context.Background(), []byte(pressBuy), a.To, a.Print, false, fixed(tc)); a.Site != "" || written || !strings.Contains(res.Detail, "another site") {
		t.Fatalf("site %q: %+v", a.Site, res)
	}
	r := newClerkRig(t, newHarness(t, map[string]any{"snapshot": blank, "click": shopReply("/done", doneShot)}, "", 0))
	if err := r.k.OpenTask(0, "t1"); err != nil {
		t.Fatal(err)
	}
	k := r.taskKey(t, "t1")
	r.run(t, 1, "look", k, read(`{"v":0,"verb":"snapshot"}`))
	r.run(t, 2, "ask", k, read(pressBuy))
	a = r.stepApproval(t, "ask")
	r.tapTask(t, 3, "t1", Approval{Site: "", Print: "ap1:other"})
	r.run(t, 4, "buy", k, submitStep(a, pressBuy))
	if res := r.result(t, "buy"); r.step("buy").Phase != kernel.PFailed || res.Error != "approval_required" || len(forwarded(t, r.h, "click")) != 0 {
		t.Fatalf("buy: %+v", res)
	}
}

// A covered navigate has no label: its STATUS line names the verb and the
// target instead.
func TestCoveredLineNamesAnUnlabelledSubmit(t *testing.T) {
	got := coveredLine(Approval{Site: "example.test", Verb: "navigate", Target: "https://shop.example.test/transfer?to=synthAlice"}, 0)
	if want := "Sent on example.test: navigate https://shop.example.test/transfer?to=synthAlice, 1970-01-01T00:00:00Z"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A covered line fits the kernel's STATUS bound whatever the site and
// label, and keeps its time: a longer line would be dropped, not shown.
func TestCoveredLineFitsStatus(t *testing.T) {
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + ".test"
	for _, a := range []Approval{
		{Site: long, Label: strconv.Quote(strings.Repeat("Place order ", 20))},
		{Site: long, Verb: "navigate", Target: "https://" + long + "/" + strings.Repeat("x", 4000)},
		{Site: strings.Repeat("d", 300) + ".test", Label: `"Pay"`},
		{Site: "pay\u202e.test", Label: `"Pay"`},
	} {
		got := coveredLine(a, 0)
		if len(got) > kernel.MaxShown || !utf8.ValidString(got) || !strings.HasSuffix(got, ", 1970-01-01T00:00:00Z") ||
			strings.ContainsFunc(got, func(r rune) bool { return unicode.Is(unicode.Cf, r) }) {
			t.Fatalf("%d bytes: %q", len(got), got)
		}
	}
}

// A covered submit the page does not answer ok gets no STATUS line: only a
// sent request is listed (CLK-3).
func TestCoveredLineOnlyWhenSent(t *testing.T) {
	r := newClerkRig(t, newHarness(t, map[string]any{
		"snapshot": shopReply("/cart", contPage),
		"click":    map[string]any{"ok": false, "error": "timeout_in_page", "url": "https://shop.example.test/cart"},
	}, "", 0))
	if err := r.k.OpenTask(0, "t1"); err != nil {
		t.Fatal(err)
	}
	k := r.taskKey(t, "t1")
	r.run(t, 1, "look", k, read(`{"v":0,"verb":"snapshot"}`))
	r.run(t, 2, "ask", k, read(pressCont))
	a := r.stepApproval(t, "ask")
	r.tapTask(t, 3, "t1", a)
	r.run(t, 4, "cont", k, submitStep(a, pressCont))
	if len(forwarded(t, r.h, "click")) != 1 {
		t.Fatal("the covered submit was not sent")
	}
	if res := r.result(t, "cont"); res.OK || res.Covered != "" {
		t.Fatalf("%+v", res)
	}
}

// A card fill after the tap is refused and sends nothing: typing private
// data claims its flow label, which the clerk cannot vouch for (C4), so no
// fill can follow a task's tap until fills are ordered against it (T4).
func TestCardFillAfterTheTapIsRefused(t *testing.T) {
	r, k := newCheckout(t, "t1")
	r.run(t, 2, "ask", k, read(pressCont))
	a := r.stepApproval(t, "ask")
	r.tapTask(t, 3, "t1", a)
	fill := read(`{"v":0,"verb":"type","ref":"e4","text":"synth-card-0000"}`)
	fill.Labels = []string{"card"}
	r.run(t, 4, "fill", k, fill)
	if s := r.step("fill"); s.Phase != kernel.PFailed || s.Detail != clerk.RClaim {
		t.Fatalf("fill: phase %s (%s)", s.Phase, s.Detail)
	}
	if got := forwarded(t, r.h, "type"); len(got) != 0 {
		t.Fatalf("typed %q", got)
	}
}

// fixed reads one task approval for every site.
func fixed(c cover) covers { return func(...string) *cover { return &c } }

// A site split: the tap covers the cart on example.test, and the next
// submit is a link to another site. The post asks again with that
// request's approval, which names its own site, so the card can offer
// the task's tap there; once tapped, it is sent (CLK-3).
func TestASiteSplitAsksForTheOtherSitesTap(t *testing.T) {
	payPage := "- main [ref=e1]:\n  - link \"Pay\" [ref=e9]:\n    - /url: https://pay.other.test/confirm?step=2"
	r := newClerkRig(t, newHarness(t, map[string]any{
		"snapshot": shopReply("/cart", contPage),
		"click":    []any{shopReply("/checkout", payPage), shopReply("/done", doneShot)},
	}, "", 0))
	if err := r.k.OpenTask(0, "t1"); err != nil {
		t.Fatal(err)
	}
	k := r.taskKey(t, "t1")
	r.run(t, 1, "look", k, read(`{"v":0,"verb":"snapshot"}`))
	r.run(t, 2, "ask", k, read(pressCont))
	a1 := r.stepApproval(t, "ask")
	r.tapTask(t, 3, "t1", a1)
	r.run(t, 4, "cont", k, submitStep(a1, pressCont))
	r.run(t, 5, "ask2", k, read(pressBuy))
	res := r.result(t, "ask2")
	if res.Error != "approval_required" || !strings.Contains(res.Detail, "another site than the task's approval") {
		t.Fatalf("read: %+v", res)
	}
	a2 := r.stepApproval(t, "ask2")
	if a2.Site != "other.test" {
		t.Fatalf("site %q", a2.Site)
	}
	r.run(t, 6, "pay", k, submitStep(a2, pressBuy))
	if res := r.result(t, "pay"); res.Error != "approval_required" || res.Approval == nil || res.Approval.Site != "other.test" ||
		!strings.Contains(res.Detail, "another site") {
		t.Fatalf("post: %+v", res)
	}
	r.tapTask(t, 7, "t1", a2)
	r.run(t, 8, "pay2", k, submitStep(a2, pressBuy))
	if s := r.step("pay2"); s.Phase != kernel.PDone {
		t.Fatalf("pay after its tap: phase %s (%s)", s.Phase, s.Detail)
	}
	if got := forwarded(t, r.h, "click"); len(got) != 2 {
		t.Fatalf("clicks %q", got)
	}
}

// A read says what a post would meet: covered by the task's tap, on
// another site, or on a secret screen, which carries its word on the
// Approval so the card asks only for this exact approval (VRB-1). With no
// task approval it reads as before.
func TestAReadSaysWhetherTheTasksTapCoversIt(t *testing.T) {
	secret := "- main [ref=e1]:\n  - heading \"Backup codes\" [ref=e2]\n  - button \"Place order\" [ref=e9]"
	for name, c := range map[string]struct {
		page            string
		tc              *cover
		err, want, word string
	}{
		"covered":      {orderPage, &cover{"example.test"}, "task_approved", "covers this request on example.test", ""},
		"other site":   {orderPage, &cover{"example.com"}, "approval_required", "another site than the task's approval", ""},
		"secret":       {secret, &cover{"example.test"}, "approval_required", `(VRB-1: "backup")`, "backup"},
		"no task":      {orderPage, nil, "approval_required", "needs the owner's approval of this exact request", ""},
		"secret alone": {secret, nil, "approval_required", "needs the owner's approval of this exact request", "backup"},
	} {
		h := newHarness(t, map[string]any{"snapshot": shopReply("/checkout", c.page)}, "", 0)
		h.do(t, `{"v":0,"verb":"snapshot"}`)
		var tasks covers
		if c.tc != nil {
			tasks = fixed(*c.tc)
		}
		res, effect, _ := h.g.do(context.Background(), []byte(pressBuy), tasks)
		if effect || res.Error != c.err || !strings.Contains(res.Detail, c.want) || res.Approval == nil || res.Approval.Secret != c.word {
			t.Fatalf("%s: %+v", name, res)
		}
		if got := forwarded(t, h, "click"); len(got) != 0 {
			t.Fatalf("%s: clicked %q", name, got)
		}
	}
}

// The gate remembers at most maxAsked sites a tap can name; past that a
// new site is not remembered, so its approval elsewhere fails unapproved
// rather than grow the set without bound.
func TestAskedSitesAreBounded(t *testing.T) {
	h := newHarness(t, map[string]any{"snapshot": shopReply("/checkout", orderPage), "click": shopReply("/done", doneShot)}, "", 0)
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	for i := len(h.g.asked); i < maxAsked; i++ {
		h.g.asked[strconv.Itoa(i)+".test"] = true
	}
	a := approvalOf(t, h.do(t, pressBuy))
	if len(h.g.asked) != maxAsked || h.g.asked["example.test"] {
		t.Fatalf("asked %d, example.test %v", len(h.g.asked), h.g.asked["example.test"])
	}
	// A tap on that unremembered site still covers it: the gate asks for
	// the request's own site first.
	tap := func(sites ...string) *cover {
		if slices.Contains(sites, "example.test") {
			return &cover{"example.test"}
		}
		return nil
	}
	if res, written, _ := h.g.submit(context.Background(), []byte(pressBuy), a.To, a.Print, false, tap); !written || !res.OK {
		t.Fatalf("past the bound: %+v", res)
	}
}
