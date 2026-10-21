package browser

// REQ: CLK-3, KRN-5, VRB-1

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

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
	r.run(t, 5, "ask2", k, read(pressBuy))
	a2 := r.stepApproval(t, "ask2")
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
	// A tap for another site in the same task covers nothing here.
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
		"held":       {orderPage, pressBuy, func(a Approval) cover { return cover{a.Site, a.Print} }, ""},
		"later":      {orderPage, pressBuy, func(a Approval) cover { return cover{a.Site, "ap1:other"} }, ""},
		"other site": {orderPage, pressBuy, func(a Approval) cover { return cover{"example.com", a.Print} }, "another site"},
		"no site":    {orderPage, pressBuy, func(a Approval) cover { return cover{"", "ap1:other"} }, "another site"},
		// A request on a secret screen never rides a task approval, even
		// the held one: it is approved per step (VRB-1).
		"held secret": {strings.Replace(orderPage, "Place order", "Change password", 1), pressBuy, func(a Approval) cover { return cover{a.Site, a.Print} }, `(VRB-1: "password")`},
		"secret checkbox": {"- main [ref=e1]:\n  - checkbox \"I saved my recovery codes\" [ref=e4]\n  - button \"Done\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site, "ap1:other"} }, `(VRB-1: "recovery")`},
		"secret radio": {"- main [ref=e1]:\n  - radio \"Text me a passcode\" [ref=e4]\n  - button \"Done\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site, "ap1:other"} }, `(VRB-1: "passcode")`},
		"secret switch": {"- main [ref=e1]:\n  - switch \"Two-step sign-in\" [ref=e4]\n  - button \"Done\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site, "ap1:other"} }, `(VRB-1: "two step")`},
		"script link": {"- main [ref=e1]:\n  - link \"Place order\" [ref=e9]:\n    - /url: javascript:void(0)", pressBuy,
			func(a Approval) cover { return cover{"example.test", "ap1:other"} }, ""},
		"cross-site link": {"- main [ref=e1]:\n  - link \"Pay\" [ref=e9]:\n    - /url: https://pay.other.test/confirm?step=2", pressBuy,
			func(a Approval) cover { return cover{"example.test", "ap1:other"} }, "another site"},
		"unparsed target": {"- main [ref=e1]:\n  - link \"Pay\" [ref=e9]:\n    - /url: https://pay.other.test\\confirm?go=1", pressBuy,
			func(a Approval) cover { return cover{"example.test", "ap1:other"} }, "another site"},
		"secret url": {orderPage, pressBuy, func(a Approval) cover { return cover{a.Site, "ap1:other"} }, "secret"},
		"secret target": {"- main [ref=e1]:\n  - link \"Continue\" [ref=e9]:\n    - /url: /confirm/recovery-codes?step=2", pressBuy,
			func(a Approval) cover { return cover{a.Site, "ap1:other"} }, "secret"},
		"secret heading": {"- main [ref=e1]:\n  - heading \"Recovery codes\" [ref=e2]\n  - button \"Generate\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site, "ap1:other"} }, "secret"},
		"secret name": {strings.Replace(orderPage, "Place order", "Change password", 1), pressBuy, func(a Approval) cover { return cover{a.Site, "ap1:other"} }, "secret"},
		"secret field": {orderPage + "\n  - textbox \"Backup codes\" [ref=e4]", pressBuy,
			func(a Approval) cover { return cover{a.Site, "ap1:other"} }, `(VRB-1: "backup")`},
		"add a device": {"- main [ref=e1]:\n  - heading \"Trusted devices\" [ref=e2]\n  - button \"Add a device\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site, "ap1:other"} }, `(VRB-1: "device")`},
		"export": {"- main [ref=e1]:\n  - button \"Export\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site, "ap1:other"} }, `(VRB-1: "export")`},
		"create token": {"- main [ref=e1]:\n  - textbox \"Token name\" [ref=e4]\n  - button \"Create\" [ref=e9]", pressBuy,
			func(a Approval) cover { return cover{a.Site, "ap1:other"} }, `(VRB-1: "token")`},
	} {
		path := "/checkout"
		if name == "secret url" {
			path = "/settings/recovery"
		}
		h := newHarness(t, map[string]any{"snapshot": shopReply(path, c.page), "click": shopReply("/done", doneShot)}, "", 0)
		h.do(t, `{"v":0,"verb":"snapshot"}`)
		a := approvalOf(t, h.do(t, c.line))
		tc := c.tc(a)
		res, written, _ := h.g.submit(ctx, []byte(c.line), a.To, a.Print, false, &tc)
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
	tc := cover{"", "ap1:other"}
	if res, written, _ := h.g.submit(context.Background(), []byte(pressBuy), a.To, a.Print, false, &tc); a.Site != "" || written || !strings.Contains(res.Detail, "another site") {
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
	if s := r.step("buy"); s.Phase != kernel.PFailed || s.Detail != "unapproved" || len(forwarded(t, r.h, "click")) != 0 {
		t.Fatalf("buy: phase %s (%s)", s.Phase, s.Detail)
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
