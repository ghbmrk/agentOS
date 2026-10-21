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
// phone passkey co-signs the task, the site and the request (CLK-3).
func (r *clerkRig) tapTask(t *testing.T, now int64, id string, a Approval) {
	t.Helper()
	by := key.Approve(r.phone, kernel.TaskHash(id, a.Site, a.Print))
	if err := r.k.ApproveTask(now, id, kernel.TaskApproval{Site: a.Site, First: a.Print, By: by}); err != nil {
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

// backPrices lets the checks after the interim box-card condition run, as
// they will once D-148 drops it (#2690).
func backPrices(t *testing.T) {
	old := boxCardBacksPrice
	boxCardBacksPrice = func() bool { return true }
	t.Cleanup(func() { boxCardBacksPrice = old })
}

// One tap covers the task's later submit on the same site: Continue, then
// Place order, each sent once, each with its STATUS line.
func TestOneTapCoversTheTasksSubmits(t *testing.T) {
	backPrices(t)
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

// Until D-148 lands, a price the clerk cannot read asks again: the held
// request is sent on the tap, the next submit is held for its own.
func TestUnreadablePriceAsksAgain(t *testing.T) {
	r, k := newCheckout(t, "t1")
	r.run(t, 2, "ask", k, read(pressCont))
	a1 := r.stepApproval(t, "ask")
	r.tapTask(t, 3, "t1", a1)
	r.run(t, 4, "cont", k, submitStep(a1, pressCont))
	r.run(t, 5, "ask2", k, read(pressBuy))
	a2 := r.stepApproval(t, "ask2")
	r.run(t, 6, "buy", k, submitStep(a2, pressBuy))
	res := r.result(t, "buy")
	if r.step("cont").Phase != kernel.PDone || r.step("buy").Phase != kernel.PFailed ||
		res.Error != "approval_required" || res.Approval == nil || res.Approval.Print != a2.Print ||
		!strings.Contains(res.Detail, "price") || len(forwarded(t, r.h, "click")) != 1 {
		t.Fatalf("buy: %s %+v", r.step("buy").Phase, res)
	}
}

// The tap covers only the task it was given in: the same flow in another
// task, or after the task ends, sends nothing.
func TestTaskApprovalStaysInItsTask(t *testing.T) {
	backPrices(t)
	r, k := newCheckout(t, "t1")
	r.run(t, 2, "ask", k, read(pressCont))
	a1 := r.stepApproval(t, "ask")
	r.tapTask(t, 3, "t1", a1)
	if err := r.k.OpenTask(4, "t2"); err != nil {
		t.Fatal(err)
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
	backPrices(t)
	ctx := context.Background()
	for name, c := range map[string]struct {
		page, line string
		tc         func(Approval) cover
		want       string
	}{
		"held":        {orderPage, pressBuy, func(a Approval) cover { return cover{a.Site, a.Print} }, ""},
		"later":       {orderPage, pressBuy, func(a Approval) cover { return cover{a.Site, "ap1:other"} }, ""},
		"other site":  {orderPage, pressBuy, func(a Approval) cover { return cover{"example.com", a.Print} }, "another site"},
		"no site":     {orderPage, pressBuy, func(a Approval) cover { return cover{"", "ap1:other"} }, "another site"},
		"secret name": {strings.Replace(orderPage, "Place order", "Change password", 1), pressBuy, func(a Approval) cover { return cover{a.Site, "ap1:other"} }, "secret"},
		"secret field": {orderPage + "\n  - textbox \"Backup codes\" [ref=e4]", pressBuy,
			func(a Approval) cover { return cover{a.Site, "ap1:other"} }, "secret"},
	} {
		h := newHarness(t, map[string]any{"snapshot": shopReply("/checkout", c.page), "click": shopReply("/done", doneShot)}, "", 0)
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
