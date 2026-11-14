package browser

// REQ: CLK-2, CLK-3, KRN-8

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/check"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// cartPage is a logged-in cart: a field the agent fills, a neutrally named
// button that places the order, and a confirm link carrying an
// anti-forgery token.
const cartPage = `- main [ref=e1]:
  - textbox "Delivery note" [ref=e3]
  - button "Place order" [ref=e6]
  - link "Confirm address" [ref=e7]:
    - /url: /confirm?csrf=synthCsrfAaa1&step=2
  - link "Electric kettle" [ref=e8]:
    - /url: /products/kettle`

func cartReply(snapshot string) map[string]any {
	return map[string]any{"ok": true, "url": "https://shop.example.test/cart", "snapshot": snapshot}
}

const pressOrder = `{"v":0,"verb":"click","ref":"e6"}`

// approvalOf is the approval a refused read carries, whether it needs a
// tap or the task's approval covers it.
func approvalOf(t *testing.T, r Result) Approval {
	t.Helper()
	if r.Error != "approval_required" && r.Error != "task_approved" || r.Approval == nil || r.Approval.Print == "" {
		t.Fatalf("not an approval: %+v", r)
	}
	return *r.Approval
}

// stepApproval is the approval in a failed read step's logged result.
func (r *clerkRig) stepApproval(t *testing.T, id string) Approval {
	t.Helper()
	var res Result
	if err := json.Unmarshal([]byte(r.step(id).Detail), &res); err != nil {
		t.Fatalf("detail %q: %v", r.step(id).Detail, err)
	}
	return approvalOf(t, res)
}

// approve is the owner's one tap for a task: the phone passkey narrows the
// home clerk's key to posts of exactly these prints, once each (OWN-9).
func (r *clerkRig) approve(t *testing.T, prints ...string) key.Key {
	t.Helper()
	k, err := key.Narrow(r.root, key.Ed25519Signer(r.phone), key.LimitVerbs(key.Post), key.LimitContent(prints...),
		key.LimitUses(int64(len(prints))), key.LimitExpires(MaxApproval/2)) // the rig's clock is the log's time, near 0
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// see puts l at ref as if the last snapshot showed it, to the gate and to
// the agent alike.
func see(g *Gate, ref string, l link) {
	g.refs[ref] = l
	if g.shown == nil {
		g.shown = map[string]link{}
	}
	g.shown[ref] = l
}

// look reads snapshot as the gate would from a reply on page, the agent's
// view after the output filter.
func look(g *Gate, snapshot, page string) {
	shown, _ := g.filter.text(snapshot)
	g.refs, g.shown, g.page = parseRefs(snapshot, page), parseRefs(shown, page), page
}

func submitStep(a Approval, line string) kernel.PlanStep {
	s := post(a.To, line)
	s.Content = a.Print
	return s
}

func newCart(t *testing.T, replies map[string]any, timeout time.Duration) *clerkRig {
	t.Helper()
	if replies == nil {
		replies = map[string]any{}
	}
	replies["snapshot"] = cartReply(cartPage)
	r := newClerkRig(t, newHarness(t, replies, "", timeout))
	r.run(t, 0, "look", r.root, read(`{"v":0,"verb":"snapshot"}`))
	if s := r.step("look"); s.Phase != kernel.PDone {
		t.Fatalf("snapshot: phase %s", s.Phase)
	}
	return r
}

// The owner approves "Place order" once: the press is sent once, and a
// second plan carrying the same print sends nothing (CLK-3, KRN-8).
func TestApprovedButtonIsSentOnce(t *testing.T) {
	r := newCart(t, nil, 0)
	r.run(t, 1, "ask", r.root, read(pressOrder))
	a := r.stepApproval(t, "ask")
	if a.Verb != "click" || a.Role != "button" || a.Label != `"Place order"` || a.To != `button "Place order" · `+a.Print {
		t.Fatalf("approval %+v", a)
	}
	if got := forwarded(t, r.h, "click"); len(got) != 0 {
		t.Fatalf("sent before approval: %q", got)
	}
	k := r.approve(t, a.Print)
	r.run(t, 2, "buy", k, submitStep(a, pressOrder))
	if s := r.step("buy"); s.Phase != kernel.PDone {
		t.Fatalf("approved press: phase %s (%s)", s.Phase, s.Detail)
	}
	// An exact approval is not a task's: its result carries no STATUS line.
	var res Result
	if err := json.Unmarshal([]byte(r.step("buy").Detail), &res); err != nil || res.Covered != "" || res.Approval != nil {
		t.Fatalf("exact submit result %+v (%v)", res, err)
	}
	r.run(t, 3, "again", k, submitStep(a, pressOrder))
	if p := r.k.State().Plans["again"]; len(p.Steps) > 0 && p.Steps[0].Phase == kernel.PDone {
		t.Fatal("the same submit ran twice")
	}
	if got := forwarded(t, r.h, "click"); len(got) != 1 {
		t.Fatalf("driver got %q", got)
	}
	// Within one process the gate refuses a print it has sent, under any key.
	res, written, _ := r.h.g.submit(context.Background(), []byte(pressOrder), a.To, a.Print, false, nil)
	if written || res.Error != "already_sent" {
		t.Fatalf("resend: %+v", res)
	}
}

// The print covers the canonical request, not the planner's bytes:
// reordered keys and added whitespace are the same submit, sent once.
func TestReorderedRequestIsTheSameSubmit(t *testing.T) {
	h := newHarness(t, map[string]any{"snapshot": cartReply(cartPage)}, "", 0)
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	a := approvalOf(t, h.do(t, pressOrder))
	reordered := " {\"ref\":\"e6\",\n\"verb\":\"click\",\"v\":0}\t"
	if p := h.g.print([]byte(reordered)); p != a.Print {
		t.Fatalf("print %q, want %q", p, a.Print)
	}
	ctx := context.Background()
	if res, _, _ := h.g.submit(ctx, []byte(reordered), a.To, a.Print, false, nil); !res.OK {
		t.Fatalf("first: %+v", res)
	}
	if res, written, _ := h.g.submit(ctx, []byte(pressOrder), a.To, a.Print, false, nil); written || res.Error != "already_sent" {
		t.Fatalf("second: %+v", res)
	}
	if res, written, _ := h.g.submit(ctx, []byte(`{"v":0,"verb":"click","ref":"e8"}`), a.To, a.Print, false, nil); written || res.Error != "not_a_submit" {
		t.Fatalf("a plain link: %+v", res)
	}
	if got := forwarded(t, h, "click"); len(got) != 1 {
		t.Fatalf("driver got %q", got)
	}
}

// A page that changed after the owner approved sends nothing: another
// label on the same ref, another target, or other typed text. A rotated
// anti-forgery token the recipe declares still sends (CLK-3, CLK-2).
func TestChangedPageSendsNothing(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct{ before, after, line string }{
		"label":  {cartPage, strings.Replace(cartPage, "Place order", "Delete account", 1), pressOrder},
		"target": {cartPage, strings.Replace(cartPage, "step=2", "step=3", 1), `{"v":0,"verb":"click","ref":"e7"}`},
	} {
		h := newHarness(t, map[string]any{"snapshot": []any{cartReply(c.before), cartReply(c.after)}}, "", 0)
		h.do(t, `{"v":0,"verb":"snapshot"}`)
		a := approvalOf(t, h.do(t, c.line))
		h.do(t, `{"v":0,"verb":"snapshot"}`)
		if res, written, _ := h.g.submit(ctx, []byte(c.line), a.To, a.Print, false, nil); written || res.Error != "changed" {
			t.Fatalf("%s: %+v", name, res)
		}
		if got := h.received(t); len(got) != 2 {
			t.Fatalf("%s: driver got %q", name, got)
		}
	}

	h := newHarness(t, map[string]any{"snapshot": cartReply(cartPage), "type": cartReply("")}, "", 0)
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	h.do(t, `{"v":0,"verb":"type","ref":"e3","text":"Leave at the door"}`)
	a := approvalOf(t, h.do(t, pressOrder))
	if len(a.Fields) != 1 || a.Fields[0].Label != `"Delivery note"` || a.Fields[0].Value != `"Leave at the door"` {
		t.Fatalf("fields %+v", a.Fields)
	}
	h.do(t, `{"v":0,"verb":"type","ref":"e3","text":"Ring twice"}`)
	if res, written, _ := h.g.submit(ctx, []byte(pressOrder), a.To, a.Print, false, nil); written || res.Error != "changed" {
		t.Fatalf("retyped: %+v", res)
	}

	rotated := strings.Replace(cartPage, "synthCsrfAaa1", "synthCsrfBbb2", 1)
	h = newHarness(t, map[string]any{"snapshot": []any{cartReply(cartPage), cartReply(rotated)}}, "", 0)
	h.g.tokens = map[string]bool{"csrf": true}
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	confirm := `{"v":0,"verb":"click","ref":"e7"}`
	a = approvalOf(t, h.do(t, confirm))
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	if res, _, _ := h.g.submit(ctx, []byte(confirm), a.To, a.Print, false, nil); !res.OK {
		t.Fatalf("rotated token: %+v", res)
	}
}

// A planner-sourced to releases nothing: without the owner's print the
// clerk's own facts refuse the claim, a standing key covers no submit, and
// under the owner's key a to that differs from what the gate read is
// refused unsent (CLK-3).
func TestToAloneReleasesNothing(t *testing.T) {
	r := newCart(t, nil, 0)
	r.run(t, 1, "ask", r.root, read(pressOrder))
	a := r.stepApproval(t, "ask")
	r.run(t, 2, "bare", r.root, post(a.To, pressOrder))
	if s := r.step("bare"); s.Phase != kernel.PFailed || s.Detail != check.RClaim {
		t.Fatalf("no print: phase %s (%s)", s.Phase, s.Detail)
	}
	// A standing key, here the root, covers no submit, print or not.
	r.run(t, 3, "standing", r.root, submitStep(a, pressOrder))
	if s := r.step("standing"); s.Phase != kernel.PFailed || s.Detail != "unapproved" {
		t.Fatalf("standing key: phase %s (%s)", s.Phase, s.Detail)
	}
	k := r.approve(t, a.Print)
	wrong := submitStep(a, pressOrder)
	wrong.Args["to"] = `link "Electric kettle" https://shop.example.test/products/kettle`
	r.run(t, 3, "wrong", k, wrong)
	if s := r.step("wrong"); s.Phase != kernel.PFailed || !strings.Contains(s.Detail, "changed") {
		t.Fatalf("other to: phase %s (%s)", s.Phase, s.Detail)
	}
	if got := forwarded(t, r.h, "click"); len(got) != 0 {
		t.Fatalf("driver got %q", got)
	}
}

// Two targets the filter shows alike have different prints, the print
// carries no raw value, and another gate's print for the same page differs,
// so a print can be neither matched across targets nor guessed (CLK-3).
func TestRedactedTargetsHaveDifferentPrints(t *testing.T) {
	page := func(tok string) string {
		return "- link \"Unsubscribe\" [ref=e2]:\n  - /url: /unsubscribe?token=" + tok
	}
	approve := func(h *harness, snap string) Approval {
		look(h.g, snap, "https://shop.example.test/mail/")
		return approvalOf(t, h.do(t, `{"v":0,"verb":"click","ref":"e2"}`))
	}
	h := newHarness(t, nil, "", 0)
	a, b := approve(h, page("synthCanaryTokAAA111")), approve(h, page("synthCanaryTokBBB222"))
	if strings.TrimSuffix(a.To, a.Print) != strings.TrimSuffix(b.To, b.Print) || !strings.Contains(a.To, Redacted) {
		t.Fatalf("shown targets %q, %q", a.To, b.To)
	}
	if a.Print == b.Print {
		t.Fatal("one print matches two targets")
	}
	if raw, _ := json.Marshal(a); strings.Contains(string(raw), "synthCanaryTokAAA111") {
		t.Fatalf("approval shows the raw token: %s", raw)
	}
	if c := approve(newHarness(t, nil, "", 0), page("synthCanaryTokAAA111")); c.Print == a.Print {
		t.Fatal("another gate computes the same print")
	}
}

// A submit whose answer is lost parks, and nothing is sent again: a fresh
// clerk, as after a restart, probes it unknown. One refused unsent probes
// notdone (KRN-8).
func TestLostSubmitParksAfterRestart(t *testing.T) {
	r := newCart(t, map[string]any{"click": "exit"}, 0)
	r.run(t, 1, "ask", r.root, read(pressOrder))
	a := r.stepApproval(t, "ask")
	k := r.approve(t, a.Print)
	step := submitStep(a, pressOrder)
	r.run(t, 2, "buy", k, step)
	if s := r.step("buy"); s.Phase != kernel.PUnknown {
		t.Fatalf("phase %s", s.Phase)
	}
	for i := int64(1); i <= kernel.MaxChecks+1; i++ {
		if err := r.k.Tick(2 + i*kernel.ProbeEvery); err != nil {
			t.Fatal(err)
		}
	}
	if s := r.step("buy"); s.Phase != kernel.PParked {
		t.Fatalf("phase %s after %d checks", s.Phase, kernel.MaxChecks)
	}
	if got := forwarded(t, r.h, "click"); len(got) != 1 {
		t.Fatalf("driver got %q", got)
	}
	req := kernel.Request{Plan: plan("buy", k, step)}
	if p := NewClerk("web", r.owner, r.h.g).Probe(req, r.k.State()).Outcome; p != "unknown" {
		t.Fatalf("fresh clerk probe %s", p)
	}

	r = newCart(t, nil, 0)
	unsent := submitStep(Approval{To: `button "Place order"`, Print: "ap1:00"}, pressOrder)
	req = kernel.Request{Plan: plan("x", r.root, unsent)}
	r.c.Do(req, r.k.State())
	if p := r.c.Probe(req, r.k.State()).Outcome; p != "notdone" {
		t.Fatalf("refused post probes %s", p)
	}
}

// Logged out, Probe answers from what Do judged, not from the refs the gate
// holds now: an effect stays unknown after a new snapshot reuses its ref
// for a plain link, and with no record, as after a restart with no refs,
// any line naming a ref is unknown (KRN-8, D-147).
func TestLoggedOutProbeUsesWhatDoJudged(t *testing.T) {
	h := newHarness(t, map[string]any{"click": "exit"}, "", 0)
	h.g.cfg.LoggedOut = true
	h.g.refs["e6"] = link{role: "button", name: "Send message"}
	r := newClerkRig(t, h)
	press := read(`{"v":0,"verb":"click","ref":"e6"}`)
	r.run(t, 0, "p1", r.root, press)
	h.g.refs["e6"] = plainLink
	req := kernel.Request{Plan: plan("p1", r.root, press)}
	if p := r.c.Probe(req, r.k.State()).Outcome; p != "unknown" {
		t.Fatalf("probe after ref reuse %s", p)
	}
	fresh := newHarness(t, nil, "", 0)
	fresh.g.cfg.LoggedOut = true
	fresh.g.refs = nil
	c := NewClerk("web", r.owner, fresh.g)
	for line, want := range map[string]string{
		`{"v":0,"verb":"click","ref":"e1"}`:                                           "unknown",
		`{"v":0,"verb":"select","ref":"e1","option":"Blue"}`:                          "unknown",
		`{"v":0,"verb":"snapshot"}`:                                                   "notdone",
		`{"v":0,"verb":"type","ref":"e1","text":"kettle"}`:                            "notdone",
		`{"v":0,"verb":"type","ref":"e1","text":"kettle","submit":true}`:              "unknown",
		`{"v":0,"verb":"navigate","url":"https://shop.example.test/products/kettle"}`: "notdone",
		navUnsub: "unknown",
	} {
		q := kernel.Request{Plan: plan("q", r.root, read(line))}
		if p := c.Probe(q, r.k.State()).Outcome; p != want {
			t.Fatalf("%s: probe %s, want %s", line, p, want)
		}
	}
}

// A logged result is bounded: a reply with a huge title, detail and list of
// refused navigations, and a snapshot of characters JSON escapes, logs at
// most MaxDetail bytes.
func TestLoggedDetailIsBounded(t *testing.T) {
	r := newClerkRig(t, newHarness(t, map[string]any{"snapshot": "huge"}, "", 0))
	r.run(t, 0, "p1", r.root, read(`{"v":0,"verb":"snapshot"}`))
	s := r.step("p1")
	if s.Phase != kernel.PDone || len(s.Detail) > MaxDetail {
		t.Fatalf("phase %s, %d bytes logged: %.200s", s.Phase, len(s.Detail), s.Detail)
	}
	var res Result
	if err := json.Unmarshal([]byte(s.Detail), &res); err != nil || !res.Truncated || res.Snapshot == "" ||
		len(res.Title) > maxTitle+3 || len(res.Detail) > maxErrDetail+3 || len(res.URL) > MaxURL+3 ||
		len(res.RefusedNavigations) > maxRefused {
		t.Fatalf("logged result: %v, truncated %v, title %d, detail %d, url %d, %d navigations", err, res.Truncated,
			len(res.Title), len(res.Detail), len(res.URL), len(res.RefusedNavigations))
	}
	// A protocol error quotes the planner's verb: it is bounded too
	// (Security delta 1).
	r.run(t, 1, "p0", r.root, read(`{"v":0,"verb":"`+strings.Repeat("<", 1200<<10)+`"}`))
	if d := r.step("p0").Detail; len(d) > MaxDetail || json.Unmarshal([]byte(d), &res) != nil || len(res.Detail) > maxErrDetail+3 {
		t.Fatalf("protocol error logged %d bytes", len(d))
	}
	if d := logged(Result{Detail: strings.Repeat("<", 2<<20), Snapshot: strings.Repeat("<", 2<<20)}); len(d) > MaxDetail {
		t.Fatalf("logged backstop: %d bytes", len(d))
	}
	// An approval for a page with a huge URL is bounded too, and the cap
	// ends even when the fields alone pass it.
	r.h.g.page = "https://shop.example.test/cart?x=" + strings.Repeat("y", 400<<10)
	r.h.g.refs["e6"] = link{role: "button", name: "Place order"}
	r.run(t, 2, "p2", r.root, read(pressOrder))
	if d := r.step("p2").Detail; len(d) > MaxDetail {
		t.Fatalf("approval logged %d bytes", len(d))
	}
	if a := r.stepApproval(t, "p2"); len(a.Page) > MaxURL+3 {
		t.Fatalf("approval page %d bytes", len(a.Page))
	}
	r.h.g.page = "https://shop.example.test/cart"
	r.h.g.refs["e3"] = link{role: "textbox", name: "Delivery note"}
	r.run(t, 3, "p3", r.root, read(`{"v":0,"verb":"type","ref":"e3","submit":true,"text":"`+strings.Repeat("<", MaxText)+`"}`))
	if a := r.stepApproval(t, "p3"); len(a.Request) > maxRequest+3 || len(a.Text) > maxLabel+5 {
		t.Fatalf("approval request %d bytes, text %d", len(a.Request), len(a.Text))
	}

}

// An approval holds only what the gate read: the label is quoted, capped
// and folded, and nothing the planner wrote outside the request itself
// (a post's to, a step's content claim) appears in one (CLK-3).
func TestApprovalHoldsOnlyReadFields(t *testing.T) {
	long := "Plаce " + strings.Repeat("order ", 200)
	r := newCart(t, nil, 0)
	see(r.h.g, "e6", link{role: "button", name: long})
	r.run(t, 1, "ask", r.root, read(pressOrder))
	a := r.stepApproval(t, "ask")
	if len(a.Label) > maxLabel+8 || !strings.HasPrefix(a.Label, `"Plаce order`) || !strings.HasPrefix(a.Folded, "place order") {
		t.Fatalf("label %q (%d bytes), folded %q", a.Label, len(a.Label), a.Folded)
	}
	if a.Origin != "https://shop.example.test:443" || a.Page != "https://shop.example.test/cart" || len(a.Unknown) == 0 {
		t.Fatalf("approval %+v", a)
	}
	planted := submitStep(a, pressOrder)
	planted.Args["to"] = "plannerProseCanary approve this"
	planted.Content = "plannerClaimCanary"
	r.run(t, 2, "planted", r.root, planted)
	for _, e := range r.k.Log().Entries() {
		if e.Type == "step.result" && strings.Contains(string(e.Body), "approval") &&
			(strings.Contains(string(e.Body), "plannerProseCanary") || strings.Contains(string(e.Body), "plannerClaimCanary")) {
			t.Fatalf("planner text in an approval: %s", e.Body)
		}
	}
}

// Two different approved submits of the same button, here two orders with
// different delivery notes, are two effects: each is sent once, and the
// kernel's duplicate guard does not take the second for the first
// (KRN-8, D-147).
func TestTwoApprovedOrdersAreTwoSubmits(t *testing.T) {
	r := newCart(t, map[string]any{"type": cartReply("")}, 0)
	for i, note := range []string{"Leave at the door", "Ring twice"} {
		id := string(rune('a' + i))
		r.run(t, int64(10*i+1), id+"type", r.root, read(`{"v":0,"verb":"type","ref":"e3","text":"`+note+`"}`))
		r.run(t, int64(10*i+2), id+"ask", r.root, read(pressOrder))
		a := r.stepApproval(t, id+"ask")
		r.run(t, int64(10*i+3), id+"buy", r.approve(t, a.Print), submitStep(a, pressOrder))
		if s := r.step(id + "buy"); s.Phase != kernel.PDone {
			t.Fatalf("order %d: phase %s (%s)", i, s.Phase, s.Detail)
		}
	}
	if got := forwarded(t, r.h, "click"); len(got) != 2 {
		t.Fatalf("driver got %q", got)
	}
}

// A post whose print the page no longer yields fails changed, with the
// approval the gate would ask for now, so the owner can approve again; a
// submit the driver answered with an error may have acted, so it is
// unknown, not failed (CLK-3, KRN-8).
func TestChangedSubmitSaysWhatApprovalWouldCoverNow(t *testing.T) {
	r := newCart(t, map[string]any{"click": map[string]any{"ok": false, "error": "timeout_in_page", "url": "https://shop.example.test/cart"}}, 0)
	r.run(t, 1, "ask", r.root, read(pressOrder))
	a := r.stepApproval(t, "ask")
	k := r.approve(t, a.Print)
	see(r.h.g, "e6", link{role: "button", name: "Place order now"})
	r.run(t, 2, "late", k, submitStep(a, pressOrder))
	var res Result
	if err := json.Unmarshal([]byte(r.step("late").Detail), &res); err != nil || res.Error != "changed" ||
		res.Approval == nil || res.Approval.Label != `"Place order now"` || res.Approval.Print == a.Print {
		t.Fatalf("changed: %v %+v", err, res)
	}
	b := *res.Approval
	r.run(t, 3, "buy", r.approve(t, b.Print), submitStep(b, pressOrder))
	if s := r.step("buy"); s.Phase != kernel.PUnknown {
		t.Fatalf("errored submit: phase %s (%s)", s.Phase, s.Detail)
	}
	if got := forwarded(t, r.h, "click"); len(got) != 1 {
		t.Fatalf("driver got %q", got)
	}
}

// A key is an approval only if its uses are capped at most at its prints'
// number: a prints-only key with no use cap releases nothing (CLK-3).
func TestUncappedPrintKeyReleasesNothing(t *testing.T) {
	r := newCart(t, nil, 0)
	r.run(t, 1, "ask", r.root, read(pressOrder))
	a := r.stepApproval(t, "ask")
	for name, cav := range map[string][]key.Caveat{
		"no cap":    {key.LimitVerbs(key.Post), key.LimitContent(a.Print)},
		"not print": {key.LimitVerbs(key.Post), key.LimitContent(a.Print, "plain"), key.LimitUses(1)},
		"over cap":  {key.LimitVerbs(key.Post), key.LimitContent(a.Print), key.LimitUses(2)},
	} {
		k, err := key.Narrow(r.root, key.Ed25519Signer(r.phone), append(cav, key.LimitExpires(MaxApproval/2))...)
		if err != nil {
			t.Fatal(err)
		}
		r.run(t, 2, name, k, submitStep(a, pressOrder))
		if s := r.step(name); s.Phase != kernel.PFailed || s.Detail != "unapproved" {
			t.Fatalf("%s: phase %s (%s)", name, s.Phase, s.Detail)
		}
	}
	if got := forwarded(t, r.h, "click"); len(got) != 0 {
		t.Fatalf("driver got %q", got)
	}
}

// Site text is filtered before it is quoted, capped or folded: a label
// carrying a vault value shows redacted in every form, and two labels the
// filter shows alike still have different prints (CRED-10, CLK-3).
func TestApprovalLabelIsFilteredFirst(t *testing.T) {
	h := newHarness(t, map[string]any{"snapshot": cartReply(cartPage)}, "", 0)
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	var prints []string
	for _, secret := range []string{"vaultCanarySessionV4lt", "pw-canary-short"} {
		see(h.g, "e6", link{role: "button", name: "Pay with " + secret})
		a := approvalOf(t, h.do(t, pressOrder))
		raw, _ := json.Marshal(a)
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(secret)) || !strings.Contains(a.Label, Redacted) {
			t.Fatalf("approval shows the secret: %s", raw)
		}
		prints = append(prints, a.Print)
	}
	if prints[0] == prints[1] {
		t.Fatal("one print for two labels")
	}
}

// Blanking a declared token keeps every other byte of the query: a pair
// the URL parser would drop, or one hidden in a token value, changes the
// print, so it is never sent under an approval of another URL (CLK-3).
func TestTokenBlankingKeepsTheRestOfTheQuery(t *testing.T) {
	const base = "https://shop.example.test/transfer?csrf=synthT1&to=synthAlice"
	nav := func(u string) string { return `{"v":0,"verb":"navigate","url":"` + u + `"}` }
	h := newHarness(t, nil, "", 0)
	h.g.tokens = map[string]bool{"csrf": true}
	h.g.page = "https://shop.example.test/"
	a := approvalOf(t, h.do(t, nav(base)))
	for _, u := range []string{"https://shop.example.test/transfer?csrf=synthT1&to=synthBob", base + "&to=synthMallory;x", base + "&to=synthMallory%zz",
		"https://shop.example.test/transfer?csrf=synthT2;to=synthMallory&to=synthAlice"} {
		if res, written, _ := h.g.submit(context.Background(), []byte(nav(u)), a.To, a.Print, false, nil); written || res.Error != "changed" {
			t.Fatalf("%s: %+v", u, res)
		}
	}
	for in, want := range map[string]string{
		"https://shop.example.test/a?csrf=synthT1#top":   "https://shop.example.test/a?csrf=#top",
		"https://shop.example.test/a#x?csrf=synthT1":     "https://shop.example.test/a#x?csrf=synthT1",
		"https://shop.example.test/a?b=1#x?csrf=synthT1": "https://shop.example.test/a?b=1#x?csrf=synthT1",
	} {
		if got := h.g.untoken(in); got != want {
			t.Fatalf("untoken %s = %s", in, got)
		}
	}
	rotated := "https://shop.example.test/transfer?csrf=synthT2&to=synthAlice"
	if res, _, _ := h.g.submit(context.Background(), []byte(nav(rotated)), a.To, a.Print, false, nil); !res.OK {
		t.Fatalf("rotated: %+v", res)
	}
}

// An approval shows the page as the agent saw it: a control named with a
// password value the gate omitted from the snapshot is withheld, in the
// label, the fold and the to alike (CRED-4, CLK-3).
func TestApprovalShowsWhatTheAgentSaw(t *testing.T) {
	page := "- textbox \"Password\" [ref=e2]: hunter2SecretPw\n- button \"Use hunter2SecretPw\" [ref=e6]"
	h := newHarness(t, map[string]any{"snapshot": cartReply(page)}, "", 0)
	if r := h.do(t, `{"v":0,"verb":"snapshot"}`); r.Snapshot != withheldMark {
		t.Fatalf("snapshot %q", r.Snapshot)
	}
	r := h.do(t, pressOrder)
	a := approvalOf(t, r)
	raw, _ := json.Marshal(r)
	if strings.Contains(strings.ToLower(string(raw)), "hunter2") || a.Label != `"`+withheld+`"` {
		t.Fatalf("refusal shows the password: %s", raw)
	}
}

// The print covers the page: the same ref and label on another page is
// another approval (CLK-3).
func TestSameControlOnAnotherPageIsAnotherPrint(t *testing.T) {
	h := newHarness(t, nil, "", 0)
	look(h.g, cartPage, "https://shop.example.test/cart")
	a := approvalOf(t, h.do(t, pressOrder))
	look(h.g, cartPage, "https://shop.example.test/cart/other")
	if b := approvalOf(t, h.do(t, pressOrder)); a.Print == b.Print {
		t.Fatal("one print on two pages")
	}
	if res, written, _ := h.g.submit(context.Background(), []byte(pressOrder), a.To, a.Print, false, nil); written || res.Error != "changed" {
		t.Fatalf("other page: %+v", res)
	}
}

// A refused redo of a written submit leaves its record standing: Probe
// stays unknown, so the kernel never takes it for unsent (KRN-8).
func TestRefusedRedoKeepsTheWrittenRecord(t *testing.T) {
	r := newCart(t, map[string]any{"click": "exit"}, 0)
	r.run(t, 1, "ask", r.root, read(pressOrder))
	a := r.stepApproval(t, "ask")
	k := r.approve(t, a.Print)
	step := submitStep(a, pressOrder)
	r.run(t, 2, "buy", k, step)
	req := kernel.Request{Plan: plan("buy", k, step)}
	if res := r.c.Do(req, r.k.State()); res.Outcome != "failed" {
		t.Fatalf("redo: %+v", res)
	}
	if p := r.c.Probe(req, r.k.State()).Outcome; p != "unknown" {
		t.Fatalf("probe after a refused redo %s", p)
	}
}

// A submit the driver answered with an error may have acted, so it parks.
// The owner's RETRY is the one way on: it sends the print once more, for
// that step only, and a fresh plan with the same print still sends nothing
// (KRN-8, CH-11; UX and Potency delta 1).
func TestRetryOfAnErroredSubmitSendsOnceMore(t *testing.T) {
	r := newCart(t, map[string]any{"click": []any{
		map[string]any{"ok": false, "error": "timeout_in_page", "url": "https://shop.example.test/cart"},
		map[string]any{"ok": true, "url": "https://shop.example.test/cart"}}}, 0)
	r.run(t, 1, "ask", r.root, read(pressOrder))
	a := r.stepApproval(t, "ask")
	// The approval lives its longest, so it outlasts the ten checks on the
	// rig's clock.
	k, err := key.Narrow(r.root, key.Ed25519Signer(r.phone), key.LimitVerbs(key.Post), key.LimitContent(a.Print), key.LimitUses(1), key.LimitExpires(MaxApproval))
	if err != nil {
		t.Fatal(err)
	}
	r.run(t, 2, "buy", k, submitStep(a, pressOrder))
	for i := int64(1); i <= kernel.MaxChecks+1; i++ {
		if err := r.k.Tick(2 + i*kernel.ProbeEvery); err != nil {
			t.Fatal(err)
		}
	}
	if s := r.step("buy"); s.Phase != kernel.PParked {
		t.Fatalf("phase %s", s.Phase)
	}
	now := 3 + int64(kernel.MaxChecks+2)*kernel.ProbeEvery
	if err := r.k.Retry(now, "buy", 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := r.k.Tick(now); err != nil {
		t.Fatal(err)
	}
	if s := r.step("buy"); s.Phase != kernel.PDone {
		t.Fatalf("after RETRY: phase %s (%s)", s.Phase, s.Detail)
	}
	if got := forwarded(t, r.h, "click"); len(got) != 2 {
		t.Fatalf("driver got %q", got)
	}
	// Any other step with that print is still refused.
	if res, written, _ := r.h.g.submit(context.Background(), []byte(pressOrder), a.To, a.Print, false, nil); written || res.Error != "already_sent" {
		t.Fatalf("resend: %+v", res)
	}
}

// A post refused for a claim other than its print (labels, an amount) says
// claim, not that the page changed: approving again would not help.
func TestOtherClaimIsNotAChangedPage(t *testing.T) {
	r := newCart(t, nil, 0)
	r.run(t, 1, "ask", r.root, read(pressOrder))
	a := r.stepApproval(t, "ask")
	s := submitStep(a, pressOrder)
	s.Labels = []string{"synth"}
	res := r.c.Do(kernel.Request{Plan: plan("x", r.approve(t, a.Print), s)}, r.k.State())
	if res.Detail != check.RClaim {
		t.Fatalf("got %+v", res)
	}
}

// The print covers the control's role and every field the agent typed on
// the approval's page, past the ones it shows, and no field typed on
// another page (CLK-3, #2678).
func TestPrintCoversRoleAndThisPagesFields(t *testing.T) {
	h := newHarness(t, nil, "", 0)
	look(h.g, cartPage, "https://shop.example.test/cart")
	p := func() string { return h.g.print([]byte(pressOrder)) }
	base := p()
	see(h.g, "e6", link{role: "link", name: "Place order"})
	if p() == base {
		t.Fatal("a role change kept the print")
	}
	see(h.g, "e6", link{role: "button", name: "Place order"})
	h.g.typed = map[string]typedField{"e90": {text: "synthElsewhere", url: "https://shop.example.test/other"}}
	if p() != base {
		t.Fatal("a field typed on another page changed the print")
	}
	for i := range maxFields + 8 {
		h.g.typed["f"+strconv.Itoa(100+i)] = typedField{text: "synthNote", url: h.g.page}
	}
	a := approvalOf(t, h.do(t, pressOrder))
	if len(a.Fields) != maxFields || a.FieldsOmitted != 8 {
		t.Fatalf("%d fields shown, %d omitted", len(a.Fields), a.FieldsOmitted)
	}
	last := "f" + strconv.Itoa(100+maxFields+7)
	h.g.typed[last] = typedField{text: "synthChanged", url: h.g.page}
	if p() == a.Print {
		t.Fatal("an omitted field's change kept the print")
	}
}

// A snapshot under MaxSnapshot raw but past it JSON-escaped is cut, so the
// log holds at most MaxSnapshot of it (BRS-7, #2678).
func TestEscapedSnapshotIsCut(t *testing.T) {
	r := newClerkRig(t, newHarness(t, map[string]any{"snapshot": "escapes"}, "", 0))
	r.run(t, 0, "p1", r.root, read(`{"v":0,"verb":"snapshot"}`))
	var res Result
	if err := json.Unmarshal([]byte(r.step("p1").Detail), &res); err != nil || !res.Truncated {
		t.Fatalf("truncated %v: %v", res.Truncated, err)
	}
	if n := len(js(strings.TrimSuffix(res.Snapshot, "\n[snapshot truncated]"))); n > MaxSnapshot {
		t.Fatalf("escaped snapshot %d bytes", n)
	}
}

// A print is sent once per gate through the clerk too: a second task's
// approval of a spent print, under another root the kernel's duplicate
// guard does not join, gets already_sent, and a key listing one print
// twice approves nothing, since the content set holds it once (KRN-8,
// #2678).
func TestSpentPrintIsRefusedThroughTheClerk(t *testing.T) {
	r := newCart(t, nil, 0)
	r.run(t, 1, "ask", r.root, read(pressOrder))
	a := r.stepApproval(t, "ask")
	r.run(t, 2, "buy", r.approve(t, a.Print), submitStep(a, pressOrder))
	if s := r.step("buy"); s.Phase != kernel.PDone {
		t.Fatalf("first: phase %s", s.Phase)
	}
	_, opriv := seedKey(1)
	hpub, _ := seedKey(2)
	root2, err := key.ClerkKey(key.Issue(key.Ed25519Signer(opriv), key.Root{Clerk: "web", Verbs: []key.Verb{key.Read, key.Post}, Serial: "r2"}), key.Ed25519Signer(opriv), hpub, 3, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	_, bpriv := seedKey(12)
	batch := []key.Key{{Root: root2.Root}, root2}
	cosign := []key.Cosign{key.Approve(key.Ed25519Signer(opriv), kernel.BatchHash(batch...)), key.Approve(key.Ed25519Signer(bpriv), kernel.BatchHash(batch...))}
	// Issued now and live a hold later: nothing is logged in the past (TIM-1).
	if err := r.k.Issue(3, cosign, batch...); err != nil {
		t.Fatal(err)
	}
	k2, err := key.Narrow(root2, key.Ed25519Signer(r.phone), key.LimitVerbs(key.Post), key.LimitContent(a.Print), key.LimitUses(1),
		key.LimitExpires(kernel.GrantHold+MaxApproval/2))
	if err != nil {
		t.Fatal(err)
	}
	r.run(t, 4+kernel.GrantHold, "again", k2, submitStep(a, pressOrder))
	if s := r.step("again"); s.Phase == kernel.PDone || !strings.Contains(s.Detail, "already_sent") {
		t.Fatalf("second task: phase %s (%s)", s.Phase, s.Detail)
	}
	if got := forwarded(t, r.h, "click"); len(got) != 1 {
		t.Fatalf("driver got %q", got)
	}
	twice, err := key.Narrow(r.root, key.Ed25519Signer(r.phone), key.LimitVerbs(key.Post), key.LimitContent(a.Print, a.Print), key.LimitUses(2))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := key.Chain(twice, r.k.State().Passkeys()); err != nil || approval(v, 0) {
		t.Fatal("a key listing one print twice is an approval")
	}
}

// Start refuses a config with a bad origin, no driver or no workspace, and
// takes the recipe's token parameters. Close stops the driver and reaps it,
// and a second Close is a no-op that does not block.
func TestStartChecksItsConfigAndCloseReaps(t *testing.T) {
	ok := Config{Driver: []string{"/bin/sh", "-c", "exec cat"}, Origins: []string{"https://shop.example.test"}, Workspace: t.TempDir()}
	for name, cfg := range map[string]Config{
		"a bad origin": {Driver: ok.Driver, Origins: []string{"shop.example.test"}, Workspace: ok.Workspace},
		"no driver":    {Origins: ok.Origins, Workspace: ok.Workspace},
		"no workspace": {Driver: ok.Driver, Origins: ok.Origins},
	} {
		if g, err := Start(context.Background(), cfg); err == nil {
			g.Close()
			t.Errorf("%s: started", name)
		}
	}
	ok.TokenParams = []string{"csrf"}
	g, err := Start(context.Background(), ok)
	if err != nil {
		t.Fatal(err)
	}
	if !g.tokens["csrf"] {
		t.Error("the recipe's token parameter was not taken")
	}
	done := make(chan struct{})
	go func() { g.Close(); g.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Close blocked")
	}
	if !g.stopped {
		t.Error("Close left the executor running")
	}
	if err := g.cmd.Wait(); err == nil || !strings.Contains(err.Error(), "already called") {
		t.Errorf("the driver was not reaped: a later Wait gave %v", err)
	}
	if _, _, _, _, refused := g.judge([]byte(`{"v":0,"verb":"snapshot"}`)); refused == nil || refused.Error != "stopped" {
		t.Errorf("a stopped gate judged %+v", refused)
	}
}

// A driver line longer than MaxLine is no reply: the gate stops reading
// and the executor is stopped.
func TestADriverLinePastMaxLineStops(t *testing.T) {
	g, err := Start(context.Background(), Config{
		Driver:    []string{"/bin/sh", "-c", "head -c " + strconv.Itoa(MaxLine+1) + " /dev/zero | tr '\\000' x; echo; exec sleep 30"},
		Origins:   []string{"https://shop.example.test"},
		Workspace: t.TempDir(),
		Timeout:   20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	if res, _, _ := g.do(context.Background(), []byte(`{"v":0,"verb":"snapshot"}`), nil); res.Error != "stopped" {
		t.Fatalf("got %+v", res)
	}
}

// small caps every field it bounds, each refused navigation too; post
// names an unknown error code "driver", floors the redaction count, marks a
// snapshot the driver cut and counts no bytes without a file.
func TestSmallAndPostBoundTheReply(t *testing.T) {
	long := strings.Repeat("y", MaxURL+maxLabel+maxErrDetail+10)
	r := small(Result{Error: long, To: long, Path: long, RefusedNavigations: []string{long}})
	if len(r.Error) > maxTitle+8 || len(r.To) > MaxURL+maxLabel+8 || len(r.Path) > maxTitle+8 || len(r.RefusedNavigations[0]) > maxTitle+8 {
		t.Errorf("small left fields long: %d %d %d %d", len(r.Error), len(r.To), len(r.Path), len(r.RefusedNavigations[0]))
	}
	h := newHarness(t, nil, "", 0)
	res, ok := h.g.post("snapshot", Result{OK: true, URL: "https://shop.example.test/", Error: "not a code!", Redactions: -5,
		Truncated: true, Snapshot: "- heading \"Hi\"", Bytes: 99})
	if !ok || res.Error != "driver" || res.Redactions != 0 || !strings.HasSuffix(res.Snapshot, "\n[snapshot truncated]") || res.Bytes != 0 {
		t.Fatalf("post: %+v", res)
	}
}

// A click on a ref the last snapshot did not show is refused.
func TestAClickOnAnUnseenRefIsRefused(t *testing.T) {
	h := newHarness(t, nil, "", 0)
	if r := h.do(t, `{"v":0,"verb":"click","ref":"e99"}`); r.Error != "unknown_ref" {
		t.Fatalf("got %+v", r)
	}
}

// Once the gate has lost track of typed text, a page with an entry field
// is withheld whole, though its value shows nowhere else.
func TestALostGateWithholdsAPageWithAField(t *testing.T) {
	h := newHarness(t, nil, "", 0)
	snap := "- textbox \"Code\" [ref=e5]: pw-canary-short"
	if out, _ := h.g.omit(snap, h.g.page); out == withheldMark {
		t.Fatalf("withheld before anything was lost: %s", out)
	}
	h.g.lost = true
	if out, n := h.g.omit(snap, h.g.page); out != withheldMark || n != 1 {
		t.Fatalf("a lost gate showed %q (%d)", out, n)
	}
}

// A request the driver cannot read stops the executor, even if a line from
// the driver follows: that line answers nothing the gate sent (K8).
func TestAWriteTheDriverCannotReadStops(t *testing.T) {
	g, err := Start(context.Background(), Config{
		Driver:    []string{"/bin/sh", "-c", `exec 0<&-; sleep 1; echo '{"ok":true,"url":"https://shop.example.test/"}'; exec sleep 30`},
		Origins:   []string{"https://shop.example.test"},
		Workspace: t.TempDir(),
		Timeout:   10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	// Newlines the driver ignores fill nothing; the first that fails is
	// past its closing its input.
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, err := g.stdin.Write([]byte("\n")); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the driver kept its input open")
		}
	}
	if res, _, _ := g.do(context.Background(), []byte(`{"v":0,"verb":"snapshot"}`), nil); res.OK || res.Error != "stopped" || !g.stopped {
		t.Fatalf("got %+v", res)
	}
}

// Close drains a line the driver wrote that nothing asked for, so the
// gate's reader ends and closes its line channel.
func TestCloseDrainsAnUnaskedLine(t *testing.T) {
	g, err := Start(context.Background(), Config{
		Driver:    []string{"/bin/sh", "-c", `echo '{"ok":true,"url":"https://shop.example.test/"}'; exec 0<&-; exec sleep 30`},
		Origins:   []string{"https://shop.example.test"},
		Workspace: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, err := g.stdin.Write([]byte("\n")); err != nil { // past the line: it closed its input after
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the driver kept its input open")
		}
	}
	time.Sleep(50 * time.Millisecond) // the reader holds the line
	g.Close()
	// Close returns only once the line is drained and the channel closed,
	// so nothing the test receives can race the drain (#5626).
	select {
	case _, open := <-g.lines:
		if open {
			t.Fatal("the unasked line was left for a reader")
		}
	default:
		t.Fatal("Close returned before the line channel was closed")
	}
}

// An approval quotes the option and text the request carries, shows no
// target where the live control has none though the agent was shown one,
// and prints typed fields in one order however the gate holds them.
func TestApprovalShowsWhatTheRequestCarries(t *testing.T) {
	h := newHarness(t, nil, "", 0)
	see(h.g, "e1", link{role: "combobox", name: "Colour"})
	a := h.g.approval(Request{Verb: "type", Ref: "e1", Text: "synthTyped", Option: "Blue"}, h.g.refs["e1"])
	if a.Option != `"Blue"` || a.Text != `"synthTyped"` {
		t.Fatalf("option %s, text %s", a.Option, a.Text)
	}
	h.g.shown["e2"] = link{role: "button", name: "Go", target: "https://shop.example.test/t"}
	h.g.refs["e2"] = link{role: "button", name: "Go"}
	if a := h.g.approval(Request{Verb: "click", Ref: "e2"}, h.g.refs["e2"]); a.Target != "" {
		t.Fatalf("a control with no target shows %q", a.Target)
	}
	h.g.typed = map[string]typedField{}
	for i := range 8 {
		h.g.typed["f"+strconv.Itoa(i)] = typedField{text: "synthNote" + strconv.Itoa(i), url: h.g.page}
	}
	first := h.g.approval(Request{Verb: "click", Ref: "e2"}, h.g.refs["e2"]).Print
	for range 8 {
		if p := h.g.approval(Request{Verb: "click", Ref: "e2"}, h.g.refs["e2"]).Print; p != first {
			t.Fatal("the print depends on the order the gate holds typed fields")
		}
	}
}

// parseRefs keeps only elements with a ref, drops a ref two elements share,
// marks a dialog's Close a dismissal, and leaves a field in a clickable
// link focused, not clicked.
func TestParseRefsDropsSharedRefsAndMarksDismissals(t *testing.T) {
	snap := "- dialog \"Confirm\" [ref=e1]:\n  - button \"Close\" [ref=e2]\n" +
		"- link \"Card\" [ref=e4] [cursor=pointer]:\n  - /url: https://shop.example.test/x\n  - textbox \"Search\" [ref=e5]\n" +
		"- button \"One\" [ref=e6]\n- button \"Two\" [ref=e6]\n- generic [cursor=pointer]:\n  - text: hi"
	refs := parseRefs(snap, "https://shop.example.test/")
	if len(refs) != 4 {
		t.Fatalf("refs %v, want e1 e2 e4 e5", refs)
	}
	if l := refs["e2"]; !l.dismiss || !l.clickable {
		t.Errorf("a dialog's Close: %+v", l)
	}
	if l := refs["e5"]; l.clickable || l.dismiss {
		t.Errorf("a field in a link: %+v", l)
	}
	if refs := parseRefs("- button \"Plain\"", "https://shop.example.test/"); len(refs) != 0 {
		t.Errorf("an element with no ref: %v", refs)
	}
}

// Parse says what is wrong with a line: not an object, not JSON, a field of
// the wrong type; a cut-off line is an error, never a panic.
func TestParseNamesWhatIsWrongWithALine(t *testing.T) {
	for raw, want := range map[string]string{
		`not json`:                       "JSON object",
		`"a string"`:                     "JSON object",
		`{"v":0,`:                        "not JSON",
		`{"v":0,"verb":5}`:               "must be a string",
		`{"v":0,"verb":"click","ref":1}`: "must be a string",
	} {
		if _, err := Parse([]byte(raw)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", raw, err, want)
		}
	}
	if !hasArg([]string{"a", "b"}, "b") || hasArg([]string{"a"}, "b") {
		t.Error("hasArg")
	}
}

// An IP host is its own site, not a suffix of it; a "token" key is dropped
// only from a query, never from a URL without one.
func TestSiteOfAnIPAndATokenOutsideAQuery(t *testing.T) {
	if s := site("https://10.0.0.1/x"); s != "10.0.0.1" {
		t.Errorf("site of an IP: %q", s)
	}
	if s := dropTokenKey("token=abc"); s != "token=abc" {
		t.Errorf("no query: %q", s)
	}
	if s := dropTokenKey("/a?token=abc&b=1"); s != "/a?=abc&b=1" {
		t.Errorf("a query: %q", s)
	}
}

// A request whose index is out of its plan's steps names the zero step.
func TestAnIndexOutOfThePlanIsTheZeroStep(t *testing.T) {
	for _, i := range []int{-1, 0, 3} {
		if s := step(kernel.Request{Index: i}); s.Verb != "" || s.Args != nil {
			t.Errorf("index %d: %+v", i, s)
		}
	}
}

// A YAML-quoted key loses its opening quote; an attribute after the ref
// does not hide the value, so a field showing the agent's own text is
// neither omitted nor forgotten.
func TestUnquotedKeysAndAttributesAfterTheRef(t *testing.T) {
	if s := unquoteKey("  - 'a': b"); s != "  - a': b" {
		t.Errorf("unquoteKey: %q", s)
	}
	if s := unquoteKey("  - a: b"); s != "  - a: b" {
		t.Errorf("unquoteKey of a plain key: %q", s)
	}
	line := "- textbox \"Code\" [ref=e5] [active]: synthShown"
	if refs, stale := entryRefs(line, map[string]string{"e5": "synthShown"}); len(refs) != 0 || len(stale) != 0 {
		t.Errorf("the agent's own text: omitted %v, stale %v", refs, stale)
	}
	if refs, stale := entryRefs(line, map[string]string{"e5": "synthOther"}); !refs["e5"] || !stale["e5"] {
		t.Errorf("other text: omitted %v, stale %v", refs, stale)
	}
}

// A line that holds two fields' values loses the longer first, so a value
// that holds the other leaves none of itself showing (CRED-4).
func TestALineWithTwoValuesLosesTheLongerWhole(t *testing.T) {
	snap := "- group \"Codes pwCode2024 pwCode\" [ref=e1]:\n  - textbox \"A\" [ref=e2]: pwCode\n  - textbox \"B\" [ref=e3]: pwCode2024"
	if out := omitValues(snap, map[string]bool{"e2": true, "e3": true}, map[string]bool{}, nil); strings.Contains(out, "2024") {
		t.Fatalf("a part of the longer value shows: %s", out)
	}
}

// A value that the omission mark itself spells is no copy of it, and a
// copy on a line beside the field's path, not above it, withholds the page.
func TestTheMarkIsNoCopyAndASiblingsIs(t *testing.T) {
	snap := "- textbox \"A\" [ref=e2]: password\n- textbox \"B\" [ref=e3]: synthOther\n  - paragraph"
	if out := omitValues(snap, map[string]bool{"e2": true, "e3": true}, map[string]bool{}, nil); out == withheldMark {
		t.Fatalf("the mark was read as a copy: %s", out)
	}
	snap = "- group \"G\":\n  - heading \"synthSecret77\"\n  - group \"H\":\n    - textbox \"A\" [ref=e2]: synthSecret77"
	if out := omitValues(snap, map[string]bool{"e2": true}, map[string]bool{}, nil); out != withheldMark {
		t.Fatalf("a copy in a sibling was scrubbed, not withheld: %s", out)
	}
	// A field's own child is on its path: its role is no copy of a value that spells it.
	snap = "- textbox \"Note\" [ref=e2]: text\n  - text: synthMore"
	if out := omitValues(snap, map[string]bool{"e2": true}, map[string]bool{}, nil); out != "- textbox \"Note\" [ref=e2]: "+omittedMark+"\n  - text: "+omittedMark {
		t.Fatalf("a field's own child was read as a copy, or lost its role: %s", out)
	}
}

// The print covers each typed field's ref and name with its text, and a
// cut never splits a character.
func TestThePrintCoversEachFieldsRefAndName(t *testing.T) {
	h := newHarness(t, nil, "", 0)
	h.g.typed = map[string]typedField{"f1": {text: "synthNote", url: h.g.page}}
	h.g.refs["f1"] = link{role: "textbox", name: "Note"}
	printOf := func() string { return h.g.approval(Request{Verb: "click", Ref: "e1"}, h.g.refs["e1"]).Print }
	a := printOf()
	h.g.refs["f1"] = link{role: "textbox", name: "Memo"}
	if printOf() == a {
		t.Error("a field's name is not in the print")
	}
	h.g.typed = map[string]typedField{"f2": {text: "synthNote", url: h.g.page}}
	h.g.refs["f2"] = link{role: "textbox", name: "Note"}
	if printOf() == a {
		t.Error("a field's ref is not in the print")
	}
	if s := capText("ééé", 3); s != "é…" {
		t.Errorf("capText cut %q", s)
	}
}

// Only the owner's passkey makes an approval: a key the home clerk derives
// itself with the right prints and use cap releases nothing, and neither
// does an owner's link over it that names no prints, caps no uses, or
// lives longer than MaxApproval.
// The same caveats on the phone's own link send once (OWN-9, #2675).
func TestOnlyThePasskeyApproves(t *testing.T) {
	hpub, hpriv := seedKey(2)
	soon := key.LimitExpires(MaxApproval / 2)
	for _, id := range []string{"minted", "bare", "uncapped", "standing", "long", "tap", "late", "below"} {
		r := newCart(t, nil, 0)
		r.run(t, 1, "ask", r.root, read(pressOrder))
		a := r.stepApproval(t, "ask")
		k, err := key.Derive(r.root, hpriv, hpub, key.LimitVerbs(key.Post), key.LimitContent(a.Print), key.LimitUses(1))
		if err != nil {
			t.Fatal(err)
		}
		switch id {
		case "minted":
			// Brief, named and capped, but the home clerk signed it, not the phone.
			if k, err = key.Derive(r.root, hpriv, hpub, key.LimitVerbs(key.Post), key.LimitContent(a.Print), key.LimitUses(1), soon); err != nil {
				t.Fatal(err)
			}
		case "bare":
			if k, err = key.Narrow(k, key.Ed25519Signer(r.phone), key.LimitUses(1), soon); err != nil {
				t.Fatal(err)
			}
		case "uncapped":
			if k, err = key.Narrow(k, key.Ed25519Signer(r.phone), key.LimitContent(a.Print), soon); err != nil {
				t.Fatal(err)
			}
		case "standing":
			if k, err = key.Narrow(k, key.Ed25519Signer(r.phone), key.LimitContent(a.Print), key.LimitUses(1)); err != nil {
				t.Fatal(err)
			}
		case "long":
			if k, err = key.Narrow(k, key.Ed25519Signer(r.phone), key.LimitContent(a.Print), key.LimitUses(1),
				key.LimitExpires(16*60*1000)); err != nil {
				t.Fatal(err)
			}
		case "tap":
			k = r.approve(t, a.Print)
		case "below":
			// The clerk's own link under the owner's tap: the tip is no longer the owner's.
			if k, err = key.Derive(r.approve(t, a.Print), hpriv, hpub, key.LimitContent(a.Print), key.LimitUses(1), soon); err != nil {
				t.Fatal(err)
			}
		case "late":
			// A link expiring just inside MaxApproval is an approval.
			if k, err = key.Narrow(r.root, key.Ed25519Signer(r.phone), key.LimitVerbs(key.Post), key.LimitContent(a.Print), key.LimitUses(1),
				key.LimitExpires(MaxApproval-60_000)); err != nil {
				t.Fatal(err)
			}
		}
		r.run(t, 2, id, k, submitStep(a, pressOrder))
		s, clicks := r.step(id), len(forwarded(t, r.h, "click"))
		if id == "tap" || id == "late" {
			if s.Phase != kernel.PDone || clicks != 1 {
				t.Fatalf("%s: phase %s (%s), %d clicks", id, s.Phase, s.Detail, clicks)
			}
		} else if s.Phase != kernel.PFailed || s.Detail != "unapproved" || clicks != 0 {
			t.Fatalf("%s: phase %s (%s), %d clicks", id, s.Phase, s.Detail, clicks)
		}
	}
}
