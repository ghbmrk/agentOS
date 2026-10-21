package browser

// REQ: CLK-2, CLK-3, KRN-8

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
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

// approvalOf is the approval a refused read carries.
func approvalOf(t *testing.T, r Result) Approval {
	t.Helper()
	if r.Error != "approval_required" || r.Approval == nil || r.Approval.Print == "" {
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

// approve is the owner's one tap for a task: a key for posts of exactly
// these prints, once each.
func (r *clerkRig) approve(t *testing.T, prints ...string) key.Key {
	t.Helper()
	hpub, hpriv := seedKey(2)
	k, err := key.Derive(r.root, hpriv, hpub, key.LimitVerbs(key.Post), key.LimitContent(prints...),
		key.LimitUses(int64(len(prints))))
	if err != nil {
		t.Fatal(err)
	}
	return k
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
	if a.Verb != "click" || a.Role != "button" || a.Label != `"Place order"` || a.To != `button "Place order"` {
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
	r.run(t, 3, "again", k, submitStep(a, pressOrder))
	if p := r.k.State().Plans["again"]; len(p.Steps) > 0 && p.Steps[0].Phase == kernel.PDone {
		t.Fatal("the same submit ran twice")
	}
	if got := forwarded(t, r.h, "click"); len(got) != 1 {
		t.Fatalf("driver got %q", got)
	}
	// Within one process the gate refuses a print it has sent, under any key.
	res, written, _ := r.h.g.submit(context.Background(), []byte(pressOrder), a.To, a.Print)
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
	if res, _, _ := h.g.submit(ctx, []byte(reordered), a.To, a.Print); !res.OK {
		t.Fatalf("first: %+v", res)
	}
	if res, written, _ := h.g.submit(ctx, []byte(pressOrder), a.To, a.Print); written || res.Error != "already_sent" {
		t.Fatalf("second: %+v", res)
	}
	if res, written, _ := h.g.submit(ctx, []byte(`{"v":0,"verb":"click","ref":"e8"}`), a.To, a.Print); written || res.Error != "not_a_submit" {
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
		if res, written, _ := h.g.submit(ctx, []byte(c.line), a.To, a.Print); written || res.Error != "changed" {
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
	if len(a.Fields) != 1 || a.Fields[0].Label != `"Delivery note"` || a.Fields[0].Value != "Leave at the door" {
		t.Fatalf("fields %+v", a.Fields)
	}
	h.do(t, `{"v":0,"verb":"type","ref":"e3","text":"Ring twice"}`)
	if res, written, _ := h.g.submit(ctx, []byte(pressOrder), a.To, a.Print); written || res.Error != "changed" {
		t.Fatalf("retyped: %+v", res)
	}

	rotated := strings.Replace(cartPage, "synthCsrfAaa1", "synthCsrfBbb2", 1)
	h = newHarness(t, map[string]any{"snapshot": []any{cartReply(cartPage), cartReply(rotated)}}, "", 0)
	h.g.tokens = map[string]bool{"csrf": true}
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	confirm := `{"v":0,"verb":"click","ref":"e7"}`
	a = approvalOf(t, h.do(t, confirm))
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	if res, _, _ := h.g.submit(ctx, []byte(confirm), a.To, a.Print); !res.OK {
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
	if s := r.step("bare"); s.Phase != kernel.PFailed || s.Detail != clerk.RClaim {
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
		h.g.refs = parseRefs(snap, "https://shop.example.test/mail/")
		h.g.page = "https://shop.example.test/mail/"
		return approvalOf(t, h.do(t, `{"v":0,"verb":"click","ref":"e2"}`))
	}
	h := newHarness(t, nil, "", 0)
	a, b := approve(h, page("synthCanaryTokAAA111")), approve(h, page("synthCanaryTokBBB222"))
	if a.To != b.To || !strings.Contains(a.To, Redacted) {
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
	r := newCart(t, map[string]any{"click": "hang"}, 300*time.Millisecond)
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
	if p := NewClerk("web", r.owner, r.h.g).Probe(req, r.k.State()); p != "unknown" {
		t.Fatalf("fresh clerk probe %s", p)
	}

	r = newCart(t, nil, 0)
	unsent := submitStep(Approval{To: `button "Place order"`, Print: "ap1:00"}, pressOrder)
	req = kernel.Request{Plan: plan("x", r.root, unsent)}
	r.c.Do(req, r.k.State())
	if p := r.c.Probe(req, r.k.State()); p != "notdone" {
		t.Fatalf("refused post probes %s", p)
	}
}

// Logged out, Probe answers from what Do judged, not from the refs the gate
// holds now: an effect stays unknown after a new snapshot reuses its ref
// for a plain link, and with no record, as after a restart with no refs,
// any line naming a ref is unknown (KRN-8, D-147).
func TestLoggedOutProbeUsesWhatDoJudged(t *testing.T) {
	h := newHarness(t, map[string]any{"click": "hang"}, "", 300*time.Millisecond)
	h.g.cfg.LoggedOut = true
	h.g.refs["e6"] = link{role: "button", name: "Send message"}
	r := newClerkRig(t, h)
	press := read(`{"v":0,"verb":"click","ref":"e6"}`)
	r.run(t, 0, "p1", r.root, press)
	h.g.refs["e6"] = plainLink
	req := kernel.Request{Plan: plan("p1", r.root, press)}
	if p := r.c.Probe(req, r.k.State()); p != "unknown" {
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
		`{"v":0,"verb":"navigate","url":"https://shop.example.test/products/kettle"}`: "notdone",
		navUnsub: "unknown",
	} {
		q := kernel.Request{Plan: plan("q", r.root, read(line))}
		if p := c.Probe(q, r.k.State()); p != want {
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
	if err := json.Unmarshal([]byte(s.Detail), &res); err != nil || !res.Truncated || res.Snapshot == "" {
		t.Fatalf("logged result: %v, truncated %v", err, res.Truncated)
	}
}

// An approval holds only what the gate read: the label is quoted, capped
// and folded, and nothing the planner wrote outside the request itself
// (a post's to, a step's content claim) appears in one (CLK-3).
func TestApprovalHoldsOnlyReadFields(t *testing.T) {
	long := "Plаce " + strings.Repeat("order ", 200)
	r := newCart(t, nil, 0)
	r.h.g.refs["e6"] = link{role: "button", name: long}
	r.run(t, 1, "ask", r.root, read(pressOrder))
	a := r.stepApproval(t, "ask")
	if len(a.Label) > maxLabel+8 || !strings.HasPrefix(a.Label, `"Plаce order`) || !strings.HasPrefix(a.Folded, "place order") {
		t.Fatalf("label %q (%d bytes), folded %q", a.Label, len(a.Label), a.Folded)
	}
	if a.Origin != "https://shop.example.test:443" || a.Page != "https://shop.example.test/cart" || a.FieldsComplete {
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
