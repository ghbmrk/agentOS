package browser

// REQ: CLK-3, CRED-4

import (
	"context"
	"os"
	"strings"
	"testing"
)

const unsubURL = "https://shop.example.test/unsubscribe?token=synthCanaryTok123"

// unsubShown is unsubURL as the agent sees it: the output filter redacts the
// token, and an approval's to gives the target in that form.
const unsubShown = "https://shop.example.test/unsubscribe?token=[REDACTED]"

// A page with a mail-style action link, a relative confirm link, a link
// named like an action, an ordinary link, a button, and elements nested in
// links: an image in an unsubscribe link and an action-named child of an
// ordinary link. Then an anchor with role="button" and a GET form's button,
// which show no target, and a hash-routed action link.
const actionPage = `- generic [ref=e1]:
  - link "Stop these emails" [ref=e2] [cursor=pointer]:
    - /url: /unsubscribe?token=synthCanaryTok123
  - link "here" [ref=e3]:
    - /url: email/confirm?t=synthCanaryT2
  - link "Unsubscribe" [ref=e4]:
    - /url: "#"
  - link "Electric kettle" [ref=e5]:
    - /url: /products/kettle
  - button "Add to basket" [ref=e6]
  - link "a [ref=e5] decoy" [ref=e7]:
    - /url: /account/delete
  - link "Gift ideas" [ref=e8]:
    - generic [ref=e9]:
      - /url: /unsubscribe
    - /url: /gifts
  - link [ref=e10]:
    - /url: /unsubscribe?token=synthCanaryTok123
    - img "logo" [ref=e11]
  - link "Kettles" [ref=e12]:
    - /url: /products/kettles
    - generic "Unsubscribe" [ref=e13]
  - button "Unsubscribe" [ref=e14] [cursor=pointer]
  - button "Unsubscribe me" [ref=e15]
  - link "Manage" [ref=e16]:
    - /url: /#/unsubscribe?token=synthCanaryT4`

func pageReply(snapshot string) map[string]any {
	return map[string]any{"ok": true, "url": "https://shop.example.test/mail/", "snapshot": snapshot}
}

func forwarded(t *testing.T, h *harness, verb string) []string {
	t.Helper()
	var out []string
	for _, r := range h.received(t) {
		if strings.Contains(r, `"verb":"`+verb+`"`) {
			out = append(out, r)
		}
	}
	return out
}

// Acceptance 1 (A5/A13): a credentialed navigate to an unsubscribe link
// waits for the owner's approval, like a POST, and is never sent.
func TestStateChangingNavigateWaitsForApproval(t *testing.T) {
	h := newHarness(t, nil, "", 0)
	r := h.do(t, `{"v":0,"verb":"navigate","url":"`+unsubURL+`"}`)
	if r.OK || r.Error != "approval_required" || r.To != unsubShown {
		t.Fatalf("got %+v", r)
	}
	if got := h.received(t); len(got) != 0 {
		t.Fatalf("the driver received %q", got)
	}
}

// Acceptance 3: clicking a link whose target or name is an action waits for
// the owner's approval of the ref's role, name and target.
func TestClickOnAStateChangingLinkWaitsForApproval(t *testing.T) {
	h := newHarness(t, map[string]any{"snapshot": pageReply(actionPage)}, "", 0)
	if r := h.do(t, `{"v":0,"verb":"snapshot"}`); !r.OK {
		t.Fatalf("snapshot %+v", r)
	}
	for ref, target := range map[string]string{
		"e2":  unsubURL,
		"e3":  "https://shop.example.test/mail/email/confirm?t=synthCanaryT2",
		"e4":  "https://shop.example.test/mail/",
		"e7":  "https://shop.example.test/account/delete",
		"e10": unsubURL,
		"e11": unsubURL,
		"e13": "https://shop.example.test/products/kettles",
		"e14": "",
		"e15": "",
		"e16": "https://shop.example.test/#/unsubscribe?token=synthCanaryT4",
	} {
		l := h.g.refs[ref]
		for _, verb := range []string{"click", "download"} {
			r := h.do(t, `{"v":0,"verb":"`+verb+`","ref":"`+ref+`"}`)
			if r.OK || r.Error != "approval_required" || r.To != h.shown(l.to()) || l.target != target {
				t.Fatalf("%s %s: %+v, link %+v, want %s", verb, ref, r, l, target)
			}
		}
	}
	if got := len(h.received(t)); got != 1 {
		t.Fatalf("driver received %d requests, want only the snapshot", got)
	}
}

// Acceptance 4: the gate must know what a link points at before it lets a
// click or download through.
func TestClickOnAnUnseenRefIsRefused(t *testing.T) {
	h := newHarness(t, map[string]any{"snapshot": pageReply(actionPage)}, "", 0)
	for _, verb := range []string{"click", "download"} {
		if r := h.do(t, `{"v":0,"verb":"`+verb+`","ref":"e5"}`); r.OK || r.Error != "unknown_ref" {
			t.Fatalf("%s before any snapshot: %+v", verb, r)
		}
	}
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	for _, ref := range []string{"e99", "f1e2"} {
		if r := h.do(t, `{"v":0,"verb":"click","ref":"`+ref+`"}`); r.OK || r.Error != "unknown_ref" {
			t.Fatalf("click %s: %+v", ref, r)
		}
	}
	if got := forwarded(t, h, "click"); len(got) != 0 {
		t.Fatalf("driver got %q", got)
	}
}

// Acceptance 5: ordinary navigation and links still pass.
func TestOrdinaryLinksStillPass(t *testing.T) {
	h := newHarness(t, map[string]any{"snapshot": pageReply(actionPage)}, "", 0)
	for _, u := range []string{"https://shop.example.test/products/kettle", "https://shop.example.test/search?q=kettle"} {
		if r := h.do(t, `{"v":0,"verb":"navigate","url":"`+u+`"}`); !r.OK {
			t.Fatalf("navigate %s: %+v", u, r)
		}
	}
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	// e8's own target is /gifts; the /url under its child is not its own.
	for _, ref := range []string{"e5", "e8"} {
		if r := h.do(t, `{"v":0,"verb":"click","ref":"`+ref+`"}`); !r.OK {
			t.Fatalf("click %s: %+v", ref, r)
		}
	}
	if got := forwarded(t, h, "click"); len(got) != 2 {
		t.Fatalf("driver got %q", got)
	}
	// Over-matching fails closed (AS2): a search for an action word needs approval.
	if r := h.do(t, `{"v":0,"verb":"navigate","url":"https://shop.example.test/search?q=cancel+culture"}`); r.Error != "approval_required" {
		t.Fatalf("got %+v", r)
	}
}

// CLK-3, fail closed: an action that shows the gate no GET target may
// submit something whatever its name, so it waits for the owner's approval
// of the exact request and is never sent: a neutrally named button, an
// element inside a link, a container, a select, and typing with submit.
func TestActionsTheGateCannotJudgeWaitForApproval(t *testing.T) {
	h := newHarness(t, map[string]any{"snapshot": pageReply(actionPage)}, "", 0)
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	for raw, to := range map[string]string{
		`{"v":0,"verb":"click","ref":"e6"}`:                              `button "Add to basket"`,
		`{"v":0,"verb":"download","ref":"e6"}`:                           `button "Add to basket"`,
		`{"v":0,"verb":"click","ref":"e9"}`:                              h.shown(h.g.refs["e9"].to()),
		`{"v":0,"verb":"click","ref":"e1"}`:                              h.shown(h.g.refs["e1"].to()),
		`{"v":0,"verb":"select","ref":"e6","option":"a"}`:                `button "Add to basket"`,
		`{"v":0,"verb":"type","ref":"e5","text":"kettle","submit":true}`: `link "Electric kettle" https://shop.example.test/products/kettle`,
	} {
		if r := h.do(t, raw); r.OK || r.Error != "approval_required" || r.To != to {
			t.Fatalf("%s: %+v, want to %q", raw, r, to)
		}
	}
	if got := h.received(t); len(got) != 1 {
		t.Fatalf("driver received %q, want only the snapshot", got)
	}
	// Typing without submit only fills a field.
	if r := h.do(t, `{"v":0,"verb":"type","ref":"e5","text":"kettle"}`); r.Error == "approval_required" {
		t.Fatalf("type: %+v", r)
	}
}

// D-145: a session holding none of the owner's identity can harm the owner
// only through a URL that acts or carries a token, so logged out a button,
// a select and a submit are free while such a URL still waits for approval.
func TestLoggedOutActionsAreFreeButActingURLsAreNot(t *testing.T) {
	h := newHarness(t, map[string]any{"snapshot": pageReply(actionPage)}, "", 0)
	h.g.cfg.LoggedOut = true
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	for _, raw := range []string{
		`{"v":0,"verb":"click","ref":"e6"}`,
		`{"v":0,"verb":"click","ref":"e14"}`,
		`{"v":0,"verb":"select","ref":"e6","option":"a"}`,
		`{"v":0,"verb":"type","ref":"e5","text":"kettle","submit":true}`,
	} {
		if r := h.do(t, raw); !r.OK {
			t.Fatalf("%s: %+v", raw, r)
		}
	}
	for _, raw := range []string{
		`{"v":0,"verb":"click","ref":"e2"}`,
		`{"v":0,"verb":"download","ref":"e10"}`,
		`{"v":0,"verb":"navigate","url":"` + unsubURL + `"}`,
	} {
		if r := h.do(t, raw); r.Error != "approval_required" {
			t.Fatalf("%s: %+v", raw, r)
		}
	}
	if got := len(h.received(t)); got != 5 {
		t.Fatalf("driver received %d requests, want the snapshot and the 4 free actions", got)
	}
}

// Acceptance 3 and 5 on a snapshot Chromium gave for testdata/clicks.html
// (testdata/snapshot.py): a target is judged by the text of its whole
// clickable subtree, so an icon-plus-text link needs approval; only links to
// plain targets and clicks into text fields pass.
func TestClicksOnARealChromiumSnapshot(t *testing.T) {
	raw, err := os.ReadFile("testdata/clicks.snapshot.txt")
	if err != nil {
		t.Fatal(err)
	}
	snap := strings.TrimSpace(string(raw))
	h := newHarness(t, map[string]any{"snapshot": pageReply(snap)}, "", 0)
	if r := h.do(t, `{"v":0,"verb":"snapshot"}`); !r.OK {
		t.Fatalf("snapshot %+v", r)
	}
	x := "https://shop.example.test/x"
	for ref, want := range map[string]link{
		"e3":  {role: "button", name: "mail icon Unsubscribe"}, // role="button" anchor, icon and text child
		"e4":  {role: "img", name: "mail icon Unsubscribe"},    // the icon inside it
		"e6":  {role: "button", name: "trash Delete"},          // a GET form's icon button
		"e7":  {role: "img", name: "trash Delete"},
		"e8":  {role: "link", name: "logo Unsubscribe", target: x}, // the link's text is a child line
		"e9":  {role: "img", name: "logo Unsubscribe", target: x},
		"e10": {role: "button", name: "Cancel subscription"},
		"e11": {role: "generic", name: "Unsubscribe"}, // a div with cursor:pointer
		"e14": {role: "button", name: "Remove"},       // a dialog's action is not a dismissal
		"e19": {role: "checkbox", name: "Unsubscribe from news"},
		"e33": {role: "listitem", name: "Kettle Remove from wishlist"}, // a pointer card is judged by its text
		"e35": {role: "button", name: "Remove from wishlist"},
		"e38": {role: "row", name: "Order 42 Cancel order"},
		"e39": {role: "cell", name: "Order 42 Cancel order"}, // no click role between it and the row
		"e42": {role: "button", name: "Cancel order"},
		"e43": {role: "link", name: "Manage", target: "/unsubscribe%zz?token=synthCanaryT6"}, // an href Go cannot parse
		"e44": {role: "button", name: `Unsubscribe\ud800 x`},                                 // a name Go cannot unquote
	} {
		r := h.do(t, `{"v":0,"verb":"click","ref":"`+ref+`"}`)
		if r.Error != "approval_required" || r.To != want.to() {
			t.Fatalf("click %s: %+v, want to %q", ref, r, want.to())
		}
	}
	if got := forwarded(t, h, "click"); len(got) != 0 {
		t.Fatalf("driver got %q", got)
	}
	// Only a link to a plain target and a click into a text field are
	// reads. A dialog's "Cancel" or "Close", a button with a neutral name
	// and every container need the owner's approval too (fail closed).
	pass := strings.Fields("e17 e20 e21 e22 e29 e31 e34 e40")
	for _, ref := range pass {
		if r := h.do(t, `{"v":0,"verb":"click","ref":"`+ref+`"}`); !r.OK {
			t.Fatalf("click %s: %+v", ref, r)
		}
	}
	for _, ref := range strings.Fields("e1 e2 e13 e15 e16 e18 e23 e24 e26 e27 e28 e30 e32 e36 e37") {
		if r := h.do(t, `{"v":0,"verb":"click","ref":"`+ref+`"}`); r.Error != "approval_required" {
			t.Fatalf("click %s: %+v", ref, r)
		}
	}
	if got := forwarded(t, h, "click"); len(got) != len(pass) {
		t.Fatalf("driver got %q", got)
	}

	// body{cursor:pointer} (click delegation): only "Log out" and the body
	// itself need approval; the other link and the search box pass.
	raw, err = os.ReadFile("testdata/pointer.snapshot.txt")
	if err != nil {
		t.Fatal(err)
	}
	h = newHarness(t, map[string]any{"snapshot": pageReply(strings.TrimSpace(string(raw)))}, "", 0)
	if r := h.do(t, `{"v":0,"verb":"snapshot"}`); !r.OK {
		t.Fatalf("snapshot %+v", r)
	}
	for ref, want := range map[string]string{"e1": "", "e2": "ok", "e3": "ok", "e4": ""} {
		r := h.do(t, `{"v":0,"verb":"click","ref":"`+ref+`"}`)
		if (want == "ok") != r.OK || (want == "" && r.Error != "approval_required") {
			t.Fatalf("body-pointer click %s: %+v", ref, r)
		}
	}
}

// Acceptance 6: the pattern table.
func TestStateLinkPatterns(t *testing.T) {
	p, err := newStateLinks([]string{"https://shop.example.test/account/close"}, Origins{"https://shop.example.test:443": true})
	if err != nil {
		t.Fatal(err)
	}
	for u, want := range map[string]bool{
		"https://shop.example.test/unsubscribe?token=synthCanaryTok123": true,
		"https://shop.example.test/mail/Unsubscribe":                    true,
		"https://shop.example.test/opt-out":                             true,
		"https://shop.example.test/email/OptOut":                        true,
		"https://shop.example.test/emailUnsubscribe":                    true,
		"https://shop.example.test/x?action=confirm":                    true,
		"https://shop.example.test/event/42/rsvp?yes=1":                 true,
		"https://shop.example.test/orders/7/cancel":                     true,
		"https://shop.example.test/log_out":                             true,
		"https://shop.example.test/p?access_token=synthTok":             true,
		"https://shop.example.test/p?csrfToken=synthTok":                true,
		"https://shop.example.test/p?sig=abc":                           true,
		"https://shop.example.test/%75nsubscribe":                       true,
		"https://shop.example.test/account/close":                       true,
		"https://shop.example.test/account/close/now":                   true,
		"https://shop.example.test/p?a=%zz":                             true,
		"https://shop.example.test/#/unsubscribe?token=synthCanaryT4":   true,
		"https://shop.example.test/app#/orders/7/cancel":                true,
		"https://shop.example.test/app#/p?nonce=synth1":                 true,
		"https://shop.example.test/oneclickunsubscribe?u=synth1":        true,
		"https://shop.example.test/unsubscribed":                        true,
		"https://shop.example.test/orders/7/canceled":                   true,
		"https://shop.example.test/account/deletion":                    true,
		"https://shop.example.test/products/kettle#unsubscribe":         true,
		"https://shop.example.test/":                                    false,
		"https://shop.example.test/products/kettle":                     false,
		"https://shop.example.test/search?q=kettle&page=2":              false,
		"https://shop.example.test/account/orders":                      false,
		"https://shop.example.test/subscriptions/manage":                false,
		"https://shop.example.test/signature-dishes":                    false,
		"https://shop.example.test/products/kettle#reviews":             false,
		"https://shop.example.test/app#/orders?page=2":                  false,
		"https://shop.example.test/un-subscribed":                       true,
		"https://shop.example.test/store/movies":                        false,
		"https://shop.example.test/code/letters":                        false,
		"https://shop.example.test/fun/subjects":                        false,
		"https://shop.example.test/products/falcon-firmware":            false,
	} {
		if got := p.match(u); got != want {
			t.Errorf("%s: got %v, want %v", u, got, want)
		}
	}
	for _, bad := range []string{"https://evil.test/account/", "https://shop.example.test", "not a url", "https://shop.example.test/a?b"} {
		if _, err := newStateLinks([]string{bad}, Origins{"https://shop.example.test:443": true}); err == nil {
			t.Errorf("accepted recipe pattern %q", bad)
		}
	}
}

func TestStateLinksFromConfig(t *testing.T) {
	if _, err := Start(context.Background(), Config{Driver: []string{"/bin/true"}, Origins: []string{"https://shop.example.test"},
		Workspace: t.TempDir(), StateLinks: []string{"https://evil.test/x"}}); err == nil {
		t.Fatal("Start accepted a recipe pattern off the declared origins")
	}
}
