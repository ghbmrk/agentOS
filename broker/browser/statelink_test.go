package browser

// REQ: ADP-14, CRED-4

import (
	"context"
	"os"
	"strings"
	"testing"
)

const unsubURL = "https://shop.example.test/unsubscribe?token=synthCanaryTok123"

// unsubShown is unsubURL as the agent sees it: the output filter redacts the
// token, and a post's to gives the target in that form.
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
// needs a post, like a POST, and is never sent as a read.
func TestStateChangingNavigateIsHeldNotSent(t *testing.T) {
	h := newHarness(t, nil, "", 0)
	r := h.do(t, `{"v":0,"verb":"navigate","url":"`+unsubURL+`"}`)
	if r.OK || r.Error != "post_required" || r.To != unsubShown {
		t.Fatalf("got %+v", r)
	}
	if got := h.received(t); len(got) != 0 {
		t.Fatalf("the driver received %q", got)
	}
}

// Acceptance 2: a post forwards exactly the request, and only when to names
// what it reaches.
func TestHeldLinkIsReleasedOnlyAsApproved(t *testing.T) {
	h := newHarness(t, nil, "", 0)
	nav := `{"v":0,"verb":"navigate","url":"` + unsubURL + `"}`
	for _, bad := range []string{unsubURL, unsubShown + "&x=1", "", "link \"x\" " + unsubShown} {
		if r := h.post(t, nav, bad); r.OK || r.Error != "target" || len(h.received(t)) != 0 {
			t.Fatalf("post to %q: %+v, driver got %q", bad, r, h.received(t))
		}
	}
	if r := h.post(t, nav, unsubShown); !r.OK {
		t.Fatalf("post: %+v", r)
	}
	if got := h.received(t); len(got) != 1 || got[0] != nav {
		t.Fatalf("driver got %q, want %q", got, nav)
	}
	// Only the verbs that can act on a link are posted.
	if r := h.post(t, `{"v":0,"verb":"snapshot"}`, ""); r.Error != "verb" || len(h.received(t)) != 1 {
		t.Fatalf("posted snapshot: %+v", r)
	}
}

// Acceptance 3: clicking a link whose target or name is an action needs a
// post to the ref's role, name and target.
func TestClickOnAStateChangingLinkIsHeld(t *testing.T) {
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
			if r.OK || r.Error != "post_required" || r.To != h.shown(l.to()) || l.target != target {
				t.Fatalf("%s %s: %+v, link %+v, want %s", verb, ref, r, l, target)
			}
		}
	}
	if got := len(h.received(t)); got != 1 {
		t.Fatalf("driver received %d requests, want only the snapshot", got)
	}
}

// A post of a click is sent only while the ref still reaches what to names:
// the gate reads the page again first (CLK-2).
func TestHeldClickReleaseRechecksThePage(t *testing.T) {
	// The filter redacts the token, so to binds the rest of the target.
	moved := strings.Replace(actionPage, "/unsubscribe?token=synthCanaryTok123", "/unsubscribe/all?token=otherSynthTok", 1)
	moved = strings.Replace(moved, `button "Unsubscribe" [ref=e14]`, `button "Unsubscribe from all" [ref=e14]`, 1)
	h := newHarness(t, map[string]any{"snapshot": []any{pageReply(actionPage), pageReply(moved)}}, "", 0)
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	link := h.do(t, `{"v":0,"verb":"click","ref":"e2"}`).To
	button := h.do(t, `{"v":0,"verb":"click","ref":"e14"}`).To
	if link != `link "Stop these emails" `+unsubShown || button != `button "Unsubscribe"` {
		t.Fatalf("to %q, %q", link, button)
	}
	if r := h.post(t, `{"v":0,"verb":"click","ref":"e2"}`, link); r.OK || r.Error != "target" || len(forwarded(t, h, "click")) != 0 {
		t.Fatalf("posted a click whose link changed: %+v", r)
	}
	// A button shows no target; it is bound to its role and name.
	if r := h.post(t, `{"v":0,"verb":"click","ref":"e14"}`, button); r.OK || r.Error != "target" || len(forwarded(t, h, "click")) != 0 {
		t.Fatalf("posted a button whose name changed: %+v", r)
	}
	if r := h.post(t, `{"v":0,"verb":"click","ref":"e2"}`, `link "Stop these emails" https://shop.example.test/unsubscribe/all?token=[REDACTED]`); !r.OK {
		t.Fatalf("post: %+v", r)
	}
	if got := forwarded(t, h, "click"); len(got) != 1 || got[0] != `{"v":0,"verb":"click","ref":"e2"}` {
		t.Fatalf("driver got %q", got)
	}
	// A page that cannot be read again sends nothing.
	h = newHarness(t, map[string]any{"snapshot": []any{pageReply(actionPage), map[string]any{"ok": false, "error": "nav"}}}, "", 0)
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	if r := h.post(t, `{"v":0,"verb":"click","ref":"e2"}`, link); r.OK || len(forwarded(t, h, "click")) != 0 {
		t.Fatalf("posted on an unread page: %+v", r)
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
	// e8's own target is /gifts; the /url under its child is not its own,
	// and that child e9 follows /gifts too.
	for _, ref := range []string{"e5", "e6", "e1", "e8", "e9"} {
		if r := h.do(t, `{"v":0,"verb":"click","ref":"`+ref+`"}`); !r.OK {
			t.Fatalf("click %s: %+v", ref, r)
		}
	}
	if got := forwarded(t, h, "click"); len(got) != 5 {
		t.Fatalf("driver got %q", got)
	}
	// Over-matching fails closed (AS2): a search for an action word needs a post.
	if r := h.do(t, `{"v":0,"verb":"navigate","url":"https://shop.example.test/search?q=cancel+culture"}`); r.Error != "post_required" {
		t.Fatalf("got %+v", r)
	}
}

// Acceptance 3 and 5 on a snapshot Chromium gave for testdata/clicks.html
// (testdata/snapshot.py): a target is judged by the text of its whole
// clickable subtree, so an icon-plus-text button or link needs a post, while
// ordinary links, dialog dismissals and form fields pass.
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
		if r.Error != "post_required" || r.To != want.to() {
			t.Fatalf("click %s: %+v, want to %q", ref, r, want.to())
		}
	}
	if got := forwarded(t, h, "click"); len(got) != 0 {
		t.Fatalf("driver got %q", got)
	}
	// Dialog "Cancel" and "Not now", "Confirm password", "Explore movies",
	// "Falcon firmware", "Encode letters", the containers, the text box
	// after a "[ref=e14]" text decoy, and the ordinary links inside a
	// pointer card and row that also hold an action button.
	pass := strings.Fields("e1 e2 e13 e15 e16 e17 e18 e20 e21 e22 e23 e24 e26 e27 e28 e29 e30 e31 e32 e34 e36 e37 e40")
	for _, ref := range pass {
		if r := h.do(t, `{"v":0,"verb":"click","ref":"`+ref+`"}`); !r.OK {
			t.Fatalf("click %s: %+v", ref, r)
		}
	}
	if got := forwarded(t, h, "click"); len(got) != len(pass) {
		t.Fatalf("driver got %q", got)
	}

	// body{cursor:pointer} (click delegation): only "Log out" and the body
	// itself need a post; the other link and the search box pass.
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
		if (want == "ok") != r.OK || (want == "" && r.Error != "post_required") {
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
