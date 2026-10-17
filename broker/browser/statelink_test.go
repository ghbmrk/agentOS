package browser

// REQ: ADP-14, CRED-4

import (
	"context"
	"strings"
	"testing"
)

const unsubURL = "https://shop.example.test/unsubscribe?token=synthCanaryTok123"

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

// Acceptance 1 (A5/A13): a credentialed navigate to an unsubscribe link is
// held for the owner like a POST and never sent unasked.
func TestStateChangingNavigateIsHeldNotSent(t *testing.T) {
	h := newHarness(t, nil, "", 0)
	r := h.do(t, `{"v":0,"verb":"navigate","url":"`+unsubURL+`"}`)
	if r.OK || r.Error != "held" || r.Hold == "" {
		t.Fatalf("got %+v", r)
	}
	if got := h.received(t); len(got) != 0 {
		t.Fatalf("the driver received %q", got)
	}
	held, ok := h.g.Held(r.Hold)
	if !ok || held.Method != "GET" || held.URL != unsubURL || held.Origin != "https://shop.example.test:443" || held.Verb != "navigate" {
		t.Fatalf("held %+v %v", held, ok)
	}
}

// Acceptance 2: the owner's release forwards exactly the held request once.
func TestHeldLinkIsReleasedOnlyAsApproved(t *testing.T) {
	h := newHarness(t, nil, "", 0)
	id := h.do(t, `{"v":0,"verb":"navigate","url":"`+unsubURL+`"}`).Hold
	ctx := context.Background()
	for _, bad := range []struct{ id, url string }{
		{"h-unknown", unsubURL},
		{id, unsubURL + "&x=1"},
		{id, ""},
	} {
		if r := h.g.Release(ctx, bad.id, bad.url); r.OK || len(h.received(t)) != 0 {
			t.Fatalf("release %q %q: %+v, driver got %q", bad.id, bad.url, r, h.received(t))
		}
	}
	if r := h.g.Release(ctx, id, unsubURL); !r.OK {
		t.Fatalf("release: %+v", r)
	}
	want := `{"v":0,"verb":"navigate","url":"` + unsubURL + `"}`
	if got := h.received(t); len(got) != 1 || got[0] != want {
		t.Fatalf("driver got %q, want %q", got, want)
	}
	if r := h.g.Release(ctx, id, unsubURL); r.OK || len(h.received(t)) != 1 {
		t.Fatalf("second release: %+v", r)
	}
	if _, ok := h.g.Held(id); ok {
		t.Fatal("hold still stored after release")
	}
}

// Acceptance 3: clicking a link whose target or name is an action is held.
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
		for _, verb := range []string{"click", "download"} {
			r := h.do(t, `{"v":0,"verb":"`+verb+`","ref":"`+ref+`"}`)
			if r.OK || r.Error != "held" || r.Hold == "" {
				t.Fatalf("%s %s: %+v", verb, ref, r)
			}
			if held, _ := h.g.Held(r.Hold); held.URL != target || held.Ref != ref || held.Verb != verb {
				t.Fatalf("%s %s held %+v, want %s", verb, ref, held, target)
			}
		}
	}
	if got := len(h.received(t)); got != 1 {
		t.Fatalf("driver received %d requests, want only the snapshot", got)
	}
}

// A held click is released only while the ref still points where it did:
// the gate looks at the page again first.
func TestHeldClickReleaseRechecksThePage(t *testing.T) {
	moved := strings.Replace(actionPage, "/unsubscribe?token=synthCanaryTok123", "/unsubscribe?token=otherSynthTok", 1)
	moved = strings.Replace(moved, `button "Unsubscribe" [ref=e14]`, `button "Unsubscribe from all" [ref=e14]`, 1)
	h := newHarness(t, map[string]any{"snapshot": []any{pageReply(actionPage), pageReply(moved)}}, "", 0)
	h.do(t, `{"v":0,"verb":"snapshot"}`)
	id := h.do(t, `{"v":0,"verb":"click","ref":"e2"}`).Hold
	button := h.do(t, `{"v":0,"verb":"click","ref":"e14"}`).Hold
	ctx := context.Background()
	if r := h.g.Release(ctx, id, unsubURL); r.OK || len(forwarded(t, h, "click")) != 0 {
		t.Fatalf("released a click whose link changed: %+v", r)
	}
	if _, ok := h.g.Held(id); ok {
		t.Fatal("a hold whose link changed is still stored")
	}
	// A held button shows no target; it is bound to its role and name.
	if r := h.g.Release(ctx, button, ""); r.OK || len(forwarded(t, h, "click")) != 0 {
		t.Fatalf("released a button whose name changed: %+v", r)
	}
	id = h.do(t, `{"v":0,"verb":"click","ref":"e2"}`).Hold
	if id == "" {
		t.Fatal("the changed link was not held")
	}
	if r := h.g.Release(ctx, id, "https://shop.example.test/unsubscribe?token=otherSynthTok"); !r.OK {
		t.Fatalf("release: %+v", r)
	}
	if got := forwarded(t, h, "click"); len(got) != 1 || got[0] != `{"v":0,"verb":"click","ref":"e2"}` {
		t.Fatalf("driver got %q", got)
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
	// Over-matching fails closed (AS2): a search for an action word is held.
	if r := h.do(t, `{"v":0,"verb":"navigate","url":"https://shop.example.test/search?q=cancel+culture"}`); r.Error != "held" {
		t.Fatalf("got %+v", r)
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
