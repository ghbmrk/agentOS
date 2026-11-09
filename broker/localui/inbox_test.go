package localui

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// REQ: CH-14
// The Inbox page shows what the owner's number sent while the session was
// locked, in full and escaped, and the owner's tap sends the marked ones
// and discards the rest; a replayed or altered form runs nothing.
func TestTheInboxPageShowsHeldMessagesAndRunsTheTap(t *testing.T) {
	r := newRig(t)
	r.runSetup()
	r.startChannel(nil)
	r.ch.Handle(context.Background(), ownerNum, "book a table <b>now</b>")
	r.ch.Handle(context.Background(), ownerNum, "spoofed")
	r.post("/unlock", url.Values{"code": {r.code()}})
	page := r.get("/inbox/")
	if !strings.Contains(page, "book a table &lt;b&gt;now&lt;/b&gt;") || !strings.Contains(page, "spoofed") {
		t.Fatalf("inbox page: %s", page)
	}
	shown := regexp.MustCompile(`name="shown" value="([^"]*)"`).FindStringSubmatch(page)
	tok := regexp.MustCompile(`name="tok" value="([^"]*)"`).FindStringSubmatch(page)
	if shown == nil || tok == nil || shown[1] != "1,2" {
		t.Fatalf("form fields: %v %v", shown, tok)
	}
	// An altered list is refused.
	w := r.post("/inbox/", url.Values{"shown": {"1"}, "tok": {tok[1]}, "run": {"1"}})
	if !strings.Contains(w.Body.String(), stalePage) {
		t.Fatalf("altered form: %s", w.Body.String())
	}
	w = r.post("/inbox/", url.Values{"shown": {shown[1]}, "tok": {tok[1]}, "run": {"1"}})
	r.ch.WaitSends()
	if !strings.Contains(w.Body.String(), "Sent 1 message.") {
		t.Fatalf("run: %s", w.Body.String())
	}
	if msgs, _, _ := r.ch.LocalHeld(); len(msgs) != 0 {
		t.Fatalf("left held: %+v", msgs)
	}
	// The same form again names messages no longer held.
	w = r.post("/inbox/", url.Values{"shown": {shown[1]}, "tok": {tok[1]}, "run": {"1"}})
	if !strings.Contains(w.Body.String(), stalePage) {
		t.Fatalf("replayed form: %s", w.Body.String())
	}
}
