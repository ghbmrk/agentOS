package localui

// REQ: ONB-6, CH-12

import (
	"context"
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// #1293: a paired text that did not go after a typed number's code still
// pairs, and the page says so once instead of dropping the error.
func TestNumberCodeSaysWhenThePairedTextDidNotGo(t *testing.T) {
	r := newRig(t)
	r.hooks.progress.Online = true
	r.hooks.sendFails = func(text string) bool { return strings.HasPrefix(text, "agentOS is running on") }
	r.get("/setup")
	r.post("/setup/number", url.Values{"number": {"+1 555 000 0001"}})
	code := regexp.MustCompile(`[0-9]{6}`).FindString(r.hooks.sent[0].Text)
	r.post("/setup/number-code", url.Values{"code": {code}})
	if r.srv.setup.st.Owner != ownerNum {
		t.Fatal("a failed paired text undid the pairing")
	}
	if page := html.UnescapeString(r.get("/setup")); !strings.Contains(page, errPairedUnsent.Error()) {
		t.Fatalf("no note: %s", page)
	}
	if page := html.UnescapeString(r.get("/setup")); strings.Contains(page, errPairedUnsent.Error()) {
		t.Fatal("the note was shown twice")
	}
}

// CH-21f-unsent: when the SIM reports no number, the owner types theirs and
// the host step has no contact card, so the unsent note sends the owner to
// the code's sender, not to a setup step the page never shows.
func TestUnsentNoteNamesNoMissingStepWhenTheSIMHasNoNumber(t *testing.T) {
	r := newRig(t)
	r.hooks.progress.Online = true
	r.hooks.noNumber = true
	r.hooks.sendFails = func(text string) bool { return strings.HasPrefix(text, "agentOS is running on") }
	r.get("/setup")
	r.post("/setup/number", url.Values{"number": {"+1 555 000 0001"}})
	code := regexp.MustCompile(`[0-9]{6}`).FindString(r.hooks.sent[0].Text)
	r.post("/setup/number-code", url.Values{"code": {code}})
	page := html.UnescapeString(r.get("/setup"))
	if !strings.Contains(page, errPairedUnsent.Error()) {
		t.Fatalf("no note: %s", page)
	}
	if strings.Contains(page, "/box.vcf") {
		t.Fatal("a SIM with no number offered a contact card")
	}
	if note := errPairedUnsent.Error(); strings.Contains(note, "later") || strings.Contains(note, "in setup") ||
		!strings.Contains(note, "the number my code came from as a contact") {
		t.Fatalf("the note promises a step the page lacks: %q", note)
	}
}

// #1293: a PAIR text's reply that did not go is sent once more after the
// retry wait, so the owner still gets the box's text.
func TestPairTextsSendAFailedReplyAgain(t *testing.T) {
	r, line, a := textRig(t)
	line.mu.Lock()
	line.fails = 1
	line.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.PairTexts(ctx, r.srv, time.Millisecond); close(done) }()
	defer func() { cancel(); <-done }()
	line.inbox <- [2]string{ownerNum, "PAIR " + r.card.SetupCode}
	got := line.texts(t, 1)
	if got[0][0] != ownerNum || !strings.HasPrefix(got[0][1], pairedText(a.HostInfo())) {
		t.Fatalf("reply %q", got[0])
	}
}
