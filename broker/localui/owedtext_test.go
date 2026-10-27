package localui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// REQ: OP-9, CH-3, CAP-9, CH-12, ONB-3

// promiseSenders names, for each line on a local page that promises the
// owner a text, the file that sends it and words from the text sent. A
// promise with no sender here fails the test below: either wire a sender
// that reaches the owner channel and add it, or drop the line (#1421,
// OPERATING §4). The vault process's notices are sent by agentosd's
// notice puller (cmd/agentosd/noticepull.go) from notice.Text's table;
// the second test below checks that main.go starts it.
var promiseSenders = map[string]struct{ file, sent string }{
	// owner.LocalSignIn's alert, sent by the owner channel.
	"I text you that a phone signed in": {"../owner/local.go", "A phone signed in on my Wi-Fi at "},
	// setup's code text, sent through page_setup_send's fixed texts.
	"I will text you a code": {"../localapi/setup.go", "gentOS setup code: "},
	// the vault process's notices, texted by agentosd's notice puller.
	"I text you when the account is changed or removed": {"../owner/notice/notice.go", "account was replaced on my Wi-Fi page."},
	"I text you when this changes":                      {"../owner/notice/notice.go", "may now get your private data: it was allowed on my Wi-Fi page."},
}

var promiseRe = regexp.MustCompile(`\bI (?:will )?text you\b[^.<"]*`)

// #1421: every "I text you" on a local page is sent to the owner by a
// named sender that reaches the owner channel.
func TestEveryTextPromisedOnALocalPageHasASender(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range promiseRe.FindAllString(string(b), -1) {
			m = strings.TrimSpace(m)
			s, ok := promiseSenders[m]
			if !ok {
				t.Errorf("%s promises %q, but no sender reaches the owner channel", f, m)
				continue
			}
			seen[m] = true
			src, err := os.ReadFile(s.file)
			if err != nil || !strings.Contains(string(src), s.sent) {
				t.Errorf("%q: %s does not send %q", m, s.file, s.sent)
			}
		}
	}
	for m := range promiseSenders {
		if !seen[m] {
			t.Errorf("sender listed for %q, which no page promises", m)
		}
	}
}

// #1421: the notice sender those promises rest on is started by agentosd.
func TestAgentosdStartsTheNoticePullerThePagesPromise(t *testing.T) {
	src, err := os.ReadFile("../cmd/agentosd/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "newNoticePuller(noticeSocket, informOwner(d.Owner)).run(ctx)") {
		t.Fatal("agentosd's main.go does not start the notice puller, so the vault's notices are never texted")
	}
}

// #1294 (CH-12): while the box cannot text, the number step names what
// the owner can check, not only Reload.
func TestTheNumberStepNamesTheSIMAndModemWhenItCannotText(t *testing.T) {
	r := newRig(t)
	r.hooks.mu.Lock()
	r.hooks.noTexts = true
	r.hooks.mu.Unlock()
	r.get("/setup")
	r.hooks.progress.Online = true
	page := r.get("/setup")
	for _, w := range []string{"Pairing is not available yet", "the SIM is in the modem", "the modem is plugged in", "reload this page"} {
		if !strings.Contains(page, w) {
			t.Fatalf("number step with no texts lacks %q: %s", w, page)
		}
	}
}
