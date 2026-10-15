package localui

import (
	"net/url"
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
// OPERATING §4). The vault process's notices are not here: until they
// reach the owner channel (P2-3) they are only logged (egress K6, K25).
var promiseSenders = map[string]struct{ file, sent string }{
	// owner.LocalSignIn's alert, sent by the owner channel.
	"I text you that a phone signed in": {"../owner/local.go", "A phone signed in on my Wi-Fi at "},
	// setup's code text, sent through page_setup_send's fixed texts.
	"I will text you a code": {"../localapi/setup.go", "gentOS setup code: "},
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

// #1294 (CH-12): while the box cannot text, the number step names what
// the owner can check, not only Reload.
func TestTheNumberStepNamesTheSIMAndModemWhenItCannotText(t *testing.T) {
	r := newRig(t)
	r.hooks.mu.Lock()
	r.hooks.noTexts = true
	r.hooks.mu.Unlock()
	r.get("/setup")
	r.post("/setup/network", url.Values{"ssid": {"Home"}, "password": {"home-pass"}})
	page := r.get("/setup")
	for _, w := range []string{"Pairing is not available yet", "the SIM is in the modem", "the modem is plugged in", "reload this page"} {
		if !strings.Contains(page, w) {
			t.Fatalf("number step with no texts lacks %q: %s", w, page)
		}
	}
}

// #1281 (ONB-3): the network list opens on a disabled placeholder, so no
// network is preselected; submitting it unchanged joins nothing.
func TestTheNetworkListPreselectsNothing(t *testing.T) {
	r := newRig(t)
	page := r.get("/setup")
	if !strings.Contains(page, `<select name="ssid"><option value="" disabled selected>Choose your network</option>`) {
		t.Fatalf("network list without a placeholder first: %s", page)
	}
	r.post("/setup/network", url.Values{"other": {""}, "password": {"home-pass"}})
	if r.hooks.joined != "" {
		t.Fatalf("joined %q with nothing chosen", r.hooks.joined)
	}
}
