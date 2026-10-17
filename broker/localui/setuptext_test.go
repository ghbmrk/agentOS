package localui

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-1, CH-12, ONB-6

// textLine is agentosd's modem line in setup mode (modemlink.SetupLine):
// it sends what localsrv lets through and holds the PAIR texts that came.
type textLine struct {
	mu       sync.Mutex
	noNumber bool // the SIM texts but does not report its number
	fails    int  // the next fails sends fail and are not sent
	sent     [][2]string
	inbox    chan [2]string
}

func (l *textLine) Ready() bool { return true }
func (l *textLine) Number() string {
	if l.noNumber {
		return ""
	}
	return boxNum
}
func (l *textLine) Send(_ context.Context, to, text string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fails > 0 {
		l.fails--
		return errors.New("modem busy")
	}
	l.sent = append(l.sent, [2]string{to, text})
	return nil
}
func (l *textLine) Next(ctx context.Context) (string, string, bool) {
	select {
	case in := <-l.inbox:
		return in[0], in[1], true
	case <-ctx.Done():
		return "", "", false
	}
}

// texts waits until the line has sent n texts and returns them.
func (l *textLine) texts(t *testing.T, n int) [][2]string {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		l.mu.Lock()
		got := append([][2]string(nil), l.sent...)
		l.mu.Unlock()
		if len(got) >= n {
			return got
		}
	}
	t.Fatalf("the line did not send %d texts", n)
	return nil
}

// viaLine is the page with the box's number and texts served by agentosd.
type viaLine struct{ viaAgentosd }

func (v viaLine) BoxNumber() (string, bool)  { return v.a.BoxNumber() }
func (v viaLine) HostInfo() string           { return v.a.HostInfo() }
func (v viaLine) Send(to, text string) error { return v.a.Send(to, text) }

// textRig is a rig whose setup texts go through agentosd's setup ops
// (localsrv), which send only setup's fixed texts.
func textRig(t *testing.T, noNumber ...bool) (*rig, *textLine, AgentosdSetup) {
	r := newRig(t)
	line := &textLine{inbox: make(chan [2]string, 4), noNumber: len(noNumber) > 0 && noNumber[0]}
	s := localsrv.NewSetup(localsrv.SetupConfig{Record: localsrv.FileRecord{Path: filepath.Join(t.TempDir(), "setup.json")},
		Enroll:   vaultEnroller{r.hooks},
		Progress: func() localapi.SetupProgress { p := r.hooks.Progress(); return localapi.SetupProgress(p) },
		Finished: func(string) {}, Now: r.clock, Line: line})
	// A named PC (P2-2w c4d): the pairing reply that names it must pass
	// agentosd's text allow-list.
	a := AgentosdSetup{Owner: InProcess(s.Ops()), Root: fakeRoot(t, "Intel(R) Client Systems", "NUC13ANHi5", memTotal8)}
	r.via = viaLine{viaAgentosd{r.hooks, a}}
	r.srv = r.open(&MemStore{})
	r.get("/setup")
	r.post("/setup/network", url.Values{"ssid": {"Home"}, "password": {"home-pass"}})
	return r, line, a
}

// §8.1, CH-12 (P2-2w c4c): while the box cannot text, the number step
// says plainly that pairing is not available yet and offers nothing that
// needs a text; once it can, the step shows the box's number.
func TestTheNumberStepSaysPlainlyWhenTheBoxCannotText(t *testing.T) {
	r := newRig(t)
	r.hooks.mu.Lock()
	r.hooks.noTexts = true
	r.hooks.mu.Unlock()
	r.get("/setup")
	r.post("/setup/network", url.Values{"ssid": {"Home"}, "password": {"home-pass"}})
	page := r.get("/setup")
	if !strings.Contains(page, "Pairing is not available yet: I cannot send texts right now.") ||
		strings.Contains(page, "sms:") || strings.Contains(page, `action="/setup/number"`) || strings.Contains(page, "I sent it") {
		t.Fatalf("number step with no texts: %s", page)
	}
	r.hooks.mu.Lock()
	r.hooks.noTexts = false
	r.hooks.mu.Unlock()
	page = html.UnescapeString(r.get("/setup"))
	if strings.Contains(page, "not available yet") || !strings.Contains(page, "sms:"+boxNum) {
		t.Fatalf("number step once the box can text: %s", page)
	}
}

// ONB-6, CH-12 (UX B1 on #1269): a SIM that texts but does not report
// its own number still pairs: the number step says why the owner cannot
// text first and opens the number entry, which texts the setup code.
func TestTheNumberStepOffersNumberEntryWhenTheBoxDoesNotKnowItsNumber(t *testing.T) {
	r, line, _ := textRig(t, true)
	page := html.UnescapeString(r.get("/setup"))
	if strings.Contains(page, "not available yet") || strings.Contains(page, "sms:") || strings.Contains(page, "I sent it") ||
		!strings.Contains(page, "I do not know my own number yet") ||
		!strings.Contains(page, "<details open>") || !strings.Contains(page, `action="/setup/number"`) {
		t.Fatalf("number step with no box number: %s", page)
	}
	if w := r.post("/setup/number", url.Values{"number": {ownerNum}}); w.Code >= 400 || r.setupErr() != "" {
		t.Fatalf("number: %d %q", w.Code, r.setupErr())
	}
	if got := line.texts(t, 1); got[0][0] != ownerNum || !strings.HasPrefix(got[0][1], "AgentOS setup code: ") {
		t.Fatalf("setup code text %q", got[0])
	}
}

// ONB-6, CH-12: the typing fallback pairs through agentosd: the setup
// code and the paired reply are setup's fixed texts, sent by the box.
func TestTheNumberFallbackTextsThroughAgentosd(t *testing.T) {
	r, line, _ := textRig(t)
	paired := pairedText("Intel(R) Client Systems NUC13ANHi5, 8 GB")
	if page := html.UnescapeString(r.get("/setup")); !strings.Contains(page, "sms:"+boxNum) {
		t.Fatalf("no box number through agentosd: %s", page)
	}
	if w := r.post("/setup/number", url.Values{"number": {ownerNum}}); w.Code >= 400 || r.setupErr() != "" {
		t.Fatalf("number: %d %q", w.Code, r.setupErr())
	}
	got := line.texts(t, 1)
	m := regexp.MustCompile(`^AgentOS setup code: ([0-9]{6})\.`).FindStringSubmatch(got[0][1])
	if got[0][0] != ownerNum || m == nil {
		t.Fatalf("setup code text %q", got[0])
	}
	r.post("/setup/number-code", url.Values{"code": {m[1]}})
	got = line.texts(t, 2)
	if r.srv.setup.st.Owner != ownerNum || got[1] != [2]string{ownerNum, paired} {
		t.Fatalf("paired %q: %q", r.srv.setup.st.Owner, got[1])
	}
}

// §8.1, CH-1, CH-12: PAIR texts that reach the box come to the page
// through agentosd, and each reply goes back from the box's number: a
// wrong code's, the card code's with its page code, and a new page code.
func TestPairTextsReachThePageAndAreAnswered(t *testing.T) {
	r, line, a := textRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.PairTexts(ctx, r.srv, time.Millisecond); close(done) }()
	defer func() { cancel(); <-done }()

	line.inbox <- [2]string{"+15550000002", "PAIR AAAA-AAAA"}
	if got := line.texts(t, 1); got[0] != [2]string{"+15550000002", "That pairing code did not match. Check the setup page."} {
		t.Fatalf("mismatch reply %q", got[0])
	}
	line.inbox <- [2]string{ownerNum, "PAIR " + r.card.SetupCode}
	got := line.texts(t, 2)
	if got[1][0] != ownerNum || !regexp.MustCompile(`^`+regexp.QuoteMeta(pairedText(a.HostInfo()))+` Page code: [0-9]{6}\.$`).MatchString(got[1][1]) {
		t.Fatalf("card reply %q", got[1])
	}
	r.asOther(func() {
		r.get("/setup")
		for i := 0; i < numberCodeTries; i++ {
			r.post("/setup/claim", url.Values{"code": {"000000"}})
		}
	})
	got = line.texts(t, 3)
	if got[2][0] != ownerNum || !regexp.MustCompile(`^AgentOS page code: [0-9]{6}\.`).MatchString(got[2][1]) {
		t.Fatalf("new page code %q", got[2])
	}
	if r.srv.setup.st.Owner != ownerNum {
		t.Fatal("the card's PAIR text did not pair")
	}
}

// PairTexts stops once agentosd answers that setup is closed.
func TestPairTextsStopWhenSetupCloses(t *testing.T) {
	r := newRig(t)
	a := AgentosdSetup{Owner: InProcess{localapi.OpSetupInbound: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
		return nil, sockets.Code(localapi.ErrSetupClosed)
	}}}
	done := make(chan struct{})
	go func() { a.PairTexts(context.Background(), r.srv, time.Millisecond); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("PairTexts kept asking a closed setup")
	}
}
