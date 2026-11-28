package inbox

// Row #6334: tests that tell each remaining statement of vrb2.go, poster.go,
// plansenders.go, inbox.go, wording.go and shadow.go from its deletion. Most
// call the function itself, so they reach no more of the package than that
// function needs; its own file keeps its imports off the other tests.

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// openedAddr refuses an address with no local part, no domain, or a domain
// IDNA's lookup refuses, though the lookup gives a partial answer.
func TestOpenedAddrRefusesWhatIsNoAddress(t *testing.T) {
	for _, a := range []string{"nolocal", "@bank.test", "a@", "a@a‍b.test"} {
		if got := openedAddr(a); got != "" {
			t.Errorf("openedAddr(%q) = %q, want none", a, got)
		}
	}
	if got := openedAddr("a@ＢＡＮＫ.test"); got != "a@bank.test" {
		t.Errorf("control: openedAddr(fullwidth) = %q", got)
	}
}

// An IP address has no organizational domain, though the public suffix list
// would give it one.
func TestOrgOfAnAddressIsNone(t *testing.T) {
	for _, d := range []string{"192.0.2.1", "198.51.100.7"} {
		if o := org(d); o != "" {
			t.Errorf("org(%q) = %q, want none", d, o)
		}
	}
}

// An undated signature is current once, whatever today is.
func TestCurrentSigsKeepsAnUndatedSignatureOnce(t *testing.T) {
	undated := []Sig{{D: "bank.test", T: -1, X: -1, Pass: true}}
	for _, today := range []string{"2026-10-19", "not a day"} {
		cur, dated := currentSigs(undated, today)
		if !dated || len(cur) != 1 {
			t.Errorf("today %q: currentSigs = %v, %v; want the one signature, dated", today, cur, dated)
		}
	}
}

// NewPoster raises a base configuration's floor to TLS 1.2 on its own copy.
func TestPosterRaisesALowTLSFloor(t *testing.T) {
	base := &tls.Config{MinVersion: tls.VersionTLS10}
	ps := NewPoster(nil, base)
	if v := ps.client.Transport.(*http.Transport).TLSClientConfig.MinVersion; v != tls.VersionTLS12 {
		t.Fatalf("MinVersion %#x, want TLS 1.2", v)
	}
	if base.MinVersion != tls.VersionTLS10 {
		t.Fatal("the caller's configuration changed")
	}
}

// A URL past postURLMax is refused; one at it is not.
func TestPostURLRefusesALongURL(t *testing.T) {
	head := "https://example.com/"
	if _, ok := postURL(head + strings.Repeat("a", postURLMax-len(head))); !ok {
		t.Fatal("control: a URL of postURLMax refused")
	}
	if _, ok := postURL(head + strings.Repeat("a", postURLMax-len(head)+1)); ok {
		t.Fatal("a URL past postURLMax accepted")
	}
}

// stopCtx is a parent context that hears when a child stops waiting on it:
// a context.WithTimeout child registers through AfterFunc and calls stop
// when it is cancelled.
type stopCtx struct {
	context.Context
	done    chan struct{}
	mu      sync.Mutex
	waiting int
}

func (c *stopCtx) Done() <-chan struct{} { return c.done }
func (c *stopCtx) Err() error            { return nil }
func (c *stopCtx) AfterFunc(func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.waiting++
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.waiting--
		return true
	}
}

// Post releases its bounded context when it returns, not when the bound ends.
func TestPosterReleasesItsContext(t *testing.T) {
	rg := newPosterRig(t, map[string][]netip.Addr{"example.com": {public}})
	ctx := &stopCtx{Context: context.Background(), done: make(chan struct{})}
	if err := rg.poster.Post(ctx, onePost("https://example.com/u")); err != nil {
		t.Fatal(err)
	}
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.waiting != 0 {
		t.Fatalf("%d children still wait on the caller's context", ctx.waiting)
	}
}

// hijack takes the raw connection of a request the rig's server read.
func hijack(t *testing.T, w http.ResponseWriter) net.Conn {
	c, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Error(err)
	}
	return c
}

// A connection that drops once the request was sent may have reached the
// endpoint: unconfirmed, never NotDone.
func TestPosterTreatsADropAfterConnectingAsUnconfirmed(t *testing.T) {
	rg := newPosterRig(t, map[string][]netip.Addr{"example.com": {public}})
	rg.response = func(w http.ResponseWriter, r *http.Request) { hijack(t, w).Close() }
	if err := rg.poster.Post(context.Background(), onePost("https://example.com/u")); err != errUnconfirmed {
		t.Fatalf("Post = %v, want %v", err, errUnconfirmed)
	}
}

// closeCount is a response body that counts its Closes.
type closeCount struct {
	io.Reader
	n *int
}

func (c closeCount) Close() error { *c.n++; return nil }

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Post closes the response body itself, not only through its context.
func TestPosterClosesTheResponseBody(t *testing.T) {
	ps := NewPoster(nil, nil)
	closes := 0
	ps.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Request: r,
			Body: closeCount{strings.NewReader("ok"), &closes}}, nil
	})
	if err := ps.Post(context.Background(), onePost("https://example.com/u")); err != nil {
		t.Fatal(err)
	}
	if closes != 1 {
		t.Fatalf("body closed %d times, want 1", closes)
	}
}

// Post reads the response body before it returns.
func TestPosterReadsTheResponseBody(t *testing.T) {
	const delay = 300 * time.Millisecond
	rg := newPosterRig(t, map[string][]netip.Addr{"example.com": {public}})
	rg.response = func(w http.ResponseWriter, r *http.Request) {
		c := hijack(t, w)
		defer c.Close()
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
		time.Sleep(delay)
		io.WriteString(c, "hello")
	}
	start := time.Now()
	if err := rg.poster.Post(context.Background(), onePost("https://example.com/u")); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el < delay {
		t.Fatalf("Post returned after %v, before the body came", el)
	}
}

// planSender trims the provider's authserv-id, and an empty one matches no
// field, not even one whose authserv-id is an empty quoted string.
func TestPlanSenderAuthServEdges(t *testing.T) {
	fs := func(ar string) [][2]string {
		return [][2]string{{"Authentication-Results", ar}, {"From", "a@bank.test"}}
	}
	if got := planSender(fs("mx.google.com; dkim=pass header.d=bank.test"), " mx.google.com\t"); got != "bank.test" {
		t.Errorf("padded authserv-id: %q, want bank.test", got)
	}
	if got := planSender(fs(`""; dkim=pass header.d=bank.test`), ""); got != "" {
		t.Errorf("empty authserv-id: %q, want none", got)
	}
}

// A listing that names no next page is read once.
func TestPlanReaderListsOncePerPage(t *testing.T) {
	box, srv := newGmail(t)
	srv.Deliver([]byte(planMail("a@bank.test", gmailAR("pass", "bank.test"))))
	got, err := box.PlanSenders(context.Background(), planAuthServ)
	if err != nil || !slices.Equal(got, []string{"bank.test"}) {
		t.Fatalf("PlanSenders = %v, %v", got, err)
	}
	if lists, _ := planRequests(srv.Requests()); len(lists) != 1 {
		t.Fatalf("%d list requests, want 1: %v", len(lists), lists)
	}
}

func TestReasonNamesTheKeysRefusals(t *testing.T) {
	for code, want := range map[string]string{key.RVerb: "outside-key", kernel.CPlan: "outside-key", "expired": "expired"} {
		if got := Reason(code); got != want {
			t.Errorf("Reason(%q) = %q, want %q", code, got, want)
		}
	}
}

// Probe says done for a done step, and unknown for an organize step past
// MaxChecks mailbox calls.
func TestProbeAnswersFromTheClerksMemory(t *testing.T) {
	a, err := NewAccount(nil, []byte(secret), func() World { return World{} }, nil, Synthetic{}, 30, "")
	if err != nil {
		t.Fatal(err)
	}
	req := func(id string) kernel.Request {
		return kernel.Request{Plan: kernel.Plan{ID: id, Steps: []kernel.PlanStep{{Verb: key.Organize, Clerk: Name}}}}
	}
	if got := a.Probe(req("fresh"), nil).Outcome; got != "notdone" {
		t.Fatalf("control: a fresh organize step probes %q", got)
	}
	a.Preload(req("done").Idem())
	if got := a.Probe(req("done"), nil).Outcome; got != "done" {
		t.Errorf("a done step probes %q, want done", got)
	}
	a.sends[req("sent").Idem()] = kernel.MaxChecks
	if got := a.Probe(req("sent"), nil).Outcome; got != "unknown" {
		t.Errorf("a step past MaxChecks probes %q, want unknown", got)
	}
}

// An unsubscribe naming a handle the clerk never gave is refused as such.
func TestUnsubscribeOfAnUnknownSenderIsRefused(t *testing.T) {
	r := spamRig(t)
	r.run(t, r.step("u", key.Unsubscribe, map[string]string{"to": "nope"}))
	if rf := r.lastRefusal(t); rf.Reason != "unknown-sender" || rf.Mail != nil {
		t.Fatalf("refusal %+v", rf)
	}
}

// A landed unsubscribe is in Posts, once.
func TestALandedUnsubscribeIsInPosts(t *testing.T) {
	w, _, raw := loadFixture(t)
	w.AuthServ, w.AlertSenders = authServ, []string{"unrelated.test"}
	r := newRigOn(t, w, []Mail{{ID: "M01", Raw: raw["M01"], Class: "bulk"}}, Synthetic{}, 30)
	h := handleOfMail(t, r, "M01")
	r.run(t, r.onKey(r.unsub, "u", key.Unsubscribe, map[string]string{"to": h}), t0+dayMS)
	if ps := r.acct.Posts(); len(ps) != 1 || ps[0].Method != "POST" || !strings.HasPrefix(ps[0].URL, "https://") {
		t.Fatalf("posts %v refusals %v", ps, r.acct.Refusals())
	}
}

// Alerts lists the verified alerts in id order, whatever the map's.
func TestAlertsAreSorted(t *testing.T) {
	good, keys := signed(t, "alerts@security.test", "https://security.test/u", "security.test", "")
	w := World{DKIMKeys: keys, Today: "2026-10-19", AuthServ: authServ, AlertSenders: []string{"security.test"}}
	raw := withAuth(good, authServ+"; dmarc=pass header.from=security.test")
	ids := []string{"a1", "a2", "a3", "a4"}
	var ms []Mail
	for _, id := range ids {
		ms = append(ms, Mail{ID: id, Raw: raw, Class: "spam"})
	}
	a, err := NewAccount(nil, []byte(secret), func() World { return w }, ms, Synthetic{}, 30, "")
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		if got := a.Alerts(); !slices.Equal(got, ids) {
			t.Fatalf("Alerts = %v, want %v", got, ids)
		}
	}
}

// Adjacent digit groups read as one code, not as a code and a group: the
// joined code is codeReach words from the code word.
func TestCodeNearWordJoinsDigitGroups(t *testing.T) {
	if !codeNearWord("482 913 a b c code") {
		t.Fatal("a joined code codeReach words from a code word is not near it")
	}
}

// lineDropper keeps every byte but CR and LF, in order.
func TestLineDropperKeepsTheRest(t *testing.T) {
	b, err := io.ReadAll(lineDropper{strings.NewReader("ab\r\ncd\nef")})
	if err != nil || string(b) != "abcdef" {
		t.Fatalf("read %q, %v", b, err)
	}
}

// A mail listed twice in one run gets one proposal.
func TestShadowProposesAMailListedTwiceOnce(t *testing.T) {
	s := &Shadow{Start: shadowStart}
	s.Propose(shadowStart, []Item{{Mail: "m1", Class: "spam"}, {Mail: "m1", Class: "spam"}}, nil)
	if len(s.Proposals) != 1 {
		t.Fatalf("proposals %v", s.Proposals)
	}
}
