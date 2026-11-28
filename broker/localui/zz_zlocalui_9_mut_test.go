package localui

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sipsign"
	"github.com/ghbmrk/agentos/broker/smsapi"
)

// REQ: CH-7, CRED-8, CAP-9, ADP-12, LOG-4

// MUT-kill-localui-9 (#6773): checks that kill the mutgate survivors in
// scan.go, secondline.go, forget.go and providers.go. The handlers are
// called directly on a bare Server, so the lines these tests run are the
// handlers' own and render's, not a whole set-up box's. They run as
// subtests of TestScanBoundsProgressiveJPEG, which runs no box either: a
// new top-level test changes localui's run list, and with forget.go's init
// mutgate then reads every localui test as changed (as recoveryEdges says).

// k9Writer counts the handler's explicit WriteHeader calls: a handler
// that answers twice (an error, then a redirect or a page) writes a
// second status, which net/http drops with a "superfluous WriteHeader"
// log line, and a page after a redirect is a body the owner never sees.
type k9Writer struct {
	*httptest.ResponseRecorder
	heads int
}

func (w *k9Writer) WriteHeader(code int) {
	w.heads++
	w.ResponseRecorder.WriteHeader(code)
}

func (w *k9Writer) pages() int { return strings.Count(w.Body.String(), "<!doctype html>") }

func k9Server(cfg Config) *Server {
	return &Server{cfg: cfg, pages: pagesFor("box.test"), formKey: []byte("k9-form-key-0123456789abcdef0123")}
}

// k9Serve calls h as the mux would after its prefix is stripped: path is
// "/" or below it.
func k9Serve(h http.HandlerFunc, method, path string, form url.Values) *k9Writer {
	body := ""
	if form != nil {
		body = form.Encode()
	}
	req := httptest.NewRequest(method, "http://box.test"+path, strings.NewReader(body))
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := &k9Writer{ResponseRecorder: httptest.NewRecorder()}
	h(w, req)
	return w
}

// k9Big is a form one byte past the pages' 16 KiB body bound.
func k9Big(v url.Values) url.Values {
	v.Set("pad", strings.Repeat("a", 16<<10))
	return v
}

type k9Vault struct {
	state string
	err   error
}

func (v *k9Vault) Status(context.Context) (VaultStatus, error) {
	return VaultStatus{State: v.state}, v.err
}
func (v *k9Vault) Unlock(context.Context, string) (VaultStatus, string, error) {
	return VaultStatus{}, "", errors.New("k9: no unlock")
}
func (v *k9Vault) Confirm(context.Context, string, string, bool) (VaultStatus, error) {
	return VaultStatus{}, errors.New("k9: no confirm")
}
func (v *k9Vault) UnlockPIN(context.Context, string) (VaultStatus, error) {
	return VaultStatus{}, errors.New("k9: no PIN")
}

type k9Providers struct {
	mu          sync.Mutex
	ps          []ProviderStatus
	listErr     error
	lists, sets int
	ctx         context.Context
}

func (p *k9Providers) ProviderList(ctx context.Context) ([]ProviderStatus, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lists++
	p.ctx = ctx
	return p.ps, p.listErr
}

func (p *k9Providers) SetProviderPrivate(context.Context, string, bool, string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sets++
	return nil
}

type k9Line struct {
	mu             sync.Mutex
	st             SecondLineStatus
	sms            SMSStatus
	stErr          error
	statuses, sets int
	ctx            context.Context
}

func (l *k9Line) SecondLineStatus(ctx context.Context) (SecondLineStatus, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.statuses++
	l.ctx = ctx
	return l.st, l.stErr
}
func (l *k9Line) SetSecondLine(context.Context, sipsign.Settings, string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sets++
	return nil
}
func (l *k9Line) ConfirmRealm(context.Context, string) error { return nil }
func (l *k9Line) RemoveSecondLine(context.Context) error     { return nil }
func (l *k9Line) SMSStatus(context.Context) (SMSStatus, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sms, nil
}
func (l *k9Line) SetSMS(context.Context, smsapi.Settings, string) error { return nil }
func (l *k9Line) RemoveSMS(context.Context) error                       { return nil }

type k9Forget struct {
	mu    sync.Mutex
	found localapi.EraseFound
	err   error
	finds int
	ctx   context.Context
}

func (f *k9Forget) ForgetFind(ctx context.Context, _, _ string) (localapi.EraseFound, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finds++
	f.ctx = ctx
	return f.found, f.err
}

func (f *k9Forget) ForgetConfirm(context.Context, string, string, []byte, []byte, []byte) (localapi.EraseDone, error) {
	return localapi.EraseDone{}, Refused(localapi.ErrEraseStale)
}

func localui9Kills(t *testing.T) {
	t.Run("ProvidersPage", k9ProvidersPage)
	t.Run("SecondLinePage", k9SecondLinePage)
	t.Run("SMSProviderName", k9SMSProviderName)
	t.Run("ShowRealmBound", k9ShowRealmBound)
	t.Run("ForgetToken", k9ForgetToken)
	t.Run("ForgetPage", k9ForgetPage)
	t.Run("ProgressiveJPEGWalk", k9ProgressiveJPEGWalk)
	t.Run("ScanManyPassphrases", k9ScanManyPassphrases)
}

func k9ProvidersPage(t *testing.T) {
	open := func() (*Server, *k9Providers) {
		p := &k9Providers{ps: []ProviderStatus{{ID: "anthropic", Name: "Anthropic", Connected: true}}}
		return k9Server(Config{Vault: &k9Vault{state: "open"}, Providers: p}), p
	}
	// A path below the page is not found, and nothing else is answered.
	s, p := open()
	if w := k9Serve(s.providers, "GET", "/x", nil); w.Code != 404 || w.pages() != 0 || p.lists != 0 {
		t.Fatalf("below the page: %d, %d pages, %d lists", w.Code, w.pages(), p.lists)
	}
	// The page's bound ends with the request.
	s, p = open()
	if w := k9Serve(s.providers, "GET", "/", nil); w.Code != 200 || p.ctx == nil || p.ctx.Err() == nil {
		t.Fatalf("the page's context outlives it: %d", w.Code)
	}
	// Down and locked are one page each, and no provider is read.
	for _, v := range []*k9Vault{{err: errors.New("k9: down")}, {state: "locked"}} {
		p := &k9Providers{}
		s := k9Server(Config{Vault: v, Providers: p})
		if w := k9Serve(s.providers, "GET", "/", nil); w.pages() != 1 || p.lists != 0 {
			t.Fatalf("vault %+v: %d pages, %d lists", v, w.pages(), p.lists)
		}
	}
	// A body past the bound is refused before any step runs.
	s, p = open()
	big := k9Big(url.Values{"step": {"allow"}, "provider": {"anthropic"}, "code": {"123456"}})
	if w := k9Serve(s.providers, "POST", "/", big); w.Code != 400 || p.sets != 0 {
		t.Fatalf("over the bound: %d, %d sets", w.Code, p.sets)
	}
	// An unknown step is one 400, never followed by a redirect.
	s, p = open()
	if w := k9Serve(s.providers, "POST", "/", url.Values{"step": {"k9"}}); w.Code != 400 || w.heads != 1 || p.lists != 0 {
		t.Fatalf("unknown step: %d, %d statuses, %d lists", w.Code, w.heads, p.lists)
	}
	// A step that went through is a redirect alone, with no page after it.
	s, p = open()
	if w := k9Serve(s.providers, "POST", "/", url.Values{"step": {"allow"}, "provider": {"anthropic"}, "code": {"1"}}); w.Code != 303 || w.pages() != 0 || p.lists != 0 {
		t.Fatalf("allowed: %d, %d pages, %d lists", w.Code, w.pages(), p.lists)
	}
	// The list failing is one page.
	s, p = open()
	p.listErr = errors.New("k9: down")
	if w := k9Serve(s.providers, "GET", "/", nil); w.pages() != 1 {
		t.Fatalf("list down: %d pages", w.pages())
	}
}

func k9SecondLinePage(t *testing.T) {
	open := func() (*Server, *k9Line) {
		l := &k9Line{}
		return k9Server(Config{Vault: &k9Vault{state: "open"}, SecondLine: l, Now: time.Now}), l
	}
	s, l := open()
	if w := k9Serve(s.secondLine, "GET", "/x", nil); w.Code != 404 || w.pages() != 0 || l.statuses != 0 {
		t.Fatalf("below the page: %d, %d pages, %d statuses", w.Code, w.pages(), l.statuses)
	}
	s, l = open()
	if w := k9Serve(s.secondLine, "GET", "/", nil); w.Code != 200 || l.ctx == nil || l.ctx.Err() == nil {
		t.Fatalf("the page's context outlives it: %d", w.Code)
	}
	// The vault process down is one page, and the line is not read.
	l = &k9Line{}
	s = k9Server(Config{Vault: &k9Vault{err: errors.New("k9: down")}, SecondLine: l})
	if w := k9Serve(s.secondLine, "GET", "/", nil); w.pages() != 1 || l.statuses != 0 {
		t.Fatalf("down: %d pages, %d statuses", w.pages(), l.statuses)
	}
	s, l = open()
	big := k9Big(lineFormK9())
	if w := k9Serve(s.secondLine, "POST", "/", big); w.Code != 400 || l.sets != 0 {
		t.Fatalf("over the bound: %d, %d sets", w.Code, l.sets)
	}
	s, l = open()
	if w := k9Serve(s.secondLine, "POST", "/", url.Values{"step": {"k9"}}); w.Code != 400 || w.heads != 1 || l.statuses != 0 {
		t.Fatalf("unknown step: %d, %d statuses written, %d read", w.Code, w.heads, l.statuses)
	}
	s, l = open()
	if w := k9Serve(s.secondLine, "POST", "/", lineFormK9()); w.Code != 303 || w.pages() != 0 || l.statuses != 0 {
		t.Fatalf("set: %d, %d pages, %d statuses", w.Code, w.pages(), l.statuses)
	}
	s, l = open()
	l.stErr = errors.New("k9: down")
	if w := k9Serve(s.secondLine, "GET", "/", nil); w.pages() != 1 {
		t.Fatalf("status down: %d pages", w.pages())
	}
	// A set account fills each form with its settings, never a secret.
	s, l = open()
	l.st = SecondLineStatus{Set: true, Settings: sipsign.Settings{Server: "sip.k9.example:5061", Domain: "k9.example", User: "k9user", Number: "+15550100001"}}
	l.sms = SMSStatus{Set: true, Settings: smsapi.Settings{Provider: smsapi.Twilio, Account: "ACk9account", Number: "+15550100002"}}
	w := k9Serve(s.secondLine, "GET", "/", nil)
	for _, want := range []string{`value="sip.k9.example:5061"`, `value="k9user"`, `value="ACk9account"`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("the forms lack %s", want)
		}
	}
	// Asking before a removal stops the page refreshing, even while it
	// waits for the first registration.
	for _, step := range []string{"remove", "sms-remove"} {
		s, l = open()
		l.st = SecondLineStatus{Set: true, WaitingForRegistration: true, SetAt: time.Now().Unix()}
		l.sms = SMSStatus{Set: true}
		w := k9Serve(s.secondLine, "POST", "/", url.Values{"step": {step}})
		if w.Code != 200 || strings.Contains(w.Body.String(), `http-equiv="refresh"`) {
			t.Fatalf("%s asks while refreshing: %d", step, w.Code)
		}
	}
	// Without the ask, the waiting page refreshes (the check above is not
	// vacuous).
	s, l = open()
	l.st = SecondLineStatus{Set: true, WaitingForRegistration: true, SetAt: time.Now().Unix()}
	if w := k9Serve(s.secondLine, "GET", "/", nil); !strings.Contains(w.Body.String(), `http-equiv="refresh"`) {
		t.Fatal("the waiting page does not refresh")
	}
}

func lineFormK9() url.Values {
	return url.Values{"step": {"set"}, "server": {"sip.k9.example:5061"}, "domain": {"k9.example"}, "user": {"k9user"},
		"number": {"+15550100001"}, "password": {"canary-k9-sip-pw"}}
}

func k9SMSProviderName(t *testing.T) {
	if n := (SMSStatus{Settings: smsapi.Settings{Provider: smsapi.SignalWire}}).ProviderName(); n != "SignalWire" {
		t.Fatalf("SignalWire reads as %q", n)
	}
	if n := (SMSStatus{Settings: smsapi.Settings{Provider: smsapi.Twilio}}).ProviderName(); n != "Twilio" {
		t.Fatalf("Twilio reads as %q", n)
	}
}

// A long realm that is not plain is cut to 120 quoted bytes and an
// ellipsis.
func k9ShowRealmBound(t *testing.T) {
	got := showRealm(strings.Repeat("\u202e", 60))
	if want := strings.Repeat(`\`+"u202e", 20); got != `"`+want[:119]+"\u2026" {
		t.Fatalf("long realm shows as %q", got)
	}
}

// forgetToken is an HMAC under the form key of "forget" and each field
// with its length before it, so it never equals another form's token and
// fields cannot trade bytes.
func k9ForgetToken(t *testing.T) {
	s := k9Server(Config{})
	v := forgetView{Handle: "h1", Challenge: "c1", Name: "Alice", Found: "Found 1"}
	m := hmac.New(sha256.New, s.formKey)
	m.Write([]byte("forget"))
	for _, p := range []string{"sess", v.Handle, v.Challenge, v.Name, v.Found} {
		m.Write(binary.AppendUvarint(nil, uint64(len(p))))
		m.Write([]byte(p))
	}
	if got := s.forgetToken("sess", v); got != hex.EncodeToString(m.Sum(nil)) {
		t.Fatalf("token %s is not the bound HMAC", got)
	}
	a := s.forgetToken("sess", forgetView{Handle: "ab", Challenge: ""})
	b := s.forgetToken("sess", forgetView{Handle: "a", Challenge: "b"})
	if a == b {
		t.Fatal("two fields trade a byte under one token")
	}
}

func k9ForgetPage(t *testing.T) {
	open := func() (*Server, *k9Forget) {
		f := &k9Forget{found: localapi.EraseFound{Text: "Found 1 item named Alice.", Handle: forgetHandle, Challenge: forgetChallenge}}
		return k9Server(Config{Forget: f, PasskeyRPID: DefaultPageName}), f
	}
	s, f := open()
	if w := k9Serve(s.forgetPage, "GET", "/x", nil); w.Code != 404 || w.pages() != 0 {
		t.Fatalf("below the page: %d, %d pages", w.Code, w.pages())
	}
	w := k9Serve(s.forgetPage, "GET", "/", nil)
	if w.Code != 200 || w.pages() != 1 || w.heads != 0 {
		t.Fatalf("GET: %d, %d pages, %d statuses", w.Code, w.pages(), w.heads)
	}
	if got := w.Header().Get("Content-Security-Policy"); got != passkeyCSP {
		t.Fatalf("CSP %q", got)
	}
	if w := k9Serve(s.forgetPage, "PUT", "/", url.Values{"step": {"find"}, "name": {"Alice"}}); w.Code != 405 || w.Header().Get("Allow") != "GET, POST" || f.finds != 0 {
		t.Fatalf("PUT: %d %q, %d finds", w.Code, w.Header().Get("Allow"), f.finds)
	}
	if w := k9Serve(s.forgetPage, "POST", "/", k9Big(url.Values{"step": {"find"}, "name": {"Alice"}})); w.Code != 400 || f.finds != 0 {
		t.Fatalf("over the bound: %d, %d finds", w.Code, f.finds)
	}
	if w := k9Serve(s.forgetPage, "POST", "/", url.Values{"step": {"k9"}}); w.Code != 400 || w.pages() != 0 {
		t.Fatalf("unknown step: %d, %d pages", w.Code, w.pages())
	}
	// A find's bound ends with the request.
	s, f = open()
	if w := k9Serve(s.forgetPage, "POST", "/", url.Values{"step": {"find"}, "name": {"Alice"}}); w.Code != 200 ||
		!strings.Contains(w.Body.String(), `id="pk-finish"`) || f.ctx == nil || f.ctx.Err() == nil {
		t.Fatalf("find: %d, or its context outlives the page", w.Code)
	}
	// A refused find never reaches the tap step, whatever came with it.
	s, f = open()
	f.err = Refused(localapi.ErrLimited)
	if w := k9Serve(s.forgetPage, "POST", "/", url.Values{"step": {"find"}, "name": {"Alice"}}); strings.Contains(w.Body.String(), `id="pk-finish"`) ||
		strings.Contains(w.Body.String(), "Found 1 item") {
		t.Fatal("a refused find shows its tap step")
	}
}

// progressiveJPEG walks a JPEG's markers to its first frame header.
func k9ProgressiveJPEGWalk(t *testing.T) {
	for _, c := range []struct {
		name string
		b    []byte
		want bool
	}{
		{"a PNG is not a JPEG", []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR"), false},
		{"two bytes", []byte{0xff, 0xd8}, false},
		{"no marker after SOI", []byte{0xff, 0xd8, 0x00, 0xc0, 0x00, 0x02, 0xff, 0xd9}, true},
		{"fill byte before SOF0", []byte{0xff, 0xd8, 0xff, 0xff, 0xc0, 0x00, 0x11, 0x08}, false},
		{"RST0 before SOF0", []byte{0xff, 0xd8, 0xff, 0xd0, 0xff, 0xc0, 0x00, 0x11, 0x08}, false},
		{"SOF2 before SOF0", []byte{0xff, 0xd8, 0xff, 0xc2, 0x00, 0x02, 0xff, 0xc0, 0x00, 0x02, 0x00, 0x00}, true},
		{"SOF0 before SOF2", []byte{0xff, 0xd8, 0xff, 0xc0, 0x00, 0x02, 0xff, 0xc2, 0x00, 0x02, 0x00, 0x00}, false},
	} {
		if got := progressiveJPEG(c.b); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

// Two different passphrase-like codes in one photo are refused as
// ambiguous, never read as no code.
func k9ScanManyPassphrases(t *testing.T) {
	img := whiteGray(1200, 600)
	drawQR(t, img, "alpha bravo charlie delta", 50, 50, 10)
	drawQR(t, img, "echo foxtrot golf hotel", 650, 50, 10)
	if p, err := ScanPassphrase(pngBytes(t, img)); !errors.Is(err, ErrManyQR) {
		t.Fatalf("two passphrases: %q %v", p, err)
	}
}
