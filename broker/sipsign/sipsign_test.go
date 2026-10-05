package sipsign_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/sipsign"
)

// REQ: CRED-1, ADP-12

const (
	user     = "acct1001"
	password = "canary-sip-password-not-real" // synthetic canary
	realm    = "voip.test realm"
)

var settings = sipsign.Settings{Server: "sip.voip.test:5061", Domain: "voip.test", User: user, Number: "+15550000300"}

func challenge(realm string) string {
	return fmt.Sprintf(`Digest realm=%q, nonce="abc", qop="auth", algorithm=MD5`, realm)
}

// The vault signs only for the recorded realm and only the requests the
// line sends, so the line's process cannot use it as a general digest
// oracle for the password (CRED-1).
func TestTheVaultSignsOnlyItsRealmAndTheLinesRequests(t *testing.T) {
	ctx := context.Background()
	acct := sipsign.Account{Username: user, Password: password, Realm: realm}
	if _, err := acct.Sign(ctx, sipsign.Challenge{Header: challenge(realm), Method: "REGISTER", URI: "sip:voip.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := acct.Sign(ctx, sipsign.Challenge{Header: challenge("mail.example"), Method: "REGISTER", URI: "sip:voip.test"}); !errors.Is(err, sipsign.ErrRealm) {
		t.Fatalf("other realm: %v", err)
	}
	for _, m := range []string{"SUBSCRIBE", "PUBLISH", "GET", ""} {
		if _, err := acct.Sign(ctx, sipsign.Challenge{Header: challenge(realm), Method: m, URI: "sip:voip.test"}); !errors.Is(err, sipsign.ErrMethod) {
			t.Errorf("%q: %v", m, err)
		}
	}
	unset := sipsign.Account{Username: user, Password: password}
	if _, err := unset.Sign(ctx, sipsign.Challenge{Header: challenge(realm), Method: "REGISTER", URI: "sip:voip.test"}); !errors.Is(err, sipsign.ErrRealm) {
		t.Fatalf("no realm recorded: %v", err)
	}
}

func TestTheVaultAccountNeverPrintsItsPassword(t *testing.T) {
	a := sipsign.Account{Username: user, Password: password, Realm: "r"}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		if s := fmt.Sprintf(f, a); strings.Contains(s, password) {
			t.Errorf("%s: %s", f, s)
		}
	}
	// RFC 2069 challenges (no qop, no client nonce) are not answered.
	if _, err := a.Sign(context.Background(), sipsign.Challenge{Header: `Digest realm="r", nonce="n"`, Method: "REGISTER", URI: "sip:x"}); err == nil {
		t.Fatal("signed a challenge without qop")
	}
}

// Setup takes only settings that cannot steer the line elsewhere: a TLS
// server as host and port, a host name for the domain, a SIP user part
// without URI syntax, and an E.164 number (ADP-12).
func TestSettingsAreCheckedAtSetup(t *testing.T) {
	if err := settings.Check(); err != nil {
		t.Fatal(err)
	}
	if got := settings.AOR(); got != "sip:acct1001@voip.test" {
		t.Fatalf("AOR %q", got)
	}
	bad := map[string]func(*sipsign.Settings){
		"no port":        func(s *sipsign.Settings) { s.Server = "sip.voip.test" },
		"port 0":         func(s *sipsign.Settings) { s.Server = "sip.voip.test:0" },
		"port text":      func(s *sipsign.Settings) { s.Server = "sip.voip.test:tls" },
		"server space":   func(s *sipsign.Settings) { s.Server = "sip voip.test:5061" },
		"server empty":   func(s *sipsign.Settings) { s.Server = ":5061" },
		"domain empty":   func(s *sipsign.Settings) { s.Domain = "" },
		"domain at":      func(s *sipsign.Settings) { s.Domain = "a@voip.test" },
		"domain params":  func(s *sipsign.Settings) { s.Domain = "voip.test;transport=udp" },
		"domain long":    func(s *sipsign.Settings) { s.Domain = strings.Repeat("a", 254) },
		"user empty":     func(s *sipsign.Settings) { s.User = "" },
		"user at":        func(s *sipsign.Settings) { s.User = "a@evil.test" },
		"user params":    func(s *sipsign.Settings) { s.User = "a;maddr=evil.test" },
		"user space":     func(s *sipsign.Settings) { s.User = "a b" },
		"user control":   func(s *sipsign.Settings) { s.User = "a\r\nb" },
		"user long":      func(s *sipsign.Settings) { s.User = strings.Repeat("a", 65) },
		"number no plus": func(s *sipsign.Settings) { s.Number = "15550000300" },
		"number short":   func(s *sipsign.Settings) { s.Number = "+12" },
		"number long":    func(s *sipsign.Settings) { s.Number = "+1234567890123456" },
		"number letters": func(s *sipsign.Settings) { s.Number = "+1555CALLNOW" },
		"number spaced":  func(s *sipsign.Settings) { s.Number = "+1 555 000 0300" },
	}
	for name, f := range bad {
		s := settings
		f(&s)
		if err := s.Check(); !errors.Is(err, sipsign.ErrSettings) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// store is the vault process's side as the handler sees it.
type store struct {
	mu      sync.Mutex
	locked  bool
	none    bool
	acct    sipsign.Account
	learned []string
	refuse  bool // learning window closed
}

func (s *store) Account() (sipsign.Settings, sipsign.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.locked:
		return sipsign.Settings{}, sipsign.Account{}, sipsign.ErrLocked
	case s.none:
		return sipsign.Settings{}, sipsign.Account{}, sipsign.ErrNoAccount
	}
	return settings, s.acct, nil
}

func (s *store) LearnRealm(r string) (sipsign.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refuse || s.acct.Realm != "" {
		return sipsign.Account{}, sipsign.ErrRealm
	}
	s.learned = append(s.learned, r)
	s.acct.Realm = r
	return s.acct, nil
}

func serve(t *testing.T, s *store) (*sipsign.Client, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sign.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: sipsign.Handler(s)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sipsign.NewClient(path), path
}

// The line's process signs over the vault process's socket and reads the
// account's settings there; the password never crosses (CRED-1).
func TestTheLineSignsThroughTheVaultSocket(t *testing.T) {
	ctx := context.Background()
	s := &store{acct: sipsign.Account{Username: user, Password: password, Realm: realm}}
	c, path := serve(t, s)
	got, err := c.Settings(ctx)
	if err != nil || got != settings {
		t.Fatalf("settings %+v, %v", got, err)
	}
	want, _ := s.acct.Sign(ctx, sipsign.Challenge{Header: challenge(realm), Method: "MESSAGE", URI: "sip:+15550000777@voip.test"})
	auth, err := c.Sign(ctx, sipsign.Challenge{Header: challenge(realm), Method: "MESSAGE", URI: "sip:+15550000777@voip.test"})
	if err != nil {
		t.Fatal(err)
	}
	// Each answer has a fresh client nonce, so compare the fixed parts.
	for _, part := range []string{`username="acct1001"`, `realm="voip.test realm"`, `uri="sip:+15550000777@voip.test"`, `qop=auth`} {
		if !strings.Contains(auth, part) || !strings.Contains(want, part) {
			t.Errorf("answer %q lacks %s", auth, part)
		}
	}
	if _, err := c.Sign(ctx, sipsign.Challenge{Header: challenge("mail.example"), Method: "REGISTER", URI: "sip:voip.test"}); !errors.Is(err, sipsign.ErrRefused) {
		t.Fatalf("other realm: %v", err)
	}
	if _, err := c.Sign(ctx, sipsign.Challenge{Header: challenge(realm), Method: "SUBSCRIBE", URI: "sip:voip.test"}); !errors.Is(err, sipsign.ErrRefused) {
		t.Fatalf("other method: %v", err)
	}

	// Nothing the socket answers carries the password.
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", path)
	}}}
	for _, p := range []string{"/account", "/sign", "/", "/password"} {
		resp, err := hc.Get("http://agentos-egress" + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(b), password) {
			t.Fatalf("%s carried the password", p)
		}
	}
	resp, err := hc.Post("http://agentos-egress/sign", "application/json", strings.NewReader(`{"header":"`+strings.Repeat("a", 64<<10)+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized request: %d", resp.StatusCode)
	}

	s.mu.Lock()
	s.locked = true
	s.mu.Unlock()
	if _, err := c.Sign(ctx, sipsign.Challenge{Header: challenge(realm), Method: "REGISTER", URI: "sip:voip.test"}); !errors.Is(err, sipsign.ErrLocked) {
		t.Fatalf("locked: %v", err)
	}
	if _, err := c.Settings(ctx); !errors.Is(err, sipsign.ErrLocked) {
		t.Fatalf("locked settings: %v", err)
	}
	s.mu.Lock()
	s.locked, s.none = false, true
	s.mu.Unlock()
	if _, err := c.Settings(ctx); !errors.Is(err, sipsign.ErrNoAccount) {
		t.Fatalf("no account: %v", err)
	}
	if _, err := sipsign.NewClient(filepath.Join(t.TempDir(), "absent.sock")).Settings(ctx); !errors.Is(err, sipsign.ErrDown) {
		t.Fatalf("no vault process: %v", err)
	}
}

// The realm is recorded from the first registration (SL3): only a REGISTER
// challenge teaches it, only while none is recorded, and only while the
// vault process keeps the window open after setup.
func TestTheRealmIsLearnedOnlyFromTheFirstRegistration(t *testing.T) {
	ctx := context.Background()
	s := &store{acct: sipsign.Account{Username: user, Password: password}}
	c, _ := serve(t, s)
	if _, err := c.Sign(ctx, sipsign.Challenge{Header: challenge(realm), Method: "MESSAGE", URI: "sip:voip.test"}); !errors.Is(err, sipsign.ErrRefused) {
		t.Fatalf("a text taught the realm: %v", err)
	}
	if _, err := c.Sign(ctx, sipsign.Challenge{Header: `Digest nonce="abc", qop="auth"`, Method: "REGISTER", URI: "sip:voip.test"}); !errors.Is(err, sipsign.ErrRefused) {
		t.Fatalf("a challenge without a realm: %v", err)
	}
	if _, err := c.Sign(ctx, sipsign.Challenge{Header: challenge(realm), Method: "REGISTER", URI: "sip:voip.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sign(ctx, sipsign.Challenge{Header: challenge("other realm"), Method: "REGISTER", URI: "sip:voip.test"}); !errors.Is(err, sipsign.ErrRefused) {
		t.Fatalf("a second realm: %v", err)
	}
	if len(s.learned) != 1 || s.learned[0] != realm {
		t.Fatalf("learned %q", s.learned)
	}

	closed := &store{acct: sipsign.Account{Username: user, Password: password}, refuse: true}
	c2, _ := serve(t, closed)
	if _, err := c2.Sign(ctx, sipsign.Challenge{Header: challenge(realm), Method: "REGISTER", URI: "sip:voip.test"}); !errors.Is(err, sipsign.ErrRefused) {
		t.Fatalf("learned after the window: %v", err)
	}
}

// Each refused setting names its field, so the page can say which one to
// fix (UX-116-1), and every one is still ErrSettings.
func TestEachRefusedSettingNamesItsField(t *testing.T) {
	for want, f := range map[error]func(*sipsign.Settings){
		sipsign.ErrServer: func(s *sipsign.Settings) { s.Server = "sip voip.test:5061" },
		sipsign.ErrDomain: func(s *sipsign.Settings) { s.Domain = "a@voip.test" },
		sipsign.ErrUser:   func(s *sipsign.Settings) { s.User = "a;b" },
		sipsign.ErrNumber: func(s *sipsign.Settings) { s.Number = "5550000300" },
	} {
		s := settings
		f(&s)
		if err := s.Check(); err != want || !errors.Is(err, sipsign.ErrSettings) {
			t.Errorf("%v: got %v", want, err)
		}
	}
}

// What an owner leaves out or types with separators is filled in: the TLS
// port and the number's spacing (UX R1 on #116).
func TestSettingsAreNormalizedBeforeTheCheck(t *testing.T) {
	s := sipsign.Settings{Server: " sip.voip.test ", Domain: "voip.test", User: user, Number: "+1 (555) 000-0300"}.Normalize()
	if s.Server != "sip.voip.test:5061" || s.Number != "+15550000300" {
		t.Fatalf("%+v", s)
	}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	if got := (sipsign.Settings{Server: "sip.voip.test:5070"}).Normalize().Server; got != "sip.voip.test:5070" {
		t.Fatalf("port replaced: %q", got)
	}
	if err := (sipsign.Settings{Server: "sip.voip.test", Domain: "voip.test", User: user, Number: "15550000300"}).Normalize().Check(); err != sipsign.ErrNumber {
		t.Fatalf("a number without its country code was guessed: %v", err)
	}
}

// Until the owner confirms the recorded realm, the account keeps the line
// registered and answers nothing else (security R1 on #116).
func TestAnUnconfirmedRealmSignsOnlyRegistration(t *testing.T) {
	ctx := context.Background()
	a := sipsign.Account{Username: user, Password: password, Realm: realm, RegisterOnly: true}
	if _, err := a.Sign(ctx, sipsign.Challenge{Header: challenge(realm), Method: "REGISTER", URI: "sip:voip.test"}); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"MESSAGE", "INVITE", "BYE", "CANCEL"} {
		if _, err := a.Sign(ctx, sipsign.Challenge{Header: challenge(realm), Method: m, URI: "sip:voip.test"}); !errors.Is(err, sipsign.ErrMethod) {
			t.Errorf("%s signed before the realm was confirmed: %v", m, err)
		}
	}
}

// limited is a store whose MESSAGE and INVITE pass a limiter first.
type limited struct {
	*store
	mu      sync.Mutex
	allowed []string
	refuse  error
}

func (l *limited) Allow(c sipsign.Challenge) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.allowed = append(l.allowed, c.Method+" "+c.URI)
	return l.refuse
}

// Security C1 and Q2 on the #142 design read: the vault process checks
// each MESSAGE and INVITE against the second line's recipient rules and
// shared budget before it signs, and the line sees why it was refused.
func TestMessagesAndCallsPassTheLimiterBeforeSigning(t *testing.T) {
	ctx := context.Background()
	l := &limited{store: &store{acct: sipsign.Account{Username: user, Password: password, Realm: realm}}}
	path := filepath.Join(t.TempDir(), "sign.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: sipsign.Handler(l)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	c := sipsign.NewClient(path)
	msg := sipsign.Challenge{Header: challenge(realm), Method: "MESSAGE", URI: "sip:+15550000777@voip.test"}
	if _, err := c.Sign(ctx, msg); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"REGISTER", "BYE", "CANCEL"} {
		if _, err := c.Sign(ctx, sipsign.Challenge{Header: challenge(realm), Method: m, URI: "sip:voip.test"}); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
	}
	if len(l.allowed) != 1 || l.allowed[0] != "MESSAGE sip:+15550000777@voip.test" {
		t.Fatalf("limiter saw %v", l.allowed)
	}
	for _, refuse := range []error{sipsign.ErrLimited, sipsign.ErrRecipient} {
		l.refuse = refuse
		for _, m := range []string{"MESSAGE", "INVITE"} {
			if _, err := c.Sign(ctx, sipsign.Challenge{Header: challenge(realm), Method: m, URI: msg.URI}); !errors.Is(err, refuse) {
				t.Fatalf("%s refused with %v: %v", m, refuse, err)
			}
		}
	}
}

// The recipient of a MESSAGE or INVITE is the Request-URI's user part,
// with its + restored for a provider that dials without it.
func TestRecipientIsTheRequestURIsNumber(t *testing.T) {
	for _, c := range []struct {
		uri    string
		noPlus bool
		want   string
	}{
		{"sip:+15550000777@voip.test", false, "+15550000777"},
		{"sips:+15550000777@voip.test;transport=tls", false, "+15550000777"},
		{"sip:+15550000777;user=x@voip.test", false, "+15550000777"},
		{"sip:15550000777@voip.test", true, "+15550000777"},
		{"sip:15550000777@voip.test", false, ""},
		{"sip:alice@voip.test", false, ""},
		{"tel:+15550000777", false, ""},
		{"sip:+1555@voip.test", false, "+1555"},
		{"sip:@voip.test", false, ""},
	} {
		if got := sipsign.Recipient(c.uri, c.noPlus); got != c.want {
			t.Errorf("%q noPlus=%v: %q, want %q", c.uri, c.noPlus, got, c.want)
		}
	}
}
