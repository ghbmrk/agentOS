package sipline_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modem/at"
	"github.com/ghbmrk/agentos/broker/modem/atsim"
	"github.com/ghbmrk/agentos/broker/modem/secondline"
	"github.com/ghbmrk/agentos/broker/modem/sipline"
	"github.com/ghbmrk/agentos/broker/modem/sipsim"
)

// REQ: ADP-12, CRED-1, CH-1, DEP-3

const (
	domain   = "voip.test"
	user     = "acct1001"
	password = "canary-sip-password-not-real" // synthetic canary
	sipNum   = "+15550000300"
	boxNum   = "+15550000100" // owner channel (CH-1)
	ownerNum = "+15550000001"
	shopNum  = "+15550000777"
)

// signer is the vault side, counting what it is asked to sign.
type signer struct {
	acct sipline.Account
	mu   sync.Mutex
	asks []sipline.Challenge
}

func (s *signer) Sign(ctx context.Context, c sipline.Challenge) (string, error) {
	s.mu.Lock()
	s.asks = append(s.asks, c)
	s.mu.Unlock()
	return s.acct.Sign(ctx, c)
}

func (s *signer) methods() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[string]int{}
	for _, a := range s.asks {
		m[a.Method]++
	}
	return m
}

func provider(t *testing.T) *sipsim.Provider {
	t.Helper()
	p, err := sipsim.Start(domain, user, password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func config(p *sipsim.Provider, s sipline.Signer) sipline.Config {
	return sipline.Config{Server: p.Addr, Domain: domain, User: user, Number: sipNum,
		TLS: &tls.Config{RootCAs: p.Roots}, Signer: s, FramePace: time.Millisecond}
}

func vault(p *sipsim.Provider) *signer {
	return &signer{acct: sipline.Account{Username: user, Password: password, Realm: p.Realm}}
}

func open(t *testing.T, p *sipsim.Provider, cfg sipline.Config) *sipline.Line {
	t.Helper()
	l, err := sipline.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestTheAccountRegistersOverVerifiedTLSWithTheVaultAnsweringChallenges(t *testing.T) {
	p := provider(t)
	s := vault(p)
	l := open(t, p, config(p, s))
	if p.Registered(user) == 0 || p.Authenticated("REGISTER") == 0 {
		t.Fatal("not registered")
	}
	if s.methods()["REGISTER"] == 0 {
		t.Fatal("the vault signer was not asked")
	}
	if l.AOR() != "sip:"+user+"@"+domain || l.Number() != sipNum {
		t.Fatalf("AOR %q number %q", l.AOR(), l.Number())
	}
	_ = l.Close()
	if p.Registered(user) != 0 {
		t.Fatal("Close left the registration")
	}
	select {
	case <-l.Done():
	default:
		t.Fatal("Done open after Close")
	}
	if err := l.Send(shopNum, "hi"); !errors.Is(err, sipline.ErrClosed) {
		t.Fatalf("Send after Close: %v", err)
	}
}

func TestTheLineRefusesAProviderItCannotVerify(t *testing.T) {
	p := provider(t)
	ctx := context.Background()
	cfg := config(p, vault(p))
	cfg.TLS = nil // system roots do not trust the simulator
	if _, err := sipline.Open(ctx, cfg); err == nil {
		t.Fatal("registered with an unverified provider")
	}
	for name, tc := range map[string]*tls.Config{
		"skip verify":   {InsecureSkipVerify: true},
		"custom verify": {RootCAs: p.Roots, VerifyConnection: func(tls.ConnectionState) error { return nil }},
	} {
		cfg := config(p, vault(p))
		cfg.TLS = tc
		if _, err := sipline.Open(ctx, cfg); !errors.Is(err, sipline.ErrInsecure) {
			t.Errorf("%s: %v", name, err)
		}
	}
	cfg = config(p, nil)
	if _, err := sipline.Open(ctx, cfg); !errors.Is(err, sipline.ErrConfig) {
		t.Fatalf("no signer: %v", err)
	}
	if p.Authenticated("REGISTER") != 0 {
		t.Fatal("something registered")
	}
}

// The vault signs only for the recorded realm and only the requests the
// line sends, so the line's process cannot use it as a general digest
// oracle for the password (CRED-1).
func TestTheVaultSignsOnlyItsRealmAndTheLinesRequests(t *testing.T) {
	ctx := context.Background()
	acct := sipline.Account{Username: user, Password: password, Realm: "voip.test realm"}
	ch := `Digest realm="voip.test realm", nonce="abc", qop="auth", algorithm=MD5`
	if _, err := acct.Sign(ctx, sipline.Challenge{Header: ch, Method: "REGISTER", URI: "sip:voip.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := acct.Sign(ctx, sipline.Challenge{Header: `Digest realm="mail.example", nonce="abc"`, Method: "REGISTER", URI: "sip:voip.test"}); !errors.Is(err, sipline.ErrRealm) {
		t.Fatalf("other realm: %v", err)
	}
	for _, m := range []string{"SUBSCRIBE", "PUBLISH", "GET", ""} {
		if _, err := acct.Sign(ctx, sipline.Challenge{Header: ch, Method: m, URI: "sip:voip.test"}); !errors.Is(err, sipline.ErrMethod) {
			t.Errorf("%q: %v", m, err)
		}
	}
	unset := sipline.Account{Username: user, Password: password}
	if _, err := unset.Sign(ctx, sipline.Challenge{Header: ch, Method: "REGISTER", URI: "sip:voip.test"}); !errors.Is(err, sipline.ErrRealm) {
		t.Fatalf("no realm recorded: %v", err)
	}

	p := provider(t)
	wrong := &signer{acct: sipline.Account{Username: user, Password: "canary-wrong", Realm: p.Realm}}
	if _, err := sipline.Open(ctx, config(p, wrong)); err == nil {
		t.Fatal("registered with the wrong password")
	}
	if p.BadAuth() == 0 || p.Registered(user) != 0 {
		t.Fatal("wrong password not refused by the provider")
	}
}

func TestTextsGoOutAsMessagesAndOnlyToPhoneNumbers(t *testing.T) {
	p := provider(t)
	s := vault(p)
	l := open(t, p, config(p, s))
	if err := l.Send(shopNum, "Table for 2 at 7?"); err != nil {
		t.Fatal(err)
	}
	got := <-p.Texts()
	if got.To != shopNum || got.From != user || got.Body != "Table for 2 at 7?" || got.ContentType != "text/plain;charset=UTF-8" {
		t.Fatalf("%+v", got)
	}
	if s.methods()["MESSAGE"] == 0 {
		t.Fatal("MESSAGE not signed by the vault")
	}
	// Anything that is not a phone number is refused before a request is
	// built, so a "number" cannot route the text elsewhere.
	for _, to := range []string{"1555@evil.example", "+15550000777;transport=udp", "sip:shop@voip.test", "+1", "555 000 07a7", "+1555+0000777", ""} {
		if err := l.Send(to, "x"); !errors.Is(err, sipline.ErrNumber) {
			t.Errorf("Send to %q: %v", to, err)
		}
	}
	p.Refuse("MESSAGE", 488)
	if err := l.Send(shopNum, "x"); err == nil {
		t.Fatal("a refused text reported sent")
	}
}

func TestNumbersCanBeDialedWithoutPlus(t *testing.T) {
	p := provider(t)
	cfg := config(p, vault(p))
	cfg.NoPlus = true
	l := open(t, p, cfg)
	if err := l.Send("+1 (555) 000-0777", "x"); err != nil {
		t.Fatal(err)
	}
	if got := <-p.Texts(); got.To != "15550000777" {
		t.Fatalf("to %q", got.To)
	}
}

// Texts to the line arrive only over its own verified connection, as data;
// a sender that is not a phone number can never pass for the owner.
func TestIncomingTextsAreDataAndNamedSendersAreAlphanumeric(t *testing.T) {
	p := provider(t)
	l := open(t, p, config(p, vault(p)))
	ctx := context.Background()
	if code, err := p.SendText(ctx, shopNum, user, "text/plain", "STOP"); err != nil || code != 200 {
		t.Fatalf("%d %v", code, err)
	}
	m := <-l.Inbox()
	if m.From != shopNum || m.Text != "STOP" || m.Alphanumeric || m.To != sipNum {
		t.Fatalf("%+v", m)
	}
	if _, err := p.SendText(ctx, "ShopCo", user, "text/plain", "Your table is ready"); err != nil {
		t.Fatal(err)
	}
	m = <-l.Inbox()
	if !m.Alphanumeric || m.From != "alpha:ShopCo" {
		t.Fatalf("%+v", m)
	}
	if code, _ := p.SendText(ctx, shopNum, user, "text/html", "<b>hi</b>"); code != 415 {
		t.Fatalf("html text: %d", code)
	}
	select {
	case m := <-l.Inbox():
		t.Fatalf("html delivered: %+v", m)
	case <-time.After(30 * time.Millisecond):
	}
}

func TestIncomingCallsAreDeclined(t *testing.T) {
	p := provider(t)
	open(t, p, config(p, vault(p)))
	if code, err := p.CallLine(context.Background(), shopNum, user); err != nil || code != 603 {
		t.Fatalf("%d %v", code, err)
	}
}

func TestTheRegistrationIsRenewed(t *testing.T) {
	p := provider(t)
	p.Grant(1)
	open(t, p, config(p, vault(p)))
	n := p.Authenticated("REGISTER")
	eventually(t, "a renewal", func() bool { return p.Authenticated("REGISTER") > n })
}

// owner opens the owner-channel modem on the AT simulator.
func owner(t *testing.T) (*at.Modem, *atsim.Device) {
	t.Helper()
	c := modem.NewCarrier()
	dev := atsim.New(at.SIMCom, "SIMCOM_SIM7600G-H", c.Line(boxNum), time.Millisecond)
	m, err := at.Open(context.Background(), at.Config{Profile: at.SIMCom, Port: dev.Port(), Number: boxNum,
		FramePace: time.Millisecond, Poll: 5 * time.Millisecond, Audio: at.SerialAudio(dev.SerialAudio)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m, dev
}

func disclosure() []byte {
	b := make([]byte, 3*at.FrameBytes)
	for i := range b {
		b[i] = byte(i*7 + 1)
	}
	return b
}

func tool(t *testing.T, l *sipline.Line, wait time.Duration) *secondline.Tool {
	t.Helper()
	o, dev := owner(t)
	tl, err := secondline.New(secondline.Config{Owner: o, Second: l,
		Roles:      secondline.Roles{OwnerICCID: dev.ICCID(), SecondAccount: l.AOR()},
		Disclosure: disclosure(), OwnerPhone: ownerNum, CountryCode: "1", AnswerWait: wait})
	if err != nil {
		t.Fatal(err)
	}
	return tl
}

// An owner with a VoIP account and no second modem gets ADP-12's tool:
// calls open with the full disclosure, over SRTP, and the owner's numbers
// stay out of reach.
func TestASIPAccountServesAsTheSecondLine(t *testing.T) {
	p := provider(t)
	s := vault(p)
	l := open(t, p, config(p, s))
	tl := tool(t, l, 5*time.Second)
	if !tl.Available() {
		t.Fatal("unavailable")
	}
	for _, to := range []string{ownerNum, boxNum, sipNum, "1 (555) 000-0300"} {
		if err := tl.Text(to, "Reply with your code"); !errors.Is(err, secondline.ErrRecipient) {
			t.Errorf("Text to %s: %v", to, err)
		}
	}
	if err := tl.Text(shopNum, "Table for 2 at 7?"); err != nil {
		t.Fatal(err)
	}
	if got := <-p.Texts(); got.To != shopNum {
		t.Fatalf("%+v", got)
	}

	type res struct {
		call secondline.Call
		err  error
	}
	got := make(chan res, 1)
	go func() {
		c, err := tl.Call(context.Background(), shopNum)
		got <- res{c, err}
	}()
	far := <-p.Calls()
	if far.To != shopNum || !far.OfferHas("RTP/SAVP") || !far.OfferHas(sipline.Suite) {
		t.Fatalf("offer to %s:\n%s", far.To, far.Offer)
	}
	if s.methods()["INVITE"] == 0 {
		t.Fatal("INVITE not signed by the vault")
	}
	_ = far.Ring()
	select {
	case r := <-got:
		t.Fatalf("Call returned before the far end answered: %v", r.err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := far.Answer(sipline.PCMU); err != nil {
		t.Fatal(err)
	}
	r := <-got
	if r.err != nil {
		t.Fatal(r.err)
	}
	want := sipline.ULaw(disclosure())
	eventually(t, "the disclosure", func() bool { return len(far.Heard()) >= len(want) })
	if h := far.Heard(); !bytes.HasPrefix(h, want) {
		t.Fatalf("far end heard %d bytes not starting with the disclosure", len(h))
	}
	if err := r.call.Say(context.Background(), make([]byte, at.FrameBytes)); err != nil {
		t.Fatal(err)
	}
	if err := r.call.Hangup(context.Background()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the far end to see the hangup", func() bool {
		select {
		case <-far.Done():
			return true
		default:
			return false
		}
	})
}

func TestACallAnsweredWithoutSRTPIsHungUpBeforeAWord(t *testing.T) {
	p := provider(t)
	l := open(t, p, config(p, vault(p)))
	c, err := l.Dial(context.Background(), shopNum)
	if err != nil {
		t.Fatal(err)
	}
	far := <-p.Calls()
	if err := far.AnswerPlain(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.Ended():
	case <-time.After(3 * time.Second):
		t.Fatal("call not ended")
	}
	select {
	case <-c.Active():
		t.Fatal("a plain-RTP call went active")
	default:
	}
	if e, ok := c.(interface{ Err() error }); !ok || !errors.Is(e.Err(), sipline.ErrNoSRTP) {
		t.Fatalf("ended with %v", c)
	}
	eventually(t, "the BYE", func() bool {
		select {
		case <-far.Done():
			return true
		default:
			return false
		}
	})
	if len(far.Heard()) != 0 {
		t.Fatal("audio sent on a plain-RTP call")
	}
	// The line is free again.
	if _, err := l.Dial(context.Background(), shopNum); err != nil {
		t.Fatal(err)
	}
}

func TestAnUnansweredCallIsCancelledAndTheLineHasOneCallAtATime(t *testing.T) {
	p := provider(t)
	l := open(t, p, config(p, vault(p)))
	tl := tool(t, l, 50*time.Millisecond)
	errc := make(chan error, 1)
	go func() {
		_, err := tl.Call(context.Background(), shopNum)
		errc <- err
	}()
	far := <-p.Calls()
	_ = far.Ring()
	if _, err := l.Dial(context.Background(), "+15550000778"); !errors.Is(err, sipline.ErrBusy) {
		t.Fatalf("second call: %v", err)
	}
	if err := <-errc; !errors.Is(err, secondline.ErrNoAnswer) {
		t.Fatalf("Call: %v", err)
	}
	select {
	case <-far.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the far end still rings")
	}
}

func TestTheFarEndHangingUpEndsTheCall(t *testing.T) {
	p := provider(t)
	l := open(t, p, config(p, vault(p)))
	c, err := l.Dial(context.Background(), shopNum)
	if err != nil {
		t.Fatal(err)
	}
	far := <-p.Calls()
	if err := far.Answer(sipline.PCMA); err != nil {
		t.Fatal(err)
	}
	<-c.Active()
	if err := c.Say(context.Background(), disclosure()); err != nil {
		t.Fatal(err)
	}
	want := sipline.ALaw(disclosure())
	eventually(t, "A-law audio", func() bool { return len(far.Heard()) >= len(want) })
	if !bytes.Equal(far.Heard()[:len(want)], want) {
		t.Fatal("A-law audio differs")
	}
	if pts := far.PayloadTypes(); len(pts) != 1 || pts[0] != sipline.PCMA {
		t.Fatalf("payload types %v", pts)
	}
	if err := far.Hangup(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.Ended():
	case <-time.After(3 * time.Second):
		t.Fatal("call not ended")
	}
	if err := c.Say(context.Background(), disclosure()); err == nil {
		t.Fatal("Say on an ended call")
	}
}

// The second line's role is bound to the account recorded at setup, and an
// account carrying the owner channel's number is refused (CH-1).
func TestTheAccountsRoleIsBoundAndKeptApartFromTheOwnerLine(t *testing.T) {
	p := provider(t)
	l := open(t, p, config(p, vault(p)))
	o, dev := owner(t)
	cfg := func(r secondline.Roles) secondline.Config {
		return secondline.Config{Owner: o, Second: l, Roles: r, Disclosure: disclosure(), OwnerPhone: ownerNum, CountryCode: "1"}
	}
	if _, err := secondline.New(cfg(secondline.Roles{OwnerICCID: dev.ICCID(), SecondAccount: "SIP:" + user + "@VOIP.TEST"})); err != nil {
		t.Fatalf("same account, other case: %v", err)
	}
	for name, r := range map[string]secondline.Roles{
		"nothing recorded":  {},
		"other account":     {OwnerICCID: dev.ICCID(), SecondAccount: "sip:acct1002@" + domain},
		"user case differs": {OwnerICCID: dev.ICCID(), SecondAccount: "sip:ACCT1001@" + domain},
		"recorded as a SIM": {OwnerICCID: dev.ICCID(), SecondICCID: "89010000000000000099"},
		"both recorded":     {OwnerICCID: dev.ICCID(), SecondICCID: "89010000000000000099", SecondAccount: l.AOR()},
		"owner unrecorded":  {SecondAccount: l.AOR()},
	} {
		if _, err := secondline.New(cfg(r)); !errors.Is(err, secondline.ErrUnbound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	c2 := config(p, vault(p))
	c2.Number = "+1 555 000 0100" // the owner channel's number
	twin := open(t, p, c2)
	if _, err := secondline.New(secondline.Config{Owner: o, Second: twin, Roles: secondline.Roles{OwnerICCID: dev.ICCID(), SecondAccount: twin.AOR()},
		Disclosure: disclosure(), OwnerPhone: ownerNum, CountryCode: "1"}); !errors.Is(err, secondline.ErrOwnerLine) {
		t.Fatalf("account with the owner line's number: %v", err)
	}
}

// The owner texting the account is pointed to the main number and never
// reaches an agent, as on a second SIM.
func TestTheOwnerTextingTheAccountIsPointedToTheMainNumber(t *testing.T) {
	p := provider(t)
	l := open(t, p, config(p, vault(p)))
	tl := tool(t, l, time.Second)
	if _, err := p.SendText(context.Background(), ownerNum, user, "text/plain", "YES K3 482913"); err != nil {
		t.Fatal(err)
	}
	got := <-p.Texts()
	if got.To != ownerNum || got.Body != secondline.MainNumberText {
		t.Fatalf("%+v", got)
	}
	select {
	case u := <-tl.Inbound():
		t.Fatalf("agent got %+v", u)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestG711(t *testing.T) {
	pcm := func(v ...int16) []byte {
		b := make([]byte, 2*len(v))
		for i, s := range v {
			b[2*i], b[2*i+1] = byte(uint16(s)), byte(uint16(s)>>8)
		}
		return b
	}
	if got := sipline.ULaw(pcm(0, 32767, -32768, -1)); !bytes.Equal(got, []byte{0xFF, 0x80, 0x00, 0x7F}) {
		t.Errorf("ULaw % X", got)
	}
	if got := sipline.ALaw(pcm(0, 32767, -32768, 16, -16)); !bytes.Equal(got, []byte{0xD5, 0xAA, 0x2A, 0xD4, 0x55}) {
		t.Errorf("ALaw % X", got)
	}
}

// Nothing the SIP stack sees reaches a log: a frame it cannot parse, which
// could carry a third party's text or an SRTP key, is dropped silently
// (CRED-1, CLAUDE.md).
func TestNoSIPMessageReachesTheLog(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(lockedWriter{&mu, &buf}, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	p := provider(t)
	l := open(t, p, config(p, vault(p)))
	const canary = "canary-third-party-text-7f3a"
	if err := p.SendRaw(user, []byte("NOT SIP AT ALL "+canary+"\r\nX: y\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	_ = l
	mu.Lock()
	defer mu.Unlock()
	if buf.Len() != 0 {
		t.Fatalf("the default logger got:\n%s", buf.String())
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (w lockedWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(b)
}

func TestTheLineRefusesTLSOlderThan12(t *testing.T) {
	p, err := sipsim.StartTLS(domain, user, password, tls.VersionTLS11)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	cfg := config(p, vault(p))
	cfg.TLS.MinVersion = tls.VersionTLS10 // asked for, raised to 1.2 anyway
	if _, err := sipline.Open(context.Background(), cfg); err == nil {
		t.Fatal("registered over TLS 1.1")
	}
	if p.Registered(user) != 0 {
		t.Fatal("registered")
	}
}

func TestTheVerifierCannotBeReplaced(t *testing.T) {
	p := provider(t)
	cfg := config(p, vault(p))
	cfg.TLS.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return nil }
	if _, err := sipline.Open(context.Background(), cfg); !errors.Is(err, sipline.ErrInsecure) {
		t.Fatalf("VerifyPeerCertificate: %v", err)
	}
}

// A BYE that carries the call's Call-ID but not its dialog's tags is not
// the far end hanging up; the call goes on.
func TestABYEForAnotherDialogDoesNotEndTheCall(t *testing.T) {
	p := provider(t)
	l := open(t, p, config(p, vault(p)))
	c, err := l.Dial(context.Background(), shopNum)
	if err != nil {
		t.Fatal(err)
	}
	far := <-p.Calls()
	if err := far.Answer(sipline.PCMU); err != nil {
		t.Fatal(err)
	}
	<-c.Active()
	if code, err := far.ForgedBye(context.Background()); err != nil || code != 481 {
		t.Fatalf("forged BYE: %d %v", code, err)
	}
	select {
	case <-c.Ended():
		t.Fatal("a forged BYE ended the call")
	case <-time.After(30 * time.Millisecond):
	}
	if err := c.Hangup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAnswersAreCheckedForSRTPAndWhereTheAudioGoes(t *testing.T) {
	key := "inline:" + base64.StdEncoding.EncodeToString(make([]byte, 30))
	sdp := func(addr, proto, crypto string) []byte {
		s := "v=0\r\no=- 1 1 IN IP4 " + addr + "\r\ns=-\r\nc=IN IP4 " + addr + "\r\nt=0 0\r\nm=audio 4000 " + proto + " 0\r\n"
		if crypto != "" {
			s += "a=crypto:" + crypto + "\r\n"
		}
		return []byte(s)
	}
	ok := "1 " + sipline.Suite + " " + key
	for name, c := range map[string]struct {
		body    []byte
		private bool
		want    error
	}{
		"public SRTP":                {sdp("203.0.113.9", "RTP/SAVP", ok), false, nil},
		"SAVP without a key":         {sdp("203.0.113.9", "RTP/SAVP", ""), false, sipline.ErrNoSRTP},
		"AVP with a key":             {sdp("203.0.113.9", "RTP/AVP", ok), false, sipline.ErrNoSRTP},
		"another tag":                {sdp("203.0.113.9", "RTP/SAVP", "2 "+sipline.Suite+" "+key), false, sipline.ErrNoSRTP},
		"another suite":              {sdp("203.0.113.9", "RTP/SAVP", "1 AES_CM_128_HMAC_SHA1_32 "+key), false, sipline.ErrNoSRTP},
		"loopback":                   {sdp("127.0.0.1", "RTP/SAVP", ok), false, sipline.ErrMediaAddress},
		"LAN host":                   {sdp("192.168.1.1", "RTP/SAVP", ok), false, sipline.ErrMediaAddress},
		"link-local":                 {sdp("169.254.169.254", "RTP/SAVP", ok), false, sipline.ErrMediaAddress},
		"multicast":                  {sdp("239.1.1.1", "RTP/SAVP", ok), false, sipline.ErrMediaAddress},
		"unspecified":                {sdp("0.0.0.0", "RTP/SAVP", ok), false, sipline.ErrMediaAddress},
		"broadcast":                  {sdp("255.255.255.255", "RTP/SAVP", ok), false, sipline.ErrMediaAddress},
		"LAN, provider on the LAN":   {sdp("192.168.1.1", "RTP/SAVP", ok), true, nil},
		"loopback, provider local":   {sdp("127.0.0.1", "RTP/SAVP", ok), true, nil},
		"multicast, provider on LAN": {sdp("239.1.1.1", "RTP/SAVP", ok), true, sipline.ErrMediaAddress},
	} {
		if err := sipline.ParseAnswer(c.body, c.private); !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func TestIncomingTextsAreBoundedAndOnlyTheProviderVouchesForNumbers(t *testing.T) {
	p := provider(t)
	l := open(t, p, config(p, vault(p)))
	ctx := context.Background()
	relay := func(in sipsim.Incoming) int {
		t.Helper()
		in.User = user
		if in.ContentType == "" {
			in.ContentType = "text/plain"
		}
		code, err := p.Relay(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		return code
	}
	got := func() modem.SMS {
		t.Helper()
		select {
		case m := <-l.Inbox():
			return m
		case <-time.After(3 * time.Second):
			t.Fatal("nothing delivered")
		}
		return modem.SMS{}
	}
	if code := relay(sipsim.Incoming{From: shopNum, Body: strings.Repeat("x", 1601)}); code != 413 {
		t.Fatalf("long text: %d", code)
	}
	if code := relay(sipsim.Incoming{From: shopNum, Body: "\xff\xfe"}); code != 415 {
		t.Fatalf("invalid UTF-8: %d", code)
	}
	relay(sipsim.Incoming{From: shopNum, Body: strings.Repeat("x", 1600)})
	if m := got(); len(m.Text) != 1600 || m.Alphanumeric {
		t.Fatalf("1600 bytes: %d %v", len(m.Text), m.Alphanumeric)
	}
	// A number in another domain's From is not the provider's word for it.
	relay(sipsim.Incoming{From: ownerNum, FromHost: "elsewhere.example", Body: "YES K3 482913"})
	if m := got(); !m.Alphanumeric || !strings.HasPrefix(m.From, "alpha:") {
		t.Fatalf("foreign From: %+v", m)
	}
	// The provider's asserted identity is.
	relay(sipsim.Incoming{From: "anonymous", FromHost: "elsewhere.example", PAI: "<tel:" + shopNum + ">", Body: "hi"})
	if m := got(); m.Alphanumeric || m.From != shopNum {
		t.Fatalf("PAI: %+v", m)
	}
	relay(sipsim.Incoming{From: "x", PAI: `"Shop" <sip:` + shopNum + `@` + domain + `;user=phone>`, Body: "hi"})
	if m := got(); m.Alphanumeric || m.From != shopNum {
		t.Fatalf("sip PAI: %+v", m)
	}
	// Named senders are short printable ASCII.
	relay(sipsim.Incoming{From: strings.Repeat("Shop%0aCo", 10), Body: "hi"})
	if m := got(); !m.Alphanumeric || len(m.From) > len("alpha:")+32 {
		t.Fatalf("long name: %q", m.From)
	}
}

func TestTheVaultAccountNeverPrintsItsPassword(t *testing.T) {
	a := sipline.Account{Username: user, Password: password, Realm: "r"}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		if s := fmt.Sprintf(f, a); strings.Contains(s, password) {
			t.Errorf("%s: %s", f, s)
		}
	}
	// RFC 2069 challenges (no qop, no client nonce) are not answered.
	if _, err := a.Sign(context.Background(), sipline.Challenge{Header: `Digest realm="r", nonce="n"`, Method: "REGISTER", URI: "sip:x"}); err == nil {
		t.Fatal("signed a challenge without qop")
	}
}
