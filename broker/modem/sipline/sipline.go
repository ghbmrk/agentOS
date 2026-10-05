// Package sipline is ADP-12's second line as an owner-held calling account:
// texts and calls to third parties through a VoIP provider over SIP, so an
// owner can have a second line without a second modem.
//
// Signaling runs only over TLS to the provider, with the provider's
// certificate verified; there is no listening socket, so every request the
// line receives arrives on its own verified connection. Call audio is
// G.711 over SRTP (SDES keys inside that TLS), and a call the provider
// answers without SRTP is hung up before anything is said. The account
// password stays in the vault process: the line only asks a Signer to
// answer digest challenges (CRED-1).
//
// Everything that reaches the line is untrusted data: the secondline tool
// owns the owner-number guards, roles and the disclosure that opens calls.
package sipline

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modem/secondline"
)

// Config configures the line.
type Config struct {
	// Server is the provider's SIP-over-TLS address, host:port.
	Server string
	// Domain and User make the account's address of record, User@Domain.
	Domain, User string
	// Number is the account's phone number (E.164), shown to the people
	// it texts and calls.
	Number string
	// NoPlus dials numbers without their leading "+", for providers that
	// want 15551234567 rather than +15551234567.
	NoPlus bool
	// TLS is the client TLS configuration; nil uses the system roots. The
	// provider's certificate is always verified.
	TLS *tls.Config
	// Signer answers digest challenges; required.
	Signer Signer
	// MediaIP is the address offered for call audio; default the
	// signaling connection's local address.
	MediaIP net.IP
	// FramePace paces call audio, one 20 ms frame per tick (default 20 ms).
	FramePace time.Duration
	// Expiry is the registration lifetime asked for (default 5 minutes).
	Expiry time.Duration
	// Log receives registration failures; nil discards them.
	Log *slog.Logger
}

// Errors.
var (
	ErrConfig   = errors.New("sipline: Server, Domain, User, Number and Signer are required")
	ErrInsecure = errors.New("sipline: the provider's certificate must be verified")
	ErrNumber   = errors.New("sipline: not a phone number")
	ErrBusy     = errors.New("sipline: a call is already in progress")
	ErrClosed   = errors.New("sipline: line closed")
)

// Line is a registered SIP account.
type Line struct {
	cfg   Config
	ua    *sipgo.UserAgent
	cli   *sipgo.Client
	srv   *sipgo.Server
	inbox chan modem.SMS
	done  chan struct{}
	once  sync.Once

	mu      sync.Mutex
	contact sip.ContactHeader
	call    *call
}

var _ secondline.Account = (*Line)(nil)

// Open registers the account. It fails if the provider cannot be reached
// over verified TLS or refuses the registration.
func Open(ctx context.Context, cfg Config) (*Line, error) {
	if cfg.Server == "" || cfg.Domain == "" || cfg.User == "" || cfg.Number == "" || cfg.Signer == nil {
		return nil, ErrConfig
	}
	host, _, err := net.SplitHostPort(cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("sipline: Server: %w", err)
	}
	tc := &tls.Config{}
	if cfg.TLS != nil {
		tc = cfg.TLS.Clone()
	}
	if tc.InsecureSkipVerify || tc.VerifyConnection != nil || tc.VerifyPeerCertificate != nil {
		return nil, ErrInsecure
	}
	if tc.ServerName == "" {
		tc.ServerName = host
	}
	if tc.MinVersion < tls.VersionTLS12 {
		tc.MinVersion = tls.VersionTLS12
	}
	if cfg.FramePace == 0 {
		cfg.FramePace = 20 * time.Millisecond
	}
	if cfg.Expiry == 0 {
		cfg.Expiry = 5 * time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	ua, err := sipgo.NewUA(sipgo.WithUserAgent("agentos"), sipgo.WithUserAgentHostname(cfg.Domain), sipgo.WithUserAgenTLSConfig(tc))
	if err != nil {
		return nil, err
	}
	l := &Line{cfg: cfg, ua: ua, inbox: make(chan modem.SMS, 64), done: make(chan struct{})}
	if l.cli, err = sipgo.NewClient(ua); err == nil {
		l.srv, err = sipgo.NewServer(ua)
	}
	if err != nil {
		_ = ua.Close()
		return nil, err
	}
	l.srv.OnMessage(l.onMessage)
	l.srv.OnInvite(l.onInvite)
	l.srv.OnBye(l.onBye)
	l.srv.OnOptions(func(req *sip.Request, tx sip.ServerTransaction) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil))
	})
	l.srv.OnNoRoute(func(req *sip.Request, tx sip.ServerTransaction) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusMethodNotAllowed, "Method Not Allowed", nil))
	})
	granted, err := l.register(ctx, cfg.Expiry)
	if err != nil {
		_ = ua.Close()
		return nil, err
	}
	go l.keep(granted)
	return l, nil
}

// Number is the account's phone number.
func (l *Line) Number() string { return l.cfg.Number }

// AOR is the account's address of record, which its role is bound to.
func (l *Line) AOR() string { return "sip:" + l.cfg.User + "@" + l.cfg.Domain }

// Inbox delivers texts received by the account.
func (l *Line) Inbox() <-chan modem.SMS { return l.inbox }

// Done is closed when the line is closed.
func (l *Line) Done() <-chan struct{} { return l.done }

// Close ends any call, unregisters and closes the connection.
func (l *Line) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.mu.Lock()
		c := l.call
		l.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if c != nil {
			_ = c.Hangup(ctx)
		}
		_, _ = l.register(ctx, 0)
		_ = l.ua.Close()
	})
	return nil
}

// Send texts a number with a SIP MESSAGE (RFC 3428).
func (l *Line) Send(to, text string) error {
	select {
	case <-l.done:
		return ErrClosed
	default:
	}
	uri, err := l.numberURI(to)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req := l.request(sip.MESSAGE, uri, uri)
	req.AppendHeader(sip.NewHeader("Content-Type", "text/plain;charset=UTF-8"))
	req.SetBody([]byte(text))
	res, err := l.do(ctx, req)
	if err != nil {
		return err
	}
	if !res.IsSuccess() {
		return fmt.Errorf("sipline: text refused: %d %s", res.StatusCode, res.Reason)
	}
	return nil
}

// numberURI makes a Request-URI from a phone number. Anything but digits,
// an optional leading "+" and visual separators is refused, so a "number"
// cannot name another host or carry URI parameters.
func (l *Line) numberURI(number string) (sip.Uri, error) {
	var b strings.Builder
	for i, r := range strings.TrimSpace(number) {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' && i == 0:
			if !l.cfg.NoPlus {
				b.WriteRune(r)
			}
		case r == ' ' || r == '-' || r == '(' || r == ')' || r == '.':
		default:
			return sip.Uri{}, ErrNumber
		}
	}
	d := strings.TrimPrefix(b.String(), "+")
	if len(d) < 3 || len(d) > 15 {
		return sip.Uri{}, ErrNumber
	}
	return sip.Uri{Scheme: "sip", User: b.String(), Host: l.cfg.Domain}, nil
}

// request starts a request from the account, sent to the provider over TLS.
func (l *Line) request(method sip.RequestMethod, recipient, to sip.Uri) *sip.Request {
	req := sip.NewRequest(method, recipient)
	req.SetTransport("TLS")
	req.SetDestination(l.cfg.Server)
	from := &sip.FromHeader{Address: sip.Uri{Scheme: "sip", User: l.cfg.User, Host: l.cfg.Domain}, Params: sip.NewParams()}
	from.Params.Add("tag", sip.GenerateTagN(16))
	req.AppendHeader(from)
	req.AppendHeader(&sip.ToHeader{Address: to, Params: sip.NewParams()})
	return req
}

// do sends a request and answers one digest challenge through the Signer.
func (l *Line) do(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	res, err := l.cli.Do(ctx, req)
	if err != nil || (res.StatusCode != sip.StatusUnauthorized && res.StatusCode != sip.StatusProxyAuthRequired) {
		return res, err
	}
	if err := l.authorize(ctx, req, res); err != nil {
		return nil, err
	}
	req.CSeq().SeqNo++
	req.RemoveHeader("Via")
	return l.cli.Do(ctx, req, sipgo.ClientRequestAddVia)
}

// authorize adds the Signer's answer to res's challenge to req.
func (l *Line) authorize(ctx context.Context, req *sip.Request, res *sip.Response) error {
	ch, auth := "WWW-Authenticate", "Authorization"
	if res.StatusCode == sip.StatusProxyAuthRequired {
		ch, auth = "Proxy-Authenticate", "Proxy-Authorization"
	}
	h := res.GetHeader(ch)
	if h == nil {
		return fmt.Errorf("sipline: %d without a challenge", res.StatusCode)
	}
	v, err := l.cfg.Signer.Sign(ctx, Challenge{Header: h.Value(), Method: req.Method.String(), URI: req.Recipient.Addr()})
	if err != nil {
		return err
	}
	req.RemoveHeader(auth)
	req.AppendHeader(sip.NewHeader(auth, v))
	return nil
}

// register registers (or with expiry 0 unregisters) the account's contact
// on the connection, first learning the connection's local address with an
// OPTIONS request so the contact names it. It returns the lifetime the
// provider granted.
func (l *Line) register(ctx context.Context, expiry time.Duration) (time.Duration, error) {
	domain := sip.Uri{Scheme: "sip", Host: l.cfg.Domain}
	aor := sip.Uri{Scheme: "sip", User: l.cfg.User, Host: l.cfg.Domain}
	if expiry > 0 {
		probe := l.request(sip.OPTIONS, domain, domain)
		if _, err := l.cli.Do(ctx, probe); err != nil {
			return 0, fmt.Errorf("sipline: provider unreachable: %w", err)
		}
		via := probe.Via()
		c := sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: l.cfg.User, Host: via.Host, Port: via.Port, UriParams: sip.NewParams()}}
		c.Address.UriParams.Add("transport", "tls")
		l.mu.Lock()
		l.contact = c
		l.mu.Unlock()
	}
	l.mu.Lock()
	contact := l.contact
	l.mu.Unlock()
	if contact.Address.Host == "" {
		return 0, nil
	}
	req := l.request(sip.REGISTER, domain, aor)
	req.AppendHeader(&contact)
	exp := sip.ExpiresHeader(uint32(expiry / time.Second))
	req.AppendHeader(&exp)
	res, err := l.do(ctx, req)
	if err != nil {
		return 0, err
	}
	if !res.IsSuccess() {
		return 0, fmt.Errorf("sipline: registration refused: %d %s", res.StatusCode, res.Reason)
	}
	granted := expiry
	if h := res.GetHeader("Expires"); h != nil {
		if s, err := strconv.Atoi(strings.TrimSpace(h.Value())); err == nil && s > 0 && time.Duration(s)*time.Second < granted {
			granted = time.Duration(s) * time.Second
		}
	}
	return granted, nil
}

// keep renews the registration at half its lifetime, and retries sooner
// after a failure, until the line is closed.
func (l *Line) keep(granted time.Duration) {
	wait := granted / 2
	for {
		t := time.NewTimer(wait)
		select {
		case <-l.done:
			t.Stop()
			return
		case <-t.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		g, err := l.register(ctx, l.cfg.Expiry)
		cancel()
		if err != nil {
			l.cfg.Log.Warn("sipline: registration renewal failed", "err", err)
			wait = min(granted/4, 30*time.Second)
			continue
		}
		granted, wait = g, g/2
	}
}

// onMessage delivers a text. It reaches the line only over its own
// connection to the provider; the sender is what the provider says, and a
// sender that is not a phone number is marked alphanumeric, so it can
// never pass for the owner (CH-1).
func (l *Line) onMessage(req *sip.Request, tx sip.ServerTransaction) {
	ct := ""
	if h := req.ContentType(); h != nil {
		ct = strings.ToLower(strings.TrimSpace(h.Value()))
	}
	if ct != "text/plain" && !strings.HasPrefix(ct, "text/plain;") {
		_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusUnsupportedMediaType, "Unsupported Media Type", nil))
		return
	}
	_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil))
	from := ""
	if f := req.From(); f != nil {
		from = f.Address.User
	}
	m := modem.SMS{From: from, To: l.cfg.Number, Text: string(req.Body()), At: time.Now()}
	if !phone(from) {
		m.From, m.Alphanumeric = "alpha:"+from, true
	}
	select {
	case l.inbox <- m:
	default: // a full inbox drops texts rather than queueing without bound
	}
}

func phone(s string) bool {
	d := strings.TrimPrefix(s, "+")
	if len(d) < 3 || len(d) > 15 {
		return false
	}
	for _, r := range d {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// onInvite declines calls to the line: answering third-party calls is a
// later package (at M13), and until then they are never picked up.
func (l *Line) onInvite(req *sip.Request, tx sip.ServerTransaction) {
	_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusGlobalDecline, "Decline", nil))
}

func (l *Line) onBye(req *sip.Request, tx sip.ServerTransaction) {
	l.mu.Lock()
	c := l.call
	l.mu.Unlock()
	id := ""
	if c != nil {
		id = c.ID()
	}
	if got, err := sip.DialogIDFromRequestUAC(req); id == "" || err != nil || got != id {
		_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusCallTransactionDoesNotExists, "Call/Transaction Does Not Exist", nil))
		return
	}
	_ = c.dlg.ReadBye(req, tx)
	c.end(nil)
}
