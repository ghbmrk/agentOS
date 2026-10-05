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
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modem/secondline"
	"github.com/ghbmrk/agentos/broker/sipsign"
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
	// NoCallsClip is the broker-rendered NoCallsText (8 kHz S16_LE mono),
	// played over SRTP to anyone who calls the line, which then hangs up.
	// Empty declines calls (603) instead.
	NoCallsClip []byte
}

// NoCallsText is what a caller to the second line hears (NoCallsClip):
// the line answers only texts until a call handler exists (at M13).
const NoCallsText = "This number can't take calls. Please text it."

// Errors.
var (
	ErrConfig   = errors.New("sipline: Server, Domain, User, Number and Signer are required")
	ErrInsecure = errors.New("sipline: the provider's certificate must be verified")
	ErrNumber   = errors.New("sipline: not a phone number")
	ErrBusy     = errors.New("sipline: a call is already in progress")
	ErrClosed   = errors.New("sipline: line closed")
	// ErrTextRefused wraps the provider's refusal of a text.
	ErrTextRefused = errors.New("sipline: text refused")
	// ErrUnreachable wraps a failure to reach or register with the
	// provider.
	ErrUnreachable = errors.New("sipline: provider unreachable")
)

// OwnerText words err for the owner: what happened and what to do, never
// a status code or the provider's reason text. Unknown errors read as the
// provider being unreachable, which the line keeps retrying.
func OwnerText(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNumber):
		return "That isn't a phone number the second line can call or text."
	case errors.Is(err, ErrBusy):
		return "The second line is already on a call. Try again when it ends."
	case errors.Is(err, ErrClosed), errors.Is(err, ErrConfig), errors.Is(err, ErrInsecure):
		return "The second line isn't connected right now."
	case errors.Is(err, ErrNoSRTP):
		return "The call was ended before anything was said: the provider didn't offer an encrypted call."
	case errors.Is(err, ErrMediaAddress):
		return "The call was ended before anything was said: the provider sent its audio somewhere the box won't send to."
	case errors.Is(err, ErrTextRefused):
		return "The second line's provider didn't accept that text. Check the number, or try again later."
	case errors.Is(err, sipsign.ErrLocked):
		return "The second line can't sign in while the box is locked. Unlock it on the local page."
	case errors.Is(err, sipsign.ErrNoAccount):
		return "The second line's calling account isn't set up. Set it up on the box's local page."
	case errors.Is(err, sipsign.ErrRefused):
		return "The second line's sign-in needs confirming. Check the provider name on the box's local page."
	}
	return "The second line couldn't reach its provider. It will keep trying."
}

// quiet discards everything the SIP stack would log. sipgo logs a whole
// message it cannot parse, which can carry a third party's text or the far
// end's SRTP key; no SIP message ever reaches a log (CRED-1, CLAUDE.md).
// It is also sipgo's process-wide default, for the places that log through
// it directly rather than through a configured logger.
var quiet = slog.New(slog.DiscardHandler)

func init() { sip.SetDefaultLogger(quiet) }

// Limits on incoming texts.
const (
	maxText = 1600 // bytes: ten SMS segments
	maxName = 32   // characters of a named (alphanumeric) sender
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

	registered atomic.Bool

	mu       sync.Mutex
	contact  sip.ContactHeader
	provider net.IP // the provider's address on the signaling connection
	call     *call
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
	ua, err := sipgo.NewUA(sipgo.WithUserAgent("agentos"), sipgo.WithUserAgentHostname(cfg.Domain), sipgo.WithUserAgenTLSConfig(tc),
		sipgo.WithUserAgentTransportLayerOptions(sip.WithTransportLayerLogger(quiet)),
		sipgo.WithUserAgentTransactionLayerOptions(sip.WithTransactionLayerLogger(quiet)))
	if err != nil {
		return nil, err
	}
	l := &Line{cfg: cfg, ua: ua, inbox: make(chan modem.SMS, 64), done: make(chan struct{})}
	if l.cli, err = sipgo.NewClient(ua, sipgo.WithClientLogger(quiet)); err == nil {
		l.srv, err = sipgo.NewServer(ua, sipgo.WithServerLogger(quiet))
	}
	if err != nil {
		_ = ua.Close()
		return nil, err
	}
	l.srv.OnMessage(l.onMessage)
	l.srv.OnInvite(l.onInvite)
	l.srv.OnBye(l.onBye)
	l.srv.OnAck(l.onAck)
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
		return fmt.Errorf("%w: %d", ErrTextRefused, res.StatusCode)
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
		res, err := l.cli.Do(ctx, probe)
		if err != nil {
			return 0, fmt.Errorf("%w: %w", ErrUnreachable, err)
		}
		host, _, _ := net.SplitHostPort(res.Source())
		via := probe.Via()
		c := sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: l.cfg.User, Host: via.Host, Port: via.Port, UriParams: sip.NewParams()}}
		c.Address.UriParams.Add("transport", "tls")
		l.mu.Lock()
		l.contact, l.provider = c, net.ParseIP(host)
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
		return 0, fmt.Errorf("%w: registration refused: %d", ErrUnreachable, res.StatusCode)
	}
	granted := expiry
	if h := res.GetHeader("Expires"); h != nil {
		if s, err := strconv.Atoi(strings.TrimSpace(h.Value())); err == nil && s > 0 && time.Duration(s)*time.Second < granted {
			granted = time.Duration(s) * time.Second
		}
	}
	l.registered.Store(expiry > 0)
	return granted, nil
}

// Registered reports whether the last registration or renewal succeeded.
// The line keeps retrying while it fails; Done closes only on Close.
func (l *Line) Registered() bool { return l.registered.Load() }

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
			l.registered.Store(false)
			l.cfg.Log.Warn("sipline: registration renewal failed", "err", err)
			wait = min(granted/4, 30*time.Second)
			continue
		}
		granted, wait = g, g/2
	}
}

// onMessage delivers a text. It reaches the line only over its own
// connection to the provider. The sender's number is believed only as the
// provider asserts it: P-Asserted-Identity, or a From in the provider's
// own domain. Any other sender, or one that is not a phone number, is
// delivered as a named sender ("alpha:"), so it can never pass for the
// owner (CH-1). Bodies are plain UTF-8 text of at most maxText bytes.
func (l *Line) onMessage(req *sip.Request, tx sip.ServerTransaction) {
	ct := ""
	if h := req.ContentType(); h != nil {
		ct = strings.ToLower(strings.TrimSpace(h.Value()))
	}
	body := req.Body()
	switch {
	case ct != "text/plain" && !strings.HasPrefix(ct, "text/plain;"), !utf8.Valid(body):
		_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusUnsupportedMediaType, "Unsupported Media Type", nil))
		return
	case len(body) > maxText:
		_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusRequestEntityTooLarge, "Request Entity Too Large", nil))
		return
	}
	_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil))
	m := modem.SMS{To: l.cfg.Number, Text: string(body), At: time.Now()}
	if from, ok := l.sender(req); ok {
		m.From = from
	} else {
		m.From, m.Alphanumeric = "alpha:"+name(from), true
	}
	select {
	case l.inbox <- m:
	default: // a full inbox drops texts rather than queueing without bound
	}
}

// sender reads who sent req and whether that is a phone number the
// provider vouches for.
func (l *Line) sender(req *sip.Request) (string, bool) {
	if h := req.GetHeader("P-Asserted-Identity"); h != nil {
		v := h.Value()
		if i, j := strings.IndexByte(v, '<'), strings.IndexByte(v, '>'); i >= 0 && j > i {
			v = v[i+1 : j]
		}
		v, _, _ = strings.Cut(v, ";")
		switch {
		case strings.HasPrefix(strings.ToLower(v), "tel:"):
			v = v[4:]
		case strings.HasPrefix(strings.ToLower(v), "sip:"):
			v, _, _ = strings.Cut(v[4:], "@")
		}
		return v, phone(v)
	}
	f := req.From()
	if f == nil {
		return "", false
	}
	return f.Address.User, phone(f.Address.User) && strings.EqualFold(f.Address.Host, l.cfg.Domain)
}

// name renders a named sender as at most maxName printable ASCII
// characters.
func name(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() == maxName {
			break
		}
		if r > ' ' && r < 0x7f {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
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

// onInvite answers a call to the line with NoCallsClip over SRTP and hangs
// up: answering third-party calls is a later package (at M13). It declines
// (603) whenever the clip cannot be played safely: no clip, a call already
// in progress, or an offer without SRTP, a G.711 codec or a public unicast
// audio address (the rules of an answer, SL7). It never answers in the
// clear.
func (l *Line) onInvite(req *sip.Request, tx sip.ServerTransaction) {
	decline := func() { _ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusGlobalDecline, "Decline", nil)) }
	if len(l.cfg.NoCallsClip) == 0 {
		decline()
		return
	}
	l.mu.Lock()
	p, contact := l.provider, l.contact
	l.mu.Unlock()
	theirs, err := parseOffer(req.Body(), p != nil && (p.IsLoopback() || p.IsPrivate()))
	if err != nil {
		decline()
		return
	}
	c, ours, err := l.claim(req, tx, contact)
	if err != nil {
		decline()
		return
	}
	defer c.end(nil)
	srtpTx, err := Context(ours.key)
	if err != nil {
		_ = c.sdlg.Respond(sip.StatusGlobalDecline, "Decline", nil)
		return
	}
	c.mu.Lock()
	c.ans, c.tx = theirs, srtpTx
	c.mu.Unlock()
	if err := c.sdlg.RespondSDP([]byte(ours.answerSDP(theirs.pt, theirs.tag))); err != nil {
		return
	}
	close(c.active)
	go c.drain()
	go func() {
		select {
		case <-c.sdlg.Context().Done():
			c.end(nil)
		case <-c.ended:
		}
	}()
	if err := c.Say(c.ctx, l.cfg.NoCallsClip); err != nil {
		return // the caller hung up
	}
	// The line is free once the clip is out, before the BYE is answered.
	c.end(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.sdlg.Bye(ctx)
}

// claim makes the incoming call the line's one call, with its audio socket
// and the line's key, or fails if a call is in progress.
func (l *Line) claim(req *sip.Request, tx sip.ServerTransaction, contact sip.ContactHeader) (*call, offer, error) {
	ip := l.cfg.MediaIP
	if ip == nil {
		ip = net.ParseIP(contact.Address.Host)
	}
	if ip == nil {
		return nil, offer{}, errors.New("sipline: no address for call audio")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.call != nil {
		select {
		case <-l.call.ended:
		default:
			return nil, offer{}, ErrBusy
		}
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
	if err != nil {
		return nil, offer{}, err
	}
	ours, err := newOffer(ip, conn.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		_ = conn.Close()
		return nil, offer{}, err
	}
	ua := &sipgo.DialogUA{Client: l.cli, ContactHDR: contact, RewriteContact: true}
	d, err := ua.ReadInvite(req, tx)
	if err != nil {
		_ = conn.Close()
		return nil, offer{}, err
	}
	c := newCall(l, conn)
	c.sdlg, c.id = d, d.ID
	l.call = c
	return c, ours, nil
}

// onAck confirms an answered incoming call.
func (l *Line) onAck(req *sip.Request, tx sip.ServerTransaction) {
	l.mu.Lock()
	c := l.call
	l.mu.Unlock()
	if c == nil || c.sdlg == nil {
		return
	}
	if id, err := sip.DialogIDFromRequestUAS(req); err == nil && id == c.sdlg.ID {
		_ = c.sdlg.ReadAck(req, tx)
	}
}

func (l *Line) onBye(req *sip.Request, tx sip.ServerTransaction) {
	l.mu.Lock()
	c := l.call
	l.mu.Unlock()
	id := ""
	if c != nil {
		id = c.ID()
	}
	dialogID := sip.DialogIDFromRequestUAC
	if c != nil && c.sdlg != nil {
		dialogID = sip.DialogIDFromRequestUAS // the caller's BYE for a call to the line
	}
	if got, err := dialogID(req); id == "" || err != nil || got != id {
		_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusCallTransactionDoesNotExists, "Call/Transaction Does Not Exist", nil))
		return
	}
	if c.sdlg != nil {
		// Answered here, not through ReadBye: over TLS the BYE's
		// transaction can terminate as the 200 goes out, and ReadBye
		// then reports an error (see sipsim's onBye).
		_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil))
	} else {
		_ = c.dlg.ReadBye(req, tx)
	}
	c.end(nil)
}
