// Package sipsim is a simulated VoIP provider for testing the SIP second
// line (package sipline): a SIP-over-TLS registrar and proxy on loopback
// with digest authentication, texts by SIP MESSAGE both ways, and calls
// whose SRTP audio it decrypts so a test can check what the far end heard.
package sipsim

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"
	"github.com/pion/rtp"

	"github.com/ghbmrk/agentos/broker/modem/sipline"
)

// Provider is the simulated provider.
type Provider struct {
	// Addr is the TLS address, host:port.
	Addr string
	// Roots trusts the provider's certificate.
	Roots *x509.CertPool
	// Realm and Domain are the provider's digest realm and SIP domain.
	Realm, Domain string

	ua     *sipgo.UserAgent
	srv    *sipgo.Server
	cli    *sipgo.Client
	dc     *sipgo.DialogServerCache
	ln     net.Listener
	cancel context.CancelFunc

	mu       sync.Mutex
	users    map[string]string // user -> password
	contacts map[string]reg
	nonces   map[string]bool
	authOK   map[string]int // method -> authenticated requests
	authBad  int
	grant    uint32
	texts    chan Text
	calls    chan *Call
	live     map[string]*Call // by Call-ID
	refuse   map[string]int   // method -> status to answer once authenticated
}

type reg struct {
	source  string
	expires uint32
}

// Text is a MESSAGE the provider received from a line.
type Text struct {
	From, To, ContentType, Body string
}

// Start starts a provider for domain with one account.
func Start(domain, user, password string) (*Provider, error) {
	return StartTLS(domain, user, password, 0)
}

// StartTLS is Start with the provider's newest TLS version capped at
// maxTLS (0 for no cap), to stand in for an outdated provider.
func StartTLS(domain, user, password string, maxTLS uint16) (*Provider, error) {
	cert, roots, err := selfSigned()
	if err != nil {
		return nil, err
	}
	ua, err := sipgo.NewUA(sipgo.WithUserAgent("sipsim"), sipgo.WithUserAgentHostname(domain))
	if err != nil {
		return nil, err
	}
	p := &Provider{Roots: roots, Realm: domain + " realm", Domain: domain, ua: ua,
		users: map[string]string{user: password}, contacts: map[string]reg{}, nonces: map[string]bool{},
		authOK: map[string]int{}, grant: 3600, texts: make(chan Text, 64), calls: make(chan *Call, 8), live: map[string]*Call{}, refuse: map[string]int{}}
	if p.srv, err = sipgo.NewServer(ua); err != nil {
		return nil, err
	}
	if p.cli, err = sipgo.NewClient(ua); err != nil {
		return nil, err
	}
	p.dc = sipgo.NewDialogServerCache(p.cli, sip.ContactHeader{Address: sip.Uri{Scheme: "sip", Host: "127.0.0.1"}})
	p.srv.OnRegister(p.onRegister)
	p.srv.OnMessage(p.onMessage)
	p.srv.OnInvite(p.onInvite)
	p.srv.OnAck(func(req *sip.Request, tx sip.ServerTransaction) { _ = p.dc.ReadAck(req, tx) })
	p.srv.OnBye(p.onBye)
	p.srv.OnOptions(func(req *sip.Request, tx sip.ServerTransaction) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil))
	})
	tc := &tls.Config{Certificates: []tls.Certificate{cert}}
	if maxTLS != 0 {
		tc.MinVersion, tc.MaxVersion = tls.VersionTLS10, maxTLS
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tc)
	if err != nil {
		return nil, err
	}
	p.ln, p.Addr = ln, ln.Addr().String()
	go func() { _ = p.srv.ServeTLS(ln) }()
	return p, nil
}

// Close stops the provider.
func (p *Provider) Close() {
	_ = p.ln.Close()
	_ = p.ua.Close()
}

// Grant sets the registration lifetime the provider grants, in seconds.
func (p *Provider) Grant(s uint32) {
	p.mu.Lock()
	p.grant = s
	p.mu.Unlock()
}

// Refuse makes the provider answer authenticated requests of method with
// status.
func (p *Provider) Refuse(method string, status int) {
	p.mu.Lock()
	p.refuse[method] = status
	p.mu.Unlock()
}

// Registered reports the user's current registration lifetime, 0 if none.
func (p *Provider) Registered(user string) uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.contacts[user].expires
}

// Authenticated counts requests of method that passed digest checks.
func (p *Provider) Authenticated(method string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.authOK[method]
}

// BadAuth counts requests with wrong credentials.
func (p *Provider) BadAuth() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.authBad
}

// Texts delivers the MESSAGEs lines send.
func (p *Provider) Texts() <-chan Text { return p.texts }

// Calls delivers the calls lines place.
func (p *Provider) Calls() <-chan *Call { return p.calls }

// authenticate challenges a request without valid credentials and reports
// whether it may proceed.
func (p *Provider) authenticate(req *sip.Request, tx sip.ServerTransaction) (string, bool) {
	h := req.GetHeader("Authorization")
	if h != nil {
		if user, ok := p.verify(req, h.Value()); ok {
			p.mu.Lock()
			p.authOK[req.Method.String()]++
			p.mu.Unlock()
			return user, true
		}
		p.mu.Lock()
		p.authBad++
		p.mu.Unlock()
		_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusForbidden, "Forbidden", nil))
		return "", false
	}
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	n := base64.RawURLEncoding.EncodeToString(nonce)
	p.mu.Lock()
	p.nonces[n] = true
	p.mu.Unlock()
	res := sip.NewResponseFromRequest(req, sip.StatusUnauthorized, "Unauthorized", nil)
	res.AppendHeader(sip.NewHeader("WWW-Authenticate", fmt.Sprintf(`Digest realm=%q, nonce=%q, qop="auth", algorithm=MD5`, p.Realm, n)))
	_ = tx.Respond(res)
	return "", false
}

func (p *Provider) verify(req *sip.Request, value string) (string, bool) {
	cred, err := digest.ParseCredentials(value)
	if err != nil {
		return "", false
	}
	p.mu.Lock()
	pw, ok := p.users[cred.Username]
	fresh := p.nonces[cred.Nonce]
	p.mu.Unlock()
	if !ok || !fresh || cred.Realm != p.Realm || cred.URI != req.Recipient.Addr() {
		return "", false
	}
	want, err := digest.Digest(&digest.Challenge{Realm: p.Realm, Nonce: cred.Nonce, Algorithm: "MD5", QOP: []string{"auth"}},
		digest.Options{Method: req.Method.String(), URI: cred.URI, Username: cred.Username, Password: pw, Cnonce: cred.Cnonce, Count: cred.Nc})
	if err != nil || want.Response != cred.Response {
		return "", false
	}
	return cred.Username, true
}

func (p *Provider) refused(req *sip.Request, tx sip.ServerTransaction) bool {
	p.mu.Lock()
	code := p.refuse[req.Method.String()]
	p.mu.Unlock()
	if code == 0 {
		return false
	}
	_ = tx.Respond(sip.NewResponseFromRequest(req, code, "Refused", nil))
	return true
}

func (p *Provider) onRegister(req *sip.Request, tx sip.ServerTransaction) {
	user, ok := p.authenticate(req, tx)
	if !ok || p.refused(req, tx) {
		return
	}
	var exp uint32 = 3600
	if h := req.GetHeader("Expires"); h != nil {
		_, _ = fmt.Sscan(h.Value(), &exp)
	}
	p.mu.Lock()
	if exp > p.grant {
		exp = p.grant
	}
	if exp == 0 {
		delete(p.contacts, user)
	} else {
		p.contacts[user] = reg{source: req.Source(), expires: exp}
	}
	p.mu.Unlock()
	res := sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil)
	res.AppendHeader(sip.NewHeader("Expires", fmt.Sprint(exp)))
	_ = tx.Respond(res)
}

func (p *Provider) onMessage(req *sip.Request, tx sip.ServerTransaction) {
	if _, ok := p.authenticate(req, tx); !ok || p.refused(req, tx) {
		return
	}
	t := Text{To: req.Recipient.User, Body: string(req.Body())}
	if f := req.From(); f != nil {
		t.From = f.Address.User
	}
	if h := req.ContentType(); h != nil {
		t.ContentType = h.Value()
	}
	_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusAccepted, "Accepted", nil))
	p.texts <- t
}

// SendText delivers a text from a number to a registered user over that
// user's own connection, as a provider relays an incoming SMS.
func (p *Provider) SendText(ctx context.Context, from, user, contentType, body string) (int, error) {
	return p.Relay(ctx, Incoming{From: from, User: user, ContentType: contentType, Body: body})
}

// Incoming is a text the provider relays to a line.
type Incoming struct {
	From              string // From's user part
	FromHost          string // From's host; default the provider's domain
	PAI               string // P-Asserted-Identity value, if any
	User              string // the registered user it is for
	ContentType, Body string
}

// Relay delivers in to its user over that user's own connection.
func (p *Provider) Relay(ctx context.Context, in Incoming) (int, error) {
	req, err := p.toLine(sip.MESSAGE, in.From, in.User)
	if err != nil {
		return 0, err
	}
	if in.FromHost != "" {
		req.From().Address.Host = in.FromHost
	}
	if in.PAI != "" {
		req.AppendHeader(sip.NewHeader("P-Asserted-Identity", in.PAI))
	}
	contentType, body := in.ContentType, in.Body
	req.AppendHeader(sip.NewHeader("Content-Type", contentType))
	req.SetBody([]byte(body))
	res, err := p.cli.Do(ctx, req)
	if err != nil {
		return 0, err
	}
	return res.StatusCode, nil
}

// CallLine places an incoming call to a registered user and returns the
// final status.
func (p *Provider) CallLine(ctx context.Context, from, user string) (int, error) {
	req, err := p.toLine(sip.INVITE, from, user)
	if err != nil {
		return 0, err
	}
	req.AppendHeader(&sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: from, Host: "127.0.0.1"}})
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	req.SetBody([]byte("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 9 RTP/AVP 0\r\n"))
	res, err := p.cli.Do(ctx, req)
	if err != nil {
		return 0, err
	}
	return res.StatusCode, nil
}

// SendRaw writes data as-is on a registered user's connection, as a
// broken or hostile provider might.
func (p *Provider) SendRaw(user string, data []byte) error {
	p.mu.Lock()
	r, ok := p.contacts[user]
	p.mu.Unlock()
	if !ok {
		return errors.New("sipsim: user not registered")
	}
	c, err := p.ua.TransportLayer().GetConnection("tls", r.source)
	if err != nil || c == nil {
		return fmt.Errorf("sipsim: no connection: %v", err)
	}
	w, ok := c.(io.Writer)
	if !ok {
		return errors.New("sipsim: connection cannot be written raw")
	}
	_, err = w.Write(data)
	return err
}

func (p *Provider) toLine(method sip.RequestMethod, from, user string) (*sip.Request, error) {
	p.mu.Lock()
	r, ok := p.contacts[user]
	p.mu.Unlock()
	if !ok {
		return nil, errors.New("sipsim: user not registered")
	}
	req := sip.NewRequest(method, sip.Uri{Scheme: "sip", User: user, Host: p.Domain})
	req.SetTransport("TLS")
	req.SetDestination(r.source)
	f := &sip.FromHeader{Address: sip.Uri{Scheme: "sip", User: from, Host: p.Domain}, Params: sip.NewParams()}
	f.Params.Add("tag", sip.GenerateTagN(8))
	req.AppendHeader(f)
	return req, nil
}

func (p *Provider) onInvite(req *sip.Request, tx sip.ServerTransaction) {
	if _, ok := p.authenticate(req, tx); !ok || p.refused(req, tx) {
		return
	}
	d, err := p.dc.ReadInvite(req, tx)
	if err != nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusInternalServerError, "Error", nil))
		return
	}
	c := &Call{p: p, invite: req, To: req.Recipient.User, Offer: append([]byte(nil), req.Body()...), d: d, bye: make(chan struct{}), done: make(chan struct{})}
	id := req.CallID().Value()
	p.mu.Lock()
	p.live[id] = c
	p.mu.Unlock()
	p.calls <- c
	select {
	case <-d.Context().Done():
	case <-c.bye:
	}
	close(c.done)
	p.mu.Lock()
	delete(p.live, id)
	p.mu.Unlock()
	c.mu.Lock()
	if c.media != nil {
		_ = c.media.Close()
	}
	c.mu.Unlock()
}

// onBye ends a call the line hangs up. It answers the BYE itself rather
// than through sipgo's DialogServerSession.ReadBye: over TLS the BYE's
// server transaction can terminate as soon as the 200 is sent, and ReadBye
// then reports that as an error and leaves the dialog open, so the
// simulator would never see the hangup.
func (p *Provider) onBye(req *sip.Request, tx sip.ServerTransaction) {
	id := ""
	if h := req.CallID(); h != nil {
		id = h.Value()
	}
	p.mu.Lock()
	c := p.live[id]
	p.mu.Unlock()
	if c == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusCallTransactionDoesNotExists, "Call/Transaction Does Not Exist", nil))
		return
	}
	_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil))
	c.byeOnce.Do(func() { close(c.bye) })
}

// Call is a call a line placed.
type Call struct {
	To      string
	Offer   []byte
	d       *sipgo.DialogServerSession
	p       *Provider
	invite  *sip.Request
	bye     chan struct{} // closed when the line hangs up
	done    chan struct{} // closed when the call ends either way
	byeOnce sync.Once

	mu    sync.Mutex
	media *net.UDPConn
	heard []byte
	pts   map[uint8]bool
}

// Ring sends 180 Ringing.
func (c *Call) Ring() error { return c.d.Respond(sip.StatusRinging, "Ringing", nil) }

// Reject answers with a final failure status.
func (c *Call) Reject(code int) error { return c.d.Respond(code, "Rejected", nil) }

// Done is closed when the call ends: the line's BYE, its CANCEL before an
// answer, or the far end's hangup.
func (c *Call) Done() <-chan struct{} { return c.done }

// ForgedBye sends the line a BYE with this call's Call-ID but a far-end
// tag that is not the dialog's, as an off-path party guessing the Call-ID
// would, and returns the line's status.
func (c *Call) ForgedBye(ctx context.Context) (int, error) {
	inv := c.invite
	req := sip.NewRequest(sip.BYE, inv.Contact().Address)
	req.SetTransport("TLS")
	req.SetDestination(inv.Source())
	f := &sip.FromHeader{Address: inv.To().Address, Params: sip.NewParams()}
	f.Params.Add("tag", "forged")
	req.AppendHeader(f)
	to := &sip.ToHeader{Address: inv.From().Address, Params: sip.NewParams()}
	if tag, ok := inv.From().Params.Get("tag"); ok {
		to.Params.Add("tag", tag)
	}
	req.AppendHeader(to)
	req.AppendHeader(sip.HeaderClone(inv.CallID()))
	res, err := c.p.cli.Do(ctx, req)
	if err != nil {
		return 0, err
	}
	return res.StatusCode, nil
}

// Hangup ends an answered call from the far end.
func (c *Call) Hangup(ctx context.Context) error { return c.d.Bye(ctx) }

// Answer answers with SRTP and the payload type pt, decrypting what the
// line sends into Heard.
func (c *Call) Answer(pt int) error { return c.answer(pt, true) }

// AnswerPlain answers without SRTP, as a provider without it would.
func (c *Call) AnswerPlain() error { return c.answer(sipline.PCMU, false) }

func (c *Call) answer(pt int, secure bool) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.media = conn
	c.mu.Unlock()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	sdp := fmt.Sprintf("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n")
	if secure {
		k := make([]byte, 30)
		_, _ = rand.Read(k)
		sdp += fmt.Sprintf("m=audio %d RTP/SAVP %d\r\na=crypto:1 %s inline:%s\r\n", port, pt, sipline.Suite, base64.StdEncoding.EncodeToString(k))
	} else {
		sdp += fmt.Sprintf("m=audio %d RTP/AVP %d\r\n", port, pt)
	}
	key, err := sipline.OfferKey(c.Offer)
	if err != nil {
		return err
	}
	rx, err := sipline.Context(key)
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var h rtp.Header
			plain, err := rx.DecryptRTP(nil, buf[:n], &h)
			if err != nil {
				continue
			}
			var pkt rtp.Packet
			if pkt.Unmarshal(plain) != nil {
				continue
			}
			c.mu.Lock()
			c.heard = append(c.heard, pkt.Payload...)
			if c.pts == nil {
				c.pts = map[uint8]bool{}
			}
			c.pts[pkt.PayloadType] = true
			c.mu.Unlock()
		}
	}()
	if err := c.d.RespondSDP([]byte(sdp)); err != nil {
		select {
		case <-c.Done():
			// The line hung up at once (as it does on an answer it
			// refuses), racing the ACK wait; the answer was delivered.
		default:
			return err
		}
	}
	return nil
}

// Heard is the G.711 audio decrypted so far.
func (c *Call) Heard() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.heard...)
}

// PayloadTypes are the RTP payload types heard.
func (c *Call) PayloadTypes() []uint8 {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []uint8
	for pt := range c.pts {
		out = append(out, pt)
	}
	return out
}

// OfferHas reports whether the line's SDP offer contains s.
func (c *Call) OfferHas(s string) bool { return strings.Contains(string(c.Offer), s) }

func selfSigned() (tls.Certificate, *x509.CertPool, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sipsim"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"sip.test"},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots, nil
}
