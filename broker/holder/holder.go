// Package holder is one account's key holder (SIM-split): a process that
// keeps one login and nothing else, and spends it only on a request in a
// shape the account's adapters declare (ADP-10).
//
// Egress hands the holder the checked upstream request with no credential,
// on the request socket. The holder picks the adapter by host, checks the
// request against the declaration again, writes its own login into the
// declared header, dials through the address policy (DEV-2), swaps an
// exchange response in the holder (CRED-5), and redacts its own secret
// from everything it returns (CRED-7). The unlock step hands it the secret
// on the hand socket, and hands it again when the holder restarts empty
// (Keeper). Nothing on either socket ever reads the secret back. An
// irreversible operation is served only once the CH-4 checker approved
// that exact request (Config.Redeem, package checker).
package holder

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/checker"
	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/sockets"
	"github.com/ghbmrk/agentos/broker/vault"
	"github.com/ghbmrk/agentos/broker/verb"
)

// The holder's two sockets, by file name in its run directory. Each admits
// one peer uid: egress on the request socket, the unlock step on the hand
// socket.
const (
	RequestSocket = "request.sock"
	HandSocket    = "hand.sock"
)

// ErrorHeader is set on an answer the holder made itself, rather than one
// the provider gave; Client turns it back into an error.
const ErrorHeader = "Agentos-Holder-Error"

// ErrorHeader values.
const (
	ErrRefused     = "refused"     // the request is outside the declaration; nothing sent
	ErrNoSecret    = "no-secret"   // nothing handed yet; nothing sent
	ErrDenied      = "denied"      // the address policy refused the destination
	ErrUnreachable = "unreachable" // the provider could not be reached
	ErrUnapproved  = "unapproved"  // a high-risk act the checker has not approved; nothing sent
)

// maxSecret caps a handed secret, in bytes.
const maxSecret = 64 << 10

// Config is one holder's declaration.
type Config struct {
	// Adapters are the account's adapters: one host each, one credential
	// for all of them.
	Adapters []egress.Adapter
	// Transport, when set, replaces the guarded default transport (tests).
	Transport http.RoundTripper
	// Guard is the address policy the default transport dials through.
	Guard *netguard.Policy
	// Swapper stores the credentials an exchange issues; required when an
	// operation exchanges credentials.
	Swapper egress.Swapper
	// MaxBody caps a request body; zero means egress.DefaultMaxBody.
	MaxBody int64
	// Redeem spends the CH-4 checker's approval for an act
	// (checker.Redeemer). An irreversible or secret operation is served
	// only when it returns true for the exact request; with no Redeem the
	// holder serves reads only.
	Redeem func(ctx context.Context, act string) (bool, error)
	// PublicFetch says the owner lets machines labelled public use
	// provider-side fetch with this login (REV-5). Without it the holder
	// holds every body to the strict form, whatever label egress claims;
	// with it, a body egress labels public gets the public form, as in
	// the proxy (ADP-10).
	PublicFetch bool
}

// Holder keeps one account's login.
type Holder struct {
	byHost  map[string]egress.Adapter
	rt      http.RoundTripper
	rtModel http.RoundTripper
	swapper egress.Swapper
	maxBody int64
	redeem  func(ctx context.Context, act string) (bool, error)
	account string
	public  bool

	mu     sync.RWMutex
	secret []byte
}

// New checks the declaration and returns a holder with no secret.
func New(cfg Config) (*Holder, error) {
	if len(cfg.Adapters) == 0 {
		return nil, errors.New("holder: no adapter")
	}
	h := &Holder{byHost: map[string]egress.Adapter{}, rt: cfg.Transport, swapper: cfg.Swapper, maxBody: cfg.MaxBody, redeem: cfg.Redeem, public: cfg.PublicFetch}
	cred := cfg.Adapters[0].Credential
	h.account = cred
	for _, a := range cfg.Adapters {
		if err := a.Validate(); err != nil {
			return nil, fmt.Errorf("holder: %v", err)
		}
		if a.Credential != cred {
			return nil, fmt.Errorf("holder: adapter %s keeps %s, not %s: one holder keeps one login", a.Name, a.Credential, cred)
		}
		if _, dup := h.byHost[a.Host]; dup {
			return nil, fmt.Errorf("holder: two adapters on host %s", a.Host)
		}
		for _, op := range a.Operations {
			if op.Response != nil && cfg.Swapper == nil {
				return nil, fmt.Errorf("holder: adapter %s: operation %s exchanges credentials and no swapper is set", a.Name, op.Name)
			}
		}
		h.byHost[a.Host] = a
	}
	if h.rt == nil {
		g := cfg.Guard
		if g == nil {
			g = netguard.New(netguard.Config{})
		}
		// Two pools, as in the proxy: a connection a model call made to a
		// pinned host is never reused by a request with no exception.
		h.rt, h.rtModel = egress.DefaultTransport(g), egress.DefaultTransport(g)
	} else {
		h.rtModel = h.rt
	}
	if h.maxBody <= 0 {
		h.maxBody = egress.DefaultMaxBody
	}
	return h, nil
}

// Hand gives the holder its secret, replacing any it held. b is copied.
func (h *Holder) Hand(b []byte) {
	s := append([]byte(nil), b...)
	h.mu.Lock()
	old := h.secret
	h.secret = s
	h.mu.Unlock()
	for i := range old {
		old[i] = 0
	}
}

// Drop zeroes and forgets the holder's secret.
func (h *Holder) Drop() { h.Hand(nil) }

// Held reports whether the holder has a secret.
func (h *Holder) Held() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.secret) > 0
}

// holds reports whether the holder's secret is b (tests).
func (h *Holder) holds(b []byte) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.secret) > 0 && subtle.ConstantTimeCompare(h.secret, b) == 1
}

func (h *Holder) current() []byte {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.secret
}

func refuse(w http.ResponseWriter, status int, why string) {
	w.Header().Set(ErrorHeader, why)
	http.Error(w, "holder: "+why, status)
}

// ServeHTTP serves the request socket.
func (h *Holder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a, ok := h.byHost[r.Host]
	if !ok || r.URL.RawQuery != "" {
		refuse(w, http.StatusForbidden, ErrRefused)
		return
	}
	op, ok := a.Match(r.Method, r.URL.Path)
	if !ok || !h.headersDeclared(a, r.Header) {
		refuse(w, http.StatusForbidden, ErrRefused)
		return
	}
	// Reads are served on the declaration alone. A high-risk verb needs
	// the checker's approval for this exact request, below; anything else
	// (draft, organize, an unknown verb) is not the holder's to serve.
	class, known := verb.ClassOf(op.Verb)
	highRisk := known && (class == verb.Irreversible || class == verb.Secret)
	if op.Verb != egress.VerbRead && !(highRisk && h.redeem != nil) {
		refuse(w, http.StatusForbidden, ErrRefused)
		return
	}
	secret := h.current()
	if len(secret) == 0 {
		refuse(w, http.StatusServiceUnavailable, ErrNoSecret)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, h.maxBody+1))
	if err != nil || int64(len(body)) > h.maxBody {
		refuse(w, http.StatusForbidden, ErrRefused)
		return
	}
	// The holder holds the body to the operation's rule itself rather than
	// trusting egress to have done so, and sends its own encoding (ADP-10).
	// The rule is idempotent, so a body egress checked passes unchanged.
	if op.Body != nil {
		public := h.public && r.Header.Get(egress.LabelHeader) == egress.LabelPublic
		if body, err = op.Body.Apply(body, public); err != nil {
			refuse(w, http.StatusForbidden, ErrRefused)
			return
		}
	}
	// The approval is spent on the act as sent: this holder's account,
	// host, method, the path on the wire and the body, so a code approves
	// this request through this login and no other (CH-4, CH-10).
	if highRisk {
		approved, err := h.redeem(r.Context(), checker.Act(h.account, a.Host, op.Method, r.URL.EscapedPath(), body))
		if err != nil {
			refuse(w, http.StatusServiceUnavailable, ErrUnapproved)
			return
		}
		if !approved {
			refuse(w, http.StatusForbidden, ErrUnapproved)
			return
		}
	}

	ctx := r.Context()
	rt := h.rt
	if op.Inference {
		ctx = netguard.WithPurpose(ctx, netguard.PurposeModelCall)
		rt = h.rtModel
	}
	u := url.URL{Scheme: "https", Host: a.Host, Path: r.URL.Path, RawPath: r.URL.RawPath}
	up, err := http.NewRequestWithContext(ctx, op.Method, u.String(), bytes.NewReader(body))
	if err != nil {
		refuse(w, http.StatusForbidden, ErrRefused)
		return
	}
	for _, k := range a.ForwardedRequestHeaders() {
		if vs := r.Header.Values(k); len(vs) > 0 {
			up.Header[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
		}
	}
	up.Header.Set("Accept-Encoding", "identity")
	up.Header.Set(a.Inject.Header, a.Inject.Prefix+string(secret))

	resp, err := rt.RoundTrip(up)
	if errors.Is(err, netguard.ErrDenied) {
		refuse(w, http.StatusForbidden, ErrDenied)
		return
	}
	if err != nil {
		refuse(w, http.StatusBadGateway, ErrUnreachable)
		return
	}
	defer resp.Body.Close()

	// An encoded body cannot be redacted: say it was encoded, send none,
	// and egress refuses it as it refuses its own.
	if egress.Encoded(resp.Header) {
		w.Header().Set("Content-Encoding", resp.Header.Get("Content-Encoding"))
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	// A refused login: the status alone stops the route in egress.
	if op.RefusesLogin(resp.StatusCode) {
		w.WriteHeader(resp.StatusCode)
		return
	}
	red := vault.NewRedactor([][]byte{secret})
	if op.Response != nil {
		h.exchange(w, resp, a, op, red)
		return
	}
	for _, k := range a.ForwardedResponseHeaders() {
		for _, v := range resp.Header.Values(k) {
			w.Header().Add(k, string(red.Redact([]byte(v))))
		}
	}
	w.WriteHeader(resp.StatusCode)
	stream(w, resp.Body, red)
}

// exchange swaps an exchange response in the holder, so an issued
// credential never leaves it (CRED-5). A response it cannot swap is
// dropped with the reason egress stops the route by (CRED-5t).
func (h *Holder) exchange(w http.ResponseWriter, resp *http.Response, a egress.Adapter, op egress.Operation, red *vault.Redactor) {
	drop := func(why string) {
		w.Header().Set(egress.HolderDropHeader, why)
		w.WriteHeader(http.StatusBadGateway)
	}
	out, commit, err := op.SwapResponse(resp, a.Name, h.swapper)
	if err == nil {
		err = commit()
	}
	if err != nil {
		if resp.StatusCode >= 400 {
			drop(egress.DropExchangeError)
		} else {
			drop(egress.DropUnswappable)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(red.Redact(out))
}

// stream copies body to w through red, flushing as it goes so a streamed
// model answer reaches the guest as it arrives.
func stream(w http.ResponseWriter, body io.Reader, red *vault.Redactor) {
	f, _ := w.(http.Flusher)
	rw := red.Writer(w)
	buf := make([]byte, 32<<10)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := rw.Write(buf[:n]); werr != nil {
				return
			}
			if f != nil {
				f.Flush()
			}
		}
		if err != nil {
			break
		}
	}
	rw.Close()
}

// headersDeclared reports whether every request header is one the proxy
// forwards for a, and the only encoding asked for is identity.
func (h *Holder) headersDeclared(a egress.Adapter, hdr http.Header) bool {
	ok := map[string]bool{"Content-Length": true, "Accept-Encoding": true, egress.LabelHeader: true}
	for _, k := range a.ForwardedRequestHeaders() {
		ok[http.CanonicalHeaderKey(k)] = true
	}
	for k, vs := range hdr {
		if !ok[http.CanonicalHeaderKey(k)] {
			return false
		}
		if http.CanonicalHeaderKey(k) == "Accept-Encoding" {
			for _, v := range vs {
				if strings.TrimSpace(v) != "identity" {
					return false
				}
			}
		}
	}
	return true
}

// hand serves the hand socket: GET /state says whether a secret is held,
// PUT /secret hands one, DELETE /secret drops it. None reads it back.
func (h *Holder) hand() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state{Held: h.Held()})
	})
	mux.HandleFunc("PUT /secret", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxSecret+1))
		if err != nil || len(b) == 0 || len(b) > maxSecret {
			http.Error(w, "holder: bad secret", http.StatusBadRequest)
			return
		}
		h.Hand(b)
		for i := range b {
			b[i] = 0
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /secret", func(w http.ResponseWriter, r *http.Request) {
		h.Drop()
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

type state struct {
	Held bool `json:"held"`
}

// Serve serves the request socket on reqs and the hand socket on hand
// until either listener fails; it closes both and returns the first error.
func (h *Holder) Serve(reqs, hand net.Listener) error {
	errs := make(chan error, 2)
	var servers []*http.Server
	for _, hd := range []http.Handler{h, h.hand()} {
		servers = append(servers, &http.Server{Handler: hd, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10, IdleTimeout: 2 * time.Minute})
	}
	go func() { errs <- servers[0].Serve(reqs) }()
	go func() { errs <- servers[1].Serve(hand) }()
	err := <-errs
	// Close the open connections too: a stopped holder answers nobody.
	for _, s := range servers {
		s.Close()
	}
	<-errs
	return err
}

// Listen opens a unix socket at path that admits only peer uid; every
// other connection is closed unread. A stale socket file is replaced.
func Listen(path string, uid int) (net.Listener, error) { return sockets.ListenPeers(path, uid) }

func unixTransport(socket string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		DisableCompression:    true,
		ResponseHeaderTimeout: 10 * time.Minute,
		IdleConnTimeout:       90 * time.Second,
	}
}

// Client is egress's transport to the holder at socket. It sends the
// request as is, to the holder rather than the provider, and turns the
// holder's own refusals back into errors: a refused destination wraps
// netguard.ErrDenied, so egress journals it as it does its own dials.
func Client(socket string) http.RoundTripper { return &client{rt: unixTransport(socket)} }

type client struct{ rt http.RoundTripper }

func (c *client) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	u := *r.URL
	u.Scheme = "http"
	r.URL = &u
	if r.Host == "" {
		r.Host = u.Host
	}
	r.Header.Set("Accept-Encoding", "identity")
	resp, err := c.rt.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	switch why := resp.Header.Get(ErrorHeader); why {
	case "":
		return resp, nil
	case ErrDenied:
		resp.Body.Close()
		return nil, fmt.Errorf("holder: %w", netguard.ErrDenied)
	default:
		resp.Body.Close()
		return nil, fmt.Errorf("holder: %s", why)
	}
}

// Keeper runs in the unlock step: it hands a holder its secret, and hands
// it again whenever the holder says it holds none (a restart) or the
// secret's version has moved since its last hand (a rotated key).
type Keeper struct {
	// Socket is the holder's hand socket.
	Socket string
	// Secret returns the secret to hand; it is called only when the
	// holder is empty or the version moved. The keeper zeroes what it
	// returns after the hand.
	Secret func() ([]byte, error)
	// Version, when set, names the secret Secret returns now; the keeper
	// hands again when it differs from the one it last handed.
	Version func() uint64
	// Every is how often Run checks; zero means every 2 seconds.
	Every time.Duration

	once sync.Once
	c    *http.Client

	mu     sync.Mutex
	handed bool
	ver    uint64
}

func (k *Keeper) client() *http.Client {
	k.once.Do(func() {
		t := unixTransport(k.Socket)
		// Each round dials afresh, so it reaches the holder serving now.
		t.DisableKeepAlives = true
		k.c = &http.Client{Transport: t, Timeout: 10 * time.Second}
	})
	return k.c
}

// Check runs one round: it asks the holder whether it holds a secret and
// hands one if not. handed reports whether it did.
func (k *Keeper) Check(ctx context.Context) (handed bool, err error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://localhost/state", nil)
	resp, err := k.client().Do(req)
	if err != nil {
		return false, err
	}
	var st state
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<10)).Decode(&st)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("holder: state: status %d: %v", resp.StatusCode, err)
	}
	var ver uint64
	if k.Version != nil {
		ver = k.Version()
	}
	k.mu.Lock()
	current := k.handed && k.ver == ver
	k.mu.Unlock()
	if st.Held && (k.Version == nil || current) {
		return false, nil
	}
	s, err := k.Secret()
	if err != nil {
		return false, err
	}
	defer func() {
		for i := range s {
			s[i] = 0
		}
	}()
	req, _ = http.NewRequestWithContext(ctx, "PUT", "http://localhost/secret", bytes.NewReader(s))
	resp, err = k.client().Do(req)
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return false, fmt.Errorf("holder: hand: status %d", resp.StatusCode)
	}
	k.mu.Lock()
	k.handed, k.ver = true, ver
	k.mu.Unlock()
	return true, nil
}

// Drop takes the holder's secret back, as the unlock step does when it
// locks. The keeper hands again on its next round.
func (k *Keeper) Drop(ctx context.Context) error {
	k.mu.Lock()
	k.handed = false
	k.mu.Unlock()
	req, _ := http.NewRequestWithContext(ctx, "DELETE", "http://localhost/secret", nil)
	resp, err := k.client().Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("holder: drop: status %d", resp.StatusCode)
	}
	return nil
}

// Run checks every k.Every until ctx ends. A failed round (the holder is
// down) is retried on the next tick. A round in flight when ctx ends runs
// to its answer, so once Run returns no hand of its is still on the way.
func (k *Keeper) Run(ctx context.Context) {
	every := k.Every
	if every <= 0 {
		every = 2 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		k.Check(context.WithoutCancel(ctx))
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
