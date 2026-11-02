// Package page is the enforcer's own HTTPS origin (SPEC NET-4, NET-6;
// briefs/ENF.md slice b): the confirm screen that renders a proposed change
// from the policy itself, issues a passkey challenge per rendered diff and
// checks the assertion, lists pending loosenings with cancel, shows whether
// the passkey is synced, resumes a paused channel, and shows NET-1's limits
// and each device's label from the signed policy.
//
// It answers only the Owner network and the wired admin port: it binds
// only their addresses and also drops any connection or request from
// another source, unanswered. Every response refuses framing, and every
// state-changing request must come from the page's own origin with the
// anti-forgery token one of its screens drew (csrf.go), checked in one
// place before any route sees it.
//
// It also serves slice s's asserted actions (package action): every
// turn-on or open of a safety-list device, unlock or disarm, camera off or
// alarm arm, each on a once-only challenge naming the device, the action
// and a short window.
//
// It also takes a safety-list device's sealed secret with the add-device
// change that names it (slice r, decision 10) and hands it to the
// enforcer's store through Secrets, which can only admit, never read.
//
// It also serves the enrolment and recovery screens (slice c, package
// enrol): the first passkey by the case code, a replacement by the
// recovery code after its wait, a factory reset, and the new passkey's
// keeping of the policy. Until a passkey is enrolled, or once the one it
// was built for is no longer in force, it serves only those screens.
//
// It is enforcer code: it imports the standard library, broker/kernel/key,
// broker/enforcer/policy, broker/enforcer/action, broker/enforcer/pairseal,
// broker/enforcer/enrol and rsc.io/qr only (broker/daemon/arc2_test.go).
// Its assumptions are in ASSUMPTIONS.md.
package page

import (
	"crypto/tls"
	"embed"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/action"
	"github.com/ghbmrk/agentos/broker/enforcer/enrol"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Policy is the part of policy.Engine the page drives. The page holds
// Config.Lock around every call.
type Policy interface {
	Current() policy.Document
	Pending() []policy.Pending
	Propose(next policy.Proposal, sig []byte, nowMS int64) (policy.Outcome, error)
	Cancel(id string) error
}

// Secrets is the part of the enforcer's device-secret store
// (devsecret.Store) the page drives: it admits a sealed secret with the
// owner's approval of the add-device change that names it, and prunes
// secrets whose change was cancelled. It has no method that returns a
// secret, so the page reads none (STO-4). The page holds Config.Lock
// around every call.
type Secrets interface {
	Admit(device string, sealed []byte, prop policy.Proposal, sig []byte) error
	Prune() error
}

// Channel is the enforcer channel's pause, which only the page lifts (NET-2
// Channel, NET-6; slice d implements it).
type Channel interface {
	Paused() bool
	Resume() error
}

// Config is what the daemon (slice l) wires in.
type Config struct {
	// Name is the enforcer's own local name: the page's origin is
	// https://Name and the owner's passkey's RP ID is Name (NET-4).
	Name string
	// Owner is the enrolled owner's passkey, an ES256 credential on Name.
	// With Enrol set it is Enrol.Owner() when the daemon built the page,
	// and the zero key before any passkey is enrolled; the page takes a tap
	// only while it is still the one in force.
	Owner key.PublicKey
	// Enrol is the enforcer's enrolment state (slice c); nil serves no
	// enrolment screens.
	Enrol *enrol.Book
	// CA is the enforcer's root certificate (Cert.Root, DER) and CoreCA the
	// core's page authority (CH-9), served for the phone to install at
	// enrolment; nil serves none.
	CA, CoreCA []byte
	// Addrs are the enforcer's own addresses on the Owner network and the
	// wired admin port: the only ones the page listens on.
	Addrs []netip.AddrPort
	// Allow is the Owner network's and the admin port's prefixes: a
	// connection from anywhere else is closed unanswered.
	Allow  []netip.Prefix
	Policy Policy
	// Lock serialises the page's Policy calls with the daemon's other
	// callers (the channel's tightenings, the clock's Tick); nil means the
	// page's own lock.
	Lock    sync.Locker
	Channel Channel // nil until slice d is wired
	// Act carries out the owner's asserted actions on safety-list devices
	// (slice s); nil serves none. ActTimeout bounds each call, and so how
	// long a tap holds Lock: zero means action.Timeout, and more is refused.
	// Log takes one line for each act that may have run without the page
	// knowing (timed out, failed, panicked); it is required with Act.
	Act        action.Actuator
	ActTimeout time.Duration
	Log        func(string)
	// Zone is the owner's time zone, the enforcer's configured one: every
	// time the page shows is in it, never in UTC (NET-4).
	Zone *time.Location
	// Secrets takes safety-list devices' sealed secrets (slice r); nil
	// refuses every link that carries one.
	Secrets Secrets
	// Heard is, for a device's Wi-Fi identity, the mDNS names the
	// enforcer's relay heard the device prove its own on that VLAN
	// (mdns.HeardBy, D-266): the page pins them for a paired device a
	// link leaves pinning none, and refuses a link that pins a name not
	// among them. nil has heard nothing.
	Heard func(wifi string) [][]string
	Cert  tls.Certificate
	Now   func() time.Time // nil means time.Now
}

var (
	ErrConfig      = errors.New("page: bad config")
	errCrossOrigin = errors.New("cross-origin")
)

// Server is the page.
type Server struct {
	cfg   Config
	mu    sync.Mutex // the page's own state below
	chals map[string]*challenge
	links []int64 // recent proposal-link times, for the limit
	acts  []int64 // recent action-link times, for their own limit
	last  uint64  // the highest version the page has drawn a challenge for
	sync  syncState
	tmpl  *template.Template
	book  *action.Book // nil when Config.Act is
	// tokenKey keys the anti-forgery tokens (csrf.go); posts is every
	// state-changing route, which ServeHTTP reaches only past guard.
	tokenKey []byte
	posts    map[string]post
}

// post is a state-changing route. An enrol route is served whenever
// Config.Enrol is set, passkey in force or not; any other only while one
// is (live).
type post struct {
	h     http.HandlerFunc
	enrol bool
}

//go:embed templates static
var files embed.FS

// New checks cfg and returns the page.
func New(cfg Config) (*Server, error) {
	if !dnsName(cfg.Name) || cfg.Policy == nil {
		return nil, ErrConfig
	}
	if cfg.Owner.Valid() || cfg.Enrol == nil {
		if cfg.Owner.Alg() != key.AlgES256 {
			return nil, ErrConfig
		}
		if want, err := key.ES256(cfg.Name, cfg.Owner.Bytes()); err != nil || want != cfg.Owner {
			return nil, ErrConfig // the passkey must be bound to the enforcer's own name
		}
	}
	if len(cfg.Addrs) == 0 || len(cfg.Allow) == 0 || cfg.Zone == nil || (cfg.Act != nil && cfg.Log == nil) {
		return nil, ErrConfig
	}
	for _, a := range cfg.Addrs {
		if !a.IsValid() || a.Addr().IsUnspecified() || !allowed(cfg.Allow, a.Addr()) {
			return nil, ErrConfig // never every interface; only Owner and admin
		}
	}
	for _, p := range cfg.Allow {
		if !p.IsValid() || p.Bits() == 0 {
			return nil, ErrConfig
		}
	}
	if cfg.Lock == nil {
		cfg.Lock = &sync.Mutex{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{cfg: cfg, chals: map[string]*challenge{}}
	var err error
	if s.tokenKey, err = newTokenKey(); err != nil {
		return nil, err
	}
	t, err := template.New("").Funcs(funcs).Funcs(template.FuncMap{"when": s.when}).ParseFS(files, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s.tmpl = t
	if cfg.Act != nil && cfg.Owner.Valid() {
		if s.book, err = action.NewBook(cfg.Owner, cfg.Act, cfg.ActTimeout); err != nil {
			return nil, err
		}
	}
	s.posts = map[string]post{
		"/approve":   {h: s.approve},
		"/challenge": {h: s.challenge},
		"/act":       {h: s.act},
	}
	if s.book != nil {
		s.posts["/do"] = post{h: s.do}
	}
	if cfg.Enrol != nil {
		s.posts["/enrol/begin"] = post{h: s.enrolBegin, enrol: true}
		s.posts["/enrol/finish"] = post{h: s.enrolFinish, enrol: true}
		s.posts["/enrol/reset"] = post{h: s.enrolReset, enrol: true}
	}
	return s, nil
}

// dnsName is a DNS name: what the passkey's RP ID and the certificate
// name.
func dnsName(s string) bool {
	if s == "" || len(s) > 253 || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func allowed(allow []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Listen binds each of Config.Addrs and serves the page on them over TLS
// until one fails. It never binds an unspecified address (New refuses one).
func (s *Server) Listen() error {
	errs := make(chan error, len(s.cfg.Addrs))
	for _, a := range s.cfg.Addrs {
		ln, err := net.Listen("tcp", a.String())
		if err != nil {
			return err
		}
		go func() { errs <- s.Serve(ln) }()
	}
	return <-errs
}

// Serve serves the page on ln over TLS, dropping every connection whose
// source is outside Config.Allow before the handshake, so another segment
// gets no answer at all (NET-6).
func (s *Server) Serve(ln net.Listener) error {
	tl := tls.NewListener(&filter{Listener: ln, allow: s.cfg.Allow}, &tls.Config{
		Certificates: []tls.Certificate{s.cfg.Cert},
		MinVersion:   tls.VersionTLS13,
	})
	hs := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	return hs.Serve(tl)
}

// filter closes, unanswered, every accepted connection from outside allow.
type filter struct {
	net.Listener
	allow []netip.Prefix
}

func (f *filter) Accept() (net.Conn, error) {
	for {
		c, err := f.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil && allowed(f.allow, ap.Addr()) {
			return c, nil
		}
		c.Close()
	}
}

// ServeHTTP is the page. A request from outside Config.Allow, for another
// host name, or that would load the page into a frame is dropped with no
// answer; every answer carries the anti-framing headers.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !allowed(s.cfg.Allow, ap.Addr()) {
		panic(http.ErrAbortHandler) // closes the connection, no response
	}
	headers(w.Header())
	if host := strings.TrimSuffix(r.Host, ":443"); host != s.cfg.Name {
		http.Error(w, "wrong host", http.StatusMisdirectedRequest) // a rebound name
		return
	}
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "iframe", "frame", "embed", "object", "fencedframe":
		http.Error(w, "not in a frame", http.StatusForbidden)
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" &&
		!(r.Method == http.MethodGet && r.Header.Get("Sec-Fetch-Mode") == "navigate") {
		http.Error(w, "cross-origin", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		if err := s.guard(r); err != nil {
			fail(w, http.StatusForbidden, err)
			return
		}
		p, ok := s.posts[r.URL.Path]
		switch {
		case !ok || r.Method != http.MethodPost:
			http.NotFound(w, r)
		case !p.enrol && !s.live():
			fail(w, http.StatusForbidden, errEnrolFirst)
		default:
			p.h(w, r)
		}
		return
	}
	if s.cfg.Enrol != nil && s.enrolRoute(w, r) {
		return
	}
	if !s.live() {
		if r.Method == http.MethodGet && r.URL.Path == "/" && s.cfg.Enrol != nil {
			http.Redirect(w, r, "/enrol", http.StatusSeeOther)
		} else if r.Method == http.MethodGet && (r.URL.Path == "/page.js" || r.URL.Path == "/page.css") {
			s.static(w, r)
		} else {
			http.Error(w, errEnrolFirst.Error(), http.StatusForbidden)
		}
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/":
		s.home(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/p":
		s.confirm(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/a" && s.book != nil:
		s.action(w, r)
	case r.Method == http.MethodGet && (r.URL.Path == "/page.js" || r.URL.Path == "/page.css"):
		s.static(w, r)
	default:
		http.NotFound(w, r)
	}
}

// enrolRoute serves the enrolment screens' GETs, whether or not a passkey is in
// force, and reports whether r was one of them.
func (s *Server) enrolRoute(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/enrol":
		s.enrolScreen(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/enrol/enforcer.crt":
		s.certificate(w, s.cfg.CA)
	case r.Method == http.MethodGet && r.URL.Path == "/enrol/core.crt":
		s.certificate(w, s.cfg.CoreCA)
	default:
		return false
	}
	return true
}

// headers refuse framing by any origin, agentOS's included (NET-4), and
// keep the page's answers out of caches and other origins.
func headers(h http.Header) {
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
}

// sameOrigin is a state-changing request sent by the page itself: its
// Origin is exactly https://Name, the browser does not call it cross-site,
// and its body is JSON, which no form or no-cors request can send.
func (s *Server) sameOrigin(r *http.Request) bool {
	if r.Header.Get("Origin") != "https://"+s.cfg.Name {
		return false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	ct := r.Header.Get("Content-Type")
	return ct == "application/json" || strings.HasPrefix(ct, "application/json;")
}

func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	b, err := files.ReadFile("static" + r.URL.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, ".js") {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	w.Write(b)
}

func (s *Server) nowMS() int64 { return s.cfg.Now().UnixMilli() }
