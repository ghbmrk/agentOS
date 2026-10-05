// Package localui is the box's local web UI (SPEC §6.2, PLAN P2-2), served
// only on the box's own Wi-Fi access point (CH-7, CH-9). It carries setup
// (§8.1, ONB-3 to ONB-8), the status page, sign-in and local unlock, STOP
// and RESUME, and a mount point for the pages later packages add behind
// sign-in (CH-8: live browser view, diffs and files, rules).
//
// Wi-Fi membership is not authority: without sign-in only the setup (while
// setup is unfinished), unlock and status pages answer. Sign-in takes a
// code-generator code or the asked grid cell and is remembered on that
// device for the CH-3 unlock period. Pages carry no script and fetch
// nothing from outside the box (ONB-1).
package localui

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/owner"
)

// Owner is the owner channel as the local UI uses it (*owner.Channel).
type Owner interface {
	LocalStatus() owner.LocalStatus
	LocalGridCell() string
	LocalSignIn(code string) (time.Time, error)
	LocalStop(ctx context.Context) error
	LocalResume() (string, error)
	// UnlockPeriod is CH-14's N: how long a sign-in is remembered.
	UnlockPeriod() time.Duration
}

// Config configures a Server.
type Config struct {
	// AP is the access point the UI is served on. Its address is the only
	// host name the UI answers to, and only its subnet may connect.
	AP APConfig
	// Port is UIPort when zero.
	Port int
	// Hooks connect setup to the rest of the box.
	Hooks Hooks
	// SetupSecret is the Owner Card's setup secret; its setup code pairs
	// the owner's number as the typing fallback (ONB-6).
	SetupSecret string
	// Store keeps setup progress across restarts.
	Store SetupStore
	// Defaults is the one line of stated defaults shown during setup
	// (§8.1 step 5).
	Defaults string
	// Vault, when set, is the vault process's unlock socket
	// (NewUnlockClient); the unknown-host vault unlock page (CRED-8,
	// P2-4e) is then served at /unlock/vault, open without sign-in like
	// /unlock.
	Vault Vault
	Now   func() time.Time
	Rand  io.Reader
}

// Server is the local UI.
type Server struct {
	cfg  Config
	host string
	mux  *http.ServeMux
	// pages carry this box's address in their footer.
	pages *template.Template

	mu       sync.Mutex
	owner    Owner
	sessions map[string]session // by SHA-256 of the cookie token
	mounts   []mount
	setup    *setup
	// vaultPend is the pending vault unlock this UI started, bound to the
	// phone that sent the passphrase.
	vaultPend *vaultPending
	// vaultKept: the last unlock kept this PC trusted.
	vaultKept bool
	// scanning admits one photo upload at a time.
	scanning chan struct{}
	// vaultTries and vaultAll are the unlock attempts in the last hour,
	// per phone address and in all (vaultTry).
	vaultTries map[string][]time.Time
	vaultAll   []time.Time
}

type mount struct{ Path, Title string }

// MaxSessions bounds remembered devices; the oldest is forgotten first.
const MaxSessions = 16

const cookieName = "agentos_session"

// New returns a Server. It refuses an access point configuration that
// could expose the UI beyond the box's Wi-Fi (CH-9).
func New(cfg Config) (*Server, error) {
	if err := cfg.AP.Validate(); err != nil {
		return nil, err
	}
	if cfg.Hooks == nil || cfg.Store == nil {
		return nil, errors.New("localui: hooks and store are required")
	}
	if cfg.Port == 0 {
		cfg.Port = UIPort
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	host := cfg.AP.Addr.Addr().String()
	if cfg.Port != 80 {
		host = net.JoinHostPort(host, strconv.Itoa(cfg.Port))
	}
	s := &Server{cfg: cfg, host: host, mux: http.NewServeMux(), sessions: map[string]session{}, pages: pagesFor(host), scanning: make(chan struct{}, 1)}
	st, err := cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	s.setup = newSetup(s, st)
	s.setup.adopt()
	s.routes()
	return s, nil
}

// SetOwner attaches the owner channel once setup has made one.
func (s *Server) SetOwner(o Owner) {
	s.mu.Lock()
	s.owner = o
	s.mu.Unlock()
}

func (s *Server) getOwner() Owner {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.owner
}

// Mount serves h at path (and below it) for signed-in devices only (CH-7,
// CH-8). title names it on the home page.
func (s *Server) Mount(path, title string, h http.Handler) {
	path = "/" + strings.Trim(path, "/") + "/"
	s.mu.Lock()
	s.mounts = append(s.mounts, mount{path, title})
	s.mu.Unlock()
	s.mux.Handle(path, s.signedIn(http.StripPrefix(strings.TrimSuffix(path, "/"), h)))
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.root)
	s.mux.HandleFunc("/status", s.status)
	s.mux.HandleFunc("/unlock", s.unlock)
	s.mux.HandleFunc("/stop", s.post(s.stop))
	s.mux.HandleFunc("/resume", s.post(s.resume))
	s.mux.HandleFunc("/signout", s.post(s.signout))
	s.mux.Handle("/home", s.signedIn(http.HandlerFunc(s.home)))
	s.mux.HandleFunc("/box.vcf", s.contact)
	if s.cfg.Vault != nil {
		s.mux.HandleFunc("/unlock/vault", s.vaultUnlock)
	}
	s.setup.routes(s.mux)
}

// pageCSP allows no script, no framing and no outside source (L6). The
// vault page adds one hashed script (vaultCSP).
const pageCSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// ServeHTTP applies the CH-9 and CH-7 guards to every request, then routes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CH-9: only clients on the access point's subnet. The listener is
	// already bound to the access point interface; this is the second
	// check.
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !s.cfg.AP.Addr.Masked().Contains(ap.Addr().Unmap()) || ap.Addr().Unmap() == s.cfg.AP.Addr.Addr() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", pageCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	// Any other host name is a phone's captive-portal check, or a page
	// trying to reach the box through DNS rebinding: send it to the box's
	// own address, and never act on it (ONB-5).
	if r.Host != s.host {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		http.Redirect(w, r, "http://"+s.host+"/", http.StatusFound)
		return
	}
	if r.Method == http.MethodPost && !s.sameOrigin(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	s.mux.ServeHTTP(w, r)
}

// sameOrigin refuses cross-site form posts. Cookies are SameSite=Strict
// too; this also covers the open forms (STOP, setup).
func (s *Server) sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && o != "http://"+s.host {
		return false
	}
	return true
}

func (s *Server) post(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		f(w, r)
	}
}

// signedIn admits only remembered devices; others go to sign-in.
func (s *Server) signedIn(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.isSignedIn(r) {
			http.Redirect(w, r, "/unlock?next="+safeNext(r.URL.Path), http.StatusSeeOther)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) isSignedIn(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	k := tokenKey(c.Value)
	now := s.cfg.Now()
	// A device is signed out when the session locks (wrong codes, an
	// unknown-host boot), even if a later unlock by text follows: its
	// sign-in must come after the last lock.
	var locks uint64
	o := s.getOwner()
	if o != nil {
		locks = o.LocalStatus().Locks
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ss, ok := s.sessions[k]
	if ok && (!now.Before(ss.exp) || (o != nil && ss.locks != locks)) {
		delete(s.sessions, k)
		ok = false
	}
	return ok
}

// session is a signed-in device: until when, and the owner channel's lock
// count when it signed in.
type session struct {
	exp   time.Time
	locks uint64
}

// remember signs the device in until until (CH-7: the CH-3 unlock period),
// under lock count locks.
func (s *Server) remember(w http.ResponseWriter, until time.Time, locks uint64) error {
	b := make([]byte, 32)
	if _, err := io.ReadFull(s.cfg.Rand, b); err != nil {
		return err
	}
	tok := hex.EncodeToString(b)
	now := s.cfg.Now()
	s.mu.Lock()
	for k, ss := range s.sessions {
		if !now.Before(ss.exp) {
			delete(s.sessions, k)
		}
	}
	for len(s.sessions) >= MaxSessions {
		keys := make([]string, 0, len(s.sessions))
		for k := range s.sessions {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return s.sessions[keys[i]].exp.Before(s.sessions[keys[j]].exp) })
		delete(s.sessions, keys[0])
	}
	s.sessions[tokenKey(tok)] = session{exp: until, locks: locks}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", Expires: until,
		MaxAge: int(until.Sub(now) / time.Second), HttpOnly: true, SameSite: http.SameSiteStrictMode})
	return nil
}

func tokenKey(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// safeNext keeps a post-sign-in redirect on this box.
func safeNext(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n?#") {
		return "/home"
	}
	return p
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !s.setup.done() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if s.isSignedIn(r) {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}

type statusView struct {
	Progress Progress
	HasOwner bool
	Owner    owner.LocalStatus
	SignedIn bool
	Done     bool
	Msg      string
	// Refresh reloads the page while the box is starting (ONB-4).
	Refresh string
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) { s.statusPage(w, r, msgText(r)) }

func (s *Server) statusPage(w http.ResponseWriter, r *http.Request, msg string) {
	v := statusView{Progress: s.cfg.Hooks.Progress(), SignedIn: s.isSignedIn(r), Done: s.setup.done(), Msg: msg}
	if v.Progress.Phase != "ready" {
		v.Refresh = "10"
	}
	if o := s.getOwner(); o != nil {
		v.HasOwner, v.Owner = true, o.LocalStatus()
	}
	s.render(w, "status", v)
}

type unlockView struct {
	HasOwner   bool
	Challenged bool
	Cell       string
	Next       string
	Err        string
	Vault      bool
	Days       int
}

func (s *Server) unlock(w http.ResponseWriter, r *http.Request) {
	o := s.getOwner()
	v := unlockView{HasOwner: o != nil, Next: safeNext(r.FormValue("next")), Vault: s.cfg.Vault != nil}
	if o != nil {
		v.Days = int(o.UnlockPeriod() / (24 * time.Hour))
	}
	if r.Method == http.MethodPost {
		if !s.sameOrigin(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if o != nil {
			if err := s.signIn(w, o, r.PostFormValue("code")); err != nil {
				v.Err = err.Error()
			} else {
				http.Redirect(w, r, v.Next, http.StatusSeeOther)
				return
			}
		}
	}
	if o != nil {
		v.Challenged = o.LocalStatus().Challenged
		v.Cell = o.LocalGridCell()
	}
	s.render(w, "unlock", v)
}

// signIn checks a code with the owner channel; on success the device is
// remembered. The returned error is owner-facing text.
func (s *Server) signIn(w http.ResponseWriter, o Owner, code string) error {
	code = strings.TrimSpace(code)
	if strings.HasPrefix(code, owner.UnlockProofPrefix) {
		// Typed codes are never the vault unlock's sign-in proof, which
		// only vaultCode presents (proofSignIn).
		return errors.New("That code did not work. Each code works once; wait for the next one.")
	}
	return s.checkSignIn(w, o, code)
}

// proofSignIn signs in the phone that just unlocked the box, with the
// vault process's one-time proof for that unlock (P2-4f).
func (s *Server) proofSignIn(w http.ResponseWriter, o Owner, ticket string) error {
	return s.checkSignIn(w, o, owner.UnlockProofPrefix+ticket)
}

func (s *Server) checkSignIn(w http.ResponseWriter, o Owner, code string) error {
	// The lock count is read first, so a lock racing the sign-in can only
	// sign the device out, never leave it signed in.
	locks := o.LocalStatus().Locks
	until, err := o.LocalSignIn(code)
	switch {
	case errors.Is(err, owner.ErrTooMany):
		return errors.New("Too many tries on the box's Wi-Fi in the last day, so sign-in here is paused for up to 24 hours. Your phone still works: text a code to the box.")
	case errors.Is(err, owner.ErrWrongCode):
		return errors.New("That code did not work. Each code works once; wait for the next one.")
	case err != nil:
		return errors.New("Could not check the code. Try again.")
	}
	if err := s.remember(w, until, locks); err != nil {
		return errors.New("Could not remember this device. Try again.")
	}
	return nil
}

func (s *Server) stop(w http.ResponseWriter, r *http.Request) {
	o := s.getOwner()
	if o == nil {
		http.Redirect(w, r, "/status", http.StatusSeeOther)
		return
	}
	msg := "stopped"
	if err := o.LocalStop(r.Context()); err != nil {
		msg = "stopfailed"
	}
	http.Redirect(w, r, "/status?m="+msg, http.StatusSeeOther)
}

// resume is RESUME on the local UI (P1-5 carry-forward): for a signed-in
// device, or with a code that signs this device in first.
func (s *Server) resume(w http.ResponseWriter, r *http.Request) {
	o := s.getOwner()
	if o == nil {
		http.Redirect(w, r, "/status", http.StatusSeeOther)
		return
	}
	if !s.isSignedIn(r) {
		if err := s.signIn(w, o, r.PostFormValue("code")); err != nil {
			s.render(w, "unlock", unlockView{HasOwner: true, Next: "/status", Err: err.Error(), Cell: o.LocalGridCell(),
				Days:       int(o.UnlockPeriod() / (24 * time.Hour)),
				Challenged: o.LocalStatus().Challenged, Vault: s.cfg.Vault != nil})
			return
		}
	}
	text, err := o.LocalResume()
	if err != nil {
		http.Redirect(w, r, "/status?m=resumefailed", http.StatusSeeOther)
		return
	}
	// The owner channel's text names each held action's new time and UNDO
	// ID (CH-16), so the page shows it rather than a fixed line (L3 on #76).
	s.statusPage(w, r, text)
}

func (s *Server) signout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, tokenKey(c.Value))
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	ms := append([]mount(nil), s.mounts...)
	s.mu.Unlock()
	s.render(w, "home", ms)
}

// contact serves the box's number as a contact card (§8.1 step 5).
func (s *Server) contact(w http.ResponseWriter, r *http.Request) {
	n := s.cfg.Hooks.BoxNumber()
	if !phoneRe.MatchString(n) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/vcard; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="AgentOS.vcf"`)
	io.WriteString(w, "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:AgentOS\r\nTEL;TYPE=CELL:"+n+"\r\nURL:http://"+s.host+"/\r\nEND:VCARD\r\n")
}

var msgs = map[string]string{
	"stopped":      "Stopped. Nothing new starts until you resume.",
	"stopfailed":   "STOP failed to record. Nothing new starts now; press STOP again.",
	"resumefailed": "RESUME failed to record. Still stopped.",
}

func msgText(r *http.Request) string { return msgs[r.URL.Query().Get("m")] }
