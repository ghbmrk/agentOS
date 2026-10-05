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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner"
)

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
	// SecondLine, when set, is the second line's routes on the same
	// socket (egress K13); its page is served at /second-line/ behind
	// sign-in (ADP-12, P2-3c). It needs Vault.
	SecondLine SecondLine
	Now        func() time.Time
	Rand       io.Reader
}

// Server is the local UI.
type Server struct {
	cfg  Config
	host string
	mux  *http.ServeMux
	// pages carry this box's address in their footer.
	pages *template.Template
	// formKey binds Approvals forms to a phone and a request; pageWrong
	// lists each phone's recent wrong approval codes (PageWrongPerMinute),
	// and its tries in flight: each holds a slot until known not to be
	// wrong, so a right code sent while the phone has 4 wrong ones and
	// another try in flight is refused too (L3 nit on #171).
	formKey   []byte
	pageWrong map[string][]time.Time

	mu     sync.Mutex
	owner  Owner
	mounts []mount
	setup  *setup
	// vaultPend is the pending vault unlock this UI started, bound to the
	// phone that sent the passphrase.
	vaultPend *vaultPending
	// vaultKept: the last unlock kept this PC trusted.
	vaultKept bool
	// vaultOpener is the cookie key of the phone that confirmed the last
	// unlock: only it, or a signed-in phone, is told the passphrase change
	// did not finish (M1 on #93).
	vaultOpener string
	// scanning admits one photo upload at a time.
	scanning chan struct{}
	// vaultTries and vaultAll are the unlock attempts in the last hour,
	// per phone address and in all (vaultTry).
	vaultTries map[string][]time.Time
	vaultAll   []time.Time
}

type mount struct{ Path, Title string }

// MaxSessions bounds remembered devices, as agentosd does
// (localsrv.MaxSessions).
const MaxSessions = 16

const cookieName = "agentos_session"

// New returns a Server. It refuses an access point configuration that
// could expose the UI beyond the box's Wi-Fi (CH-9).
func New(cfg Config) (*Server, error) {
	validate := cfg.AP.Validate
	if cfg.Hooks == nil {
		validate = cfg.AP.ValidateServe
	}
	if err := validate(); err != nil {
		return nil, err
	}
	if (cfg.Hooks == nil) != (cfg.Store == nil) {
		return nil, errors.New("localui: hooks and store go together")
	}
	if cfg.SecondLine != nil && cfg.Vault == nil {
		return nil, errors.New("localui: the second line needs the vault socket")
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
	s := &Server{cfg: cfg, host: host, mux: http.NewServeMux(), pages: pagesFor(host), scanning: make(chan struct{}, 1)}
	s.formKey = make([]byte, 32)
	if _, err := io.ReadFull(cfg.Rand, s.formKey); err != nil {
		return nil, err
	}
	if cfg.Hooks != nil {
		st, err := cfg.Store.Load()
		if err != nil {
			return nil, err
		}
		s.setup = newSetup(s, st)
		s.setup.adopt()
	}
	s.routes()
	return s, nil
}

// SetOwner attaches agentosd's localui.sock once setup has made the owner
// channel.
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
	s.Mount("/approvals", "Approvals", http.HandlerFunc(s.approvals))
	if s.cfg.SecondLine != nil {
		s.Mount("/second-line", "Second line", http.HandlerFunc(s.secondLine))
	}
	if s.setup != nil {
		s.setup.routes(s.mux)
	} else {
		// No setup hooks (agentos-localui until setup moves into agentosd,
		// Security L6 on the P2-2w plan): every setup route is refused.
		s.mux.HandleFunc("/setup", s.notReady)
		s.mux.HandleFunc("/setup/", s.notReady)
	}
}

// notReady is the fixed page for a box this page cannot set up.
func (s *Server) notReady(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusServiceUnavailable)
	s.render(w, "notready", nil)
}

// setupDone says setup is done. Without setup hooks it is done when
// agentosd answers: the page then has an owner channel to serve.
func (s *Server) setupDone(r *http.Request) bool {
	if s.setup == nil {
		_, ok := s.ownerStatus(r.Context())
		return ok
	}
	return s.setup.done()
}

// progress is the box's boot progress (ONB-4); without setup hooks it is
// ready once agentosd answers.
func (s *Server) progress(r *http.Request) Progress {
	if s.cfg.Hooks != nil {
		return s.cfg.Hooks.Progress()
	}
	if _, ok := s.ownerStatus(r.Context()); ok {
		return Progress{Phase: "ready", Updated: true, Online: true}
	}
	return Progress{Phase: "booting"}
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
	tok := cookieToken(r)
	if tok == "" {
		return false
	}
	// agentosd decides: it ends a session at its time, on sign-out and on
	// a session lock (wrong codes, an unknown-host boot), even if a later
	// unlock by text follows.
	var ses localapi.Session
	return s.call(r.Context(), localapi.OpSession, localapi.Auth{Token: tok}, &ses) == nil
}

// cookieToken is the phone's session token, "" if it has none of the
// form agentosd mints.
func cookieToken(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil || len(c.Value) != 2*localapi.TokenBytes {
		return ""
	}
	return c.Value
}

// remember sets the phone's cookie to the session agentosd minted.
func (s *Server) remember(w http.ResponseWriter, ses localapi.Session) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: ses.Token, Path: "/", Expires: ses.Until,
		MaxAge: int(ses.Until.Sub(s.cfg.Now()) / time.Second), HttpOnly: true, SameSite: http.SameSiteStrictMode})
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
	if !s.setupDone(r) {
		if s.setup == nil {
			s.notReady(w, r)
			return
		}
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
	Owner    localapi.Status
	SignedIn bool
	Done     bool
	Msg      string
	// Refresh reloads the page while the box is starting (ONB-4).
	Refresh string
	// AskCode: the RESUME form asks a signed-in phone for a code, as
	// agentosd needs one for an old sign-in.
	AskCode bool
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) { s.statusPage(w, r, msgText(r)) }

func (s *Server) statusPage(w http.ResponseWriter, r *http.Request, msg string) {
	s.statusPageWith(w, r, msg, false)
}

func (s *Server) statusPageWith(w http.ResponseWriter, r *http.Request, msg string, askCode bool) {
	v := statusView{Progress: s.progress(r), SignedIn: s.isSignedIn(r), Done: s.setupDone(r), Msg: msg, AskCode: askCode}
	if v.Progress.Phase != "ready" {
		v.Refresh = "10"
	}
	v.Owner, v.HasOwner = s.ownerStatus(r.Context())
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
	v := unlockView{Next: safeNext(r.FormValue("next")), Vault: s.cfg.Vault != nil}
	if r.Method == http.MethodPost {
		if !s.sameOrigin(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if s.getOwner() != nil {
			if _, err := s.signIn(w, r, r.PostFormValue("code")); err != nil {
				v.Err = err.Error()
			} else {
				http.Redirect(w, r, v.Next, http.StatusSeeOther)
				return
			}
		}
	}
	s.renderUnlock(w, r, v)
}

// renderUnlock fills the sign-in page's challenge from agentosd.
func (s *Server) renderUnlock(w http.ResponseWriter, r *http.Request, v unlockView) {
	if st, ok := s.ownerStatus(r.Context()); ok {
		v.HasOwner, v.Challenged, v.Days = true, st.Challenged, st.UnlockDays
		var cell localapi.Text
		if s.call(r.Context(), localapi.OpGridCell, struct{}{}, &cell) == nil {
			v.Cell = cell.Text
		}
	}
	s.render(w, "unlock", v)
}

// signIn checks a code with agentosd; on success the phone gets the
// session it minted. The returned error is owner-facing text.
func (s *Server) signIn(w http.ResponseWriter, r *http.Request, code string) (string, error) {
	code = strings.TrimSpace(code)
	if strings.HasPrefix(code, owner.UnlockProofPrefix) {
		// Typed codes are never the vault unlock's sign-in proof, which
		// only vaultCode presents (proofSignIn).
		return "", errors.New(wrongCodeText)
	}
	return s.checkSignIn(w, r, code)
}

// proofSignIn signs in the phone that just unlocked the box, with the
// vault process's one-time proof for that unlock (P2-4f).
func (s *Server) proofSignIn(w http.ResponseWriter, r *http.Request, ticket string) error {
	_, err := s.checkSignIn(w, r, owner.UnlockProofPrefix+ticket)
	return err
}

const (
	wrongCodeText = "That code did not work. Each code works once; wait for the next one."
	limitedText   = "Too many wrong codes were tried on this Wi-Fi. Wait a minute, then try again."
)

// checkSignIn returns the new session's token.
func (s *Server) checkSignIn(w http.ResponseWriter, r *http.Request, code string) (string, error) {
	if code == "" || len(code) > localapi.MaxCode {
		return "", errors.New(wrongCodeText)
	}
	var ses localapi.Session
	err := s.call(r.Context(), localapi.OpSignIn, localapi.SignIn{Code: code}, &ses)
	switch {
	case refused(err, localapi.RefusedTooMany):
		return "", errors.New("Too many tries on the box's Wi-Fi in the last day, so sign-in here is paused for up to 24 hours. Your phone still works: text a code to the box.")
	case refused(err, localapi.RefusedWrongCode):
		return "", errors.New(wrongCodeText)
	case refused(err, localapi.ErrLimited):
		return "", errors.New(limitedText)
	case err != nil:
		return "", errors.New("Could not check the code. Try again.")
	}
	s.remember(w, ses)
	return ses.Token, nil
}

func (s *Server) stop(w http.ResponseWriter, r *http.Request) {
	if s.getOwner() == nil {
		http.Redirect(w, r, "/status", http.StatusSeeOther)
		return
	}
	msg := "stopped"
	if err := s.call(r.Context(), localapi.OpStop, struct{}{}, nil); err != nil {
		msg = "stopfailed"
	}
	http.Redirect(w, r, "/status?m="+msg, http.StatusSeeOther)
}

// resume is RESUME on the local UI (P1-5 carry-forward): for a signed-in
// device, or with a code that signs this device in first. agentosd asks
// for a code once the sign-in is localapi.FreshFor old (Security S2 on
// P2-2w a); the form then asks for one, on the same page.
func (s *Server) resume(w http.ResponseWriter, r *http.Request) {
	if s.getOwner() == nil {
		http.Redirect(w, r, "/status", http.StatusSeeOther)
		return
	}
	code, tok := strings.TrimSpace(r.PostFormValue("code")), cookieToken(r)
	if !s.isSignedIn(r) {
		// The code signs this phone in, and the fresh sign-in resumes:
		// it is not spent twice.
		var err error
		if tok, err = s.signIn(w, r, code); err != nil {
			s.renderUnlock(w, r, unlockView{Next: "/status", Err: err.Error(), Vault: s.cfg.Vault != nil})
			return
		}
		code = ""
	}
	if strings.HasPrefix(code, owner.UnlockProofPrefix) || len(code) > localapi.MaxCode {
		s.statusPageResume(w, r, wrongCodeText)
		return
	}
	var a localapi.Answered
	err := s.call(r.Context(), localapi.OpResume, localapi.Resume{Token: tok, Code: code}, &a)
	switch {
	case refused(err, localapi.ErrLimited):
		s.statusPageResume(w, r, limitedText)
		return
	case err != nil:
		http.Redirect(w, r, "/status?m=resumefailed", http.StatusSeeOther)
		return
	}
	switch a.Refusal {
	case "":
	case localapi.RefusedCodeNeeded:
		s.statusPageResume(w, r, resumeCodeText)
		return
	case localapi.RefusedTooMany:
		s.statusPageResume(w, r, "Too many tries on the box's Wi-Fi in the last day, so resuming here is paused for up to 24 hours. Text RESUME to the box instead.")
		return
	default:
		s.statusPageResume(w, r, wrongCodeText)
		return
	}
	// The owner channel's text names each held action's new time and UNDO
	// ID (CH-16), so the page shows it rather than a fixed line (L3 on #76).
	s.statusPage(w, r, a.Text)
}

// resumeCodeText asks for a code when the sign-in is old (UX on S2).
const resumeCodeText = "To resume, enter a code from your code generator (not the one I texted)."

// statusPageResume shows the status page with the RESUME form asking for
// a code.
func (s *Server) statusPageResume(w http.ResponseWriter, r *http.Request, msg string) {
	s.statusPageWith(w, r, msg, true)
}

func (s *Server) signout(w http.ResponseWriter, r *http.Request) {
	if tok := cookieToken(r); tok != "" {
		_ = s.call(r.Context(), localapi.OpSignOut, localapi.Auth{Token: tok}, nil)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	ms := append([]mount(nil), s.mounts...)
	s.mu.Unlock()
	v := struct {
		Mounts  []mount
		Waiting int
	}{Mounts: ms}
	var rq localapi.Requests
	if s.call(r.Context(), localapi.OpRequests, localapi.Auth{Token: cookieToken(r)}, &rq) == nil {
		v.Waiting = len(rq.Requests)
	}
	s.render(w, "home", v)
}

// contact serves the box's number as a contact card (§8.1 step 5).
func (s *Server) contact(w http.ResponseWriter, r *http.Request) {
	n := ""
	if s.cfg.Hooks != nil {
		n = s.cfg.Hooks.BoxNumber()
	}
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
