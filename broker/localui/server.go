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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner"
)

// Config configures a Server.
type Config struct {
	// Page is where the page is served: port 1's interface and the page
	// name (CH-9, D-178). Plain HTTP answers that name or the address a
	// connection reached; only private home sources may connect.
	Page Page
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
	// Providers, when set, is the provider routes on the same socket
	// (#1266); the AI providers page is served at /providers/ behind
	// sign-in, where the owner changes a provider's private-data answer
	// after setup (CAP-9, CH-3). It needs Vault.
	Providers Providers
	// Accounts, when set, is the account clerks' sign-in (#2852); the
	// Connect step for each of Connect's declared accounts is then served
	// at /accounts/ behind sign-in (#2853, D-150). They go together.
	Accounts Accounts
	Connect  []ConnectDeclaration
	// Passkeys, when set with PasskeyRPID (the owner page's name, the
	// WebAuthn RP ID), serves the passkey page at /passkeys/ behind
	// sign-in (#2779a). They go together.
	Passkeys    Passkeys
	PasskeyRPID string
	// Backups, when set with Passkeys, serves the Backups page at
	// /backups/ behind sign-in (BAK-1, e4b): its add is a hardware key's
	// tap on the passkey page's name. When unset, Passkeys that also serve
	// the backup ops (AgentosdPasskeys, on the same socket) serve it.
	Backups Backups
	// Recovery, when set with Passkeys, serves the Recovery key page at
	// /recovery/ behind sign-in (REC-4, r4a): its tap is on the passkey
	// page's name. When unset, Passkeys that also serve the recovery ops
	// (AgentosdPasskeys) serve it.
	Recovery Recovery
	// RecoveryCard makes the Recovery key page's new card; card.Generate
	// when nil (tests wrap it).
	RecoveryCard func(io.Reader) (*card.Card, error)
	// PageAuthority is the page authority's certificate
	// (PageTLS.Authority): the Recovery key page's new card prints its
	// fingerprint (REC-4, HW-1), and without one it makes no card.
	PageAuthority func() []byte
	// Claim, when set, is the box's claim (HW-10): setup waits for the
	// claim code from the box's sticker at /claim, then continues only on
	// the phone that typed it.
	Claim BoxClaim
	// Card, when set, is the first-boot Owner Card step (HW-1,
	// firstboot.CardStep): after approval codes setup shows the card at
	// /setup/card to the phone that paired, and neither the recovery
	// step nor finish runs while Card.Hold() refuses. It needs Hooks.
	Card OwnerCard
	// CodesVoid, when set, is marked by the card step's vault answers
	// that void the code generator entry (F10, CardBox): setup then sends
	// the owner back to the codes step with a note to replace the entry.
	CodesVoid *CodesVoid
	// Rotation, when set, is the box's card rotation (REC-4): a waiting
	// rotation's new parts are shown at /rotate/card to a signed-in phone
	// until the owner confirms or cancels them.
	Rotation RotationCard
	// HTTPS: the HTTPS listener serves this Server too, so a request on
	// the plain listener for the page name (Page.PageName) is sent there
	// (#3153). Unset, the plain listener serves the page name itself.
	HTTPS bool
	// PageRestore: agentosd answered that the box's page authority is
	// missing on a claimed box; the status page says to restore it.
	PageRestore bool
	Now         func() time.Time
	Rand        io.Reader
}

// Server is the local UI.
type Server struct {
	cfg Config
	mux *http.ServeMux
	// pages carry the page's name in their footer.
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
	// plan is the owner's Set up and Later on the account plan.
	plan planChoices
	// vaultPend is the pending vault unlock this UI started, bound to the
	// phone that sent the passphrase.
	vaultPend *vaultPending
	// vaultKept: the last unlock kept this PC trusted.
	vaultKept bool
	// vaultOpener is the cookie key of the phone that confirmed the last
	// unlock: only it, or a signed-in phone, is told the passphrase change
	// did not finish (M1 on #93).
	vaultOpener string
	// recovery is the Recovery key page's one pending replacement.
	recovery recoveryState
	// scanning admits one photo upload at a time.
	scanning chan struct{}
	// claimWait holds a slot for each claim post running or waiting
	// (claimQueue + 1); claimRun admits one at a time (claimTurn).
	claimWait, claimRun chan struct{}
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

// New returns a Server. It refuses a page configuration that could expose
// the UI beyond port 1 (CH-9).
func New(cfg Config) (*Server, error) {
	if err := cfg.Page.Validate(); err != nil {
		return nil, err
	}
	if (cfg.Hooks == nil) != (cfg.Store == nil) {
		return nil, errors.New("localui: hooks and store go together")
	}
	if cfg.Card != nil && cfg.Hooks == nil {
		return nil, errors.New("localui: the Owner Card step needs setup hooks")
	}
	if cfg.SecondLine != nil && cfg.Vault == nil {
		return nil, errors.New("localui: the second line needs the vault socket")
	}
	if cfg.Providers != nil && cfg.Vault == nil {
		return nil, errors.New("localui: the providers page needs the vault socket")
	}
	if (cfg.Accounts == nil) != (len(cfg.Connect) == 0) {
		return nil, errors.New("localui: the accounts page needs its clerk and its declarations")
	}
	if (cfg.Passkeys == nil) != (cfg.PasskeyRPID == "") {
		return nil, errors.New("localui: the passkey page needs agentosd's passkey ops and the RP ID")
	}
	if b, ok := cfg.Passkeys.(Backups); ok && cfg.Backups == nil {
		cfg.Backups = b
	}
	if cfg.Backups != nil && cfg.Passkeys == nil {
		return nil, errors.New("localui: the Backups page needs the passkey page's name")
	}
	if rc, ok := cfg.Passkeys.(Recovery); ok && cfg.Recovery == nil {
		cfg.Recovery = rc
	}
	if cfg.Recovery != nil && cfg.Passkeys == nil {
		return nil, errors.New("localui: the Recovery key page needs the passkey page's name")
	}
	seen := map[string]bool{}
	for _, d := range cfg.Connect {
		if err := d.validate(); err != nil {
			return nil, err
		}
		if seen[d.ID] {
			return nil, errors.New("localui: two accounts share an ID")
		}
		seen[d.ID] = true
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
	s := &Server{cfg: cfg, mux: http.NewServeMux(), pages: pagesFor(cfg.Page.pageName()), scanning: make(chan struct{}, 1),
		claimWait: make(chan struct{}, claimQueue+1), claimRun: make(chan struct{}, 1)}
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
	s.mux.Handle("/line/sim", s.signedIn(s.post(s.adoptSIM)))
	s.mux.Handle("/plan/signin", s.signedIn(s.post(s.planSignIn)))
	s.mux.HandleFunc("/box.vcf", s.contact)
	if s.cfg.Vault != nil {
		s.mux.HandleFunc("/unlock/vault", s.vaultUnlock)
	}
	if s.cfg.Claim != nil {
		s.mux.HandleFunc("/claim", s.claimPage)
	}
	if s.cfg.Rotation != nil {
		s.mux.Handle("/rotate/card", s.signedIn(http.HandlerFunc(s.rotationCard)))
		if rot, ok := s.cfg.Rotation.(*Rotation); ok {
			s.Mount("/rotate", "Replace Owner Card parts", s.rotatePages(rot))
		}
	}
	s.Mount("/approvals", "Approvals", http.HandlerFunc(s.approvals))
	s.Mount("/follow", "Update source", http.HandlerFunc(s.follow))
	s.Mount("/paused", "Paused", http.HandlerFunc(s.paused))
	if s.cfg.SecondLine != nil {
		s.Mount("/second-line", "Second line", http.HandlerFunc(s.secondLine))
	}
	if s.cfg.Providers != nil {
		s.Mount("/providers", "AI providers", http.HandlerFunc(s.providers))
	}
	if s.cfg.Accounts != nil {
		s.Mount("/accounts", "Accounts", http.HandlerFunc(s.accountsPage))
		if _, ok := s.cfg.Accounts.(AccountPlan); ok {
			s.Mount("/account-plan", "Your accounts", http.HandlerFunc(s.accountPlanPage))
		}
	}
	if s.cfg.Passkeys != nil {
		s.Mount("/passkeys", "Passkeys", http.HandlerFunc(s.passkeysPage))
	}
	if s.cfg.Backups != nil {
		s.Mount("/backups", "Backups", http.HandlerFunc(s.backupsPage))
	}
	if s.cfg.Recovery != nil {
		s.Mount("/recovery", "Recovery key", http.HandlerFunc(s.recoveryPage))
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
	// Setup's hooks answer only until setup is done (agentosd refuses
	// them after finish); then progress is the owner channel's.
	if s.cfg.Hooks != nil && s.setup != nil && !s.setup.done() {
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

// cspWith is pageCSP admitting only the scripts whose SHA-256 hashes
// (base64) it is given: the one way a page adds a ceremony script, over
// HTTP or HTTPS (vaultCSP; #2779a's passkey page).
func cspWith(hashes ...string) string {
	if len(hashes) == 0 {
		return pageCSP
	}
	csp := pageCSP + "; script-src"
	for _, h := range hashes {
		csp += " 'sha256-" + h + "'"
	}
	return csp
}

// hstsAge is two years: a phone that has seen the HTTPS page once never
// clicks through a bad certificate for it (CH-9).
const hstsAge = "max-age=63072000"

// ServeHTTP applies the CH-9 and CH-7 guards to every request, then routes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CH-9: only private home sources, never the box itself. The
	// listener is already bound to port 1's interface; this is the second
	// check.
	if !homeSource(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", pageCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	if r.TLS != nil {
		// HTTPS answers the page name only: never a redirect, so a
		// DNS-rebound name gets nothing (#3153). SNI was checked at the
		// handshake (PageTLS.Config).
		if !s.isPageHost(r.Host, HTTPSPort) || r.TLS.ServerName != s.cfg.Page.pageName() {
			http.Error(w, "Misdirected request", http.StatusMisdirectedRequest)
			return
		}
		h.Set("Strict-Transport-Security", hstsAge)
	} else if s.isPageHost(r.Host, s.cfg.Port) {
		if s.cfg.HTTPS {
			// The page name over plain HTTP goes to HTTPS, same path, so
			// a phone that trusts the authority never stays on HTTP.
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			http.Redirect(w, r, "https://"+s.cfg.Page.pageName()+safeNext(r.URL.Path), http.StatusFound)
			return
		}
		// No HTTPS: the plain listener serves the page name as it is.
	} else if r.Host == "" || r.Host != reachedHost(r) {
		// Any other host name, IP literals of other addresses included, is a page trying to reach the box through
		// DNS rebinding, or a captive-portal check: the core runs no
		// captive portal (ONB-5, D-178), so it is never redirected, and
		// never acted on.
		http.Error(w, "Misdirected request", http.StatusMisdirectedRequest)
		return
	}
	if r.Method == http.MethodPost && !s.sameOrigin(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if s.claimGate(w, r) {
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
	if o := r.Header.Get("Origin"); o != "" && o != s.origin(r) {
		return false
	}
	return true
}

// origin is the page's own origin for r: https://<page name> over HTTPS,
// else http:// and the host ServeHTTP admitted.
func (s *Server) origin(r *http.Request) string {
	if r.TLS != nil {
		return "https://" + s.cfg.Page.pageName()
	}
	if s.isPageHost(r.Host, s.cfg.Port) {
		return "http://" + r.Host
	}
	return "http://" + reachedHost(r)
}

// isPageHost: host is the page name, with the listener's port or none.
func (s *Server) isPageHost(host string, port int) bool {
	name := s.cfg.Page.pageName()
	return host == name || host == net.JoinHostPort(name, strconv.Itoa(port))
}

// hostPrefix is the cookie name prefix over HTTPS (CH-9): a __Host-
// cookie is Secure, has no Domain and Path=/, so no other name can set or
// read it.
const hostPrefix = "__Host-"

// setCookie sets c; over HTTPS under a __Host- name, Secure, Path=/, no
// Domain, SameSite=Strict, HttpOnly.
func setCookie(w http.ResponseWriter, r *http.Request, c *http.Cookie) {
	if r.TLS != nil {
		c.Name, c.Secure, c.Path, c.Domain = hostPrefix+c.Name, true, "/", ""
		c.SameSite, c.HttpOnly = http.SameSiteStrictMode, true
	}
	http.SetCookie(w, c)
}

// readCookie reads the cookie setCookie set under name for r's scheme.
func readCookie(r *http.Request, name string) (*http.Cookie, error) {
	if r.TLS != nil {
		name = hostPrefix + name
	}
	return r.Cookie(name)
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
	c, err := readCookie(r, cookieName)
	if err != nil || len(c.Value) != 2*localapi.TokenBytes {
		return ""
	}
	return c.Value
}

// remember sets the phone's cookie to the session agentosd minted.
func (s *Server) remember(w http.ResponseWriter, r *http.Request, ses localapi.Session) {
	setCookie(w, r, &http.Cookie{Name: cookieName, Value: ses.Token, Path: "/", Expires: ses.Until,
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
	// Restore: the box's page authority is missing (Config.PageRestore).
	Restore bool
	// Backups: the Backups page is served.
	Backups bool
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) { s.statusPage(w, r, msgText(r)) }

func (s *Server) statusPage(w http.ResponseWriter, r *http.Request, msg string) {
	s.statusPageWith(w, r, msg, false)
}

func (s *Server) statusPageWith(w http.ResponseWriter, r *http.Request, msg string, askCode bool) {
	v := statusView{Progress: s.progress(r), SignedIn: s.isSignedIn(r), Done: s.setupDone(r), Msg: msg, AskCode: askCode,
		Restore: s.cfg.PageRestore, Backups: s.cfg.Backups != nil}
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
	wrongCodeText = "That code didn't work. Try the next code from your code generator." // UX-2wb-2
	limitedText   = "Too many wrong codes were tried on this Wi-Fi. Wait a minute, then try again."
	lockedText    = "No more codes can be tried for now. Use your recovery key, or try again later."
)

// refusalText is the page's line for a refused code: what is left of the
// day's tries comes from agentosd, in a signed-in response to this code
// only; before sign-in the lockout line is fixed (Security D1).
func refusalText(refusal, left string) string {
	switch {
	case refusal == localapi.RefusedTooMany && left != "":
		return left
	case refusal == localapi.RefusedTooMany:
		return lockedText
	}
	return strings.TrimSpace(wrongCodeText + " " + left)
}

// checkSignIn returns the new session's token.
func (s *Server) checkSignIn(w http.ResponseWriter, r *http.Request, code string) (string, error) {
	if code == "" || len(code) > localapi.MaxCode {
		return "", errors.New(wrongCodeText)
	}
	var ses localapi.Session
	err := s.call(r.Context(), localapi.OpSignIn, localapi.SignIn{Code: code}, &ses)
	switch {
	case err == nil && ses.Refusal != "":
		return "", errors.New(refusalText(ses.Refusal, ""))
	case refused(err, localapi.ErrLimited):
		return "", errors.New(limitedText)
	case err != nil:
		return "", errors.New("Could not check the code. Try again.")
	}
	s.remember(w, r, ses)
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
	default:
		s.statusPageResume(w, r, refusalText(a.Refusal, a.Text))
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

// signout revokes the phone's session in agentosd and clears its cookie.
// A token agentosd refuses as unauthorized is already dead (never minted, or
// revoked by an earlier try whose answer was lost), so that ends the sign-out
// too. Any other failure leaves the session possibly live: the cookie is kept,
// since the retry needs it, and the page says the sign-out is incomplete and
// offers that retry, a same-origin POST like this one (#1725, CH-12).
func (s *Server) signout(w http.ResponseWriter, r *http.Request) {
	if tok := cookieToken(r); tok != "" {
		err := s.call(r.Context(), localapi.OpSignOut, localapi.Auth{Token: tok}, nil)
		if err != nil && !refused(err, localapi.ErrUnauthorized) {
			w.Header().Set("Cache-Control", "no-store")
			s.render(w, "signoutfail", nil)
			return
		}
	}
	setCookie(w, r, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}

// The sign-out failure page is defined here, beside its handler, and parsed
// into tmpl at init like the other handler-owned pages, so every pagesFor
// clone carries it.
func init() {
	template.Must(tmpl.Parse(`{{define "signoutfail"}}{{template "head" ""}}
<h1>Sign-out incomplete</h1>
<p class="err">I could not confirm that this phone is signed out, so it may still be signed in. Try again; if it keeps failing, wait a minute and try once more.</p>
<form method="post" action="/signout"><button>Try sign-out again</button></form>
<p><a href="/status">Status</a></p>
{{template "foot"}}{{end}}`))
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	s.homePage(w, r, "", "")
}

// homePage is the signed-in home page, with msg or errText from a form
// on it.
func (s *Server) homePage(w http.ResponseWriter, r *http.Request, msg, errText string) {
	s.homeView(w, r, msg, errText, "", localapi.DeviceCode{})
}

// homeView is homePage with planErr, an error from the plan's sign-in
// form, or plan, the sign-in it started (#1264).
func (s *Server) homeView(w http.ResponseWriter, r *http.Request, msg, errText, planErr string, plan localapi.DeviceCode) {
	s.mu.Lock()
	ms := append([]mount(nil), s.mounts...)
	s.mu.Unlock()
	v := struct {
		Mounts    []mount
		Waiting   int
		LineNote  string
		LineTexts []string
		// SIM and SIMEnds name a SIM to adopt as the owner line's (P2-2w
		// d2b); Cell is the grid cell its code field may take.
		SIM, SIMEnds, Cell string
		Msg, Err           string
		// PlanReady offers the plan's sign-in again (ONB-9, #1264); Plan
		// is the one started, PlanErr the form's error.
		PlanReady bool
		Plan      localapi.DeviceCode
		PlanErr   string
	}{Mounts: ms, Msg: msg, Err: errText, Plan: plan, PlanErr: planErr}
	auth := localapi.Auth{Token: cookieToken(r)}
	var rq localapi.Requests
	if s.call(r.Context(), localapi.OpRequests, auth, &rq) == nil {
		v.Waiting = len(rq.Requests)
	}
	// The owner line's counts come only over the tokened op (Security D1).
	var line localapi.Line
	if s.call(r.Context(), localapi.OpLine, auth, &line) == nil {
		v.LineNote, v.LineTexts = line.Note, lineTexts(line, time.Local)
		v.SIM, v.SIMEnds = line.SIM, line.SIMEnds
	}
	// A sign-in this session started that still waits comes back in place
	// of the form (#1945).
	var ps localapi.PlanSignIn
	if plan.Link == "" && s.call(r.Context(), localapi.OpPlanSignInReady, auth, &ps) == nil {
		v.PlanReady = ps.Ready
		if ps.Ready && ps.Link != "" {
			v.Plan = ps.DeviceCode
		}
	}
	if v.SIM != "" || v.PlanReady {
		var cell localapi.Text
		if s.call(r.Context(), localapi.OpGridCell, struct{}{}, &cell) == nil {
			v.Cell = cell.Text
		}
	}
	s.render(w, "home", v)
}

// adoptSIM adopts the SIM the home page showed as the owner line's (P2-2w
// d2b). It always takes a code, however fresh the sign-in: adopting
// re-opens the owner channel on that SIM's line (CH-19).
func (s *Server) adoptSIM(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.PostFormValue("code"))
	if strings.HasPrefix(code, owner.UnlockProofPrefix) || len(code) > localapi.MaxCode {
		s.homePage(w, r, "", wrongCodeText)
		return
	}
	var a localapi.Answered
	err := s.call(r.Context(), localapi.OpSIM, localapi.AdoptSIM{Token: cookieToken(r), SIM: r.PostFormValue("sim"), Code: code}, &a)
	switch {
	case refused(err, localapi.ErrLimited):
		s.homePage(w, r, "", limitedText)
	case refused(err, localapi.ErrBadArgs):
		s.homePage(w, r, "", simStaleText)
	case err != nil:
		s.homePage(w, r, "", simFailedText)
	case a.Refusal == "":
		s.homePage(w, r, a.Text, "")
	case a.Refusal == localapi.RefusedCodeNeeded:
		s.homePage(w, r, "", simCodeText)
	case a.Refusal == localapi.RefusedChanged:
		s.homePage(w, r, "", simStaleText)
	default:
		s.homePage(w, r, "", refusalText(a.Refusal, a.Text))
	}
}

const (
	simCodeText   = "To use this SIM, enter a code from your code generator (not the one I texted)."
	simStaleText  = "My phone modem's SIM changed since this page loaded. Check the SIM below and try again."
	simFailedText = "I can't answer right now. Nothing changed. Reload to try again."
)

// contact serves the box's number as a contact card (§8.1 step 5).
func (s *Server) contact(w http.ResponseWriter, r *http.Request) {
	n := ""
	if s.cfg.Hooks != nil {
		n, _ = s.cfg.Hooks.BoxNumber()
	}
	if !phoneRe.MatchString(n) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/vcard; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="AgentOS.vcf"`)
	// The page's name may not resolve on a home network yet; until HTTPS is
	// up, the card links the address this phone reached (WIFI-del-a3).
	page := s.cfg.Page.pageName()
	if h := reachedHost(r); !s.cfg.HTTPS && r.TLS == nil && h != "" {
		page = h
	}
	// The name holds only letters, spaces, hyphens and apostrophes
	// (boxname.Check), none of which vCard escapes.
	io.WriteString(w, "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:"+s.setup.cardName()+"\r\nTEL;TYPE=CELL:"+n+"\r\nURL:http://"+page+"/\r\nEND:VCARD\r\n")
}

var msgs = map[string]string{
	"stopped":      "Stopped. Nothing new starts until you resume.",
	"stopfailed":   "STOP failed to record. Nothing new starts now; press STOP again.",
	"resumefailed": "RESUME failed to record. Still stopped.",
}

func msgText(r *http.Request) string { return msgs[r.URL.Query().Get("m")] }
