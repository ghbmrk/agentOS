package localui

import (
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/owner"
)

// Progress is the box's boot state for the status and setup pages (ONB-4).
type Progress struct {
	// Phase is "booting", "updating" or "ready".
	Phase string
	// Updated is true once the first-boot update (UPD-3) has finished or
	// was not needed. Only AI and account connection wait for it.
	Updated bool
	// Online is true when the box has an uplink. Ethernet makes the
	// network step a no-op.
	Online bool
}

// Provider is an AI provider setup can connect (§8.1 step 6).
type Provider struct {
	ID, Name   string
	APIKey     bool // an API key may be entered on this page
	DeviceCode bool // an OAuth device-code sign-in on the phone
	Connected  bool
	// PrivateOK: the owner allows this provider to see private data
	// (CAP-9). Asked once at connection, ticked by default.
	PrivateOK bool
}

// Hooks connect setup to the rest of the box. Each is implemented by the
// package that owns the effect (uplink, modem, vault, host trust, provider
// adapters); setup only sequences them.
type Hooks interface {
	Progress() Progress
	// Networks lists home Wi-Fi networks in range.
	Networks() []string
	// JoinNetwork joins a home Wi-Fi network. The password is the home
	// network's, typed here, and goes nowhere else.
	JoinNetwork(ssid, password string) error
	// BoxNumber is the SIM's number, e.g. +15550000100.
	BoxNumber() string
	// HostInfo names the PC for the pairing reply, e.g. "GEEKOM Air12, 8 GB".
	HostInfo() string
	// Send texts from the box's number (broker templates only).
	Send(to, text string) error
	// SaveCodeSeed puts the code generator's seed in the vault (CRED-8).
	SaveCodeSeed(seed []byte) error
	// TrustHost makes this PC a trusted host, or not (§8.1, CRED-9).
	TrustHost(trusted bool) error
	Providers() []Provider
	// ConnectAPIKey stores a provider API key in the vault (CRED-5).
	ConnectAPIKey(id, key string) error
	// StartDeviceCode begins an OAuth device-code sign-in and returns the
	// provider's page and the code to enter there.
	StartDeviceCode(id string) (link, code string, err error)
	// SetPrivateOK records whether a provider may see private data
	// (CAP-9), as the owner answered at connection.
	SetPrivateOK(id string, ok bool) error
	// AlreadySetUp reports that setup finished before: Finish completed
	// and the owner channel exists. An enrolled code seed alone does not
	// count, since setup can stop or start over after enrollment. It is
	// asked at start whenever setup is not done, so a lost state file or a
	// failed save after Finish never reopens setup.
	AlreadySetUp() bool
	// Finish is called once, when setup completes, with the owner's
	// number. The caller starts the owner channel, attaches it with
	// SetOwner, and sends AllSetText (ONB-8) with the connected accounts
	// and whether any provider may see private data.
	Finish(ownerNumber string) error
}

// SetupState is setup's durable progress. It holds no secret: the code
// seed goes to the vault through Hooks.SaveCodeSeed.
type SetupState struct {
	Network bool   `json:"network"`
	Owner   string `json:"owner,omitempty"`
	// Device is the SHA-256 of the setup cookie of the phone that paired:
	// once the owner's number is known, only that phone continues setup.
	// "" with an owner set means the pairing came by the card's setup
	// code and the phone has yet to claim setup with the texted page code.
	Device      string `json:"device,omitempty"`
	Codes       bool   `json:"codes"`
	Recovery    bool   `json:"recovery"`
	Host        bool   `json:"host"`
	HostTrusted bool   `json:"host_trusted"`
	Done        bool   `json:"done"`
}

// SetupStore persists SetupState.
type SetupStore interface {
	Load() (SetupState, error)
	Save(SetupState) error
}

// MemStore keeps SetupState in memory, for tests.
type MemStore struct {
	mu sync.Mutex
	s  SetupState
}

func (m *MemStore) Load() (SetupState, error) { m.mu.Lock(); defer m.mu.Unlock(); return m.s, nil }
func (m *MemStore) Save(s SetupState) error   { m.mu.Lock(); defer m.mu.Unlock(); m.s = s; return nil }

// FileStore keeps SetupState in one JSON file, replaced atomically.
type FileStore struct{ Path string }

func (f FileStore) Load() (SetupState, error) {
	var s SetupState
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

func (f FileStore) Save(s SetupState) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".setup-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}

// Pairing and enrollment limits.
// Pairing and enrollment limits.
const (
	// PairTriesPerHour caps wrong pairing texts; beyond it the box stays
	// silent, so the 40-bit setup code is not guessable by text.
	PairTriesPerHour = 10
	// NumberTextsPerHour caps codes texted during setup (to a typed
	// number, or page codes to the owner).
	NumberTextsPerHour = 3
	numberCodeTTL      = 15 * time.Minute
	numberCodeTries    = 3
	// maxPairDevices bounds the per-phone pairing codes kept at once.
	maxPairDevices = 8
)

const setupCookie = "agentos_setup"

// SetupCookieFor is how long a phone keeps its setup cookie.
const SetupCookieFor = 7 * 24 * time.Hour

var (
	phoneRe = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)
	pairRe  = regexp.MustCompile(`(?i)^\s*pair\s+([a-z0-9 -]{4,20})\s*[.!]?\s*$`)
)

// errElsewhere refuses a setup step from a phone other than the one that
// paired.
var errElsewhere = errors.New("Setup is continuing on the phone that texted the box.")

// setup is the §8.1 step 5 and 6 sequence. Until the owner's number is
// known any phone on the box's Wi-Fi may set up; from then on only the
// phone that paired (its setup cookie), so a second device on the Wi-Fi
// can neither replace the number nor see the code-generator seed.
type setup struct {
	s *Server

	mu sync.Mutex
	st SetupState
	// pair holds a one-time pairing code per phone (setup cookie hash),
	// so the text that pairs also names the phone that continues.
	pair map[string]string
	// pairOrder lists pair's keys oldest first, for eviction.
	pairOrder []string
	seed      []byte // code-generator seed being enrolled; never stored here
	// seedGen counts seeds made or wiped, so an enrollment checked
	// against one seed never saves after a restart replaced it.
	seedGen uint64
	wrong   []time.Time
	// number fallback (ONB-6): a code texted to a typed number, accepted
	// only from the phone that asked for it.
	numTo      string
	numDevice  string
	numCode    string
	numExpires time.Time
	numTries   int
	texts      []time.Time
	// resets are wrong reset-secret attempts in the last hour.
	resets []time.Time
	// claim is the page code texted after a pairing by the card's setup
	// code; the phone that types it continues setup.
	claimCode    string
	claimExpires time.Time
	claimTries   int
	device       map[string][2]string // provider -> link, code
	err          map[string]string    // per phone
	finishing    bool
}

func newSetup(s *Server, st SetupState) *setup {
	return &setup{s: s, st: st, pair: map[string]string{}, device: map[string][2]string{}, err: map[string]string{}}
}

func (u *setup) done() bool { u.mu.Lock(); defer u.mu.Unlock(); return u.st.Done }

// adopt marks setup done when Finish already completed, so neither a lost
// state file nor a failed save of Done reopens setup and re-enrollment. A
// reboot mid-setup, or after starting over, resumes where it was, since
// AlreadySetUp counts only a completed Finish.
func (u *setup) adopt() {
	if u.st.Done || !u.s.cfg.Hooks.AlreadySetUp() {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := u.save(func(s *SetupState) { s.Done = true }); err != nil {
		// Closed in memory regardless; AlreadySetUp closes it again on
		// the next start.
		u.st.Done = true
	}
}

// stepLocked names the first unfinished step.
func (u *setup) stepLocked(p Progress) string {
	switch {
	case u.st.Done:
		return "done"
	case u.st.Owner == "" && !u.st.Network && !p.Online:
		return "network"
	case u.st.Owner == "":
		return "number"
	case !u.st.Codes:
		return "codes"
	case !u.st.Recovery:
		return "recovery"
	case !u.st.Host:
		return "host"
	}
	return "ai"
}

// mayLocked reports whether the phone with setup cookie hash key may run
// setup steps now.
func (u *setup) mayLocked(key string) bool {
	return u.st.Owner == "" || (u.st.Device != "" && key == u.st.Device)
}

func (u *setup) save(f func(*SetupState)) error {
	next := u.st
	f(&next)
	if err := u.s.cfg.Store.Save(next); err != nil {
		return err
	}
	u.st = next
	return nil
}

// phone returns the setup cookie hash of the requesting phone, issuing a
// cookie when issue is set and it has none ("" otherwise).
func (u *setup) phone(w http.ResponseWriter, r *http.Request, issue bool) string {
	if c, err := r.Cookie(setupCookie); err == nil && len(c.Value) == 64 {
		return tokenKey(c.Value)
	}
	if !issue {
		return ""
	}
	b := make([]byte, 32)
	if _, err := io.ReadFull(u.s.cfg.Rand, b); err != nil {
		return ""
	}
	tok := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{Name: setupCookie, Value: tok, Path: "/setup", MaxAge: int(SetupCookieFor / time.Second),
		HttpOnly: true, SameSite: http.SameSiteStrictMode})
	return tokenKey(tok)
}

func (u *setup) routes(mux *http.ServeMux) {
	mux.HandleFunc("/setup", u.page)
	for path, f := range map[string]func(*http.Request, string) error{
		"/setup/network":     u.network,
		"/setup/number":      u.number,
		"/setup/number-code": u.numberCode,
		"/setup/claim":       u.claim,
		"/setup/codes":       u.codes,
		"/setup/recovery":    u.recovery,
		"/setup/host":        u.host,
		"/setup/ai-key":      u.aiKey,
		"/setup/ai-device":   u.aiDevice,
		"/setup/restart":     u.restart,
	} {
		path, f := path, f
		mux.HandleFunc(path, u.s.post(func(w http.ResponseWriter, r *http.Request) {
			if u.done() {
				http.Redirect(w, r, "/status", http.StatusSeeOther)
				return
			}
			key := u.phone(w, r, false)
			u.mu.Lock()
			ok := key != "" && (u.mayLocked(key) || path == "/setup/claim" || path == "/setup/restart")
			u.mu.Unlock()
			err := errElsewhere
			if key == "" {
				err = errors.New("Reload the setup page and try again.")
			} else if ok {
				err = f(r, key)
			}
			u.mu.Lock()
			delete(u.err, key)
			if err != nil && key != "" {
				u.err[key] = err.Error()
			}
			u.mu.Unlock()
			if err == nil {
				u.maybeFinish()
			}
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
		}))
	}
}

type setupView struct {
	Step      string
	Progress  Progress
	Err       string
	Networks  []string
	BoxNumber string
	SMSLink   template.URL
	PairCode  string
	NumTo     string
	Paired    string // the owner's number, masked
	OTPLink   template.URL
	OTPQR     template.HTML
	OTPSecret string
	Defaults  string
	Providers []Provider
	Device    map[string][2]string
	// Refresh reloads the page only while it waits on the box and has
	// nothing to type into (ONB-4).
	Refresh string
}

// page shows the current step. Setup pages are open without sign-in only
// until setup is done (CH-7), and after pairing only to the phone that
// paired.
func (u *setup) page(w http.ResponseWriter, r *http.Request) {
	if u.done() {
		http.Redirect(w, r, "/status", http.StatusSeeOther)
		return
	}
	key := u.phone(w, r, true)
	if key == "" {
		http.Error(w, "Setup could not start. Reload the page.", http.StatusInternalServerError)
		return
	}
	p := u.s.cfg.Hooks.Progress()
	if u.stepIs("ai") {
		u.maybeFinish()
		if u.done() {
			http.Redirect(w, r, "/status", http.StatusSeeOther)
			return
		}
	}
	v := setupView{Progress: p, Defaults: u.s.cfg.Defaults, Device: map[string][2]string{}}
	var err error
	u.mu.Lock()
	v.Step = u.stepLocked(p)
	switch {
	case u.st.Owner != "" && u.st.Device == "":
		v.Step = "claim"
	case !u.mayLocked(key):
		v.Step = "elsewhere"
	}
	v.Err = u.err[key]
	delete(u.err, key)
	if u.st.Owner != "" {
		v.Paired = mask(u.st.Owner)
	}
	for k, d := range u.device {
		v.Device[k] = d
	}
	if key == u.numDevice {
		v.NumTo = u.numTo
	}
	var seed []byte
	switch v.Step {
	case "number":
		if u.pair[key] == "" {
			// The oldest phone's code goes first, so phones opening
			// the page cannot void the code a slower phone is texting.
			for len(u.pair) >= maxPairDevices && len(u.pairOrder) > 0 {
				delete(u.pair, u.pairOrder[0])
				u.pairOrder = u.pairOrder[1:]
			}
			u.pair[key], err = randomSymbols(u.s.cfg.Rand, 8)
			u.pairOrder = append(u.pairOrder, key)
		}
		v.PairCode = u.pair[key]
	case "codes":
		if u.seed == nil {
			u.seed = make([]byte, 20)
			u.seedGen++
			if _, err = io.ReadFull(u.s.cfg.Rand, u.seed); err != nil {
				u.seed = nil
			}
		}
		seed = append([]byte(nil), u.seed...)
	}
	u.mu.Unlock()
	if err != nil {
		http.Error(w, "Setup could not start this step. Reload the page.", http.StatusInternalServerError)
		return
	}
	switch v.Step {
	case "network":
		v.Networks = u.s.cfg.Hooks.Networks()
	case "number":
		v.BoxNumber = u.s.cfg.Hooks.BoxNumber()
		v.SMSLink = smsLink(v.BoxNumber, "PAIR "+v.PairCode)
	case "codes":
		if seed != nil {
			v.OTPSecret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
			link := otpLink(u.s.cfg.AP.SSID, v.OTPSecret)
			v.OTPLink = template.URL(link)
			if v.OTPQR, err = card.QRSVG(link); err != nil {
				http.Error(w, "Setup could not start this step. Reload the page.", http.StatusInternalServerError)
				return
			}
		}
	case "ai":
		v.Providers = u.s.cfg.Hooks.Providers()
		if !p.Updated {
			v.Refresh = "10"
		}
	}
	u.s.render(w, "setup", v)
}

func (u *setup) stepIs(step string) bool {
	p := u.s.cfg.Hooks.Progress()
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.stepLocked(p) == step
}

// mask shows only the last four digits of a number.
func mask(n string) string {
	if len(n) <= 4 {
		return n
	}
	return "ending " + n[len(n)-4:]
}

// smsLink opens the phone's messaging app with the box's number and body
// filled in (ONB-6). "?&body=" is read by both iOS and Android.
func smsLink(number, body string) template.URL {
	if !phoneRe.MatchString(number) {
		return ""
	}
	return template.URL("sms:" + number + "?&body=" + url.PathEscape(body))
}

// otpLink is the standard key-URI for code generators (ONB-6): RFC 6238
// defaults, which owner.Channel checks.
func otpLink(label, secret string) string {
	l := url.PathEscape("AgentOS:" + label)
	return "otpauth://totp/" + l + "?secret=" + secret + "&issuer=AgentOS&algorithm=SHA1&digits=6&period=30"
}

func (u *setup) network(r *http.Request, _ string) error {
	ssid, pw := r.PostFormValue("ssid"), r.PostFormValue("password")
	u.mu.Lock()
	paired := u.st.Owner != ""
	u.mu.Unlock()
	if paired {
		return nil // the network step is over once the number is known
	}
	if r.PostFormValue("ethernet") == "" {
		if ssid == "" {
			return errors.New("Choose your home Wi-Fi.")
		}
		if err := u.s.cfg.Hooks.JoinNetwork(ssid, pw); err != nil {
			return errors.New("Could not join that Wi-Fi. Check the password and try again.")
		}
	} else if !u.s.cfg.Hooks.Progress().Online {
		return errors.New("No Ethernet connection found. Plug in a cable, or choose your Wi-Fi.")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.save(func(s *SetupState) { s.Network = true })
}

// OfferText takes a text that reached the box before it has an owner. A
// text of the form "PAIR <code>" makes its sender the owner's number, and
// the box replies from its own number, proving the path both ways (§8.1).
// With a phone's one-time pairing code (the sms: link), that phone
// continues setup. With the card's setup code (the typing fallback), the
// reply carries a page code, and the phone that types it continues. Other
// texts are ignored. reply is "" when nothing should be sent.
func (s *Server) OfferText(from, text string) (reply string, handled bool) {
	u := s.setup
	now := s.cfg.Now()
	m := pairRe.FindStringSubmatch(text)
	u.mu.Lock()
	if u.st.Owner != "" || u.st.Done || !phoneRe.MatchString(from) || m == nil {
		u.mu.Unlock()
		return "", false
	}
	u.wrong = recentTimes(u.wrong, now, time.Hour)
	if len(u.wrong) >= PairTriesPerHour {
		u.mu.Unlock()
		return "", true
	}
	got := card.Normalize(m[1])
	phone := ""
	for k, c := range u.pair {
		if subtle.ConstantTimeCompare([]byte(got), []byte(c)) == 1 {
			phone = k
		}
	}
	byCard := phone == "" && s.cfg.SetupSecret != "" && card.CheckSetupCode(s.cfg.SetupSecret, got)
	if phone == "" && !byCard {
		u.wrong = append(u.wrong, now)
		u.mu.Unlock()
		return "That pairing code did not match. Check the setup page.", true
	}
	var claim string
	if byCard {
		var err error
		if claim, err = randomDigits(s.cfg.Rand, 6); err != nil {
			u.mu.Unlock()
			return "Could not save your number. Try again.", true
		}
	}
	err := u.save(func(st *SetupState) { st.Owner, st.Device = from, phone })
	if err == nil {
		u.pair, u.pairOrder = map[string]string{}, nil
		u.numCode, u.numTo, u.numDevice = "", "", ""
		u.claimCode, u.claimExpires, u.claimTries = claim, now.Add(numberCodeTTL), 0
	}
	u.mu.Unlock()
	if err != nil {
		return "Could not save your number. Try again.", true
	}
	reply = pairedText(s.cfg.Hooks.HostInfo())
	if byCard {
		reply += " Page code: " + claim + "."
	}
	return reply, true
}

func pairedText(host string) string {
	host = gsmSafe(host, 40)
	if host == "" {
		host = "this PC"
	}
	return "AgentOS is running on " + host + ". This is your box's number; save it as AgentOS."
}

// number is the typing fallback for pairing (ONB-6): the owner types their
// number, the box texts it a code, and the owner types the code here, on
// the same phone. Refused once the number is known.
func (u *setup) number(r *http.Request, key string) error {
	n := strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '(' || r == ')' || r == '.' {
			return -1
		}
		return r
	}, r.PostFormValue("number"))
	if !phoneRe.MatchString(n) {
		return errors.New("Enter your number with its country code, like +1 555 010 0000.")
	}
	now := u.s.cfg.Now()
	u.mu.Lock()
	if u.st.Owner != "" {
		u.mu.Unlock()
		return errElsewhere
	}
	u.texts = recentTimes(u.texts, now, time.Hour)
	if len(u.texts) >= NumberTextsPerHour {
		u.mu.Unlock()
		return errors.New("Too many codes sent. Use Text my box, or try again in an hour.")
	}
	code, err := randomDigits(u.s.cfg.Rand, 6)
	if err != nil {
		u.mu.Unlock()
		return err
	}
	u.texts = append(u.texts, now)
	u.numTo, u.numDevice, u.numCode, u.numExpires, u.numTries = n, key, code, now.Add(numberCodeTTL), 0
	u.mu.Unlock()
	if err := u.s.cfg.Hooks.Send(n, "AgentOS setup code: "+code+". Type it on the setup page."); err != nil {
		return errors.New("The box could not send a text. Check the SIM, or use Text my box.")
	}
	return nil
}

func (u *setup) numberCode(r *http.Request, key string) error {
	got := strings.TrimSpace(r.PostFormValue("code"))
	now := u.s.cfg.Now()
	u.mu.Lock()
	if u.st.Owner != "" {
		u.mu.Unlock()
		return errElsewhere
	}
	if u.numCode == "" || key != u.numDevice || !now.Before(u.numExpires) {
		u.numCode, u.numTo, u.numDevice = "", "", ""
		u.mu.Unlock()
		return errors.New("That code has expired. Send a new one.")
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(u.numCode)) != 1 {
		u.numTries++
		if u.numTries >= numberCodeTries {
			u.numCode, u.numTo, u.numDevice = "", "", ""
		}
		u.mu.Unlock()
		return errors.New("That code did not match.")
	}
	to := u.numTo
	u.numCode, u.numTo, u.numDevice = "", "", ""
	err := u.save(func(s *SetupState) { s.Owner, s.Device = to, key })
	if err == nil {
		u.pair, u.pairOrder = map[string]string{}, nil
	}
	u.mu.Unlock()
	if err != nil {
		return err
	}
	_ = u.s.cfg.Hooks.Send(to, pairedText(u.s.cfg.Hooks.HostInfo()))
	return nil
}

// claim lets the phone that types the texted page code continue setup,
// after a pairing by the card's setup code. Three wrong codes or an expired
// one text the owner a new code (within NumberTextsPerHour).
func (u *setup) claim(r *http.Request, key string) error {
	got := strings.TrimSpace(r.PostFormValue("code"))
	now := u.s.cfg.Now()
	u.mu.Lock()
	if u.st.Owner == "" || u.st.Device != "" {
		ok := u.mayLocked(key)
		u.mu.Unlock()
		if ok {
			return nil
		}
		return errElsewhere
	}
	if u.claimCode != "" && now.Before(u.claimExpires) && subtle.ConstantTimeCompare([]byte(got), []byte(u.claimCode)) == 1 {
		u.claimCode = ""
		defer u.mu.Unlock()
		return u.save(func(s *SetupState) { s.Device = key })
	}
	u.claimTries++
	if u.claimCode != "" && now.Before(u.claimExpires) && u.claimTries < numberCodeTries {
		u.mu.Unlock()
		return errors.New("That code did not match. Use the page code the box texted you.")
	}
	u.texts = recentTimes(u.texts, now, time.Hour)
	if len(u.texts) >= NumberTextsPerHour {
		u.claimCode = ""
		u.mu.Unlock()
		return errors.New("Too many tries. Try again in an hour.")
	}
	code, err := randomDigits(u.s.cfg.Rand, 6)
	if err != nil {
		u.mu.Unlock()
		return err
	}
	u.texts = append(u.texts, now)
	u.claimCode, u.claimExpires, u.claimTries = code, now.Add(numberCodeTTL), 0
	to := u.st.Owner
	u.mu.Unlock()
	if err := u.s.cfg.Hooks.Send(to, "AgentOS page code: "+code+". Type it on the setup page."); err != nil {
		return errors.New("The box could not send a text. Check the SIM.")
	}
	return errors.New("That code did not match. The box texted you a new page code.")
}

// ResetTriesPerHour caps wrong reset secrets typed on the setup page.
const ResetTriesPerHour = 5

// restart starts setup over from pairing: the lost-device escape
// (arbitrator ruling on #32). The phone that paired may do it; any other
// phone needs the card's setup secret (the reset secret on the recovery
// sheet). Enrollment, the recovery acknowledgment and the trusted-PC
// choice are asked again; the vault's seed is replaced at re-enrollment.
func (u *setup) restart(r *http.Request, key string) error {
	now := u.s.cfg.Now()
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.st.Owner == "" {
		return nil
	}
	if key != u.st.Device {
		u.resets = recentTimes(u.resets, now, time.Hour)
		if len(u.resets) >= ResetTriesPerHour {
			return errors.New("Too many tries. Try again in an hour.")
		}
		want := card.Normalize(u.s.cfg.SetupSecret)
		if want == "" || subtle.ConstantTimeCompare([]byte(card.Normalize(r.PostFormValue("secret"))), []byte(want)) != 1 {
			u.resets = append(u.resets, now)
			return errors.New("That reset secret did not match. It is on your card's recovery sheet.")
		}
	}
	for i := range u.seed {
		u.seed[i] = 0
	}
	u.seed = nil
	u.seedGen++
	u.pair, u.pairOrder = map[string]string{}, nil
	u.claimCode, u.numCode, u.numTo, u.numDevice = "", "", "", ""
	u.device = map[string][2]string{}
	return u.save(func(s *SetupState) {
		s.Owner, s.Device, s.Codes, s.Recovery, s.Host, s.HostTrusted = "", "", false, false, false, false
	})
}

// codes confirms code-generator enrollment with one entered code (ONB-3),
// then hands the seed to the vault and forgets it.
func (u *setup) codes(r *http.Request, _ string) error {
	got := strings.TrimSpace(r.PostFormValue("code"))
	now := u.s.cfg.Now()
	u.mu.Lock()
	if u.st.Owner == "" || u.seed == nil {
		u.mu.Unlock()
		return errors.New("Start this step again.")
	}
	seed, gen := append([]byte(nil), u.seed...), u.seedGen
	u.mu.Unlock()
	ok := false
	// The phone's clock may be a step either side of the box's.
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		if subtle.ConstantTimeCompare([]byte(got), []byte(owner.TOTP(seed, now.Add(d)))) == 1 {
			ok = true
		}
	}
	if !ok {
		return errors.New("That code did not match. Type the code your phone shows now.")
	}
	// Setup may have started over while the code was checked.
	stale := func() bool { return u.seedGen != gen || u.seed == nil || u.st.Owner == "" }
	u.mu.Lock()
	if stale() {
		u.mu.Unlock()
		return errors.New("Start this step again.")
	}
	u.mu.Unlock()
	if err := u.s.cfg.Hooks.SaveCodeSeed(seed); err != nil {
		return errors.New("Could not save. Try again.")
	}
	for i := range seed {
		seed[i] = 0
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if stale() {
		// A restart replaced this seed; the next enrollment overwrites
		// the one just saved.
		return errors.New("Start this step again.")
	}
	for i := range u.seed {
		u.seed[i] = 0
	}
	u.seed = nil
	return u.save(func(s *SetupState) { s.Codes = true })
}

func (u *setup) recovery(r *http.Request, _ string) error {
	if r.PostFormValue("stored") == "" {
		return errors.New("Tear off the recovery sheet, store it, then tick the box.")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.st.Codes {
		return errors.New("Add approval codes first.")
	}
	return u.save(func(s *SetupState) { s.Recovery = true })
}

// host makes this PC trusted by default; "not my PC" opts out. The default
// is allowed only after code enrollment on this page (§8.1, CH-3).
func (u *setup) host(r *http.Request, _ string) error {
	trusted := r.PostFormValue("not_mine") == ""
	u.mu.Lock()
	ready := u.st.Codes && u.st.Recovery
	u.mu.Unlock()
	if !ready {
		return errors.New("Finish the earlier steps first.")
	}
	if err := u.s.cfg.Hooks.TrustHost(trusted); err != nil {
		return errors.New("Could not save. Try again.")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.save(func(s *SetupState) { s.Host, s.HostTrusted = true, trusted })
}

func (u *setup) aiReady() error {
	u.mu.Lock()
	ready := u.st.Host
	u.mu.Unlock()
	if !ready {
		return errors.New("Finish the earlier steps first.")
	}
	if !u.s.cfg.Hooks.Progress().Updated {
		return errors.New("The box is still updating. AI can be connected when it finishes.")
	}
	return nil
}

// privateOK records the owner's CAP-9 answer for a provider: the box asks
// once, ticked by default.
func (u *setup) privateOK(r *http.Request, id string) error {
	if err := u.s.cfg.Hooks.SetPrivateOK(id, r.PostFormValue("private") != ""); err != nil {
		return errors.New("Could not save. Try again.")
	}
	return nil
}

// aiKey takes an API key typed on this page, never by text (§8.1 step 6).
// The key goes to the vault hook and is not kept, echoed, or logged.
func (u *setup) aiKey(r *http.Request, _ string) error {
	if err := u.aiReady(); err != nil {
		return err
	}
	id, key := r.PostFormValue("provider"), strings.TrimSpace(r.PostFormValue("key"))
	if !u.providerHas(id, func(p Provider) bool { return p.APIKey }) || key == "" || len(key) > 512 || !printable(key) {
		return errors.New("Paste the API key from your provider's page.")
	}
	if err := u.privateOK(r, id); err != nil {
		return err
	}
	if err := u.s.cfg.Hooks.ConnectAPIKey(id, key); err != nil {
		return errors.New("The provider did not accept that key.")
	}
	return nil
}

func (u *setup) aiDevice(r *http.Request, _ string) error {
	if err := u.aiReady(); err != nil {
		return err
	}
	id := r.PostFormValue("provider")
	if !u.providerHas(id, func(p Provider) bool { return p.DeviceCode }) {
		return errors.New("Choose a provider.")
	}
	if err := u.privateOK(r, id); err != nil {
		return err
	}
	link, code, err := u.s.cfg.Hooks.StartDeviceCode(id)
	if err != nil {
		return errors.New("Could not start sign-in with that provider. Try again.")
	}
	if pu, perr := url.Parse(link); perr != nil || pu.Scheme != "https" {
		return errors.New("Could not start sign-in with that provider. Try again.")
	}
	u.mu.Lock()
	u.device[id] = [2]string{link, code}
	u.mu.Unlock()
	return nil
}

func (u *setup) providerHas(id string, f func(Provider) bool) bool {
	for _, p := range u.s.cfg.Hooks.Providers() {
		if p.ID == id && f(p) {
			return true
		}
	}
	return false
}

// maybeFinish completes setup once one provider is connected (ONB-3). It
// runs after each step and whenever the AI step is shown, so a device-code
// sign-in finished on the provider's site completes setup too. Finish is
// called at most once at a time, and not again once it succeeded.
func (u *setup) maybeFinish() {
	u.mu.Lock()
	if !u.st.Host || u.st.Done || u.finishing {
		u.mu.Unlock()
		return
	}
	u.finishing = true
	who := u.st.Owner
	u.mu.Unlock()
	defer func() { u.mu.Lock(); u.finishing = false; u.mu.Unlock() }()
	connected := false
	for _, p := range u.s.cfg.Hooks.Providers() {
		connected = connected || p.Connected
	}
	if !connected {
		return
	}
	if err := u.s.cfg.Hooks.Finish(who); err != nil {
		u.mu.Lock()
		u.err[u.st.Device] = "Could not finish setup. Try again."
		u.mu.Unlock()
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := u.save(func(s *SetupState) { s.Done = true }); err != nil {
		// Finish already ran: keep setup closed in memory so it is not
		// called twice, and let AlreadySetUp close it after a restart.
		u.st.Done = true
	}
}

func recentTimes(ts []time.Time, now time.Time, d time.Duration) []time.Time {
	var out []time.Time
	for _, t := range ts {
		if now.Sub(t) < d {
			out = append(out, t)
		}
	}
	return out
}

func randomSymbols(r io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = card.Alphabet[b[i]&31] // 256 is a multiple of 32: unbiased
	}
	return string(b), nil
}

func randomDigits(r io.Reader, n int) (string, error) {
	var b strings.Builder
	buf := make([]byte, 1)
	for b.Len() < n {
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		if buf[0] < 250 { // reject 250-255 so each digit is uniform
			fmt.Fprintf(&b, "%d", buf[0]%10)
		}
	}
	return b.String(), nil
}
