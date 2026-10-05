package localui

import (
	"crypto/subtle"
	"encoding/base32"
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
	// Finish is called once, when setup completes, with the owner's
	// number. The caller starts the owner channel, attaches it with
	// SetOwner, and sends AllSetText (ONB-8).
	Finish(ownerNumber string) error
}

// SetupState is setup's durable progress. It holds no secret: the code
// seed goes to the vault through Hooks.SaveCodeSeed.
type SetupState struct {
	Network     bool   `json:"network"`
	Owner       string `json:"owner,omitempty"`
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
const (
	// PairTriesPerHour caps wrong pairing texts; beyond it the box stays
	// silent, so the 40-bit setup code is not guessable by text.
	PairTriesPerHour = 10
	// NumberTextsPerHour caps setup codes texted to a typed number.
	NumberTextsPerHour = 3
	numberCodeTTL      = 15 * time.Minute
	numberCodeTries    = 3
)

var (
	phoneRe = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)
	pairRe  = regexp.MustCompile(`(?i)^\s*pair\s+([a-z0-9 -]{4,20})\s*[.!]?\s*$`)
)

// setup is the §8.1 step 5 and 6 sequence.
type setup struct {
	s *Server

	mu    sync.Mutex
	st    SetupState
	pair  string // one-time pairing code for the sms: link
	seed  []byte // code-generator seed being enrolled; never stored here
	wrong []time.Time
	// number fallback (ONB-6): a code texted to a typed number.
	numTo      string
	numCode    string
	numExpires time.Time
	numTries   int
	numTexts   []time.Time
	device     map[string][2]string // provider -> link, code
	err        string
}

func newSetup(s *Server, st SetupState) *setup {
	return &setup{s: s, st: st, device: map[string][2]string{}}
}

func (u *setup) done() bool { u.mu.Lock(); defer u.mu.Unlock(); return u.st.Done }

// step names the first unfinished step.
func (u *setup) stepLocked(p Progress) string {
	switch {
	case u.st.Done:
		return "done"
	case !u.st.Network && !p.Online:
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

func (u *setup) save(f func(*SetupState)) error {
	next := u.st
	f(&next)
	if err := u.s.cfg.Store.Save(next); err != nil {
		return err
	}
	u.st = next
	return nil
}

func (u *setup) routes(mux *http.ServeMux) {
	mux.HandleFunc("/setup", u.page)
	for path, f := range map[string]func(*http.Request) error{
		"/setup/network":     u.network,
		"/setup/number":      u.number,
		"/setup/number-code": u.numberCode,
		"/setup/codes":       u.codes,
		"/setup/recovery":    u.recovery,
		"/setup/host":        u.host,
		"/setup/ai-key":      u.aiKey,
		"/setup/ai-device":   u.aiDevice,
	} {
		f := f
		mux.HandleFunc(path, u.s.post(func(w http.ResponseWriter, r *http.Request) {
			if u.done() {
				http.Redirect(w, r, "/status", http.StatusSeeOther)
				return
			}
			err := f(r)
			u.mu.Lock()
			u.err = ""
			if err != nil {
				u.err = err.Error()
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
// until setup is done (CH-7).
func (u *setup) page(w http.ResponseWriter, r *http.Request) {
	if u.done() {
		http.Redirect(w, r, "/status", http.StatusSeeOther)
		return
	}
	p := u.s.cfg.Hooks.Progress()
	u.mu.Lock()
	v := setupView{Step: u.stepLocked(p), Progress: p, Err: u.err, Defaults: u.s.cfg.Defaults, NumTo: u.numTo, Device: map[string][2]string{}}
	u.err = ""
	for k, d := range u.device {
		v.Device[k] = d
	}
	var err error
	switch v.Step {
	case "network":
		u.mu.Unlock()
		v.Networks = u.s.cfg.Hooks.Networks()
		u.mu.Lock()
	case "number":
		if u.pair == "" {
			u.pair, err = randomSymbols(u.s.cfg.Rand, 8)
		}
		v.PairCode = u.pair
		v.BoxNumber = u.s.cfg.Hooks.BoxNumber()
		v.SMSLink = smsLink(v.BoxNumber, "PAIR "+u.pair)
	case "codes":
		if u.seed == nil {
			u.seed = make([]byte, 20)
			if _, err = io.ReadFull(u.s.cfg.Rand, u.seed); err != nil {
				u.seed = nil
			}
		}
		if u.seed != nil {
			v.OTPSecret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(u.seed)
			link := otpLink(u.s.cfg.AP.SSID, v.OTPSecret)
			v.OTPLink = template.URL(link)
			v.OTPQR, err = card.QRSVG(link)
		}
	case "ai":
		u.mu.Unlock()
		v.Providers = u.s.cfg.Hooks.Providers()
		u.mu.Lock()
		if !p.Updated {
			v.Refresh = "10"
		}
	}
	u.mu.Unlock()
	if err != nil {
		http.Error(w, "Setup could not start this step. Reload the page.", http.StatusInternalServerError)
		return
	}
	render(w, "setup", v)
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

func (u *setup) network(r *http.Request) error {
	ssid, pw := r.PostFormValue("ssid"), r.PostFormValue("password")
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
// text of the form "PAIR <code>", with the setup page's one-time pairing
// code or the card's setup code, makes its sender the owner's number, and
// the box replies from its own number, proving the path both ways (§8.1).
// Other texts are ignored. reply is "" when nothing should be sent.
func (s *Server) OfferText(from, text string) (reply string, handled bool) {
	u := s.setup
	now := s.cfg.Now()
	u.mu.Lock()
	if u.st.Owner != "" || u.st.Done || !phoneRe.MatchString(from) {
		u.mu.Unlock()
		return "", false
	}
	m := pairRe.FindStringSubmatch(text)
	if m == nil {
		u.mu.Unlock()
		return "", false
	}
	u.wrong = recentTimes(u.wrong, now, time.Hour)
	if len(u.wrong) >= PairTriesPerHour {
		u.mu.Unlock()
		return "", true
	}
	got := card.Normalize(m[1])
	ok := (u.pair != "" && subtle.ConstantTimeCompare([]byte(got), []byte(u.pair)) == 1) ||
		(s.cfg.SetupSecret != "" && card.CheckSetupCode(s.cfg.SetupSecret, got))
	if !ok {
		u.wrong = append(u.wrong, now)
		u.mu.Unlock()
		return "That pairing code did not match. Check the setup page.", true
	}
	err := u.save(func(st *SetupState) { st.Owner = from })
	u.pair = ""
	u.mu.Unlock()
	if err != nil {
		return "Could not save your number. Try again.", true
	}
	return pairedText(s.cfg.Hooks.HostInfo()), true
}

func pairedText(host string) string {
	host = gsmSafe(host, 40)
	if host == "" {
		host = "this PC"
	}
	return "AgentOS is running on " + host + ". This is your box's number; save it as AgentOS."
}

// number is the typing fallback for pairing (ONB-6): the owner types their
// number, the box texts it a code, and the owner types the code here.
func (u *setup) number(r *http.Request) error {
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
	u.numTexts = recentTimes(u.numTexts, now, time.Hour)
	if len(u.numTexts) >= NumberTextsPerHour {
		u.mu.Unlock()
		return errors.New("Too many codes sent. Use Text my box, or try again in an hour.")
	}
	code, err := randomDigits(u.s.cfg.Rand, 6)
	if err != nil {
		u.mu.Unlock()
		return err
	}
	u.numTexts = append(u.numTexts, now)
	u.numTo, u.numCode, u.numExpires, u.numTries = n, code, now.Add(numberCodeTTL), 0
	u.mu.Unlock()
	if err := u.s.cfg.Hooks.Send(n, "AgentOS setup code: "+code+". Type it on the setup page."); err != nil {
		return errors.New("The box could not send a text. Check the SIM, or use Text my box.")
	}
	return nil
}

func (u *setup) numberCode(r *http.Request) error {
	got := strings.TrimSpace(r.PostFormValue("code"))
	now := u.s.cfg.Now()
	u.mu.Lock()
	if u.numCode == "" || !now.Before(u.numExpires) {
		u.numCode, u.numTo = "", ""
		u.mu.Unlock()
		return errors.New("That code has expired. Send a new one.")
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(u.numCode)) != 1 {
		u.numTries++
		if u.numTries >= numberCodeTries {
			u.numCode, u.numTo = "", ""
		}
		u.mu.Unlock()
		return errors.New("That code did not match.")
	}
	to := u.numTo
	u.numCode, u.numTo = "", ""
	err := u.save(func(s *SetupState) { s.Owner = to })
	u.mu.Unlock()
	if err != nil {
		return err
	}
	_ = u.s.cfg.Hooks.Send(to, pairedText(u.s.cfg.Hooks.HostInfo()))
	return nil
}

// codes confirms code-generator enrollment with one entered code (ONB-3),
// then hands the seed to the vault and forgets it.
func (u *setup) codes(r *http.Request) error {
	got := strings.TrimSpace(r.PostFormValue("code"))
	now := u.s.cfg.Now()
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.st.Owner == "" || u.seed == nil {
		return errors.New("Start this step again.")
	}
	ok := false
	// The phone's clock may be a step either side of the box's.
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		if subtle.ConstantTimeCompare([]byte(got), []byte(owner.TOTP(u.seed, now.Add(d)))) == 1 {
			ok = true
		}
	}
	if !ok {
		return errors.New("That code did not match. Type the code your phone shows now.")
	}
	if err := u.s.cfg.Hooks.SaveCodeSeed(u.seed); err != nil {
		return errors.New("Could not save. Try again.")
	}
	for i := range u.seed {
		u.seed[i] = 0
	}
	u.seed = nil
	return u.save(func(s *SetupState) { s.Codes = true })
}

func (u *setup) recovery(r *http.Request) error {
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
func (u *setup) host(r *http.Request) error {
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

// aiKey takes an API key typed on this page, never by text (§8.1 step 6).
// The key goes to the vault hook and is not kept, echoed, or logged.
func (u *setup) aiKey(r *http.Request) error {
	if err := u.aiReady(); err != nil {
		return err
	}
	id, key := r.PostFormValue("provider"), strings.TrimSpace(r.PostFormValue("key"))
	if !u.providerHas(id, func(p Provider) bool { return p.APIKey }) || key == "" || len(key) > 512 || !printable(key) {
		return errors.New("Paste the API key from your provider's page.")
	}
	if err := u.s.cfg.Hooks.ConnectAPIKey(id, key); err != nil {
		return errors.New("The provider did not accept that key.")
	}
	return nil
}

func (u *setup) aiDevice(r *http.Request) error {
	if err := u.aiReady(); err != nil {
		return err
	}
	id := r.PostFormValue("provider")
	if !u.providerHas(id, func(p Provider) bool { return p.DeviceCode }) {
		return errors.New("Choose a provider.")
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

// maybeFinish completes setup once one provider is connected (ONB-3).
func (u *setup) maybeFinish() {
	u.mu.Lock()
	ready := u.st.Host && !u.st.Done
	who := u.st.Owner
	u.mu.Unlock()
	if !ready {
		return
	}
	connected := false
	for _, p := range u.s.cfg.Hooks.Providers() {
		connected = connected || p.Connected
	}
	if !connected {
		return
	}
	if err := u.s.cfg.Hooks.Finish(who); err != nil {
		u.mu.Lock()
		u.err = "Could not finish setup. Try again."
		u.mu.Unlock()
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := u.save(func(s *SetupState) { s.Done = true }); err != nil {
		u.err = "Could not finish setup. Try again."
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
