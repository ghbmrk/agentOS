package localui

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/firstboot"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// Progress is the box's boot state for the status and setup pages (ONB-4).
type Progress struct {
	// Phase is "booting", "updating", "offline" or "ready". "offline"
	// means a first boot with no uplink: the box runs the image it
	// shipped with and updates when next online (UPD-3).
	Phase string
	// Updated is true once the first-boot update (UPD-3) has finished or
	// was not needed. Only AI and account connection wait for it.
	Updated bool
	// Online is true when the box has an uplink. Ethernet makes the
	// network step a no-op.
	Online bool
	// NeverOnline: the home Wi-Fi was saved but the box has not got
	// online with it (netjoin L8.4, P2-2w c4). Setup continues with a
	// note.
	NeverOnline bool
}

// The never-online notes (CH-12): before pairing the owner can still
// rejoin, after it only Ethernet helps. With no station device (#936)
// a rejoin cannot help either, so the Ethernet note shows before
// pairing too (P2-2w c4 r1).
const (
	neverOnlineNote       = "I saved your home Wi-Fi but have not got online with it. Setup can continue. Check the Wi-Fi name and password below and join again, or plug in an Ethernet cable."
	neverOnlinePairedNote = "I saved your home Wi-Fi but have not got online with it. Setup can continue, and AI waits until I am online. Plug in an Ethernet cable to get online now."
)

// Provider is an AI provider setup can connect (§8.1 step 6).
type Provider struct {
	ID, Name   string
	APIKey     bool // an API key may be entered on this page
	DeviceCode bool // an OAuth device-code sign-in on the phone
	Connected  bool
	// PrivateOK: the owner allows this provider to see private content
	// (CAP-9, REV-6). Asked once at connection: ticked by default on a
	// plan sign-in, unticked on an API key (D-115).
	PrivateOK bool
	// PrivateByConfig: the box's configuration allows this provider
	// private content whatever the owner answers, so the AI step shows
	// the box ticked and fixed and records no answer for it (#1608).
	PrivateByConfig bool
	// Owed: the answer agentosd recorded as owed to the vault and the
	// vault has not confirmed (#1544), or nil.
	Owed *bool
	// SigningIn: the provider's sign-in still waits for the owner
	// (UX3-F1). A code this page showed is shown only while it holds.
	SigningIn bool
}

// privateBox is one form's private-content question as the page shows it.
type privateBox struct {
	Name    string
	Checked bool
	Fixed   bool // the configuration allows it; the owner can't change it
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
	// BoxNumber is the SIM's number, e.g. +15550000100, and whether the
	// box can text (P2-2w c4c). While it cannot, the number step says
	// pairing is not available yet; while it can but the SIM does not
	// report its number (""), the step offers only the number entry.
	BoxNumber() (number string, canText bool)
	// HostInfo names the PC for the pairing reply, e.g. "GEEKOM Air12, 8 GB".
	HostInfo() string
	// Send texts from the box's number (broker templates only).
	Send(to, text string) error
	// EnrollCode asks the vault process for a new code-generator seed and
	// returns its otpauth link (CRED-8; egress K17). Each call makes a new
	// seed, which only the newest link confirms; the page shows it once
	// and keeps nothing. ErrCodesEnrolled: the vault already holds a
	// sealed seed, so setup shows none.
	EnrollCode() (link string, err error)
	// ConfirmCode checks one code from the newest seed; true seals it in
	// the vault. ErrNoCodeEnrollment: no seed waits; ErrCodesLimited: too
	// many wrong codes for now.
	ConfirmCode(code string) (bool, error)
	// TrustHost makes this PC a trusted host, or not (§8.1, CRED-9).
	TrustHost(trusted bool) error
	Providers() []Provider
	// ConnectAPIKey stores a provider API key in the vault (CRED-5).
	ConnectAPIKey(id, key string) error
	// StartDeviceCode begins an OAuth device-code sign-in and returns the
	// provider's page, the code to enter there and who issued the code
	// (§8.1 step 6). ErrSignInBusy while that provider's last sign-in
	// still waits for the owner.
	StartDeviceCode(id string) (link, code, from string, err error)
	// SetPrivateOK records whether a provider may see private data
	// (CAP-9), as the owner answered at connection.
	SetPrivateOK(id string, ok bool) error
	// AlreadySetUp reports that setup finished before: Finish completed
	// and the owner channel exists. It must read a durable marker that
	// Finish writes (such as the owner channel's own state), and return
	// true when in doubt (an unreadable marker), since a false true only
	// keeps setup closed while a false false reopens it on an owned box.
	// An enrolled code seed alone does not count, since setup can stop or
	// start over after enrollment. It is asked at start whenever setup is
	// not done, and after a failed Finish, so neither a lost state file
	// nor a failed save after Finish reopens setup.
	AlreadySetUp() bool
	// Finish is called once, when setup completes, with the owner's
	// number. The caller starts the owner channel, attaches it with
	// SetOwner, and sends AllSetText (ONB-8) with the connected accounts
	// and whether any provider may see private data.
	Finish(ownerNumber string) error
}

// SetupState is setup's durable progress. It holds no secret: the code
// seed is made in the vault process (Hooks.EnrollCode).
type SetupState struct {
	Network bool   `json:"network"`
	Owner   string `json:"owner,omitempty"`
	// Device is the SHA-256 of the setup cookie of the phone that paired:
	// once the owner's number is known, only that phone continues setup.
	// "" with an owner set means the pairing came by the card's setup
	// code and the phone has yet to claim setup with the texted page code.
	Device string `json:"device,omitempty"`
	Codes  bool   `json:"codes"`
	// ReplaceCodes: the code generator entry was voided (F10, CodesVoid),
	// so the codes step says to replace the old entry until it completes.
	ReplaceCodes bool `json:"replace_codes,omitempty"`
	Recovery     bool `json:"recovery"`
	Host         bool `json:"host"`
	HostTrusted  bool `json:"host_trusted"`
	// Unsaved maps a provider to the owner's private-content answer that
	// the vault did not record (#1467). It is set when the save fails and
	// cleared once an answer for that provider is saved, so setup does not
	// finish with the provider keeping an older answer. It lasts only as
	// long as the SetupStore does; agentosd's owed record (#1544) restores
	// it after a restart and holds finish on its own.
	Unsaved map[string]bool `json:"unsaved,omitempty"`
	Done    bool            `json:"done"`
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
	return change.FileStore{Path: f.Path}.Save(b)
}

// HeldStore keeps every field of SetupState in Inner but Unsaved, which it
// also writes to its own file at Path (#1264 c4e2b, ONB-private-save-fail
// s3). A private-content answer the vault did not record then outlives a
// reboot of the box while the rest of setup's progress stays in memory
// (L18): the file holds provider IDs and yes/no answers, never the
// owner's number or phone. agentosd's owed record (#1544) cannot cover an
// answer posted while its socket is down, since agentosd never heard it.
type HeldStore struct {
	Inner SetupStore
	Path  string
}

// Load is Inner's state with Unsaved read from Path. An unreadable file
// fails the load, so the page does not start and finish over a hold it
// lost.
func (h HeldStore) Load() (SetupState, error) {
	s, err := h.Inner.Load()
	if err != nil {
		return s, err
	}
	b, err := os.ReadFile(h.Path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	var held map[string]bool
	if err := json.Unmarshal(b, &held); err != nil {
		return s, fmt.Errorf("held answers %s: %w", h.Path, err)
	}
	if len(held) > 0 {
		s.Unsaved = held
	}
	return s, nil
}

// Save writes Unsaved to Path, replaced durably, before Inner saves, so a
// hold is on disk before the page shows it and a cleared hold stays
// cleared.
func (h HeldStore) Save(s SetupState) error {
	b, err := json.Marshal(s.Unsaved)
	if err != nil {
		return err
	}
	if err := (change.FileStore{Path: h.Path}).Save(b); err != nil {
		return err
	}
	return h.Inner.Save(s)
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
// The vault process's refusals of code enrollment, as Hooks report them.
var (
	ErrCodesEnrolled    = errors.New("code generator already set up")
	ErrNoCodeEnrollment = errors.New("no code-generator enrollment waiting")
	ErrCodesLimited     = errors.New("code-generator enrollment paused")
	// ErrCodesUnavailable: the vault cannot finish setup's enrollment (it
	// was never opened for setup, or it is sealed with no confirmation
	// recorded), so no step on this page can.
	ErrCodesUnavailable = errors.New("code-generator enrollment unavailable")
)

// ErrWiFiUnavailable: the box cannot join Wi-Fi at all (no
// NetworkManager, or another error no password can fix), as JoinNetwork
// reports it (#1429).
var ErrWiFiUnavailable = errors.New("Wi-Fi join unavailable")

// ErrAnswerOwed: agentosd holds an owner's private-content answer the
// vault has not confirmed, so it will not finish setup (#1544), as Finish
// reports it.
var ErrAnswerOwed = errors.New("a private-content answer is not saved yet")

// noWiFiJoin is the network step's error when the box cannot join Wi-Fi:
// no station device beside the access point, or ErrWiFiUnavailable. It
// names the network step's Ethernet button rather than the password
// (#1429, UX U-1 on #1407).
const (
	ethernetButton = "I plugged in an Ethernet cable"
	noWiFiJoin     = "I cannot join Wi-Fi yet. Plug in an Ethernet cable, then tap \"" + ethernetButton + "\"."
)

// The vault process's answers to an API key, as Hooks report them
// (ONB-3, #1265). The page shows each its own text.
var (
	// ErrKeyRefused: the provider did not accept the key when the vault
	// process checked it.
	ErrKeyRefused = errors.New("the provider did not accept the key")
	// ErrKeyUnchecked: the vault process could not reach the provider to
	// check the key, so it did not store it.
	ErrKeyUnchecked = errors.New("the key could not be checked with the provider")
	// ErrKeysLimited: too many keys were tried in the last minute.
	ErrKeysLimited = errors.New("too many keys tried")
	// ErrKeyNotTaken: the vault process does not take this provider or key.
	ErrKeyNotTaken = errors.New("the vault does not take that provider or key")
	// ErrSetupClosed: setup is closed, so no step can store a key.
	ErrSetupClosed = errors.New("setup is closed")
	// ErrSignInBusy: the provider's last device-code sign-in still waits
	// for the owner, so no second one starts.
	ErrSignInBusy = errors.New("a sign-in is still waiting")
)

// replaceCodesNote is the codes step's note after the vault voided the code
// generator entry (F10, #1210 R1). It is GSM-7, like the page's texts.
const replaceCodesNote = "I had to make your approval codes again. In your phone's code generator, delete the old agentOS entry, then add the new one below."

// cardRestartNote is the card step's note (LATER CTRL-card l2): a box that
// restarts before the confirm makes a new card.
const cardRestartNote = "If I restart before you confirm, I make a new card: a card printed or saved before the restart is void. Only the card I show now counts."

// cannotFinish is what the page says on ErrCodesUnavailable.
const cannotFinish = "I cannot finish setup: I cannot add approval codes. Ask whoever installed my software to prepare me for setup again."

// cardAgain is what the page says on ErrCardAgain (#1330): the vault holds
// no Owner Card, so setup goes back to the card step with a new one.
const cardAgain = "I need to make your Owner Card again. Any card I showed you before will not work."

// cardNotMade is what the page says while the card step's rerun has shown
// no card because its vault reset failed (#2362): each reload by the
// paired phone retries it.
const cardNotMade = "I could not make your new Owner Card yet. Reload this page to try again. Any card I showed you before will not work."

// answerOwed is what the page says on ErrAnswerOwed (#1554 UX R5): a
// reload adopts the owed answer as a hold and asks the question again.
const answerOwed = "Your answer about private content was not saved yet. Reload this page to answer again."

var errElsewhere = errors.New("Setup is continuing on the phone that texted me.")

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
	// gen counts setup restarts, so an enrollment confirmed for the
	// pairing before a restart never counts for the one after it.
	gen   uint64
	wrong []time.Time
	// shown: a code-generator link was shown for pairing gen shownGen, so
	// later views ask only for its code; a typo then needs no new scan.
	// Neither holds the seed.
	shown    bool
	shownGen uint64
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
	device       map[string][3]string // provider -> link, code, issuer
	// parked is a started sign-in's link, code and issuer held back while
	// its private answer is unsaved (#1467: no link then); the link comes
	// back once the answer saves, since the sign-in still waits for the
	// owner and a new one would only meet it busy (#1888 PUX L1).
	parked map[string][3]string
	// lapsed is a shown sign-in's link, code and issuer that a failed new
	// code took off the page: the provider's contract cannot say whether
	// it ended (expired, declined, failed) or still waits, so it is no
	// longer shown as current, and comes back only when a Sign in meets
	// that provider busy, which proves it still waits (UX3-1).
	lapsed map[string][3]string
	// answer is the owner's private-content answer from a Connect AI form
	// that did not go through, keyed by form ("ai-key openai"), so the
	// box comes back as the owner left it (U-4).
	answer    map[string]bool
	err       map[string]string // per phone
	finishing bool
	// busy is the providers with an AI post in flight: one at a time
	// each, none while Finish runs, and no Finish while any is (#1467).
	busy map[string]bool
}

func newSetup(s *Server, st SetupState) *setup {
	return &setup{s: s, st: st, pair: map[string]string{}, device: map[string][3]string{}, parked: map[string][3]string{}, lapsed: map[string][3]string{}, answer: map[string]bool{}, err: map[string]string{}, busy: map[string]bool{}}
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
	case !u.st.Recovery && u.cardHeld():
		return "card"
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

// errSetupDone refuses a step that raced setup closing.
var errSetupDone = errors.New("Setup is already done.")

// save applies f to the setup state and persists it. Once setup is done
// nothing changes it, so a step that passed the handler's done check and
// then raced Finish (or a restart racing it) is refused here, under u.mu.
func (u *setup) save(f func(*SetupState)) error {
	if u.st.Done {
		return errSetupDone
	}
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
	if u.s.cfg.Card != nil {
		mux.HandleFunc("/setup/card", u.card)
	}
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
		"/setup/ai-retry":    u.aiRetry,
		"/setup/ai-private":  u.aiPrivate,
		"/setup/restart":     u.restart,
	} {
		path, f := path, f
		mux.HandleFunc(path, u.s.post(func(w http.ResponseWriter, r *http.Request) {
			if u.done() {
				http.Redirect(w, r, "/status", http.StatusSeeOther)
				return
			}
			key := u.phone(w, r, false)
			u.voidCodes()
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
	Step     string
	Progress Progress
	Err      string
	// Note is the never-online note; Rejoin adds the network form to
	// the number step.
	Note      string
	Rejoin    bool
	Networks  []string
	BoxNumber string
	CanText   bool
	SMSLink   template.URL
	PairCode  string
	NumTo     string
	Paired    string // the owner's number, masked
	OTPLink   template.URL
	OTPQR     template.HTML
	OTPSecret string
	// CodesEnrolled: the vault already holds a sealed seed, so the codes
	// step shows none and only continues.
	CodesEnrolled bool
	// CodesUnavailable: the vault cannot finish setup's enrollment, so the
	// codes step offers nothing to do (ErrCodesUnavailable).
	CodesUnavailable bool
	// CodesShown: the link was shown already; the step asks for its code
	// and offers a new one.
	CodesShown bool
	// Replace is replaceCodesNote while ReplaceCodes is set; CardRestart
	// is cardRestartNote.
	Replace     string
	CardRestart string
	Defaults    string
	Providers   []Provider
	Device      map[string][3]string
	// Ended names each provider whose shown code's sign-in no longer
	// waits and did not connect: its code is off the page and it shows
	// as ended, with a new-code control (UX3-F2).
	Ended map[string]bool
	// Plan and Key are each provider's private-content box on its plan
	// sign-in and API key forms.
	Plan, Key map[string]privateBox
	// Unsaved is the retry box of each provider whose answer did not
	// save (#1467).
	Unsaved map[string]*privateBox
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
	u.voidCodes()
	u.retryCard(key)
	p := u.s.cfg.Hooks.Progress()
	if u.stepIs("ai") {
		u.maybeFinish()
		if u.done() {
			http.Redirect(w, r, "/status", http.StatusSeeOther)
			return
		}
	}
	v := setupView{Progress: p, Defaults: u.s.cfg.Defaults, Device: map[string][3]string{}}
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
	v.CardRestart = cardRestartNote
	if u.st.ReplaceCodes {
		v.Replace = replaceCodesNote
	}
	noStation := p.NeverOnline && u.s.cfg.Station != nil && !u.s.cfg.Station()
	if p.NeverOnline {
		v.Note = neverOnlineNote
		if u.st.Owner != "" || noStation {
			v.Note = neverOnlinePairedNote
		}
	}
	if u.st.Owner != "" {
		v.Paired = mask(u.st.Owner)
	}
	for k, d := range u.device {
		v.Device[k] = d
	}
	if key == u.numDevice {
		v.NumTo = u.numTo
	}
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
		v.CodesShown = u.shown && u.shownGen == u.gen
	}
	gen := u.gen
	u.mu.Unlock()
	if err != nil {
		http.Error(w, "Setup could not start this step. Reload the page.", http.StatusInternalServerError)
		return
	}
	switch v.Step {
	case "network":
		v.Networks = u.s.cfg.Hooks.Networks()
	case "number":
		n, ok := u.s.cfg.Hooks.BoxNumber()
		v.CanText = ok
		if ok && phoneRe.MatchString(n) {
			v.BoxNumber, v.SMSLink = n, smsLink(n, "PAIR "+v.PairCode)
		}
		if p.NeverOnline && !noStation {
			v.Rejoin, v.Networks = true, u.s.cfg.Hooks.Networks()
		}
	case "codes":
		if v.CodesShown {
			break
		}
		// Only the phone that paired gets here (mayLocked). The seed is
		// made in the vault process, a new one each time a link is shown.
		link, err := u.s.cfg.Hooks.EnrollCode()
		switch {
		case errors.Is(err, ErrCodesEnrolled):
			v.CodesEnrolled = true
		case errors.Is(err, ErrCodesUnavailable):
			v.CodesUnavailable, v.Err = true, cannotFinish
		case errors.Is(err, ErrCodesLimited):
			v.Err = "Too many new codes in a minute. Wait a minute, then reload this page."
		case err != nil:
			http.Error(w, "Setup could not start this step. Reload the page.", http.StatusInternalServerError)
			return
		default:
			secret, ok := otpSecret(link)
			if !ok {
				http.Error(w, "Setup could not start this step. Reload the page.", http.StatusInternalServerError)
				return
			}
			v.OTPSecret, v.OTPLink = secret, template.URL(link)
			if v.OTPQR, err = card.QRSVG(link); err != nil {
				http.Error(w, "Setup could not start this step. Reload the page.", http.StatusInternalServerError)
				return
			}
			u.mu.Lock()
			if u.gen == gen {
				u.shown, u.shownGen = true, gen
			}
			u.mu.Unlock()
		}
	case "ai":
		v.Providers = u.s.cfg.Hooks.Providers()
		v.Plan, v.Key, v.Unsaved, v.Ended = map[string]privateBox{}, map[string]privateBox{}, map[string]*privateBox{}, map[string]bool{}
		u.mu.Lock()
		for _, pr := range v.Providers {
			// u.device keeps the code so the new-code control still works.
			if _, shown := v.Device[pr.ID]; shown && !pr.SigningIn && !pr.Connected {
				delete(v.Device, pr.ID)
				v.Ended[pr.ID] = true
			}
			v.Plan[pr.ID] = u.boxLocked("ai-device", pr)
			v.Key[pr.ID] = u.boxLocked("ai-key", pr)
			if ok, held := u.st.Unsaved[pr.ID]; held {
				v.Unsaved[pr.ID] = &privateBox{Name: pr.Name, Checked: ok || pr.PrivateByConfig, Fixed: pr.PrivateByConfig}
			}
		}
		u.mu.Unlock()
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

// otpSecret checks an enrollment link from the vault process and returns
// its base32 secret, for typing by hand. The link goes into an href as
// is, so anything but an otpauth TOTP link with a well-formed secret is
// refused.
func otpSecret(link string) (string, bool) {
	if len(link) > 512 || !strings.HasPrefix(link, "otpauth://totp/") {
		return "", false
	}
	u, err := url.Parse(link)
	if err != nil {
		return "", false
	}
	secret := u.Query().Get("secret")
	if !otpSecretRe.MatchString(secret) {
		return "", false
	}
	return secret, true
}

var otpSecretRe = regexp.MustCompile(`^[A-Z2-7]{16,64}$`)

func (u *setup) network(r *http.Request, _ string) error {
	ssid, pw := r.PostFormValue("ssid"), r.PostFormValue("password")
	if o := r.PostFormValue("other"); o != "" {
		ssid = o // a name typed because the list missed it
	}
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
		if u.s.cfg.Station != nil && !u.s.cfg.Station() {
			return errors.New(noWiFiJoin)
		}
		if err := u.s.cfg.Hooks.JoinNetwork(ssid, pw); errors.Is(err, ErrWiFiUnavailable) {
			return errors.New(noWiFiJoin)
		} else if err != nil {
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
		return "", true
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

// hostMax is the most of the pairing reply the PC's name and RAM take;
// agentosd sends no longer one (localapi.SetupText).
const hostMax = localapi.SetupHostMax

// pairedText names the PC in the pairing reply. The host keeps no '.',
// '/' or ':' and starts with a letter or digit, as localapi.SetupText
// allows, so no link or domain can ride in it.
func pairedText(host string) string {
	host = strings.Map(func(r rune) rune {
		if strings.ContainsRune(".:/", r) {
			return -1
		}
		return r
	}, host)
	host = strings.TrimLeft(gsmSafe(host, hostMax), " ,()+'-")
	if host == "" {
		host = "this PC"
	}
	return "agentOS is running on " + host + ". This is your box's number; save it as agentOS."
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
	if err := u.s.cfg.Hooks.Send(n, "agentOS setup code: "+code+". Type it on the setup page."); err != nil {
		return errors.New("I could not send a text. Check the SIM, or use Text my box.")
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
	if u.s.cfg.Hooks.Send(to, pairedText(u.s.cfg.Hooks.HostInfo())) != nil {
		// #1293: paired regardless; the owner learns the box's number
		// from the code text instead.
		return errPairedUnsent
	}
	return nil
}

// errPairedUnsent is the number step's note when the paired text did not
// go (#1293). The pairing stands, so the page moves on and shows it once.
var errPairedUnsent = errors.New("You are paired, but my text did not go. Save the number my code came from as agentOS.")

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
		return errors.New("That code did not match. Use the page code I texted you.")
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
	if err := u.s.cfg.Hooks.Send(to, "agentOS page code: "+code+". Type it on the setup page."); err != nil {
		return errors.New("I could not send a text. Check the SIM.")
	}
	return errors.New("That code did not match. I texted you a new page code.")
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
	if u.st.Done {
		return errSetupDone
	}
	if u.st.Owner == "" {
		return nil
	}
	if u.finishing {
		return errors.New("Setup is finishing. Reload the page.")
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
	u.gen++
	u.pair, u.pairOrder = map[string]string{}, nil
	u.claimCode, u.numCode, u.numTo, u.numDevice = "", "", "", ""
	u.device, u.parked, u.lapsed, u.answer = map[string][3]string{}, map[string][3]string{}, map[string][3]string{}, map[string]bool{}
	return u.save(func(s *SetupState) {
		s.Owner, s.Device, s.Codes, s.Recovery, s.Host, s.HostTrusted = "", "", false, false, false, false
	})
}

// codes confirms code-generator enrollment with one entered code (ONB-3)
// from the newest seed the vault process made. "enrolled" continues past
// a vault that already holds a sealed seed, which the vault itself
// reports again.
func (u *setup) codes(r *http.Request, _ string) error {
	got := strings.TrimSpace(r.PostFormValue("code"))
	u.mu.Lock()
	paired, gen := u.st.Owner != "", u.gen
	u.mu.Unlock()
	if !paired {
		return errors.New("Start this step again.")
	}
	var ok bool
	var err error
	if r.PostFormValue("new") == "1" {
		u.mu.Lock()
		u.shown = false
		u.mu.Unlock()
		return nil
	}
	if r.PostFormValue("enrolled") == "1" {
		if _, err = u.s.cfg.Hooks.EnrollCode(); err == nil {
			return errors.New("Start this step again.")
		}
	} else if got == "" || len(got) > 64 {
		return errors.New("That code did not match. Type the code your phone shows now.")
	} else {
		ok, err = u.s.cfg.Hooks.ConfirmCode(got)
	}
	switch {
	case errors.Is(err, ErrCodesEnrolled):
	case errors.Is(err, ErrCodesUnavailable):
		return errors.New(cannotFinish)
	case errors.Is(err, ErrNoCodeEnrollment):
		u.mu.Lock()
		u.shown = false
		u.mu.Unlock()
		return errors.New("That key is no longer waiting. Add the new one below.")
	case errors.Is(err, ErrCodesLimited):
		return errors.New("Too many wrong codes. Wait a few minutes, then try again.")
	case err != nil:
		return errors.New("Could not check the code. Try again.")
	case !ok:
		return errors.New("That code did not match. Type the code your phone shows now.")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.gen != gen || u.st.Owner == "" {
		// Setup started over while the code was checked.
		return errors.New("Start this step again.")
	}
	return u.save(func(s *SetupState) { s.Codes, s.ReplaceCodes = true, false })
}

// voidCodes takes CodesVoid: when the vault voided the code generator
// entry, step 3 is not done until a new code is confirmed, and its link is
// shown afresh. It reports whether it took a mark.
func (u *setup) voidCodes() bool {
	if !u.s.cfg.CodesVoid.Take() {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.shown = false
	if err := u.save(func(s *SetupState) { s.Codes, s.ReplaceCodes = false, true }); err != nil && !u.st.Done {
		// Held in memory regardless, so this start cannot pass the
		// card step on a void code generator.
		u.st.Codes, u.st.ReplaceCodes = false, true
	}
	return true
}

func (u *setup) recovery(r *http.Request, _ string) error {
	if r.PostFormValue("stored") == "" {
		return errors.New("Tear off the recovery sheet, store it, then tick the checkbox.")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.st.Codes {
		return errors.New("Add approval codes first.")
	}
	if u.cardHeld() {
		return errCardFirst
	}
	return u.save(func(s *SetupState) { s.Recovery = true })
}

// errNoTrustChip is the host step's text for a PC without a TPM (CH-12).
var errNoTrustChip = errors.New(`This PC has no security chip, so it cannot restart your box by itself. Tick "This is not my PC" to continue.`)

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
		// The page shows one text for every cause but a PC with no TPM;
		// the journal keeps the real one (it holds no secret) for the e2e
		// driver and the owner.
		log.Printf("localui: setup host hook: %v", err)
		if errors.Is(err, ErrNoTrustChip) {
			return errNoTrustChip
		}
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
	if p := u.s.cfg.Hooks.Progress(); !p.Updated {
		if p.Phase == "offline" {
			return errors.New("I am offline and have not updated yet. AI can be connected once I am online and updated.")
		}
		return errors.New("I am still updating. AI can be connected when I finish.")
	}
	return nil
}

// boxLocked is a form's private-content box: as the owner left it on a
// form that did not go through, else yes on a plan sign-in and no on an
// API key (D-115, §8.1 step 6). A provider the configuration allows is
// ticked and fixed (#1608). Caller holds u.mu.
func (u *setup) boxLocked(form string, p Provider) privateBox {
	if p.PrivateByConfig {
		return privateBox{Name: p.Name, Checked: true, Fixed: true}
	}
	checked, ok := u.answer[form+" "+p.ID]
	if !ok {
		// A yes already given for this provider holds on every route, so
		// saving a key after a plan sign-in doesn't undo it (R1).
		checked = form == "ai-device" || p.PrivateOK
	}
	return privateBox{Name: p.Name, Checked: checked}
}

// keepAnswer keeps the owner's private-content answer from a form that
// did not go through, for the page only (U-4).
func (u *setup) keepAnswer(r *http.Request, form, id string) {
	u.mu.Lock()
	u.answer[form+" "+id] = r.PostFormValue("private") != ""
	u.mu.Unlock()
}

// errUnsaved is the page's text for a private-content answer that did not
// save.
var errUnsaved = errors.New("Could not save. Try again.")

// errUnkept is the page's text for a private-content answer the vault did
// not save and the page could not hold on disk either (HeldStore, L55): the
// answer holds only until the box restarts, so the owner hears that, not
// the vault-failure text (#1888 Security R1).
var errUnkept = errors.New("I could not save your answer, and I could not keep it through a restart either. Try again before you turn me off.")

// privateOK records the owner's CAP-9 answer for a provider once its form
// went through, never before (U-4), and releases the provider's hold. A
// failed save keeps the box as the owner left it and holds setup open on
// the answer (#1467). A provider the configuration allows takes no answer
// from the page, whatever was posted: its box is fixed (#1608).
func (u *setup) privateOK(r *http.Request, form, id string) error {
	if u.providerHas(id, func(p Provider) bool { return p.PrivateByConfig }) {
		u.mu.Lock()
		defer u.mu.Unlock()
		delete(u.answer, form+" "+id)
		if err := u.holdLocked(id, nil); err != nil {
			return errUnsaved
		}
		return nil
	}
	ok := r.PostFormValue("private") != ""
	if err := u.s.cfg.Hooks.SetPrivateOK(id, ok); err != nil {
		u.keepAnswer(r, form, id)
		u.mu.Lock()
		herr := u.holdLocked(id, &ok)
		u.mu.Unlock()
		if herr != nil {
			return errUnkept
		}
		return errUnsaved
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.answer, form+" "+id)
	if err := u.holdLocked(id, nil); err != nil {
		return errUnsaved
	}
	return nil
}

// holdLocked sets provider id's unsaved answer to *ok, or clears it when
// ok is nil, in the setup record (#1467). A hold the store fails to save
// still holds in memory; a clear the store fails to save does not clear.
// Caller holds u.mu.
func (u *setup) holdLocked(id string, ok *bool) error {
	if _, held := u.st.Unsaved[id]; !held && ok == nil {
		return nil
	}
	m := make(map[string]bool, len(u.st.Unsaved)+1) // save copies the state shallowly
	for k, v := range u.st.Unsaved {
		m[k] = v
	}
	if ok == nil {
		delete(m, id)
	} else {
		m[id] = *ok
	}
	if len(m) == 0 {
		m = nil
	}
	err := u.save(func(s *SetupState) { s.Unsaved = m })
	if err != nil && ok != nil && !u.st.Done {
		u.st.Unsaved = m
	}
	return err
}

// begin claims provider id for one AI post, or refuses while another post
// for it is in flight or Finish runs; end releases it.
func (u *setup) begin(id string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	switch {
	case u.st.Done:
		return errSetupDone
	case u.finishing:
		return errors.New("Setup is finishing. Reload the page.")
	case u.busy[id]:
		return errors.New("I am still saving your last answer for this provider. Reload the page in a moment.")
	}
	u.busy[id] = true
	return nil
}

func (u *setup) end(id string) { u.mu.Lock(); delete(u.busy, id); u.mu.Unlock() }

// aiKey takes an API key typed on this page, never by text (§8.1 step 6).
// The key goes to the vault hook and is not kept, echoed, or logged.
// A no is saved before the key and a yes after it, so a failure or a
// restart at any point leaves the provider with no wider answer than the
// owner gave: a no that fails stores no key (#1467).
func (u *setup) aiKey(r *http.Request, _ string) error {
	if err := u.aiReady(); err != nil {
		return err
	}
	id, key := r.PostFormValue("provider"), strings.TrimSpace(r.PostFormValue("key"))
	if !u.providerHas(id, func(p Provider) bool { return p.APIKey }) || key == "" || len(key) > 512 || !printable(key) {
		return errors.New("Paste the API key from your provider's page.")
	}
	if err := u.begin(id); err != nil {
		return err
	}
	defer u.end(id)
	if r.PostFormValue("private") == "" {
		if err := u.privateOK(r, "ai-key", id); err != nil {
			return err
		}
	}
	if err := u.s.cfg.Hooks.ConnectAPIKey(id, key); err != nil {
		u.keepAnswer(r, "ai-key", id)
		return errors.New(keyErrText(err))
	}
	if r.PostFormValue("private") == "" {
		return nil
	}
	return u.privateOK(r, "ai-key", id)
}

// aiPrivate retries the private-content answer of a provider held by
// Unsaved, with the box alone (#1467).
func (u *setup) aiPrivate(r *http.Request, _ string) error {
	if err := u.aiReady(); err != nil {
		return err
	}
	id := r.PostFormValue("provider")
	u.mu.Lock()
	_, held := u.st.Unsaved[id]
	u.mu.Unlock()
	if !held {
		return errors.New("Choose a provider.")
	}
	if err := u.begin(id); err != nil {
		return err
	}
	defer u.end(id)
	u.mu.Lock()
	d, parked := u.parked[id]
	u.mu.Unlock()
	if parked {
		return u.showDevice(r, "ai-private", id, d)
	}
	return u.privateOK(r, "ai-private", id)
}

// keyErrText is the page's text for a key the vault did not store: only a
// key the provider refused is blamed on the provider (U-2, #1265).
func keyErrText(err error) string {
	switch {
	case errors.Is(err, ErrKeyRefused):
		return "The provider did not accept that key."
	case errors.Is(err, ErrKeyUnchecked):
		return "I could not reach the provider to check that key, so I did not save it. Try again in a minute."
	case errors.Is(err, ErrKeysLimited):
		return "Too many keys tried in the last minute. Wait a minute and try again."
	case errors.Is(err, ErrKeyNotTaken):
		return "Paste the API key from your provider's page."
	case errors.Is(err, ErrSetupClosed):
		return errSetupDone.Error()
	case errors.Is(err, ErrCodesUnavailable):
		return cannotFinish
	}
	return "Could not save the key. Try again."
}

func (u *setup) aiDevice(r *http.Request, _ string) error {
	if err := u.aiReady(); err != nil {
		return err
	}
	id := r.PostFormValue("provider")
	if !u.providerHas(id, func(p Provider) bool { return p.DeviceCode }) {
		return errors.New("Choose a provider.")
	}
	if err := u.begin(id); err != nil {
		return err
	}
	defer u.end(id)
	d, err := u.startDevice(id)
	if errors.Is(err, ErrSignInBusy) {
		u.mu.Lock()
		d, parked := u.parked[id]
		if !parked { // this page's own sign-in a failed new code took off
			d, parked = u.lapsed[id]
		}
		u.mu.Unlock()
		if parked { // this page's own sign-in, still waiting
			return u.showDevice(r, "ai-device", id, d)
		}
		u.keepAnswer(r, "ai-device", id)
		return errors.New("A sign-in with that provider is still waiting. Enter its code on the provider's page, or try again once the code expires.")
	}
	if err != nil {
		if errors.Is(err, errRefused) { // a new sign-in started, so no older one waits
			u.mu.Lock()
			delete(u.device, id) // a stale tab's Sign in while a code shows (#2336)
			delete(u.parked, id)
			delete(u.lapsed, id)
			u.mu.Unlock()
		}
		u.keepAnswer(r, "ai-device", id)
		return errors.New("Could not start sign-in with that provider. Try again.")
	}
	return u.showDevice(r, "ai-device", id, d)
}

// errRefused: the provider started a new sign-in but the page will not
// show it. The provider's older sign-in has then ended, since a start
// while one waits answers busy.
var errRefused = errors.New("sign-in refused")

// startDevice starts provider id's device-code sign-in and answers its
// link, code and issuer, refusing (errRefused) a link that is not https
// or a code with no issuer.
func (u *setup) startDevice(id string) ([3]string, error) {
	link, code, from, err := u.s.cfg.Hooks.StartDeviceCode(id)
	if err == nil {
		if pu, perr := url.Parse(link); perr != nil || pu.Scheme != "https" || pu.Host == "" {
			err = fmt.Errorf("%w: not https", errRefused)
		} else if from == "" {
			err = fmt.Errorf("%w: no issuer", errRefused) // the page names who sent the code (§8.1 step 6)
		}
	}
	return [3]string{link, code, from}, err
}

// aiRetry gets a new code for the sign-in this page shows (UX3-1): the
// owner asks once the shown code expired or was declined on the
// provider's page. While the provider's sign-in still waits it keeps the
// shown code, which still works; a new one replaces it; any other answer
// takes the shown code off the page (lapsed), since nothing then shows
// it still waits, and offers Sign in again. A new code the page refuses
// drops the shown one outright: its sign-in has ended. The private answer was saved
// when the shown sign-in started, so it is not asked or saved again.
func (u *setup) aiRetry(r *http.Request, _ string) error {
	if err := u.aiReady(); err != nil {
		return err
	}
	id := r.PostFormValue("provider")
	u.mu.Lock()
	_, shown := u.device[id]
	u.mu.Unlock()
	if !shown || !u.providerHas(id, func(p Provider) bool { return p.DeviceCode }) {
		return errors.New("Choose a provider.")
	}
	if err := u.begin(id); err != nil {
		return err
	}
	defer u.end(id)
	d, err := u.startDevice(id)
	u.mu.Lock()
	defer u.mu.Unlock()
	old, shown := u.device[id]
	if !shown { // a restart took it meanwhile
		return errors.New("Choose a provider.")
	}
	switch {
	case errors.Is(err, ErrSignInBusy):
		return errors.New("Your code is still waiting. Enter it on the provider's page, or get a new code once it expires.")
	case errors.Is(err, errRefused): // the shown code's sign-in ended
		delete(u.device, id)
		delete(u.parked, id)
		delete(u.lapsed, id)
		return errors.New("Could not get a new code. Sign in again, or try again in a minute.")
	case err != nil:
		delete(u.device, id)
		u.lapsed[id] = old
		return errors.New("Could not get a new code. Sign in again, or try again in a minute.")
	}
	delete(u.lapsed, id)
	u.device[id] = d
	return nil
}

// showDevice saves the owner's private answer for a started sign-in and
// then shows its link; while the answer is unsaved the link is parked,
// not shown (#1467), and it comes back once the answer saves.
func (u *setup) showDevice(r *http.Request, form, id string, d [3]string) error {
	err := u.privateOK(r, form, id)
	u.mu.Lock()
	defer u.mu.Unlock()
	if err != nil {
		delete(u.device, id)
		u.parked[id] = d
		return err
	}
	delete(u.parked, id)
	delete(u.lapsed, id)
	u.device[id] = d
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
	// An unsaved answer, or an AI post in flight, holds setup open (#1467).
	if !u.st.Host || u.st.Done || u.finishing || len(u.st.Unsaved) > 0 || len(u.busy) > 0 {
		u.mu.Unlock()
		return
	}
	u.finishing = true
	who := u.st.Owner
	u.mu.Unlock()
	defer func() { u.mu.Lock(); u.finishing = false; u.mu.Unlock() }()
	// agentosd keeps each answer owed to the vault in its own record,
	// which outlives this page's store (#1544): adopt it as a hold, so a
	// page restart after a failed save shows the retry. finishing keeps AI
	// posts out meanwhile, so no save races the list.
	ps := u.s.cfg.Hooks.Providers()
	u.mu.Lock()
	for _, p := range ps {
		if _, held := u.st.Unsaved[p.ID]; p.Owed != nil && !held {
			u.holdLocked(p.ID, p.Owed) // a hold the store fails to save still holds
		}
	}
	held := len(u.st.Unsaved) > 0
	u.mu.Unlock()
	if held {
		return
	}
	if u.cardHeld() {
		// HW-1: the box finishes only once the owner holds the card.
		u.mu.Lock()
		u.err[u.st.Device] = errCardFirst.Error()
		u.mu.Unlock()
		return
	}
	connected := false
	for _, p := range ps {
		connected = connected || p.Connected
	}
	if !connected {
		return
	}
	if err := u.s.cfg.Hooks.Finish(who); err != nil && !u.s.cfg.Hooks.AlreadySetUp() {
		msg := "Could not finish setup. Try again."
		switch {
		case errors.Is(err, ErrCodesUnavailable):
			msg = cannotFinish
		case errors.Is(err, ErrAnswerOwed):
			msg = answerOwed
		case errors.Is(err, ErrCardAgain):
			msg = cardAgain
		}
		u.mu.Lock()
		defer u.mu.Unlock()
		// A rerun that failed (its vault reset did) leaves the card held
		// with none shown (#2362): back to the card step, whose page
		// retries it.
		rerunFailed := !errors.Is(err, ErrCardAgain) && u.cardHeld()
		if rerunFailed {
			msg = cardNotMade
		}
		u.err[u.st.Device] = msg
		if errors.Is(err, ErrCardAgain) || rerunFailed {
			// The card step comes before the recovery step: the new card
			// is shown only once the recovery step is open again. A store
			// that fails to save still routes in memory.
			if u.save(func(s *SetupState) { s.Recovery = false }) != nil {
				u.st.Recovery = false
			}
		}
		return
	}
	// Finish succeeded, or failed after the owner channel came to exist:
	// either way setup is over.
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := u.save(func(s *SetupState) { s.Done = true }); err != nil {
		// Finish already ran: keep setup closed in memory so it is not
		// called twice, and let AlreadySetUp close it after a restart.
		u.st.Done = true
	}
}

// retryCard retries the card step's rerun when its vault reset failed
// (#2362, firstboot.RetryRerun), so setup does not wait for a restart. Only
// the paired phone's page load retries it.
func (u *setup) retryCard(key string) {
	if u.s.cfg.Card == nil {
		return
	}
	u.mu.Lock()
	paired := !u.st.Done && u.st.Device != "" && key == u.st.Device
	u.mu.Unlock()
	if !paired {
		return
	}
	retried, err := firstboot.RetryRerun(u.s.cfg.Card)
	if !retried {
		return
	}
	msg := cardAgain
	if err != nil {
		msg = cardNotMade
	}
	u.mu.Lock()
	u.err[key] = msg
	u.mu.Unlock()
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
