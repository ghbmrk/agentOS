package localsrv

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/privfile"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Setup serves setup's ops on localui.sock (P2-2w c2; Security L6 on the
// P2-2w plan) on a box with no owner yet. It is a separate server from
// Server: agentosd runs it alone, before the owner channel exists, and
// stops it once finish is recorded; Server's ops never include setup's.
// Setup itself refuses every op once its record says finished, or when
// the record cannot be read, so a restart, a second instance or a lost
// race cannot reopen it. The code generator's seed is made in the vault
// process (egress K17): Setup relays its link and never keeps it, and
// finish has the vault seal the seed the finishing pairing confirmed.
type Setup struct {
	cfg SetupConfig

	// answer serializes private-data answers, so an owed answer is
	// cleared only by the call that owed it (#1544).
	answer  sync.Mutex
	mu      sync.Mutex
	rec     SetupRecord
	closed  bool
	enrolls []time.Time
	joins   []time.Time
	keys    []time.Time
	scans   []time.Time
	texts   []time.Time
	signins []time.Time
}

// SetupConfig configures a Setup.
type SetupConfig struct {
	// Record is setup's durable record (FileRecord).
	Record RecordStore
	// Enroll is the vault process's enrollment (modelroute.Verifier),
	// its refusals mapped to EnrollClosed, EnrollNotOpen, EnrollNone and
	// EnrollPaused.
	Enroll Enroller
	// Progress is the box's boot progress for setup's pages.
	Progress func() localapi.SetupProgress
	// Finished is called once, after finish is recorded, with the owner's
	// number. It must not block.
	Finished func(owner string)
	// Join has the netjoin helper join the home Wi-Fi (P2-2w c3;
	// Security L8): nil when it joined or saved the network, an error
	// otherwise. JoinUnavailable answers ErrJoinUnavailable, any other
	// error, or nil Join, answers ErrNotJoined. The
	// password goes nowhere else: not the record, not an error, not a log.
	Join func(ctx context.Context, ssid, password string) error
	// Providers is the vault process's provider setup (P2-2w c4e). Nil
	// lists no provider and refuses every key.
	Providers Providers
	// SignIn starts a provider's plan sign-in (c4e2). Nil, or a provider
	// it is not Ready for, lists that provider without device code and
	// refuses its sign-in.
	SignIn SignIn
	// Networks lists the home networks the helper sees (P2-2w c4b).
	// Nil Networks, or an error, answers an empty list.
	Networks func(ctx context.Context) ([]string, error)
	// Line is the owner line's modem bridge while setup runs (P2-2w c4c;
	// modemlink.SetupLine); nil answers that setup cannot text.
	Line SetupLine
	Now  func() time.Time
}

// Enroller is the vault process's code-generator enrollment (egress K17).
type Enroller interface {
	Enroll() (uri string, err error)
	ConfirmEnroll(code string) (bool, error)
	// SealEnroll closes enrollment for good. EnrollNone: no seed was
	// confirmed since the last Enroll.
	SealEnroll() error
}

// The vault's refusals, as an Enroller reports them.
var (
	// EnrollClosed: setup's seal is written (410). Setup counts it as
	// enrolled only after a confirmation it saw, with no seed since.
	EnrollClosed = errors.New("enrollment closed")
	// EnrollNotOpen: init -setup never opened enrollment (412); setup
	// cannot finish on this vault (P2-2w c2 r1).
	EnrollNotOpen = errors.New("enrollment not open")
	// EnrollNone: no seed waits for confirmation (409).
	EnrollNone = errors.New("no enrollment waiting")
	// EnrollCardRequired: the vault holds no Owner Card (428); finish
	// answers "card pending".
	EnrollCardRequired = errors.New("vault has no Owner Card")
	// EnrollPaused: too many wrong codes for now (429).
	EnrollPaused = errors.New("enrollment paused")
)

// EnrollsPerMinute bounds new seeds: each enroll writes one to the vault.
const EnrollsPerMinute = 6

// JoinsPerMinute bounds join tries: each one writes NetworkManager's
// stored connection (Security L6.4).
const JoinsPerMinute = 6

// ScansPerMinute bounds network lists: each one has the helper read
// NetworkManager's access points.
const ScansPerMinute = 20

// SetupRecord is setup's durable record. It holds no secret.
type SetupRecord struct {
	// Enrolled: agentosd saw the vault confirm a code from a new seed and
	// has asked for no seed since. The vault's seal at finish is what
	// decides; this only spares it a call.
	Enrolled bool   `json:"enrolled"`
	Finished bool   `json:"finished"`
	Owner    string `json:"owner,omitempty"`
	// Owed maps a provider the vault lists to the owner's private-data
	// answer that the vault has not confirmed (#1544, CAP-9). It is
	// written before the vault is asked and cleared once the vault
	// records the answer; finish waits while any answer is owed, so setup
	// never finishes with the vault keeping an older, wider answer.
	Owed map[string]bool `json:"owed,omitempty"`
}

// RecordStore persists SetupRecord.
type RecordStore interface {
	Load() (SetupRecord, error)
	Save(SetupRecord) error
}

// FileRecord keeps SetupRecord in one JSON file, mode 0600, replaced
// atomically. A missing file is an empty record.
type FileRecord struct{ Path string }

func (f FileRecord) Load() (SetupRecord, error) {
	var r SetupRecord
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return SetupRecord{}, err
	}
	if r.Finished && !phoneRe.MatchString(r.Owner) {
		return SetupRecord{}, errors.New("setup record: finished without a well-formed owner")
	}
	return r, nil
}

func (f FileRecord) Save(r SetupRecord) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return privfile.WriteAtomic(filepath.Dir(f.Path), filepath.Base(f.Path), b, nil)
}

var phoneRe = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

var (
	errSetupClosed  = sockets.Code(localapi.ErrSetupClosed)
	errEnrolled     = sockets.Code(localapi.ErrEnrolled)
	errNoEnrollment = sockets.Code(localapi.ErrNoEnrollment)
	errNotEnrolled  = sockets.Code(localapi.ErrNotEnrolled)
	errUnavailable  = sockets.Code(localapi.ErrEnrollUnavailable)
	errCardPending  = sockets.Code(localapi.ErrCardPending)
	errNotJoined    = sockets.Code(localapi.ErrNotJoined)
	errNoJoin       = sockets.Code(localapi.ErrJoinUnavailable)
	errAnswerOwed   = sockets.Code(localapi.ErrAnswerOwed)
)

// JoinUnavailable: the box cannot join Wi-Fi at all, so the page should
// not ask for the password again (#1429).
var JoinUnavailable = errors.New("home Wi-Fi join unavailable")

// NewSetup reads the record; one that cannot be read closes setup.
func NewSetup(cfg SetupConfig) *Setup {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Setup{cfg: cfg}
	rec, err := cfg.Record.Load()
	s.rec, s.closed = rec, err != nil || rec.Finished
	return s
}

// Owner is the owner's number once finish is recorded.
func (s *Setup) Owner() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rec.Owner, s.rec.Finished
}

// Closed reports whether setup's ops are refused.
func (s *Setup) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Ops are setup's handlers, keyed by op name.
func (s *Setup) Ops() map[string]sockets.Handler {
	return map[string]sockets.Handler{
		localapi.OpSetupProgress: s.open(s.progress),
		localapi.OpSetupEnroll:   s.open(s.enroll),
		localapi.OpSetupConfirm:  s.open(s.confirm),
		localapi.OpSetupFinish:   s.open(s.finish),
		localapi.OpSetupJoin:     s.open(s.join),
		localapi.OpSetupNetworks: s.open(s.networks),
		localapi.OpSetupLine:     s.open(s.line),
		localapi.OpSetupSend:     s.open(s.send),
		localapi.OpSetupInbound:  s.open(s.inbound),

		localapi.OpSetupProviders: s.open(s.providers),
		localapi.OpSetupAPIKey:    s.open(s.apiKey),
		localapi.OpSetupPrivateOK: s.open(s.privateOK),

		localapi.OpSetupDeviceCode: s.open(s.deviceCode),
	}
}

// open refuses h once setup is closed. The ops that change the record
// check again under the lock, so one that raced finish changes nothing.
func (s *Setup) open(h sockets.Handler) sockets.Handler {
	return func(ctx context.Context, p sockets.Peer, args json.RawMessage) (any, error) {
		if s.Closed() {
			return nil, errSetupClosed
		}
		return h(ctx, p, args)
	}
}

func (s *Setup) progress(context.Context, sockets.Peer, json.RawMessage) (any, error) {
	if s.cfg.Progress == nil {
		return localapi.SetupProgress{Phase: "booting"}, nil
	}
	return s.cfg.Progress(), nil
}

func (s *Setup) enroll(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	if err := decode(args, &struct{}{}); err != nil {
		return nil, err
	}
	if !s.allow(&s.enrolls, EnrollsPerMinute) {
		return nil, errLimited
	}
	uri, err := s.cfg.Enroll.Enroll()
	if err != nil {
		// A refused enroll replaced nothing, so a confirmation recorded
		// before it still stands (P2-2w c2 r1): it is what lets finish
		// accept a seal whose record was lost.
		return nil, s.vaultErr(err)
	}
	// A new seed is for a pairing that has yet to confirm (L3 on #367).
	// The vault decides at the seal: a crash before this save leaves a
	// pending seed, which the seal refuses.
	if err := s.setEnrolled(false); err != nil {
		return nil, err
	}
	if len(uri) > localapi.MaxEnrollLink || !strings.HasPrefix(uri, "otpauth://totp/") {
		return nil, errFailed
	}
	return localapi.EnrollLink{URI: uri}, nil
}

// allow counts one try in *tries unless n were made in the last minute.
func (s *Setup) allow(tries *[]time.Time, n int) bool {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := (*tries)[:0]
	for _, t := range *tries {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	*tries = kept
	if len(kept) >= n {
		return false
	}
	*tries = append(kept, now)
	return true
}

// join hands the home network to the helper (P2-2w c3). agentosd checks
// the shape only (Security L8.8); the helper checks the exact rule. No
// lock is held across the call, which can take up to the helper's wait.
func (s *Setup) join(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var a localapi.Join
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	if !s.allow(&s.joins, JoinsPerMinute) {
		return nil, errLimited
	}
	if len(a.SSID) == 0 || len(a.SSID) > localapi.MaxSSID ||
		len(a.Password) < localapi.MinPassword || len(a.Password) > localapi.MaxPassword {
		return nil, errBadArgs
	}
	if s.cfg.Join == nil {
		return nil, errNotJoined
	}
	if err := s.cfg.Join(ctx, a.SSID, a.Password); errors.Is(err, JoinUnavailable) {
		return nil, errNoJoin
	} else if err != nil {
		return nil, errNotJoined
	}
	return struct{}{}, nil
}

// networks relays the helper's list of home networks (P2-2w c4b). Past
// ScansPerMinute, with no helper or on its error, the list is empty: the
// page then takes a typed name.
func (s *Setup) networks(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	if err := decode(args, &struct{}{}); err != nil {
		return nil, err
	}
	none := localapi.Networks{SSIDs: []string{}}
	if s.cfg.Networks == nil || !s.allow(&s.scans, ScansPerMinute) {
		return none, nil
	}
	l, err := s.cfg.Networks(ctx)
	if err != nil || l == nil {
		return none, nil
	}
	if len(l) > localapi.MaxNetworks {
		l = l[:localapi.MaxNetworks]
	}
	return localapi.Networks{SSIDs: l}, nil
}

func (s *Setup) confirm(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var a localapi.Confirm
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	if a.Code == "" || len(a.Code) > localapi.MaxCode {
		return nil, errBadArgs
	}
	ok, err := s.cfg.Enroll.ConfirmEnroll(a.Code)
	if err != nil {
		return nil, s.vaultErr(err)
	}
	if ok {
		if err := s.setEnrolled(true); err != nil {
			return nil, err
		}
	}
	return localapi.Confirmed{OK: ok}, nil
}

// vaultErr maps the vault's refusal to a fixed code. A sealed vault is
// "enrolled" only when finish would accept it: after a confirmation this
// Setup saw, with no seed since. Otherwise setup cannot finish here.
func (s *Setup) vaultErr(err error) error {
	switch {
	case errors.Is(err, EnrollClosed):
		s.mu.Lock()
		enrolled := s.rec.Enrolled
		s.mu.Unlock()
		if enrolled {
			return errEnrolled
		}
		return errUnavailable
	case errors.Is(err, EnrollNotOpen):
		return errUnavailable
	case errors.Is(err, EnrollNone):
		return errNoEnrollment
	case errors.Is(err, EnrollPaused):
		return errLimited
	}
	return errFailed
}

func (s *Setup) setEnrolled(v bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setEnrolledLocked(v)
}

func (s *Setup) setEnrolledLocked(v bool) error {
	if s.closed {
		return errSetupClosed
	}
	if s.rec.Enrolled == v {
		return nil
	}
	next := s.rec
	next.Enrolled = v
	if s.cfg.Record.Save(next) != nil {
		return errFailed
	}
	s.rec = next
	return nil
}

func (s *Setup) finish(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var a localapi.Finish
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	if !phoneRe.MatchString(a.Owner) {
		return nil, errBadArgs
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errSetupClosed
	}
	if !s.rec.Enrolled {
		s.mu.Unlock()
		return nil, errNotEnrolled
	}
	if s.owedListedLocked() {
		s.mu.Unlock()
		return nil, errAnswerOwed
	}
	// The vault seals only a confirmation made since its last enroll. A
	// closed vault after a confirmation with no enroll since is this
	// Setup's own seal whose record was lost: nothing else seals.
	switch err := s.cfg.Enroll.SealEnroll(); {
	case err == nil, errors.Is(err, EnrollClosed):
	case errors.Is(err, EnrollNotOpen):
		s.mu.Unlock()
		return nil, errUnavailable
	case errors.Is(err, EnrollCardRequired):
		s.mu.Unlock()
		return nil, errCardPending
	case errors.Is(err, EnrollNone):
		err := s.setEnrolledLocked(false)
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, errNotEnrolled
	default:
		s.mu.Unlock()
		return nil, errFailed
	}
	next := s.rec
	next.Finished, next.Owner = true, a.Owner
	if s.cfg.Record.Save(next) != nil {
		s.mu.Unlock()
		return nil, errFailed
	}
	s.rec, s.closed = next, true
	s.mu.Unlock()
	if s.cfg.Finished != nil {
		s.cfg.Finished(a.Owner)
	}
	return struct{}{}, nil
}
