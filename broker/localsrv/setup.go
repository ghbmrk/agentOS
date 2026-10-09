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

	mu      sync.Mutex
	rec     SetupRecord
	closed  bool
	enrolls []time.Time
}

// SetupConfig configures a Setup.
type SetupConfig struct {
	// Record is setup's durable record (FileRecord).
	Record RecordStore
	// Enroll is the vault process's enrollment (modelroute.Verifier),
	// its refusals mapped to EnrollClosed, EnrollNone and EnrollPaused.
	Enroll Enroller
	// Progress is the box's boot progress for setup's pages.
	Progress func() localapi.SetupProgress
	// Finished is called once, after finish is recorded, with the owner's
	// number. It must not block.
	Finished func(owner string)
	Now      func() time.Time
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
	// EnrollClosed: enrollment is sealed, or was never opened (410).
	// Setup never counts it as enrolled: only a confirmation it saw does.
	EnrollClosed = errors.New("enrollment closed")
	// EnrollNone: no seed waits for confirmation (409).
	EnrollNone = errors.New("no enrollment waiting")
	// EnrollPaused: too many wrong codes for now (429).
	EnrollPaused = errors.New("enrollment paused")
)

// EnrollsPerMinute bounds new seeds: each enroll writes one to the vault.
const EnrollsPerMinute = 6

// SetupRecord is setup's durable record. It holds no secret.
type SetupRecord struct {
	// Enrolled: agentosd saw the vault confirm a code from a new seed and
	// has asked for no seed since. The vault's seal at finish is what
	// decides; this only spares it a call.
	Enrolled bool   `json:"enrolled"`
	Finished bool   `json:"finished"`
	Owner    string `json:"owner,omitempty"`
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
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".setup-*")
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
	if err := os.Rename(tmp.Name(), f.Path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(f.Path)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

var phoneRe = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

var (
	errSetupClosed  = sockets.Code(localapi.ErrSetupClosed)
	errEnrolled     = sockets.Code(localapi.ErrEnrolled)
	errNoEnrollment = sockets.Code(localapi.ErrNoEnrollment)
	errNotEnrolled  = sockets.Code(localapi.ErrNotEnrolled)
)

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
	now := s.cfg.Now()
	s.mu.Lock()
	kept := s.enrolls[:0]
	for _, t := range s.enrolls {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	s.enrolls = kept
	if len(s.enrolls) >= EnrollsPerMinute {
		s.mu.Unlock()
		return nil, errLimited
	}
	s.enrolls = append(s.enrolls, now)
	s.mu.Unlock()
	// A new seed is for a pairing that has yet to confirm (L3 on #367):
	// forget the confirmation before the vault replaces what it covers.
	if err := s.setEnrolled(false); err != nil {
		return nil, err
	}
	uri, err := s.cfg.Enroll.Enroll()
	if err != nil {
		return nil, s.vaultErr(err)
	}
	if len(uri) > localapi.MaxEnrollLink || !strings.HasPrefix(uri, "otpauth://totp/") {
		return nil, errFailed
	}
	return localapi.EnrollLink{URI: uri}, nil
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

// vaultErr maps the vault's refusal to a fixed code.
func (s *Setup) vaultErr(err error) error {
	switch {
	case errors.Is(err, EnrollClosed):
		return errEnrolled
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
	// The vault seals only a confirmation made since its last enroll. A
	// closed vault after a confirmation with no enroll since is this
	// Setup's own seal whose record was lost: nothing else seals.
	switch err := s.cfg.Enroll.SealEnroll(); {
	case err == nil, errors.Is(err, EnrollClosed):
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
