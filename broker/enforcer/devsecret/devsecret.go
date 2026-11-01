// Package devsecret is the enforcer's store of safety-list devices'
// secrets (SPEC STO-4, STO-3; briefs/ENF.md slice r, decision 10). A
// secret arrives sealed to the enforcer's pairing key (package pairseal)
// inside an add-device loosening, and the store opens it only for a diff
// the owner's passkey signed that adds that device and names that
// envelope's hash, while that loosening is the one waiting. It keeps the
// secrets in the enforcer's sealed state, releases each one only to the
// process that drives its device, reports only the envelope's hash to the
// channel, and erases a secret when its device leaves the policy or its
// loosening is cancelled.
//
// It is enforcer code: it imports the standard library,
// broker/kernel/key, broker/enforcer/policy and broker/enforcer/pairseal
// only (broker/daemon/arc2_test.go); the page and the channel do not link
// it. Its assumptions are in ASSUMPTIONS.md.
package devsecret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/ghbmrk/agentos/broker/enforcer/pairseal"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

var (
	ErrConfig    = errors.New("devsecret: bad config")
	ErrNotAdd    = errors.New("devsecret: the signed change does not add this safety-list device")
	ErrUnnamed   = errors.New("devsecret: the signed diff does not name this device's sealed secret")
	ErrNotLive   = errors.New("devsecret: the signed change is not the loosening waiting")
	ErrNoSecret  = errors.New("devsecret: no secret held for the device")
	ErrNotHolder = errors.New("devsecret: the asking process does not drive the device")
	ErrCorrupt   = errors.New("devsecret: stored state does not read")
)

// Policy is the part of policy.Engine the store reads. The caller holds the
// daemon's policy lock around every Store call, as the page does
// (page.Config.Lock), so the store reads one consistent policy.
type Policy interface {
	Current() policy.Document
	Pending() []policy.Pending
}

// Box seals the store's state as the enforcer seals all its state on its
// state partition (ENF-m). Open refuses state another box sealed or anyone
// changed.
type Box interface {
	Seal(plain []byte) ([]byte, error)
	Open(sealed []byte) ([]byte, error)
}

// Disk keeps the sealed state across restarts. Save replaces it whole; Load
// returns nil when nothing was saved.
type Disk interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// Peer is the process asking for a secret, as the daemon authenticated it:
// the user ID the kernel reports for the other end of its socket
// (SO_PEERCRED). Each radio stack and driver runs as its own user (ENF-k).
type Peer struct{ UID uint32 }

// Config is what the daemon (slice l) wires in.
type Config struct {
	// Owner is the enrolled owner's passkey, as the policy engine's.
	Owner key.PublicKey
	// Key is the enforcer's pairing key, from its sealed state.
	Key    *pairseal.Key
	Policy Policy
	Box    Box
	Disk   Disk
	// Process is the process that drives device: its radio stack's or
	// driver's user, from the signed policy and the radio host's layout.
	Process func(device string) (Peer, bool)
}

// Store is the enforcer's device-secret store. Its methods are safe for
// concurrent use.
type Store struct {
	cfg Config
	mu  sync.Mutex
	st  state
	// dirty is set while the disk holds a secret st has erased: a Prune
	// whose save failed. The next Prune saves while it is set.
	dirty bool
}

// state is what the store keeps, sealed by Box.
type state struct {
	// Floor is the highest version a secret was admitted under: an
	// assertion is good for one admission (replay).
	Floor   uint64            `json:"floor"`
	Secrets map[string]record `json:"secrets"`
}

type record struct {
	Serial  string                 `json:"serial"`  // the add-device version's key serial
	Version uint64                 `json:"version"` // its document's version
	Hash    [pairseal.HashLen]byte `json:"hash"`    // the envelope's hash
	Secret  []byte                 `json:"secret"`
}

// Open loads the store's state through cfg.Box.
func Open(cfg Config) (*Store, error) {
	if cfg.Owner.Alg() != key.AlgES256 || cfg.Key == nil || cfg.Policy == nil || cfg.Box == nil ||
		cfg.Disk == nil || cfg.Process == nil {
		return nil, ErrConfig
	}
	s := &Store{cfg: cfg, st: state{Secrets: map[string]record{}}}
	b, err := cfg.Disk.Load()
	if err != nil {
		return nil, err
	}
	if b == nil {
		return s, nil
	}
	plain, err := cfg.Box.Open(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	defer clear(plain)
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s.st); err != nil || dec.More() || s.st.Secrets == nil {
		return nil, ErrCorrupt
	}
	return s, nil
}

// Admit opens env, device's sealed secret, and holds it. prop and sig are
// the add-device loosening the owner approved on the page: sig must be the
// owner's passkey assertion over prop, prop must add device as a
// safety-list device to the policy in force, its diff must hold
// pairseal.Statement for device and env's hash, it must be the loosening
// waiting, and its version must be above every version a secret was
// admitted under. Then env must open for device with the enforcer's key.
func (s *Store) Admit(device string, env []byte, prop policy.Proposal, sig []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !pairseal.Device(device) {
		return pairseal.ErrDevice
	}
	cur := s.cfg.Policy.Current()
	k, err := policy.Verify(s.cfg.Owner, max(s.st.Floor, cur.Version), prop, sig)
	if err != nil {
		return err
	}
	if dev := prop.Doc.Device(device); dev == nil || dev.Everyday || cur.Device(device) != nil {
		return ErrNotAdd
	}
	if !slices.Contains(strings.Split(string(prop.Diff), "\n"), pairseal.Statement(device, pairseal.HashHex(env))) {
		return ErrUnnamed
	}
	if !slices.ContainsFunc(s.cfg.Policy.Pending(), func(p policy.Pending) bool { return p.ID == k.Root.Serial }) {
		return ErrNotLive
	}
	secret, err := s.cfg.Key.Open(device, env)
	if err != nil {
		return err
	}
	st := s.clone()
	old, had := st.Secrets[device]
	st.Secrets[device] = record{Serial: k.Root.Serial, Version: prop.Doc.Version, Hash: pairseal.Hash(env), Secret: secret}
	st.Floor = prop.Doc.Version
	if err := s.save(st); err != nil {
		clear(secret)
		return err
	}
	if had {
		clear(old.Secret)
	}
	return nil
}

// Fingerprint is device's secret's fingerprint, the hash of the envelope it
// arrived in: what the channel's fingerprint read reports, so the core
// knows the enforcer holds it and drops its sealed copy. Its type holds a
// hash and nothing else (channel.Config.Fingerprint).
func (s *Store) Fingerprint(device string) ([pairseal.HashLen]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.st.Secrets[device]
	return r.Hash, ok
}

// Release is device's secret for p, only if p is the process that drives
// device (Config.Process) and the add-device change it came with has
// landed: the device is a safety-list device in the policy in force at or
// above that version, and that change is no longer waiting. The caller
// gets its own copy.
func (s *Store) Release(device string, p Peer) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.st.Secrets[device]
	if !ok || !s.landed(r, device, s.cfg.Policy.Current()) {
		return nil, ErrNoSecret
	}
	if want, ok := s.cfg.Process(device); !ok || want != p {
		return nil, ErrNotHolder
	}
	return bytes.Clone(r.Secret), nil
}

func (s *Store) landed(r record, device string, cur policy.Document) bool {
	dev := cur.Device(device)
	return dev != nil && !dev.Everyday && r.Version <= cur.Version && !s.waiting(r)
}

func (s *Store) waiting(r record) bool {
	return slices.ContainsFunc(s.cfg.Policy.Pending(), func(p policy.Pending) bool { return p.ID == r.Serial })
}

// Prune erases every secret that is neither waiting on its add-device
// change nor landed with it: its device was removed or made everyday, or
// its change was cancelled. The page calls it after every change it
// approves or cancels and the daemon after every change that lands, under
// the policy lock, so a cancelled secret is gone before another change
// could add a device of the same name without one.
func (s *Store) Prune() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.cfg.Policy.Current()
	st := s.clone()
	gone := false
	for d, r := range st.Secrets {
		if !s.waiting(r) && !s.landed(r, d, cur) {
			delete(st.Secrets, d)
			gone = true
		}
	}
	if !gone && !s.dirty {
		return nil
	}
	old := s.st
	err := s.save(st)
	// Fail closed: an erase the disk refused still happens in memory, so
	// a cancelled or removed device's secret is never released, and dirty
	// makes every later Prune retry the save until one succeeds (as does
	// a successful Admit, which saves the erased state too).
	s.st = st
	s.dirty = err != nil
	for d, r := range old.Secrets {
		if _, kept := st.Secrets[d]; !kept {
			clear(r.Secret)
		}
	}
	return err
}

// clone copies the state's map, not the secrets it points to.
func (s *Store) clone() state {
	st := state{Floor: s.st.Floor, Secrets: make(map[string]record, len(s.st.Secrets))}
	for d, r := range s.st.Secrets {
		st.Secrets[d] = r
	}
	return st
}

// save seals st and saves it, then makes it the store's state.
func (s *Store) save(st state) error {
	plain, err := json.Marshal(st)
	if err != nil {
		return err
	}
	defer clear(plain)
	b, err := s.cfg.Box.Seal(plain)
	if err != nil {
		return err
	}
	if err := s.cfg.Disk.Save(b); err != nil {
		return err
	}
	s.st = st
	s.dirty = false
	return nil
}
