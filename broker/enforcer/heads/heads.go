// Package heads is the enforcer's head-copy store and revocation set (SPEC
// STO-1, STO-4, KEY-7; briefs/ENF.md slice h).
//
// The enforcer is an anchor that keeps entries: it keeps every log head
// the kernel sends, signed by the kernel's sub-key under the head domain,
// with the key-change entries (grants, revocations, pauses, enrolments)
// and the erase entries, so a restore can replay them (REC-1) and a
// rolled-back core cannot re-grow past an anchor that forgot. A second
// head at a seq it holds with another hash, a head below the newest it
// holds, and an entry whose hash differs from what it holds at that seq
// are forks: refused, reported, and never kept over what it holds.
//
// The revocation set is what the channel's Revoked checks (slice d) and
// what any later enforcer key check reads: key IDs the kernel logged as
// revoked or paused, edge keys and passkeys it logged as revoked, and the
// kernel's own sub-key once the owner revokes it with the enforcer passkey
// (SPEC STO-4's stolen core). A revocation is final. Once the sub-key is
// revoked, nothing it signs is kept, and after a core trip (KRN-12,
// DECOY-d) nothing is kept at all.
//
// It is enforcer code: it imports the standard library, broker/kernel/key
// and broker/enforcer/wire only (broker/daemon/arc2_test.go). The head and
// entry encodings are the kernel's (broker/kernel/log.go), copied because
// the enforcer links nothing else of agentOS; the tests sign with the
// kernel's own code so the copy cannot drift. Its assumptions are in
// ASSUMPTIONS.md.
package heads

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/ghbmrk/agentos/broker/enforcer/wire"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The kernel's signing domains (broker/kernel/log.go), so a head and a key
// derivation never verify as one another (KEY-3).
const (
	domainHead  = "agentos.head.v1\x00"
	domainEntry = "agentos.log.entry.v1\x00"
)

// Clerk is the clerk an owner-signed sub-key revocation's root names, the
// enforcer's as for its policy versions (brief decision 2).
const Clerk = "enforcer"

// kept is the closed set of entry types the store keeps, with the body
// version the kernel writes (broker/kernel/state.go schema): the key
// changes and the erase entries (STO-1, KEY-7, LOG-4). Every other entry
// is the core's alone.
var kept = map[string]int{
	"key.issued": 2, "key.revoked": 1, "key.paused": 1, "key.resumed": 1,
	"passkey.enrolled": 1, "passkey.revoked": 1,
	"edge.enrolled": 1, "edge.revoked": 1,
	"subject.erased": 1, "erase.confirmed": 1,
}

// Errors Head, Entry and RevokeSubKey return.
var (
	ErrConfig   = errors.New("heads: config incomplete")
	ErrBadSig   = errors.New("heads: not signed by the kernel's sub-key")
	ErrFork     = errors.New("heads: differs from or rewinds a head or entry the enforcer holds")
	ErrRevoked  = errors.New("heads: the kernel's sub-key is revoked")
	ErrTripped  = errors.New("heads: the core tripped; nothing is kept")
	ErrType     = errors.New("heads: not a key-change or erase entry")
	ErrEncoding = errors.New("heads: not the kernel's encoding")
	ErrNotOwner = errors.New("heads: not the owner's enforcer passkey")
	ErrCorrupt  = errors.New("heads: journal corrupt")
)

// Journal is the store's durable record: one line per change, appended.
// Append must be durable when it returns; Load returns every byte
// appended, a torn last line included; Truncate cuts the record to n
// bytes. Slice l backs it with a file.
type Journal interface {
	Load() ([]byte, error)
	Append([]byte) error
	Truncate(n int) error
}

// Config is what a store is built from. Kernel and Journal are required.
type Config struct {
	// Kernel is the kernel's sub-key, pinned at enrolment.
	Kernel ed25519.PublicKey
	// Journal keeps what the store holds across a restart.
	Journal Journal
	// Fork is told the seq of each fork refused, so the daemon can raise
	// the alert (slice l). It runs on its own goroutine: the channel calls
	// Head and Entry holding its lock, and the alert goes out on the
	// channel.
	Fork func(seq uint64)
}

// entry is the kernel's log entry (broker/kernel.Entry), field for field
// and in order, so json.Marshal gives the bytes the kernel hashed.
type entry struct {
	Seq  uint64          `json:"seq"`
	Prev hash            `json:"prev"`
	At   int64           `json:"at"`
	Type string          `json:"type"`
	V    int             `json:"v"`
	Body json.RawMessage `json:"body"`
}

type hash [wire.HashLen]byte

func (h hash) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(h[:])), nil }

func (h *hash) UnmarshalText(b []byte) error {
	d, err := hex.DecodeString(string(b))
	if err != nil || len(d) != len(h) {
		return ErrEncoding
	}
	copy(h[:], d)
	return nil
}

func (e entry) hash() hash {
	b, _ := json.Marshal(e)
	return sha256.Sum256(append([]byte(domainEntry), b...))
}

// record is one journal line; exactly one field is set.
type record struct {
	Head    *wire.Head      `json:"head,omitempty"`
	Entry   json.RawMessage `json:"entry,omitempty"`
	Revoke  []byte          `json:"revoke,omitempty"` // a sub-key the owner revoked
	Tripped bool            `json:"tripped,omitempty"`
}

// Store is the head-copy store and revocation set. It is safe for
// concurrent use: the channel writes it and every key check reads it.
type Store struct {
	cfg Config

	mu      sync.Mutex
	heads   map[uint64]wire.Head
	latest  uint64
	entries map[uint64][]byte // seq -> the kernel's encoding
	hashes  map[uint64]hash
	tripped bool

	revokedSub  map[string]bool // ed25519 keys: the owner's sub-key revocations
	revokedEdge map[string]bool
	revokedPK   map[string]bool // key.PublicKey.Encode()
	revokedID   map[key.ID]bool
	paused      map[key.ID]bool
}

// Open builds a store and replays its journal. A torn last line is
// dropped; any other bad line is ErrCorrupt.
func Open(cfg Config) (*Store, error) {
	if len(cfg.Kernel) != ed25519.PublicKeySize || cfg.Journal == nil {
		return nil, ErrConfig
	}
	s := &Store{cfg: cfg, heads: map[uint64]wire.Head{}, entries: map[uint64][]byte{}, hashes: map[uint64]hash{},
		revokedSub: map[string]bool{}, revokedEdge: map[string]bool{}, revokedPK: map[string]bool{},
		revokedID: map[key.ID]bool{}, paused: map[key.ID]bool{}}
	raw, err := cfg.Journal.Load()
	if err != nil {
		return nil, err
	}
	raw, err = whole(cfg.Journal, raw)
	if err != nil {
		return nil, err
	}
	for i, ln := range bytes.Split(raw, []byte{'\n'}) {
		if len(ln) == 0 {
			continue
		}
		if err := s.replay(ln); err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrCorrupt, i+1, err)
		}
	}
	return s, nil
}

func (s *Store) replay(ln []byte) error {
	var r record
	d := json.NewDecoder(bytes.NewReader(ln))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return err
	}
	switch {
	case r.Head != nil:
		s.keepHead(*r.Head)
	case r.Entry != nil:
		e, err := parse(r.Entry)
		if err != nil {
			return err
		}
		return s.keepEntry(e, r.Entry)
	case len(r.Revoke) == ed25519.PublicKeySize:
		s.revokedSub[string(r.Revoke)] = true
	case r.Tripped:
		s.tripped = true
	default:
		return ErrCorrupt
	}
	return nil
}

func (s *Store) write(r record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return s.cfg.Journal.Append(append(b, '\n'))
}

// headMsg is the kernel's head message: the head domain, the seq and the
// chain hash.
func headMsg(seq uint64, h [wire.HashLen]byte) []byte {
	b := binary.BigEndian.AppendUint64([]byte(domainHead), seq)
	return append(b, h[:]...)
}

// gate refuses everything once the core tripped or its sub-key is revoked.
func (s *Store) gate() error {
	switch {
	case s.tripped:
		return ErrTripped
	case s.revokedSub[string(s.cfg.Kernel)]:
		return ErrRevoked
	}
	return nil
}

// Head keeps one head the kernel sent: the channel's Heads.Head. A resend
// of a head it holds is no change.
func (s *Store) Head(h wire.Head) error {
	s.mu.Lock()
	err := s.head(h)
	s.mu.Unlock()
	return s.reported(h.Seq, err)
}

func (s *Store) head(h wire.Head) error {
	if err := s.gate(); err != nil {
		return err
	}
	if !ed25519.Verify(s.cfg.Kernel, headMsg(h.Seq, h.Hash), h.Sig[:]) {
		return ErrBadSig
	}
	h.ID = h.Seq // the channel's request id is not the head's
	if old, ok := s.heads[h.Seq]; ok {
		if old.Hash != h.Hash {
			return ErrFork
		}
		return nil
	}
	if h.Seq < s.latest {
		return ErrFork // heads only rise; a lower new one is a rewound log
	}
	if eh, ok := s.hashes[h.Seq]; ok && eh != h.Hash {
		return ErrFork
	}
	if next, ok := s.next(h.Seq); ok && next != h.Hash {
		return ErrFork
	}
	if err := s.write(record{Head: &h}); err != nil {
		return err
	}
	s.keepHead(h)
	return nil
}

func (s *Store) keepHead(h wire.Head) {
	s.heads[h.Seq] = h
	s.latest = max(s.latest, h.Seq)
}

// Entry keeps one key-change or erase entry, in the kernel's encoding: the
// channel's Heads.Entry. A resend of an entry it holds is no change.
func (s *Store) Entry(w wire.Entry) error {
	e, err := parse(w.Body)
	if err != nil {
		return err
	}
	s.mu.Lock()
	err = s.entry(e, w.Body)
	s.mu.Unlock()
	return s.reported(e.Seq, err)
}

func (s *Store) entry(e entry, body []byte) error {
	if err := s.gate(); err != nil {
		return err
	}
	h := e.hash()
	if old, ok := s.hashes[e.Seq]; ok {
		if old != h {
			return ErrFork
		}
		return nil
	}
	if hd, ok := s.heads[e.Seq]; ok && hd.Hash != h {
		return ErrFork
	}
	if prev, ok := s.hashes[e.Seq-1]; ok && prev != e.Prev {
		return ErrFork
	}
	if hd, ok := s.heads[e.Seq-1]; ok && hash(hd.Hash) != e.Prev {
		return ErrFork
	}
	if next, ok := s.next(e.Seq); ok && next != h {
		return ErrFork
	}
	b := slices.Clone(body)
	if err := s.write(record{Entry: b}); err != nil {
		return err
	}
	return s.keepEntry(e, b)
}

// next is the Prev of the entry held right after seq, if any.
func (s *Store) next(seq uint64) (hash, bool) {
	b, ok := s.entries[seq+1]
	if !ok {
		return hash{}, false
	}
	e, _ := parse(b)
	return e.Prev, true
}

func (s *Store) keepEntry(e entry, body []byte) error {
	if err := s.apply(e); err != nil {
		return err
	}
	s.entries[e.Seq] = body
	s.hashes[e.Seq] = e.hash()
	return nil
}

func (s *Store) reported(seq uint64, err error) error {
	if errors.Is(err, ErrFork) && s.cfg.Fork != nil {
		go s.cfg.Fork(seq)
	}
	return err
}

// parse reads an entry in the kernel's one encoding: a kept type at its
// version, every field known, the bytes exactly what json.Marshal gives,
// and an interpreted body in its one encoding too.
func parse(b []byte) (entry, error) {
	var e entry
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil || d.More() {
		return entry{}, ErrEncoding
	}
	if v, ok := kept[e.Type]; !ok || v != e.V {
		return entry{}, ErrType
	}
	if c, err := json.Marshal(e); err != nil || !bytes.Equal(c, b) || e.Seq == 0 {
		return entry{}, ErrEncoding
	}
	if len(e.Body) == 0 || e.Body[0] != '{' {
		return entry{}, ErrEncoding
	}
	if _, err := body(e); err != nil {
		return entry{}, err
	}
	return e, nil
}

// Body shapes the store interprets, as the kernel writes them.
type (
	keyID       struct{ ID key.ID }
	edgeRevoked struct {
		Key ed25519.PublicKey `json:"key"`
	}
)

// body decodes the bodies that change the revocation set and checks they
// are in their one encoding; the others are kept as they came.
func body(e entry) (any, error) {
	var v any
	switch e.Type {
	case "key.revoked", "key.paused", "key.resumed":
		v = &keyID{}
	case "edge.revoked":
		v = &edgeRevoked{}
	case "passkey.revoked":
		v = &key.Unenrollment{}
	default:
		return nil, nil
	}
	d := json.NewDecoder(bytes.NewReader(e.Body))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return nil, ErrEncoding
	}
	if c, err := json.Marshal(v); err != nil || !bytes.Equal(c, e.Body) {
		return nil, ErrEncoding
	}
	if r, ok := v.(*edgeRevoked); ok && len(r.Key) != ed25519.PublicKeySize {
		return nil, ErrEncoding
	}
	if u, ok := v.(*key.Unenrollment); ok && !u.Passkey.Valid() {
		return nil, ErrEncoding
	}
	return v, nil
}

// apply folds one entry into the revocation set. A revocation is final;
// a pause lasts until a resume.
func (s *Store) apply(e entry) error {
	v, err := body(e)
	if err != nil {
		return err
	}
	switch b := v.(type) {
	case *keyID:
		switch e.Type {
		case "key.revoked":
			s.revokedID[b.ID] = true
		case "key.paused":
			s.paused[b.ID] = true
		default:
			delete(s.paused, b.ID)
		}
	case *edgeRevoked:
		s.revokedEdge[string(b.Key)] = true
	case *key.Unenrollment:
		s.revokedPK[string(b.Passkey.Encode())] = true
	}
	return nil
}

// SubKeyRoot is the unsigned root the owner's enforcer passkey signs to
// revoke the kernel sub-key sub: the page hands
// key.Challenge(key.RootMsg(root)) to WebAuthn get(), as for a policy
// version (brief decision 2). Its serial names the key, so the assertion
// revokes that key and no other, and never verifies as a policy version.
func SubKeyRoot(owner key.PublicKey, sub ed25519.PublicKey) key.Root {
	return key.PrepareRoot(owner, key.Root{Clerk: Clerk, Serial: "revoke/" + hex.EncodeToString(sub)})
}

// RevokeSubKey revokes the kernel sub-key sub on the owner's enforcer
// passkey assertion sig over SubKeyRoot (KEY-6, KEY-7, SPEC STO-4's stolen
// core). owner is the enrolled enforcer passkey (slice c); the page
// collects the assertion at home (slice b). It reaches the enforcer
// without the core, so a stolen core cannot withhold it.
func (s *Store) RevokeSubKey(owner key.PublicKey, sub ed25519.PublicKey, sig []byte) error {
	if owner.Alg() != key.AlgES256 {
		return ErrNotOwner
	}
	if len(sub) != ed25519.PublicKeySize || !owner.Verify(key.RootMsg(SubKeyRoot(owner, sub)), sig) {
		return ErrBadSig
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revokedSub[string(sub)] {
		return nil
	}
	// Refused from now even if the journal fails, which is returned so the
	// page can say the revocation will not survive a restart.
	s.revokedSub[string(sub)] = true
	return s.write(record{Revoke: slices.Clone(sub)})
}

// Trip stops the store keeping anything from the core: after a core trip
// the enforcer keeps no head (STO-1, KRN-12). DECOY-d calls it and owns
// lifting it.
func (s *Store) Trip() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tripped {
		return nil
	}
	s.tripped = true // as RevokeSubKey: in force even if the journal fails
	return s.write(record{Tripped: true})
}

// Revoked reports whether an Ed25519 key is revoked: a kernel sub-key the
// owner revoked or an edge key the kernel logged as revoked. It is the
// channel's Config.Revoked.
func (s *Store) Revoked(pub ed25519.PublicKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokedSub[string(pub)] || s.revokedEdge[string(pub)]
}

// RevokedPasskey reports whether the kernel logged pk as revoked.
func (s *Store) RevokedPasskey(pk key.PublicKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return pk.Valid() && s.revokedPK[string(pk.Encode())]
}

// RevokedID reports whether any of ids, a key's chain, is revoked: a key
// fails if any key it derives from does (KEY-7).
func (s *Store) RevokedID(ids ...key.ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.ContainsFunc(ids, func(id key.ID) bool { return s.revokedID[id] })
}

// Paused reports whether any of ids is paused and not yet resumed.
func (s *Store) Paused(ids ...key.ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.ContainsFunc(ids, func(id key.ID) bool { return s.paused[id] })
}

// Latest is the newest head held.
func (s *Store) Latest() (wire.Head, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.heads[s.latest]
	return h, ok
}

// Heads is every head held, by seq.
func (s *Store) Heads() []wire.Head {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]wire.Head, 0, len(s.heads))
	for _, seq := range slices.Sorted(maps.Keys(s.heads)) {
		out = append(out, s.heads[seq])
	}
	return out
}

// Entries is every entry held, in the kernel's encoding and seq order, for
// a restore to replay (REC-1).
func (s *Store) Entries() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	seqs := slices.Sorted(maps.Keys(s.entries))
	out := make([][]byte, len(seqs))
	for i, seq := range seqs {
		out[i] = slices.Clone(s.entries[seq])
	}
	return out
}

// whole cuts a torn last append, a line with no newline, from the journal
// and returns the rest. Append writes a record and its newline in one
// call, so a line without one was never acknowledged, and cutting it
// keeps the next Append from landing on the fragment.
func whole(j Journal, raw []byte) ([]byte, error) {
	n := bytes.LastIndexByte(raw, '\n') + 1
	if n == len(raw) {
		return raw, nil
	}
	if err := j.Truncate(n); err != nil {
		return nil, err
	}
	return raw[:n], nil
}
