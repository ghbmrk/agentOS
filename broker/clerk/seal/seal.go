// Package seal is the sealed store (STO-2): one file on the core's internal
// SSD that holds the store key's slots and the store's few entries (the
// approval-code verifiers, the box's policy key and the like). The store key
// itself is never on the drive. Each slot wraps it under a key of its own:
//
//   - tpm: a random key sealed to this PC's TPM under a signed PCR policy
//     (broker/tpmseal, HW-5a), with an optional boot PIN;
//   - passphrase: Argon2id of the Owner Card's store passphrase, at least
//     256 MiB, its parameters kept in the slot;
//   - recovery: the recovery key (REC-1), through HKDF.
//
// So nothing stored on the SSD alone releases the key (STO-2, A8). Once a
// slot opens, the store derives one key per purpose under its own HKDF label:
// the log's AES-256-GCM key, the kernel's head-signing seed, and one sealing
// key per clerk, which Sealer hands out as that clerk's clerk.Sealer. The
// store key stays with whoever unlocked the store (the unlock step, STO-2b),
// and each process gets only the derived keys it needs (CLK-1).
//
// The whole file is MAC'd under a key derived from the store key, so a slot
// added, removed or altered on the drive by anyone without the key makes the
// store refuse to open. Replacing the whole file with a store of someone
// else's is a different attack: the MAC is then under their key. A
// passphrase or recovery unlock refuses it because the owner's factor opens
// no slot in it; a TPM unlock refuses it because it must be given the
// store's anchor, a value derived from the store key and kept off the drive
// (see TPM). Every change is written to a temporary file, synced and
// renamed into place.
package seal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"sync"

	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/argon2"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/tpmseal"
)

// Bounds on what the file may hold. A file past them does not parse, so a
// hostile drive cannot make the unlock step allocate or hash without limit.
const (
	MaxFile     = 1 << 20 // the whole file
	MaxSlots    = 16
	MaxPolicies = 16 // signed boot paths per tpm slot
	MaxEntries  = 64
	MaxEntry    = 4 << 10 // one entry's value

	// ArgonFloorKiB is SPEC STO-2's memory floor for the passphrase slot.
	ArgonFloorKiB = 256 << 10
	argonCapKiB   = 4 << 20 // 4 GiB: more is a hostile header, not a tuning
	argonCapTime  = 64
	// MinPassphrase refuses a passphrase too short to be the Owner Card's
	// (seven words from a 7,776-word list, STO-2).
	MinPassphrase = 16
	// RecoveryLen is the recovery key's length in bytes.
	RecoveryLen = 32
)

const (
	version = 1
	keyLen  = 32
	idLen   = 16
	saltLen = 16
	wrapLen = 12 + keyLen + 16 // nonce, key, tag
	label   = "agentos-store/v1/"
)

// Errors callers act on. None carries key material.
var (
	// ErrCorrupt: the file does not parse, is truncated, or breaks a bound.
	ErrCorrupt = errors.New("seal: the store file is damaged")
	// ErrTampered: a slot opened, but the file's MAC does not match, so
	// something without the store key changed it.
	ErrTampered = errors.New("seal: the store file was changed without its key")
	// ErrNoSlot: the store has no slot this factor can open (no slot of
	// its kind, or no tpm slot sealed to this TPM).
	ErrNoSlot = errors.New("seal: no slot for this factor")
	// ErrWrongFactor: a slot of this kind exists, and the factor opens none.
	ErrWrongFactor = errors.New("seal: the factor does not open the store")
	// ErrLastSlot: removing the slot would leave the store unopenable.
	ErrLastSlot = errors.New("seal: the last slot cannot be removed")
	// ErrClosed: the store was closed and its key wiped.
	ErrClosed = errors.New("seal: the store is closed")
	// ErrNoPolicyKey: a TPM unlock was asked without the box's policy key.
	ErrNoPolicyKey = errors.New("seal: a tpm unlock needs my policy key")
	// ErrNoAnchor: a TPM unlock was asked without the store's anchor.
	ErrNoAnchor = errors.New("seal: a tpm unlock needs my store's anchor")
	// ErrExists: Create found a file already at the path.
	ErrExists = errors.New("seal: a store already exists there")
)

// Kind is a slot's kind, from a closed list.
type Kind string

const (
	KindTPM        Kind = "tpm"
	KindPassphrase Kind = "passphrase"
	KindRecovery   Kind = "recovery"
)

// Factor opens a slot, or makes one.
type Factor interface{ kind() Kind }

// TPM is the trusted-host factor. Unlock needs TPM, PolicyKey, Anchor and,
// if the slot has a boot PIN, PIN. PolicyKey is the box's policy key, whose
// private half belongs in this store (HW-5a); Unlock tries only slots
// sealed under it. That alone does not authenticate the store: sealing to
// this TPM under the policy key needs only its public half, and the signed
// boot paths are public, so anyone with the drive can write a whole store
// of their own that unseals here. Anchor (Store.Anchor) commits to the
// store key itself, and Unlock refuses a store whose key does not derive
// it. Neither is secret, but both must come from somewhere the drive's
// writer cannot change (STO-2b, STO-2c). Enrolling a slot (Create, AddSlot)
// needs PolicyKey and the boot paths it signed, at least one, but no
// Anchor; Host names the PC for the owner.
type TPM struct {
	TPM       transport.TPM
	PIN       string
	PolicyKey *ecdsa.PublicKey
	Anchor    []byte
	Policies  []tpmseal.Policy
	Host      string
}

// Passphrase is the Owner Card's store passphrase. Argon is used only when
// a slot is made; the zero value means DefaultArgon.
type Passphrase struct {
	Phrase []byte
	Argon  Argon
}

// Recovery is the recovery key, RecoveryLen random bytes.
type Recovery struct{ Key []byte }

func (TPM) kind() Kind        { return KindTPM }
func (Passphrase) kind() Kind { return KindPassphrase }
func (Recovery) kind() Kind   { return KindRecovery }

// Argon is a passphrase slot's Argon2id cost.
type Argon struct {
	Time    uint32 `json:"time"`
	MemKiB  uint32 `json:"mem_kib"`
	Threads uint8  `json:"threads"`
}

// DefaultArgon is the floor. Tuning it to about one second on the core is
// #826; a slot keeps its own parameters, so a retune needs no migration.
var DefaultArgon = Argon{Time: 1, MemKiB: ArgonFloorKiB, Threads: 4}

func (a Argon) valid() bool {
	return a.Time >= 1 && a.Time <= argonCapTime && a.MemKiB >= ArgonFloorKiB &&
		a.MemKiB <= argonCapKiB && a.Threads >= 1
}

// slot is one wrap of the store key. Nothing in it is secret.
type slot struct {
	ID       string           `json:"id"`
	Kind     Kind             `json:"kind"`
	Salt     []byte           `json:"salt,omitempty"`
	Argon    *Argon           `json:"argon,omitempty"`
	Sealed   *tpmseal.Sealed  `json:"sealed,omitempty"`
	Policies []tpmseal.Policy `json:"policies,omitempty"`
	// Wrap is AES-256-GCM of the store key under the slot's key, with
	// the store's ID and the rest of the slot as associated data.
	Wrap []byte `json:"wrap"`
}

// file is the store as it is on the drive.
type file struct {
	V     int    `json:"v"`
	ID    []byte `json:"id"`
	Slots []slot `json:"slots"`
	// Entries is AES-256-GCM of the entries' JSON under the entries key.
	Entries []byte `json:"entries"`
	// MAC is HMAC-SHA256 under the MAC key over the file with MAC empty.
	MAC []byte `json:"mac"`
}

var slotID = regexp.MustCompile(`^[0-9a-f]{16}$`)

// parse reads a store file and checks every bound. It touches no key.
func parse(b []byte) (*file, error) {
	if len(b) > MaxFile {
		return nil, ErrCorrupt
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var f file
	if err := d.Decode(&f); err != nil {
		return nil, ErrCorrupt
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrCorrupt
	}
	if f.V != version || len(f.ID) != idLen || len(f.Slots) == 0 || len(f.Slots) > MaxSlots ||
		len(f.MAC) != sha256.Size || len(f.Entries) < 12+16 {
		return nil, ErrCorrupt
	}
	seen := map[string]bool{}
	for i := range f.Slots {
		s := &f.Slots[i]
		if !slotID.MatchString(s.ID) || seen[s.ID] || len(s.Wrap) != wrapLen {
			return nil, ErrCorrupt
		}
		seen[s.ID] = true
		var ok bool
		switch s.Kind {
		case KindTPM:
			ok = s.Sealed != nil && s.Salt == nil && s.Argon == nil && len(s.Policies) <= MaxPolicies
		case KindPassphrase:
			ok = s.Sealed == nil && s.Policies == nil && len(s.Salt) == saltLen && s.Argon != nil && s.Argon.valid()
		case KindRecovery:
			ok = s.Sealed == nil && s.Policies == nil && len(s.Salt) == saltLen && s.Argon == nil
		}
		if !ok {
			return nil, ErrCorrupt
		}
	}
	// Only the canonical encoding parses: no spacing, key order, duplicate
	// key or base64 padding bits that the MAC (over the re-encoded file)
	// would not see. So any byte changed on the drive is refused.
	if again, err := json.Marshal(f); err != nil || !bytes.Equal(again, b) {
		return nil, ErrCorrupt
	}
	return &f, nil
}

// Store is an unlocked store. Its methods are safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	path    string
	key     []byte // nil once closed
	f       file
	entries map[string][]byte
}

func derive(key, id []byte, purpose string, n int) []byte {
	k, err := hkdf.Key(sha256.New, key, id, label+purpose, n)
	if err != nil {
		panic(err) // only for n past 255 hashes
	}
	return k
}

func gcm(key []byte) cipher.AEAD {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // keys here are always 32 bytes
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}
	return g
}

func seal(key, plain, aad []byte) ([]byte, error) {
	g := gcm(key)
	n := make([]byte, g.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return g.Seal(n, n, plain, aad), nil
}

func open(key, blob, aad []byte) ([]byte, error) {
	g := gcm(key)
	if len(blob) < g.NonceSize() {
		return nil, ErrCorrupt
	}
	return g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], aad)
}

func wipe(b []byte) { clear(b) }

func random(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// slotAAD binds a wrap to its store and to every other field of its slot,
// so a wrap moved to another store or another slot does not open, and a
// passphrase slot's Argon2 cost cannot be lowered in place. A tpm slot's
// boot paths are left out, so an update can change them (SetPolicies): the
// file's MAC covers them, and the TPM checks each one's signature.
func slotAAD(id []byte, s slot) []byte {
	s.Wrap, s.Policies = nil, nil
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return append(append([]byte(label+"slot\x00"), id...), b...)
}

func entriesAAD(id []byte) []byte { return append([]byte(label+"entries\x00"), id...) }

func mac(key []byte, f file) []byte {
	f.MAC = nil
	b, err := json.Marshal(f)
	if err != nil {
		panic(err)
	}
	m := derive(key, f.ID, "mac", sha256.Size)
	defer wipe(m)
	h := hmac.New(sha256.New, m)
	h.Write(b)
	return h.Sum(nil)
}

// slotKey is the key a factor gives for one slot.
func slotKey(s *slot, f Factor) ([]byte, error) {
	switch f := f.(type) {
	case Passphrase:
		a := s.Argon
		return argon2.IDKey(f.Phrase, s.Salt, a.Time, a.MemKiB, a.Threads, keyLen), nil
	case Recovery:
		if len(f.Key) != RecoveryLen {
			return nil, ErrWrongFactor
		}
		return hkdf.Key(sha256.New, f.Key, s.Salt, label+"recovery-slot", keyLen)
	case TPM:
		k, err := tpmseal.Unseal(f.TPM, s.Sealed, s.Policies, f.PIN)
		if err != nil {
			return nil, err
		}
		// SealTo can seal any secret under the box's public policy key,
		// so a planted slot may unseal to a key of the wrong length.
		if len(k) != keyLen {
			wipe(k)
			return nil, fmt.Errorf("%w: a tpm slot unsealed to %d bytes", ErrCorrupt, len(k))
		}
		return k, nil
	}
	return nil, ErrNoSlot
}

// makeSlot wraps key in a new slot for f.
func makeSlot(id, key []byte, f Factor) (slot, error) {
	sid, err := random(8)
	if err != nil {
		return slot{}, err
	}
	s := slot{ID: hex.EncodeToString(sid), Kind: f.kind()}
	var k []byte
	switch f := f.(type) {
	case Passphrase:
		if len(f.Phrase) < MinPassphrase {
			return slot{}, fmt.Errorf("seal: a passphrase needs at least %d bytes", MinPassphrase)
		}
		a := f.Argon
		if a == (Argon{}) {
			a = DefaultArgon
		}
		if !a.valid() {
			return slot{}, errors.New("seal: Argon2id cost below the floor or past its cap")
		}
		if s.Salt, err = random(saltLen); err != nil {
			return slot{}, err
		}
		s.Argon = &a
	case Recovery:
		if len(f.Key) != RecoveryLen {
			return slot{}, fmt.Errorf("seal: a recovery key is %d bytes", RecoveryLen)
		}
		if s.Salt, err = random(saltLen); err != nil {
			return slot{}, err
		}
	case TPM:
		if f.TPM == nil || f.PolicyKey == nil || len(f.Policies) == 0 || len(f.Policies) > MaxPolicies {
			return slot{}, errors.New("seal: a tpm slot needs the TPM, the policy key and 1 to 16 signed boot paths")
		}
		for _, p := range f.Policies {
			if !tpmseal.SignedBy(p, f.PolicyKey) {
				return slot{}, errors.New("seal: a boot path is not signed by the policy key")
			}
		}
		if k, err = random(keyLen); err != nil {
			return slot{}, err
		}
		defer wipe(k)
		if s.Sealed, err = tpmseal.Seal(f.TPM, k, f.PolicyKey, f.PIN, f.Host); err != nil {
			return slot{}, err
		}
		s.Policies = slices.Clone(f.Policies)
	default:
		return slot{}, errors.New("seal: unknown factor")
	}
	if k == nil {
		if k, err = slotKey(&s, f); err != nil {
			return slot{}, err
		}
		defer wipe(k)
	}
	if s.Wrap, err = seal(k, key, slotAAD(id, s)); err != nil {
		return slot{}, err
	}
	return s, nil
}

// Create makes a new store at path with one slot for f, and returns it
// unlocked. It refuses a path that already exists.
func Create(path string, f Factor) (*Store, error) {
	if _, err := os.Lstat(path); err == nil {
		return nil, ErrExists
	}
	key, err := random(keyLen)
	if err != nil {
		return nil, err
	}
	id, err := random(idLen)
	if err != nil {
		wipe(key)
		return nil, err
	}
	s := &Store{path: path, key: key, f: file{V: version, ID: id}, entries: map[string][]byte{}}
	sl, err := makeSlot(id, key, f)
	if err != nil {
		wipe(key)
		return nil, err
	}
	nf := s.f
	nf.Slots = []slot{sl}
	b, err := s.encode(nf, s.entries)
	if err != nil {
		wipe(key)
		return nil, err
	}
	if err := writeNew(path, b); err != nil {
		wipe(key)
		return nil, err
	}
	s.f = nf
	return s, nil
}

// Unlock opens the store at path with f. It tries every slot of f's kind
// (for a TPM, every slot sealed to that TPM) and returns the store once one
// slot opens and the file's MAC checks under the key it gave.
func Unlock(path string, f Factor) (*Store, error) {
	b, err := readFile(path)
	if err != nil {
		return nil, err
	}
	fl, err := parse(b)
	if err != nil {
		return nil, err
	}
	var srk []byte
	t, isTPM := f.(TPM)
	if isTPM {
		if t.TPM == nil {
			return nil, ErrNoSlot
		}
		if t.PolicyKey == nil {
			return nil, ErrNoPolicyKey
		}
		if len(t.Anchor) != AnchorLen {
			return nil, ErrNoAnchor
		}
		if srk, err = tpmseal.Identity(t.TPM); err != nil {
			return nil, err
		}
	}
	tried := false
	var errs []error
	for i := range fl.Slots {
		sl := &fl.Slots[i]
		if sl.Kind != f.kind() {
			continue
		}
		// A tpm slot opens only on its own TPM and only if sealed under
		// the box's policy key: a slot sealed under any other key is
		// someone else's store, so it is skipped before any unseal (A8).
		if isTPM && (!bytes.Equal(sl.Sealed.SRKName, srk) || !sealedUnder(sl.Sealed, t.PolicyKey)) {
			continue
		}
		tried = true
		k, err := slotKey(sl, f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		key, err := open(k, sl.Wrap, slotAAD(fl.ID, *sl))
		wipe(k)
		if err != nil {
			continue
		}
		if !hmac.Equal(mac(key, *fl), fl.MAC) {
			wipe(key)
			return nil, ErrTampered
		}
		// A whole store someone else wrote MACs under their own key, and
		// its tpm slot unseals here; only the off-drive anchor tells it
		// from the owner's.
		if isTPM && !hmac.Equal(anchor(key, fl.ID), t.Anchor) {
			wipe(key)
			return nil, ErrTampered
		}
		ek := derive(key, fl.ID, "entries", keyLen)
		plain, err := open(ek, fl.Entries, entriesAAD(fl.ID))
		wipe(ek)
		if err != nil {
			wipe(key)
			return nil, ErrTampered
		}
		entries := map[string][]byte{}
		err = json.Unmarshal(plain, &entries)
		wipe(plain)
		if err != nil || !validEntries(entries) {
			wipe(key)
			return nil, ErrCorrupt
		}
		return &Store{path: path, key: key, f: *fl, entries: entries}, nil
	}
	if !tried {
		return nil, ErrNoSlot
	}
	// A TPM refusal (a modified boot path, a wrong PIN, lockout) says why.
	return nil, errors.Join(append([]error{ErrWrongFactor}, errs...)...)
}

func sealedUnder(s *tpmseal.Sealed, key *ecdsa.PublicKey) bool {
	pub, err := s.PolicyPublicKey()
	return err == nil && pub.Equal(key)
}

// ReadID returns the ID of the store at path without unlocking it. It is
// the drive's word, not authenticated: use it only to find what is keyed
// by the ID off the drive (the TPM pins), which then checks it.
func ReadID(path string) ([]byte, error) {
	b, err := readFile(path)
	if err != nil {
		return nil, err
	}
	f, err := parse(b)
	if err != nil {
		return nil, err
	}
	return f.ID, nil
}

// Pinned is the TPM factor for the store at path on this PC: its policy key
// and anchor come from the store's pins index on this TPM (tpmseal.ReadPins,
// STO-2a-k), never from the drive. The ID that finds the index is the
// drive's, but a changed ID finds no pins or another store's, whose anchor
// this store's key does not derive, so Unlock still refuses. A TPM with no
// pins for the store is tpmseal.ErrNoPins: the unlock fails closed, and the
// owner's passphrase or recovery slot is the way in.
func Pinned(t transport.TPM, path string) (TPM, error) {
	id, err := ReadID(path)
	if err != nil {
		return TPM{}, err
	}
	srk, err := tpmseal.Identity(t)
	if err != nil {
		return TPM{}, err
	}
	p, err := tpmseal.ReadPins(t, srk, id)
	if err != nil {
		return TPM{}, err
	}
	return TPM{TPM: t, PolicyKey: p.PolicyKey, Anchor: p.Anchor}, nil
}

// ID is the store's ID, which the file's MAC covers.
func (s *Store) ID() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.f.ID)
}

// AnchorLen is the length of a store's anchor.
const AnchorLen = 32

func anchor(key, id []byte) []byte { return derive(key, id, "anchor", AnchorLen) }

// Anchor commits to the store key: a one-way value under its own HKDF
// label, which a TPM unlock must be given (see TPM). It is not secret; it
// never changes, since the store key is never rotated (STO-2a-d).
func (s *Store) Anchor() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.live(); err != nil {
		return nil, err
	}
	return anchor(s.key, s.f.ID), nil
}

func readFile(path string) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, MaxFile+1))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// encode is the file's bytes with nf's slots and entries e, MAC'd.
func (s *Store) encode(nf file, e map[string][]byte) ([]byte, error) {
	plain, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	ek := derive(s.key, nf.ID, "entries", keyLen)
	nf.Entries, err = seal(ek, plain, entriesAAD(nf.ID))
	wipe(ek)
	wipe(plain)
	if err != nil {
		return nil, err
	}
	nf.MAC = mac(s.key, nf)
	b, err := json.Marshal(nf)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFile {
		return nil, errors.New("seal: the store would exceed its size bound")
	}
	return b, nil
}

// commit writes the store with slots and entries e, then takes them. A
// write that fails before the rename leaves both the file and the store as
// they were. Once the rename is done the file holds the new slots, so the
// store takes them even if the directory sync then fails, and returns that
// error: otherwise the next commit would write the old slots back, and a
// failed Replace of a compromised passphrase would revive it (REC-4).
func (s *Store) commit(slots []slot, e map[string][]byte) error {
	nf := s.f
	nf.Slots = slots
	b, err := s.encode(nf, e)
	if err != nil {
		return err
	}
	renamed, err := writeAtomic(s.path, b)
	if renamed {
		s.f, s.entries = nf, e
	}
	return err
}

func (s *Store) live() error {
	if s.key == nil {
		return ErrClosed
	}
	return nil
}

// SlotInfo describes a slot for the owner. It holds nothing secret.
type SlotInfo struct {
	ID   string
	Kind Kind
	Host string // a tpm slot's PC, if named
	// PolicyKey is the key a tpm slot was sealed under, so a rotation can
	// tell the old key's slots from the new one's.
	PolicyKey *ecdsa.PublicKey
	// Policies is a tpm slot's signed boot paths, in order, so a rotation
	// re-signs what enrollment measured (HW-5a) without reading the PCRs,
	// which the unlock step has capped by then (#2977).
	Policies []tpmseal.Policy
}

// Slots lists the store's slots.
func (s *Store) Slots() []SlotInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SlotInfo, 0, len(s.f.Slots))
	for _, sl := range s.f.Slots {
		in := SlotInfo{ID: sl.ID, Kind: sl.Kind}
		if sl.Sealed != nil {
			in.Host = sl.Sealed.Host
			in.PolicyKey, _ = sl.Sealed.PolicyPublicKey()
		}
		for _, p := range sl.Policies {
			p.PCRs, p.Digest, p.Signature = slices.Clone(p.PCRs), slices.Clone(p.Digest), slices.Clone(p.Signature)
			in.Policies = append(in.Policies, p)
		}
		out = append(out, in)
	}
	return out
}

// AddSlot wraps the store key in a new slot for f and returns its ID.
func (s *Store) AddSlot(f Factor) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.live(); err != nil {
		return "", err
	}
	if len(s.f.Slots) >= MaxSlots {
		return "", fmt.Errorf("seal: a store holds at most %d slots", MaxSlots)
	}
	sl, err := makeSlot(s.f.ID, s.key, f)
	if err != nil {
		return "", err
	}
	return s.committed(sl.ID, s.commit(append(slices.Clone(s.f.Slots), sl), s.entries))
}

// committed returns the new slot's id with err when the slot is in place, which
// it is after a rename even if the directory sync failed: the caller must
// still learn its ID.
func (s *Store) committed(id string, err error) (string, error) {
	if err != nil && s.find(id) < 0 {
		return "", err
	}
	return id, err
}

func (s *Store) find(id string) int {
	return slices.IndexFunc(s.f.Slots, func(sl slot) bool { return sl.ID == id })
}

// RemoveSlot drops a slot. It refuses the last one.
func (s *Store) RemoveSlot(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.live(); err != nil {
		return err
	}
	i := s.find(id)
	if i < 0 {
		return ErrNoSlot
	}
	if len(s.f.Slots) == 1 {
		return ErrLastSlot
	}
	return s.commit(slices.Delete(slices.Clone(s.f.Slots), i, i+1), s.entries)
}

// Replace puts a new slot for f in place of slot id in one write: a new
// passphrase or recovery key (REC-4), or a TPM slot sealed again. The old
// slot no longer opens the store once Replace returns.
func (s *Store) Replace(id string, f Factor) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.live(); err != nil {
		return "", err
	}
	i := s.find(id)
	if i < 0 {
		return "", ErrNoSlot
	}
	sl, err := makeSlot(s.f.ID, s.key, f)
	if err != nil {
		return "", err
	}
	slots := slices.Clone(s.f.Slots)
	slots[i] = sl
	return s.committed(sl.ID, s.commit(slots, s.entries))
}

// SetPolicies replaces a tpm slot's signed boot paths: an update adds the
// next release's path before it reboots (HW-5a). Each must be signed by the
// policy key the slot was sealed under; the TPM checks that again at unseal.
func (s *Store) SetPolicies(id string, ps []tpmseal.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.live(); err != nil {
		return err
	}
	i := s.find(id)
	if i < 0 || s.f.Slots[i].Kind != KindTPM {
		return ErrNoSlot
	}
	if len(ps) == 0 || len(ps) > MaxPolicies {
		return fmt.Errorf("seal: a tpm slot keeps 1 to %d boot paths", MaxPolicies)
	}
	pub, err := s.f.Slots[i].Sealed.PolicyPublicKey()
	if err != nil {
		return err
	}
	for _, p := range ps {
		if !tpmseal.SignedBy(p, pub) {
			return errors.New("seal: a boot path is not signed by the slot's policy key")
		}
	}
	slots := slices.Clone(s.f.Slots)
	slots[i].Policies = slices.Clone(ps)
	return s.commit(slots, s.entries)
}

var entryName = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,63}$`)

func validEntries(e map[string][]byte) bool {
	if len(e) > MaxEntries {
		return false
	}
	for k, v := range e {
		if !entryName.MatchString(k) || len(v) > MaxEntry {
			return false
		}
	}
	return true
}

// Put stores an entry (an approval-code verifier, the policy key), durably.
func (s *Store) Put(name string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.live(); err != nil {
		return err
	}
	e, err := s.withEntry(name, value)
	if err != nil {
		return err
	}
	return s.commit(s.f.Slots, e)
}

// ReplaceAndPut is Replace and Put in one write: a new recovery key's slot
// in place of slot id, and its backup recipient as entry name (REC-4,
// BAK-1, MIG-4-recovery-r2). A crash leaves the old slot and old entry, or
// the new slot and new entry, never one without the other.
func (s *Store) ReplaceAndPut(id string, f Factor, name string, value []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.live(); err != nil {
		return "", err
	}
	i := s.find(id)
	if i < 0 {
		return "", ErrNoSlot
	}
	e, err := s.withEntry(name, value)
	if err != nil {
		return "", err
	}
	sl, err := makeSlot(s.f.ID, s.key, f)
	if err != nil {
		return "", err
	}
	slots := slices.Clone(s.f.Slots)
	slots[i] = sl
	return s.committed(sl.ID, s.commit(slots, e))
}

// withEntry is the store's entries with name set to a copy of value.
func (s *Store) withEntry(name string, value []byte) (map[string][]byte, error) {
	if !entryName.MatchString(name) || len(value) > MaxEntry {
		return nil, errors.New("seal: bad entry name or value too long")
	}
	e := make(map[string][]byte, len(s.entries)+1)
	for k, v := range s.entries {
		e[k] = v
	}
	e[name] = slices.Clone(value)
	if len(e) > MaxEntries {
		return nil, fmt.Errorf("seal: a store holds at most %d entries", MaxEntries)
	}
	return e, nil
}

// Get returns a copy of an entry.
func (s *Store) Get(name string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.live(); err != nil {
		return nil, false, err
	}
	v, ok := s.entries[name]
	return slices.Clone(v), ok, nil
}

// Delete drops an entry, durably. Dropping a missing entry is not an error.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.live(); err != nil {
		return err
	}
	if _, ok := s.entries[name]; !ok {
		return nil
	}
	e := make(map[string][]byte, len(s.entries))
	for k, v := range s.entries {
		if k != name {
			e[k] = v
		}
	}
	return s.commit(s.f.Slots, e)
}

// Entries lists the entries' names.
func (s *Store) Entries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.entries))
	for k := range s.entries {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *Store) derived(purpose string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.live(); err != nil {
		return nil, err
	}
	return derive(s.key, s.f.ID, purpose, keyLen), nil
}

// LogKey is the log's AES-256-GCM key (STO-1, run.KernelConfig.Key).
func (s *Store) LogKey() ([32]byte, error) {
	var k [32]byte
	b, err := s.derived("log")
	if err != nil {
		return k, err
	}
	copy(k[:], b)
	wipe(b)
	return k, nil
}

// HeadKey is the kernel's head-signing key (KEY-3's head domain,
// run.KernelConfig.Sign). Its public half is HeadKey().Public().
func (s *Store) HeadKey() (ed25519.PrivateKey, error) {
	b, err := s.derived("head")
	if err != nil {
		return nil, err
	}
	defer wipe(b)
	return ed25519.NewKeyFromSeed(b), nil
}

var clerkName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Sealer is clerk's sealer: AES-256-GCM under a key derived for that clerk
// alone, so one clerk's sealer opens nothing another's sealed (CLK-1).
func (s *Store) Sealer(clerkID string) (clerk.Sealer, error) {
	if !clerkName.MatchString(clerkID) {
		return nil, errors.New("seal: a clerk name is lower-case letters, digits and hyphens")
	}
	b, err := s.derived("sealer/" + clerkID)
	if err != nil {
		return nil, err
	}
	defer wipe(b)
	return clerk.NewAESSealer(b)
}

// Close wipes the store key. Keys already handed out are the caller's.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	wipe(s.key)
	s.key = nil
	for _, v := range s.entries {
		wipe(v)
	}
	s.entries = nil
}

// writeAtomic replaces path with b: a temporary file in the same
// directory, synced, renamed over path, and the directory synced. renamed
// says whether path now holds b, even when err is the directory sync's.
func writeAtomic(path string, b []byte) (renamed bool, err error) {
	tmp, err := writeTemp(path, b)
	if err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil { // durable:exempt lifecycle:exempt durable is old core (tools/old_core.txt), so the new core cannot list here; this is key material, not a lifecycle, and the file and directory are synced here
		os.Remove(tmp)
		return false, err
	}
	return true, syncDir(filepath.Dir(path))
}

// writeNew is writeAtomic that refuses to replace an existing file.
func writeNew(path string, b []byte) error {
	tmp, err := writeTemp(path, b)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return err
	}
	return syncDir(filepath.Dir(path))
}

// writeTemp is a variable so a test can make a write fail before the rename.
var writeTemp = func(path string, b []byte) (string, error) {
	fh, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return "", err
	}
	name := fh.Name()
	_, err = fh.Write(b)
	if err == nil {
		err = fh.Chmod(0o600)
	}
	if err == nil {
		err = fh.Sync()
	}
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// syncDir is a variable so a test can make the directory sync fail.
var syncDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
