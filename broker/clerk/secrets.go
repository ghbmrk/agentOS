package clerk

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"sync"
)

// Sealer seals and opens one secret under a key that never leaves it. The
// core binds the real key to the TPM (STO-4); AESSealer is the software form.
type Sealer interface {
	Seal(plain, aad []byte) ([]byte, error)
	Open(blob, aad []byte) ([]byte, error)
}

type aesSealer struct{ g cipher.AEAD }

// NewAESSealer seals with AES-256-GCM under a 32-byte key.
func NewAESSealer(key []byte) (Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("clerk: sealing key must be 32 bytes")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return aesSealer{g}, nil
}

func (s aesSealer) Seal(plain, aad []byte) ([]byte, error) {
	n := make([]byte, s.g.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return s.g.Seal(n, n, plain, aad), nil
}

func (s aesSealer) Open(blob, aad []byte) ([]byte, error) {
	if len(blob) < s.g.NonceSize() {
		return nil, errors.New("clerk: sealed secret too short")
	}
	return s.g.Open(nil, blob[:s.g.NonceSize()], blob[s.g.NonceSize():], aad)
}

// Kind is what a slot holds. A clerk path opens only its own kind, and the
// kind is bound into the seal, so a slot of one kind never opens as the other
// (CLK-1, default deny).
type Kind string

// The closed list of slot kinds.
const (
	KindStatic Kind = "static" // a secret sent as is, e.g. an API key
	KindGrant  Kind = "grant"  // an OAuth refresh grant, never sent to the API
)

func (k Kind) valid() bool { return k == KindStatic || k == KindGrant }

// Secrets holds the clerks' credentials as sealed slots (CLK-1, STO-2). A
// secret is opened only inside this package, for one request, and no method
// returns it: the planner, the log and the caller of a clerk never see it.
// The one way out is Login, the mail transport's credential for one
// connection inside the clerk's own process.
type Secrets struct {
	s     Sealer
	write func(atRest []byte) error
	mu    sync.Mutex // also serializes writes, so the last one written is the last one put
	m     map[string]sealed
}

// sealed is one slot at rest: its kind in the clear, bound to the blob by the
// seal's AAD.
type sealed struct {
	Kind Kind   `json:"kind"`
	Blob []byte `json:"blob"`
}

// NewSecrets makes an empty store. write, if not nil, makes the store durable:
// every Put hands it the whole at-rest form and returns only once it returns,
// so it must return only when the bytes are on disk, and must replace the
// old form atomically (write a temporary file, fsync, rename), so a crash
// leaves one whole form or the other. nil keeps the store in memory
// only, for tests and the sim.
func NewSecrets(s Sealer, write func(atRest []byte) error) *Secrets {
	return &Secrets{s: s, write: write, m: map[string]sealed{}}
}

// slotAAD binds a blob to its slot name and kind, so slots cannot be swapped
// and a kind cannot be relabelled. A kind holds no "/", so the two never blur.
func slotAAD(slot string, k Kind) []byte {
	return []byte("agentos/clerk/slot/" + string(k) + "/" + slot)
}

// Put seals secret into slot as kind. With a durable store it returns only
// after the at-rest form holding it is written; if sealing or writing fails,
// the store is unchanged.
func (s *Secrets) Put(slot string, k Kind, secret []byte) error {
	if slot == "" || len(secret) == 0 || !k.valid() {
		return errors.New("clerk: a slot needs a name, a kind and a secret")
	}
	blob, err := s.s.Seal(secret, slotAAD(slot, k))
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := maps.Clone(s.m)
	next[slot] = sealed{k, blob}
	if s.write != nil {
		b, err := json.Marshal(next)
		if err != nil {
			return err
		}
		if err := s.write(b); err != nil {
			return err
		}
	}
	s.m = next
	return nil
}

// Remove deletes slot. With a durable store it returns only after the at-rest
// form without it is written; if writing fails, the store is unchanged. A
// missing slot writes nothing.
func (s *Secrets) Remove(slot string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[slot]; !ok {
		return nil
	}
	next := maps.Clone(s.m)
	delete(next, slot)
	if s.write != nil {
		b, err := json.Marshal(next)
		if err != nil {
			return err
		}
		if err := s.write(b); err != nil {
			return err
		}
	}
	s.m = next
	return nil
}

// RemovePrefix deletes every slot under prefix but keep, in one write as
// Remove does; if writing fails, the store is unchanged, and when no slot
// matches nothing is written. An empty prefix is refused: it would name every
// clerk's slots.
func (s *Secrets) RemovePrefix(prefix, keep string) error {
	if prefix == "" {
		return errors.New("clerk: RemovePrefix needs a prefix")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := maps.Clone(s.m)
	maps.DeleteFunc(next, func(slot string, _ sealed) bool { return slot != keep && strings.HasPrefix(slot, prefix) })
	if len(next) == len(s.m) {
		return nil
	}
	if s.write != nil {
		b, err := json.Marshal(next)
		if err != nil {
			return err
		}
		if err := s.write(b); err != nil {
			return err
		}
	}
	s.m = next
	return nil
}

// MailSlots prefixes the only slots Login opens: a mailbox password.
const MailSlots = "mail/"

// MailLogin is a mailbox password as Login gives it. The mail transport
// turns it into its own login (run's mailBox), so this package, which the
// kernel's clerk check path links, links no mail parser (KRN-2, #2937).
type MailLogin struct {
	User   string
	Secret string
}

// Login is the mail transport's credential (imapsmtp.Config.Credential) from
// a static slot under MailSlots (MIG-4-mail-a-8); any other slot does not
// open, so Login is no getter for another clerk's secret. Each call opens
// the slot afresh, so a removed or replaced password takes effect at the
// next connection, and a slot of another kind does not open. The Secret
// string is a copy that clear cannot wipe; it lives for one connection in
// the clerk's own process, as the exit's header does.
func (s *Secrets) Login(slot, user string) func(context.Context) (MailLogin, error) {
	return func(context.Context) (MailLogin, error) {
		var l MailLogin
		if !strings.HasPrefix(slot, MailSlots) {
			return l, errors.New("clerk: Login opens only a mail slot")
		}
		err := s.with(slot, KindStatic, func(p []byte) error {
			l = MailLogin{User: user, Secret: string(p)}
			return nil
		})
		return l, err
	}
}

// DeviceSlots prefixes the only slots DeviceKey opens: a device's shared
// key, such as a Withings scale's kl.
const DeviceSlots = "device/"

// DeviceKey opens a static slot under DeviceSlots for each call of the
// function it returns, hands the key to fn and wipes it when fn returns;
// any other slot does not open, so DeviceKey is no getter for another
// clerk's secret. fn must not keep the key: the device clerk proves with it
// and returns only the proof (CLK-1).
func (s *Secrets) DeviceKey(slot string) func(fn func(key []byte) error) error {
	return func(fn func(key []byte) error) error {
		if !strings.HasPrefix(slot, DeviceSlots) {
			return errors.New("clerk: DeviceKey opens only a device slot")
		}
		return s.with(slot, KindStatic, fn)
	}
}

func (s *Secrets) Has(slot string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[slot]
	return ok
}

// Len is how many slots the store holds; a nil store holds none.
func (s *Secrets) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// with opens slot as kind for fn and wipes the plaintext after it returns. A
// slot of another kind does not open: its AAD differs.
func (s *Secrets) with(slot string, k Kind, fn func(secret []byte) error) error {
	s.mu.Lock()
	b, ok := s.m[slot]
	s.mu.Unlock()
	if !ok {
		return errors.New("clerk: no such secret slot")
	}
	plain, err := s.s.Open(b.Blob, slotAAD(slot, k))
	if err != nil {
		return err
	}
	defer clear(plain)
	return fn(plain)
}

// MarshalBinary is the store's at-rest form: sealed blobs and their kinds only.
func (s *Secrets) MarshalBinary() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Marshal(s.m)
}

// UnmarshalBinary loads a store and opens every slot once, so a wrong key, a
// swapped slot or a relabelled kind fails here, not at the first request.
func (s *Secrets) UnmarshalBinary(b []byte) error {
	m := map[string]sealed{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for slot, v := range m {
		plain, err := s.s.Open(v.Blob, slotAAD(slot, v.Kind))
		if err != nil {
			return errors.New("clerk: secret slot does not open: " + slot)
		}
		clear(plain)
	}
	s.mu.Lock()
	s.m = m
	s.mu.Unlock()
	return nil
}
