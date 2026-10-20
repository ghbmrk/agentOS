package clerk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
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

// Secrets holds the clerks' credentials as sealed slots (CLK-1, STO-2). A
// secret is opened only inside this package, for one request, and no method
// returns it: the planner, the log and the caller of a clerk never see it.
type Secrets struct {
	s  Sealer
	mu sync.Mutex
	m  map[string][]byte
}

func NewSecrets(s Sealer) *Secrets { return &Secrets{s: s, m: map[string][]byte{}} }

// slotAAD binds a blob to its slot name, so slots cannot be swapped.
func slotAAD(slot string) []byte { return []byte("agentos/clerk/slot/" + slot) }

func (s *Secrets) Put(slot string, secret []byte) error {
	if slot == "" || len(secret) == 0 {
		return errors.New("clerk: a slot needs a name and a secret")
	}
	blob, err := s.s.Seal(secret, slotAAD(slot))
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.m[slot] = blob
	s.mu.Unlock()
	return nil
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

// with opens slot for fn and wipes the plaintext after it returns.
func (s *Secrets) with(slot string, fn func(secret []byte) error) error {
	s.mu.Lock()
	blob, ok := s.m[slot]
	s.mu.Unlock()
	if !ok {
		return errors.New("clerk: no such secret slot")
	}
	plain, err := s.s.Open(blob, slotAAD(slot))
	if err != nil {
		return err
	}
	defer clear(plain)
	return fn(plain)
}

// MarshalBinary is the store's at-rest form: sealed blobs only.
func (s *Secrets) MarshalBinary() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Marshal(s.m)
}

// UnmarshalBinary loads a store and opens every slot once, so a wrong key or
// a swapped slot fails here, not at the first request.
func (s *Secrets) UnmarshalBinary(b []byte) error {
	m := map[string][]byte{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for slot, blob := range m {
		plain, err := s.s.Open(blob, slotAAD(slot))
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
