// Package setest is an in-memory secure element for tests: a P-256 key and
// two counters behind se.Element, with the element's own rules (counters
// only rise, within 32 bits; no export). Production code never imports it
// (TestServerImportsNoTestElement in broker/camnode).
package setest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"

	"github.com/ghbmrk/agentos/broker/camnode/se"
)

// Memory is the fake element. Its key is generated per run, or set by
// NewMemoryKey for a canary test.
type Memory struct {
	mu       sync.Mutex
	key      *ecdsa.PrivateKey
	counters map[se.Kind]uint64
	pin      [32]byte
	pinned   bool
	// Signs counts Sign calls.
	Signs int
}

var _ se.Element = (*Memory)(nil)

// NewMemory is an element with a fresh key and zero counters.
func NewMemory() *Memory {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return NewMemoryKey(k)
}

// NewMemoryKey is an element holding k.
func NewMemoryKey(k *ecdsa.PrivateKey) *Memory {
	return &Memory{key: k, counters: map[se.Kind]uint64{}}
}

func (m *Memory) Public() ([se.PointLen]byte, error) {
	var out [se.PointLen]byte
	b, err := m.key.PublicKey.Bytes()
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

func (m *Memory) Sign(digest [32]byte) ([]byte, error) {
	m.mu.Lock()
	m.Signs++
	m.mu.Unlock()
	return ecdsa.SignASN1(rand.Reader, m.key, digest[:])
}

func (m *Memory) Counter(k se.Kind) (uint64, error) {
	if k != se.Settings && k != se.Image {
		return 0, se.ErrCounter
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counters[k], nil
}

func (m *Memory) Raise(k se.Kind, to uint64) error {
	if k != se.Settings && k != se.Image {
		return se.ErrCounter
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if to <= m.counters[k] || to > 1<<32-1 {
		return se.ErrCounter
	}
	m.counters[k] = to
	return nil
}

func (m *Memory) OwnerPin() ([32]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pin, m.pinned, nil
}

func (m *Memory) SetOwnerPin(pin [32]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pin, m.pinned = pin, true
	return nil
}

func (m *Memory) ClearOwnerPin() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pin, m.pinned = [32]byte{}, false
	return nil
}
