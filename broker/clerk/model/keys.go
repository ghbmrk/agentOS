package model

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/ghbmrk/agentos/broker/clerk"
)

// Keys is the model clerk's API keys in one sealed value (CLK-1, STO-2): a
// key and its private-data label per provider, sealed under a key that
// never leaves the Sealer. No method returns a key: it is opened inside
// this package, for one call, and wiped after.
type Keys struct {
	s     clerk.Sealer
	write func(atRest []byte) error
	mu    sync.Mutex // also serializes changes, so the last one written is the last one made
	blob  []byte     // nil: no key stored
}

type keyEntry struct {
	Key     string `json:"key"`
	Private bool   `json:"private"`
}

var keysAAD = []byte("agentos/clerk/model/api-keys")

var errNoKey = errors.New("model: no key is set for this provider")

// ErrKeysOpen is a stored value that does not open under this sealer.
var ErrKeysOpen = errors.New("model: the API keys do not open")

// NewKeys makes an empty store. write, if not nil, makes it durable: every
// change hands it the whole at-rest form and returns only once it returns,
// so it must return only when the bytes are on disk, replaced atomically.
// nil keeps the store in memory only, for tests.
func NewKeys(s clerk.Sealer, write func(atRest []byte) error) *Keys {
	return &Keys{s: s, write: write}
}

// Load takes the at-rest form a durable store wrote; empty is no key. A
// value that does not open is refused, and the store stays empty.
func (k *Keys) Load(atRest []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.blob = nil
	if len(atRest) == 0 {
		return nil
	}
	plain, err := k.s.Open(atRest, keysAAD)
	if err != nil {
		return ErrKeysOpen
	}
	var m map[string]keyEntry
	err = json.Unmarshal(plain, &m)
	clear(plain)
	if err != nil {
		return ErrKeysOpen
	}
	k.blob = append([]byte(nil), atRest...)
	return nil
}

// MarshalBinary is the at-rest form: the sealed blob alone.
func (k *Keys) MarshalBinary() ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]byte(nil), k.blob...), nil
}

// openLocked opens the stored keys; the caller holds mu and wipes them.
func (k *Keys) openLocked() (map[string]keyEntry, error) {
	m := map[string]keyEntry{}
	if k.blob == nil {
		return m, nil
	}
	plain, err := k.s.Open(k.blob, keysAAD)
	if err != nil {
		return nil, ErrKeysOpen
	}
	defer clear(plain)
	if json.Unmarshal(plain, &m) != nil {
		return nil, ErrKeysOpen
	}
	return m, nil
}

// change applies fn to the stored keys and seals the result; on any
// failure the store is unchanged.
func (k *Keys) change(fn func(m map[string]keyEntry) error) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	m, err := k.openLocked()
	if err != nil {
		return err
	}
	if err := fn(m); err != nil {
		return err
	}
	var blob []byte
	if len(m) > 0 {
		plain, err := json.Marshal(m)
		if err != nil {
			return err
		}
		blob, err = k.s.Seal(plain, keysAAD)
		clear(plain)
		if err != nil {
			return err
		}
	}
	if k.write != nil {
		if err := k.write(blob); err != nil {
			return err
		}
	}
	k.blob = blob
	return nil
}

func (k *Keys) set(provider, key string, private bool) error {
	return k.change(func(m map[string]keyEntry) error {
		m[provider] = keyEntry{key, private}
		return nil
	})
}

func (k *Keys) label(provider string, private bool) error {
	return k.change(func(m map[string]keyEntry) error {
		e, ok := m[provider]
		if !ok {
			return errNoKey
		}
		e.Private = private
		m[provider] = e
		return nil
	})
}

func (k *Keys) remove(provider string) error {
	return k.change(func(m map[string]keyEntry) error {
		delete(m, provider)
		return nil
	})
}

// state is each set provider's private-data label.
func (k *Keys) state() (map[string]bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	m, err := k.openLocked()
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for p, e := range m {
		out[p] = e.Private
	}
	return out, nil
}

// use opens provider's key for fn and wipes it after fn returns. The lock
// is not held across fn, so one slow call holds up no other.
func (k *Keys) use(provider string, fn func(key []byte, private bool) error) error {
	k.mu.Lock()
	m, err := k.openLocked()
	k.mu.Unlock()
	if err != nil {
		return err
	}
	e, ok := m[provider]
	if !ok {
		return errNoKey
	}
	key := []byte(e.Key)
	defer clear(key)
	return fn(key, e.Private)
}
