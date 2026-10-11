// Package vault holds the box's reusable authentication material, encrypted
// at rest, inside the broker (ARC-1, CRED-1, PLAN P1-3).
//
// The vault never hands a value to anything model-directed. Its only reader
// is the egress proxy, which writes a value into an outbound request header
// and nowhere else; imports_test.go fails if any other broker package
// imports this one. A Secret formats as a placeholder, so a value printed or
// serialized by mistake shows nothing.
//
// The data key is wrapped under key slots in a keys file beside the vault
// (keyslot.go, CRED-8): CreateSealed and OpenSealed never let it reach the
// drive. Create and Open take a raw key and are for tests and for the slot
// code itself.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/ghbmrk/agentos/broker/durable"
)

// KeySize is the data key length: AES-256.
const KeySize = 32

// MinValueLen is the shortest value accepted. Redaction (CRED-7) matches
// values verbatim, and a very short value would match innocent text.
const MinValueLen = 12

// KindAPIKey is a provider API key, injected by the egress proxy (CRED-5).
const KindAPIKey = "api_key"

// fileMagic and the version are bound into every seal as associated data,
// so a file from another format or version fails to open rather than being
// misread. Version 2 adds the vault ID and the rollback anchors (V6,
// rollback.go). Version 1 is no longer read: it has no ID, so a copy from
// before the upgrade would skip the rollback check.
const fileMagic = "agentos-vault"
const fileVersion = 2

// Entry describes a stored secret without its value.
type Entry struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type record struct {
	Kind  string `json:"kind"`
	Value []byte `json:"value"`
}

// payload is what a version 2 file seals.
type payload struct {
	Entries map[string]record `json:"entries"`
	// ID names this vault to a rollback counter; CounterAuth is the
	// counter's authorization value. Both stay the same across writes and
	// change only on Rebase.
	ID          []byte   `json:"id"`
	CounterAuth []byte   `json:"counter_auth"`
	Anchors     []Anchor `json:"anchors,omitempty"`
	// Keys is the SHA-256 hash of the keys file this vault goes with
	// (keysbind.go), as a one-element list.
	Keys [][]byte `json:"keys,omitempty"`
	// Next is the whole keys file a slot change is moving to, while the
	// change is under way; OpenSealed rolls forward to it.
	Next []byte `json:"next_keys,omitempty"`
}

type envelope struct {
	Magic   string `json:"magic"`
	Version int    `json:"version"`
	// KeyID names the data key this file is sealed under once the vault
	// has been re-encrypted (reencrypt.go), so the key slots for it can be
	// told from the ones for the key before. Empty until then.
	KeyID  []byte `json:"key_id,omitempty"`
	Nonce  []byte `json:"nonce"`
	Sealed []byte `json:"sealed"`
}

// Vault is an open vault. It is safe for concurrent use.
type Vault struct {
	path string
	aead cipher.AEAD

	mu      sync.RWMutex
	entries map[string]record
	closed  bool
	// keysPath and key are set when the vault was opened through its key
	// slots (keyslot.go), for AddSlot; Close wipes key.
	keysPath string
	key      []byte
	// id, counterAuth and anchors are the rollback binding (rollback.go).
	// counter is the bound counter, whose anchor is anchors[bound].
	id          []byte
	counterAuth []byte
	anchors     []Anchor
	counter     Counter
	bound       int
	// keyID is the envelope's KeyID (reencrypt.go).
	keyID []byte
	// keysOK holds the hash of the keys file this vault accepts, and
	// nextKeys the keys file a slot change is moving to (keysbind.go).
	keysOK   [][]byte
	nextKeys []byte
	// unfinished: OpenSealed found a passphrase change that never took
	// effect (ChangeUnfinished).
	unfinished bool
	// warn tells the owner about a rollback check left unfinished.
	warn func(string)
}

// ErrClosed is returned by every method called after Close.
var ErrClosed = errors.New("vault: closed")

// Create makes a new, empty vault at path. It refuses to replace an
// existing file.
func Create(path string, key []byte) (*Vault, error) { return create(path, key, nil) }

// create is Create recording the keys files the vault goes with.
func create(path string, key []byte, keys [][]byte) (*Vault, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		return nil, errors.New("vault: file already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	v := &Vault{path: path, aead: aead, entries: map[string]record{}, bound: -1, keysOK: keys}
	if err := v.save(); err != nil {
		return nil, err
	}
	return v, nil
}

// Open decrypts the vault at path. A wrong key, a truncated file, or any
// modified byte fails with the same error.
func Open(path string, key []byte) (*Vault, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Magic != fileMagic || env.Version != fileVersion || len(env.Nonce) != aead.NonceSize() {
		return nil, errors.New("vault: not a vault file this version can read")
	}
	plain, err := aead.Open(nil, env.Nonce, env.Sealed, aad(env.Version, env.KeyID))
	if err != nil {
		return nil, errors.New("vault: cannot decrypt (wrong key or modified file)")
	}
	defer wipe(plain)
	var p payload
	if err := json.Unmarshal(plain, &p); err != nil || len(p.ID) != idSize || len(p.CounterAuth) != authSize {
		return nil, errors.New("vault: corrupt contents")
	}
	if p.Entries == nil {
		p.Entries = map[string]record{}
	}
	return &Vault{path: path, aead: aead, entries: p.Entries,
		id: p.ID, counterAuth: p.CounterAuth, anchors: p.Anchors, bound: -1, keyID: env.KeyID, keysOK: p.Keys, nextKeys: p.Next}, nil
}

// Put stores or replaces a secret and writes the vault before returning.
func (v *Vault) Put(name, kind string, value []byte) error {
	if name == "" || kind == "" {
		return errors.New("vault: name and kind are required")
	}
	if len(value) < MinValueLen {
		return fmt.Errorf("vault: value shorter than %d bytes", MinValueLen)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	old, had := v.entries[name]
	v.entries[name] = record{Kind: kind, Value: append([]byte(nil), value...)}
	if err := v.save(); err != nil {
		if had {
			v.entries[name] = old
		} else {
			delete(v.entries, name)
		}
		return err
	}
	if had {
		wipe(old.Value)
	}
	return nil
}

// Delete removes a secret. Deleting a missing name is not an error.
func (v *Vault) Delete(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	old, had := v.entries[name]
	if !had {
		return nil
	}
	delete(v.entries, name)
	if err := v.save(); err != nil {
		v.entries[name] = old
		return err
	}
	wipe(old.Value)
	return nil
}

// List names every secret, sorted, without values. After Close it is empty.
func (v *Vault) List() []Entry {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]Entry, 0, len(v.entries))
	for n, r := range v.entries {
		out = append(out, Entry{Name: n, Kind: r.Kind})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Secret returns the named secret. After Close it finds nothing.
func (v *Vault) Secret(name string) (Secret, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	r, ok := v.entries[name]
	if !ok || v.closed {
		return Secret{}, false
	}
	return Secret{p: &secretBytes{b: append([]byte(nil), r.Value...)}}, true
}

// Redactor matches every value currently in the vault (CRED-7).
func (v *Vault) Redactor() (*Redactor, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return nil, ErrClosed
	}
	vals := make([][]byte, 0, len(v.entries))
	for _, r := range v.entries {
		vals = append(vals, r.Value)
	}
	return NewRedactor(vals), nil
}

// Close zeroes the vault's own copies of the decrypted values and makes
// every later call fail. Copies already handed out (Reveal strings,
// redactor patterns) are immutable Go strings and are not wiped.
func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.closed = true
	wipe(v.key)
	for n, r := range v.entries {
		wipe(r.Value)
		delete(v.entries, n)
	}
	return nil
}

// save seals the whole vault and replaces the file atomically: a crash
// leaves either the old file or the new one. With a counter bound, the
// file carries the counter's next value and the counter advances after
// the write (rollback.go). Caller holds mu.
func (v *Vault) save() error {
	if err := v.ensureID(); err != nil {
		return err
	}
	if v.counter == nil {
		return v.write(v.anchors)
	}
	return v.advance()
}

// write seals the entries with anchors and replaces the file. Caller holds
// mu.
func (v *Vault) write(anchors []Anchor) error {
	plain, err := json.Marshal(payload{Entries: v.entries, ID: v.id, CounterAuth: v.counterAuth, Anchors: anchors, Keys: v.keysOK, Next: v.nextKeys})
	if err != nil {
		return err
	}
	defer wipe(plain)
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	raw, err := json.Marshal(envelope{
		Magic: fileMagic, Version: fileVersion, KeyID: v.keyID, Nonce: nonce,
		Sealed: v.aead.Seal(nil, nonce, plain, aad(fileVersion, v.keyID)),
	})
	if err != nil {
		return err
	}
	return writeFile(v.path, raw, 0o600)
}

// writeFile replaces a vault file, mode 0600: a crash leaves either the old
// file or the new one. A variable so tests can fail it after the new file
// is in place, as a failed directory sync would.
var writeFile = durable.WriteFile

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("vault: key must be %d bytes", KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// aad binds the format version and, once re-encrypted, the key ID.
func aad(version int, keyID []byte) []byte {
	if len(keyID) == 0 {
		return []byte(fmt.Sprintf("%s/v%d", fileMagic, version))
	}
	return []byte(fmt.Sprintf("%s/v%d/%x", fileMagic, version, keyID))
}

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Secret is one credential value. It formats, marshals, and logs as a
// placeholder; only Reveal returns the value. The bytes sit behind a
// pointer so that fmt, which cannot call Format on a value in an unexported
// field, prints an address there rather than the bytes.
type Secret struct{ p *secretBytes }

type secretBytes struct{ b []byte }

const shown = "[vault secret]"

// Reveal returns the value. Only the egress proxy calls it, to write the
// value into an outbound request to a declared endpoint (CRED-5, ADP-10).
func (s Secret) Reveal() string {
	if s.p == nil {
		return ""
	}
	return string(s.p.b)
}

// String implements fmt.Stringer with a placeholder.
func (s Secret) String() string { return shown }

// GoString implements fmt.GoStringer with a placeholder.
func (s Secret) GoString() string { return shown }

// Format makes every fmt verb print the placeholder.
func (s Secret) Format(f fmt.State, _ rune) { f.Write([]byte(shown)) }

// MarshalJSON marshals the placeholder.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(shown) }

// MarshalText marshals the placeholder.
func (s Secret) MarshalText() ([]byte, error) { return []byte(shown), nil }
