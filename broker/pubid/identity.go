// Package pubid is the box's publication identity (SPEC OSS-6): the
// pseudonymous key it signs public output with, rotated on a schedule
// shared by every installation, and the outbox that publishes that output
// in delayed daily batches.
//
// The key is drawn from crypto/rand and from nothing else, so it cannot be
// linked to the owner's identity, number or accounts; the file that holds
// it holds the epoch and the seed and nothing more. Each epoch's key is
// fresh: no signature or record links one epoch's key to the next, and the
// old seed is overwritten when the epoch turns. Epochs are fixed UTC
// periods from one public reference, so every installation rotates at the
// same instant and a key change does not single one out.
//
// The package holds no other secret, reads no private store and makes no
// network call; the Sender it is given publishes.
package pubid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EpochLength is how long one publication key is used.
const EpochLength = 28 * 24 * time.Hour

// Reference is the public start of epoch 0, the same for every
// installation (a Sunday, 00:00 UTC).
var Reference = time.Date(2026, 1, 4, 0, 0, 0, 0, time.UTC)

// EpochOf is the epoch t falls in.
func EpochOf(t time.Time) int64 {
	d := t.Sub(Reference)
	e := int64(d / EpochLength)
	if d < 0 && d%EpochLength != 0 {
		e--
	}
	return e
}

// ErrDamaged means the identity file is not exactly an epoch and a seed.
var ErrDamaged = errors.New("pubid: identity file damaged")

// Identity is the box's current publication key.
type Identity struct {
	path string
	now  func() time.Time
	rand io.Reader

	mu    sync.Mutex
	epoch int64
	priv  ed25519.PrivateKey
}

type identityFile struct {
	Epoch int64  `json:"epoch"`
	Seed  string `json:"seed"`
}

// Open reads the identity at path, making one for the current epoch if
// there is none. now nil means time.Now. A damaged file is an error, never
// replaced: what the box published under it may still need answering for,
// and a silent new key would hide that the file was touched. A file others
// could read gets a fresh key at once, written 0600: the old one may have
// been copied, and a new random key reveals nothing (L3 on #163).
func Open(path string, now func() time.Time) (*Identity, error) {
	if now == nil {
		now = time.Now
	}
	id := &Identity{path: path, now: now, rand: rand.Reader}
	// Others who can write the directory could swap the file (L3 on #163).
	if err := checkDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := sweepTemp(filepath.Dir(path)); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := id.rotate(EpochOf(now())); err != nil {
			return nil, err
		}
		return id, nil
	case err != nil:
		return nil, err
	}
	f, err := parseIdentity(b)
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(path); err != nil {
		return nil, err
	} else if fi.Mode().Perm()&0o077 != 0 {
		if err := id.rotate(EpochOf(now())); err != nil {
			return nil, err
		}
		return id, nil
	}
	seed, err := base64.StdEncoding.DecodeString(f.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: seed", ErrDamaged)
	}
	id.epoch, id.priv = f.Epoch, ed25519.NewKeyFromSeed(seed)
	return id, nil
}

// Key is a copy of the current epoch's private key, and that epoch. When
// the clock is in another epoch than the key's, later or earlier, it
// rotates first: a key kept past the global boundary would single this box
// out and link its publications, while a fresh random key reveals nothing
// (L3 on #163). An old key is gone and is never made again.
func (id *Identity) Key() (ed25519.PrivateKey, int64, error) {
	id.mu.Lock()
	defer id.mu.Unlock()
	if e := EpochOf(id.now()); e != id.epoch {
		if err := id.rotate(e); err != nil {
			return nil, 0, err
		}
	}
	return append(ed25519.PrivateKey(nil), id.priv...), id.epoch, nil
}

// rotate draws a fresh key for epoch e and replaces the file with it in
// one rename, so the old seed is not left beside the new one.
func (id *Identity) rotate(e int64) error {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(id.rand, seed); err != nil {
		return err
	}
	b, err := json.Marshal(identityFile{Epoch: e, Seed: base64.StdEncoding.EncodeToString(seed)})
	if err != nil {
		return err
	}
	if err := writeAtomic(id.path, b); err != nil {
		return err
	}
	clear(id.priv)
	id.epoch, id.priv = e, ed25519.NewKeyFromSeed(seed)
	clear(seed)
	return nil
}

func parseIdentity(b []byte) (identityFile, error) {
	if err := exactKeys(b, "epoch", "seed"); err != nil {
		return identityFile{}, err
	}
	var f identityFile
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&f); err != nil {
		return identityFile{}, fmt.Errorf("%w: %v", ErrDamaged, err)
	}
	return f, nil
}

// exactKeys checks that b is one flat JSON object with each of keys
// exactly once, no other key, and only scalar values.
func exactKeys(b []byte, keys ...string) error {
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if tok, err := d.Token(); err != nil || tok != json.Delim('{') {
		return fmt.Errorf("%w: not an object", ErrDamaged)
	}
	seen := map[string]bool{}
	for d.More() {
		tok, err := d.Token()
		k, ok := tok.(string)
		if err != nil || !ok || !want[k] || seen[k] {
			return fmt.Errorf("%w: fields", ErrDamaged)
		}
		seen[k] = true
		if v, err := d.Token(); err != nil {
			return fmt.Errorf("%w: %v", ErrDamaged, err)
		} else if _, nested := v.(json.Delim); nested {
			return fmt.Errorf("%w: %s is not a value", ErrDamaged, k)
		}
	}
	if tok, err := d.Token(); err != nil || tok != json.Delim('}') || len(seen) != len(keys) {
		return fmt.Errorf("%w: fields", ErrDamaged)
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing data", ErrDamaged)
	}
	return nil
}

// writeAtomic replaces path with b, readable only by the broker
// (os.CreateTemp makes the file 0600), and syncs the directory.
func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pubid-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	// The rename must be on disk before anything relies on it: a batch
	// confirmed sent, or an old seed taken as gone (L3 on #163).
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
