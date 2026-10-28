package camnode

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// Store keeps signed bundles by their SHA-256, so the element's record
// names exactly one: a bundle written but never committed (a crash between
// Put and CommitBundle) leaves the committed one readable.
type Store interface {
	Put(p []byte) error
	Get(digest [32]byte) ([]byte, error)
	Keep(digest [32]byte) error // removes every bundle but digest
	Erase() error
}

// ErrAltered is a stored bundle that does not hash to its name.
var ErrAltered = errors.New("camnode: stored bundle altered or missing")

// FileStore is a Store in one directory on the node's data partition.
type FileStore struct{ Dir string }

const storeSuffix = ".bundle"

func (s FileStore) path(d [32]byte) string {
	return filepath.Join(s.Dir, hex.EncodeToString(d[:])+storeSuffix)
}

// Put writes p under its digest: a temporary file, synced, renamed, then
// the directory synced.
func (s FileStore) Put(p []byte) error {
	if len(p) > camwire.MaxSigned {
		return camwire.ErrMalformed
	}
	f, err := os.CreateTemp(s.Dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(p); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path(sha256.Sum256(p))); err != nil {
		return err
	}
	return s.syncDir()
}

// Get reads the bundle named digest and checks it hashes to its name.
func (s FileStore) Get(d [32]byte) ([]byte, error) {
	f, err := os.Open(s.path(d))
	if err != nil {
		return nil, ErrAltered
	}
	defer f.Close()
	p, err := io.ReadAll(io.LimitReader(f, camwire.MaxSigned+1))
	if err != nil || len(p) > camwire.MaxSigned || sha256.Sum256(p) != d {
		return nil, ErrAltered
	}
	return p, nil
}

// Keep removes every stored bundle but d.
func (s FileStore) Keep(d [32]byte) error { return s.remove(s.path(d)) }

// Erase removes every stored bundle.
func (s FileStore) Erase() error { return s.remove("") }

func (s FileStore) remove(keep string) error {
	ents, err := os.ReadDir(s.Dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		p := filepath.Join(s.Dir, e.Name())
		if strings.HasSuffix(e.Name(), storeSuffix) && p != keep {
			if err := os.Remove(p); err != nil {
				return err
			}
		}
	}
	return s.syncDir()
}

func (s FileStore) syncDir() error {
	d, err := os.Open(s.Dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
