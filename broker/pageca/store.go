package pageca

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// Sealer seals and opens the authority's file: clerk.Sealer's method set,
// so a clerk sealer serves without this package linking clerk.
type Sealer interface {
	Seal(plain, aad []byte) ([]byte, error)
	Open(blob, aad []byte) ([]byte, error)
}

// File is the sealed authority's name in its directory.
const File = "page-authority.sealed"

// aad binds the sealed blob to this use.
var aad = []byte("agentos page authority v1")

// maxFile bounds the sealed file read back.
const maxFile = 16 << 10

// Store keeps the authority sealed in Dir, which must be this uid's and
// writable by no other: agentosd's own state directory (root). The file is
// 0600, written whole or not at all, and never opened through a link.
type Store struct {
	Dir    string
	Sealer Sealer
}

// ErrMissing: no authority file.
var ErrMissing = errors.New("pageca: no authority file")

// ErrRestore: the box is claimed and its authority is missing or does not
// open. A new one is never made, since the Owner Card carries the old
// fingerprint: the box must be restored (brief design 3).
var ErrRestore = errors.New("pageca: the claimed box has no authority; restore it")

type sealed struct {
	Cert []byte `json:"cert"`
	Key  []byte `json:"key"` // PKCS#8
}

// Save seals a and replaces the file.
func (s Store) Save(a *Authority) error {
	if s.Sealer == nil {
		return errors.New("pageca: no sealer")
	}
	if err := checkDir(s.Dir); err != nil {
		return err
	}
	k, err := x509.MarshalPKCS8PrivateKey(a.key)
	if err != nil {
		return err
	}
	plain, err := json.Marshal(sealed{Cert: a.cert.Raw, Key: k})
	if err != nil {
		return err
	}
	blob, err := s.Sealer.Seal(plain, aad)
	if err != nil {
		return err
	}
	return privfile.WriteAtomic(s.Dir, File, blob, nil)
}

// Open opens the sealed authority for name: ErrMissing when there is no
// file; any other error when the file is a link, open to another uid, or
// does not unseal into this page's authority.
func (s Store) Open(name string) (*Authority, error) {
	if s.Sealer == nil {
		return nil, errors.New("pageca: no sealer")
	}
	if err := checkDir(s.Dir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.Dir, File), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrMissing
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := privfile.CheckFile(f); err != nil {
		return nil, err
	}
	blob, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(blob) > maxFile {
		return nil, errors.New("pageca: authority file too large")
	}
	plain, err := s.Sealer.Open(blob, aad)
	if err != nil {
		return nil, err
	}
	var v sealed
	if err := json.Unmarshal(plain, &v); err != nil {
		return nil, err
	}
	pk, err := x509.ParsePKCS8PrivateKey(v.Key)
	if err != nil {
		return nil, err
	}
	key, ok := pk.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("pageca: not an ECDSA key")
	}
	return fromParts(name, v.Cert, key)
}

// OpenOrCreate opens the sealed authority, or, only when no file exists
// and the box is not claimed, makes one, seals it and returns it. A claimed
// box whose file is missing or does not open gets ErrRestore and never a
// new authority; on a fresh box a file that exists but does not open (a
// link, another uid's, the wrong sealer) is that error, not a new one.
func OpenOrCreate(s Store, name string, built time.Time, claimed bool, r io.Reader) (*Authority, error) {
	a, err := s.Open(name)
	switch {
	case err == nil:
		return a, nil
	case claimed:
		return nil, ErrRestore
	case !errors.Is(err, ErrMissing):
		return nil, err
	}
	a, err = New(name, built, r)
	if err != nil {
		return nil, err
	}
	if err := s.Save(a); err != nil {
		return nil, err
	}
	return a, nil
}

// checkDir refuses a directory that is a link, not this uid's, or writable
// by another uid, who could otherwise plant or swap the file.
func checkDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || int(st.Uid) != os.Geteuid() || fi.Mode().Perm()&0o022 != 0 {
		return errors.New("pageca: the authority's directory is not this uid's alone to write")
	}
	return nil
}
