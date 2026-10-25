package proc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// FileKeys is the subject-key table on disk (kernel.Keys, LOG-4,
// KRN-erase): one file per subject in a directory open to this uid only,
// each the subject's data key sealed under the log's AES-GCM key with the
// subject ID as AAD, so a file moved to another subject's name does not
// open. Put writes atomically; Delete unlinks the file and syncs the
// directory, so a deleted key does not come back after a crash. The
// directory is outside the log and is never rebuilt from it: a key in the
// log could not be destroyed. The kernel's start-up (#2682) wires it.
type FileKeys struct {
	dir  string
	aead cipher.AEAD
}

const keyExt = ".key"

// ErrKeyFile is a key file that does not open as its subject's.
var ErrKeyFile = errors.New("run: a subject key file does not open as its subject's")

// OpenFileKeys opens the table in dir, made 0700 if missing, sealed under
// logKey. A directory or file open to another uid is refused.
func OpenFileKeys(dir string, logKey [32]byte) (*FileKeys, error) {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := privfile.Check(dir, true); err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(logKey[:])
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &FileKeys{dir: dir, aead: a}, nil
}

func keyAAD(subject string) []byte { return []byte("agentos.keytable.v1\x00" + subject) }

func (f *FileKeys) path(subject string) (string, error) {
	if !kernel.ValidSubject(subject) {
		return "", fmt.Errorf("run: %q is not a subject id", subject)
	}
	return filepath.Join(f.dir, subject+keyExt), nil
}

func (f *FileKeys) Put(subject string, k kernel.SubjectKey) error {
	if _, err := f.path(subject); err != nil {
		return err
	}
	nonce := make([]byte, f.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	return privfile.WriteAtomic(f.dir, subject+keyExt, f.aead.Seal(nonce, nonce, k[:], keyAAD(subject)), nil)
}

func (f *FileKeys) Get(subject string) (kernel.SubjectKey, bool, error) {
	var k kernel.SubjectKey
	p, err := f.path(subject)
	if err != nil {
		return k, false, err
	}
	fd, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return k, false, nil
	}
	if err != nil {
		return k, false, err
	}
	defer fd.Close()
	if err := privfile.CheckFile(fd); err != nil {
		return k, false, err
	}
	b, err := io.ReadAll(io.LimitReader(fd, 256))
	if err != nil {
		return k, false, err
	}
	ns := f.aead.NonceSize()
	if len(b) < ns {
		return k, false, ErrKeyFile
	}
	pt, err := f.aead.Open(nil, b[:ns], b[ns:], keyAAD(subject))
	if err != nil || len(pt) != len(k) {
		return k, false, ErrKeyFile
	}
	copy(k[:], pt)
	return k, true, nil
}

// Delete unlinks subject's key file and syncs the directory. On an SSD
// the unlink is logical: the blocks may survive until reused
// (ASSUMPTIONS.md KRN-erase-c).
func (f *FileKeys) Delete(subject string) error {
	p, err := f.path(subject)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return privfile.SyncDir(f.dir)
}

// List names every subject with a key file. A temporary a crash left is
// not a key.
func (f *FileKeys) List() ([]string, error) {
	des, err := os.ReadDir(f.dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, de := range des {
		sub, ok := strings.CutSuffix(de.Name(), keyExt)
		if ok && kernel.ValidSubject(sub) {
			out = append(out, sub)
		}
	}
	slices.Sort(out)
	return out, nil
}
