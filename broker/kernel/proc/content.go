package proc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// FileContent is one content store on disk (kernel.ContentStore, LOG-4,
// KRN-content): a directory open to this uid only, one file per item named
// by the SHA-256 of its ciphertext. Items arrive sealed under their
// subject's key (kernel.Seal), so the store holds ciphertext only and no
// key: erase destroys the key in FileKeys, then deletes the files. Put
// writes atomically; Delete unlinks the file and syncs the directory, and
// succeeds for an absent item.
type FileContent struct {
	dir  string
	stop func(i int) bool // tests: crash Put's file write after step i
}

const (
	itemExt = ".item"
	tmpExt  = ".tmp" // privfile.WriteAtomic's temporary
	// MaxItem bounds one sealed item's plaintext, in bytes, so a seal and
	// a readfor fit the socket's call and answer bounds.
	MaxItem = 1 << 20
	// maxSealed is MaxItem sealed: the nonce and the tag.
	maxSealed = MaxItem + 64
)

// storeName is a content store's name, which is its directory's: the name
// of the content clerk that seals into it.
var storeName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// ValidStoreName reports whether s can name a file-backed content store.
func ValidStoreName(s string) bool { return storeName.MatchString(s) && kernel.ValidStore(s) }

// ErrStoreName refuses a store name ValidStoreName does not take.
var ErrStoreName = errors.New("run: a content store's name is 1 to 32 of a-z, 0-9 and -, starting with a letter")

// OpenContentStores opens every store under dir, made 0700 if missing:
// each of names, made if missing, and each store directory already there,
// so a store no longer named still has its items erased. A temporary a
// torn write left is removed: its item was never logged (kernel.Seal puts
// before it logs); so is a restore's staging a crash left beside dir. A
// directory or file open to another uid is refused.
func OpenContentStores(dir string, names []string) (map[string]kernel.ContentStore, error) {
	parent, err := os.ReadDir(filepath.Dir(dir))
	if err != nil {
		return nil, err
	}
	for _, de := range parent {
		if strings.HasPrefix(de.Name(), restoreStage) {
			if err := os.RemoveAll(filepath.Join(filepath.Dir(dir), de.Name())); err != nil {
				return nil, err
			}
		}
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := privfile.Check(dir, true); err != nil {
		return nil, err
	}
	all := map[string]bool{}
	for _, n := range names {
		if !ValidStoreName(n) {
			return nil, fmt.Errorf("%w: %q", ErrStoreName, n)
		}
		all[n] = true
	}
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, de := range des {
		if ValidStoreName(de.Name()) {
			all[de.Name()] = true
		}
	}
	out := map[string]kernel.ContentStore{}
	for n := range all {
		c, err := openFileContent(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		out[n] = c
	}
	return out, privfile.SyncDir(dir)
}

func openFileContent(dir string) (*FileContent, error) {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := privfile.Check(dir, true); err != nil {
		return nil, err
	}
	if err := dropTemps(dir); err != nil {
		return nil, err
	}
	return &FileContent{dir: dir}, nil
}

// dropTemps removes every temporary a torn write left in dir, and syncs it.
func dropTemps(dir string) error {
	des, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, de := range des {
		if strings.HasSuffix(de.Name(), tmpExt) {
			if err := os.Remove(filepath.Join(dir, de.Name())); err != nil {
				return err
			}
		}
	}
	return privfile.SyncDir(dir)
}

func itemName(h kernel.Hash) string { return hex.EncodeToString(h[:]) + itemExt }

// dropUnlogged deletes every item file the log does not name in its store:
// a put a crash stopped after its rename (kernel.Seal puts before it
// logs), which no read reaches and no erase would delete (#4368).
func dropUnlogged(s *kernel.State, stores map[string]kernel.ContentStore) error {
	for name, cs := range stores {
		f, ok := cs.(*FileContent)
		if !ok {
			continue
		}
		des, err := os.ReadDir(f.dir)
		if err != nil {
			return err
		}
		for _, de := range des {
			x, _ := strings.CutSuffix(de.Name(), itemExt)
			b, err := hex.DecodeString(x)
			if err != nil || len(b) != len(kernel.Hash{}) || itemName(kernel.Hash(b)) != de.Name() {
				continue
			}
			if st, ok := s.ItemStore(kernel.Hash(b)); !ok || st != name {
				if err := f.Delete(kernel.Hash(b)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (f *FileContent) Put(h kernel.Hash, ct []byte) error {
	if len(ct) > maxSealed {
		return kernel.ErrItem
	}
	return privfile.WriteAtomic(f.dir, itemName(h), ct, f.stop)
}

// Get reads the item named h; kernel.Read checks it against h.
func (f *FileContent) Get(h kernel.Hash) ([]byte, error) {
	fd, err := os.OpenFile(filepath.Join(f.dir, itemName(h)), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, kernel.ErrItem
	}
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	if err := privfile.CheckFile(fd); err != nil {
		return nil, err
	}
	ct, err := io.ReadAll(io.LimitReader(fd, maxSealed+1))
	if err != nil {
		return nil, err
	}
	if len(ct) > maxSealed {
		return nil, kernel.ErrItem
	}
	return ct, nil
}

// Delete unlinks the item named h and syncs the directory. On an SSD the
// unlink is logical, as for a key file (ASSUMPTIONS.md KRN-erase-c); the
// blocks hold ciphertext under a destroyed key.
func (f *FileContent) Delete(h kernel.Hash) error {
	if err := os.Remove(filepath.Join(f.dir, itemName(h))); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return privfile.SyncDir(f.dir)
}
