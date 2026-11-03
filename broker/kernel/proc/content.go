package proc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
// before it logs). A directory or file open to another uid is refused. It
// returns the stores and, by store, the items each holds (unlogged).
func OpenContentStores(dir string, names []string) (map[string]kernel.ContentStore, map[string][]kernel.Hash, error) {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, nil, err
	}
	if err := privfile.Check(dir, true); err != nil {
		return nil, nil, err
	}
	all := map[string]bool{}
	for _, n := range names {
		if !ValidStoreName(n) {
			return nil, nil, fmt.Errorf("%w: %q", ErrStoreName, n)
		}
		all[n] = true
	}
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	for _, de := range des {
		if ValidStoreName(de.Name()) {
			all[de.Name()] = true
		}
	}
	out, found := map[string]kernel.ContentStore{}, map[string][]kernel.Hash{}
	for n := range all {
		c, items, err := openFileContent(filepath.Join(dir, n))
		if err != nil {
			return nil, nil, err
		}
		out[n], found[n] = c, items
	}
	return out, found, privfile.SyncDir(dir)
}

// openFileContent opens the store at dir and returns the items it holds.
func openFileContent(dir string) (*FileContent, []kernel.Hash, error) {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, nil, err
	}
	if err := privfile.Check(dir, true); err != nil {
		return nil, nil, err
	}
	des, err := dropTemps(dir)
	if err != nil {
		return nil, nil, err
	}
	var items []kernel.Hash
	for _, de := range des {
		x, _ := strings.CutSuffix(de.Name(), itemExt)
		if b, err := hex.DecodeString(x); err == nil && len(b) == len(kernel.Hash{}) && itemName(kernel.Hash(b)) == de.Name() {
			items = append(items, kernel.Hash(b))
		}
	}
	return &FileContent{dir: dir}, items, nil
}

// dropTemps removes every temporary a torn write left in dir, syncs it, and
// returns what dir held.
func dropTemps(dir string) ([]os.DirEntry, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, de := range des {
		if strings.HasSuffix(de.Name(), tmpExt) {
			if err := os.Remove(filepath.Join(dir, de.Name())); err != nil {
				return nil, err
			}
		}
	}
	return des, privfile.SyncDir(dir)
}

func itemName(h kernel.Hash) string { return hex.EncodeToString(h[:]) + itemExt }

// unlogged names, as store/hash, every item found in a store that the log
// does not name in that store: a put a crash stopped after its rename
// (kernel.Seal puts before it logs), or a copy in another store's folder.
// They are kept, as unnamed keys are: a stale log the anchor still takes
// cannot tell them from items whose entries it lost (#4368).
func unlogged(s *kernel.State, found map[string][]kernel.Hash) []string {
	var out []string
	for name, items := range found {
		for _, h := range items {
			if st, ok := s.ItemStore(h); !ok || st != name {
				out = append(out, name+"/"+hex.EncodeToString(h[:]))
			}
		}
	}
	slices.Sort(out)
	return out
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
