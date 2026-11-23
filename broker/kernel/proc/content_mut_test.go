package proc

// REQ: LOG-4
//
// MUT-kill-6305-proc (#6367): the content stores' refusals and bounds, each
// checked by what they return or leave on disk.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// A content directory, or a store in it, that this uid cannot list stops
// the open: its items would go unreported and unerased.
func TestAnUnlistableContentDirStopsTheOpen(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any directory; CI runs these as a plain user")
	}
	dir := filepath.Join(t.TempDir(), "content")
	if err := os.Mkdir(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenContentStores(dir, []string{"mail"}); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("open of an unlistable content dir: %v, want a permission error", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "mail"), 0o300); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenContentStores(dir, nil); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("open of an unlistable store: %v, want a permission error", err)
	}
	if _, err := OpenFileKeys(filepath.Join(dir, "mail"), [32]byte{}); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("open of an unlistable key table: %v, want a permission error", err)
	}
}

// A store's open drops a torn write's temporary and still lists every item.
func TestAStoreOpenDropsTemporariesAndListsItems(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mail")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ct := []byte("sealed")
	h := kernel.Hash(sha256.Sum256(ct))
	for name, b := range map[string][]byte{itemName(h): ct, itemName(h) + tmpExt: []byte("torn")} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, items, err := openFileContent(dir)
	if err != nil || len(items) != 1 || items[0] != h {
		t.Fatalf("open: %v %v, want the one item", items, err)
	}
	if _, err := os.Stat(filepath.Join(dir, itemName(h)+tmpExt)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the temporary stayed: %v", err)
	}
}

// unlogged names every item no entry names, sorted, whatever order the
// stores come in.
func TestUnloggedIsSorted(t *testing.T) {
	found := map[string][]kernel.Hash{}
	var want []string
	for _, s := range []string{"a", "b", "c", "d", "e", "f"} {
		h := kernel.Hash(sha256.Sum256([]byte(s)))
		found[s] = []kernel.Hash{h}
		want = append(want, s+"/"+itemHex(h))
	}
	for range 20 {
		if got := unlogged(&kernel.State{}, found); !slices.Equal(got, want) {
			t.Fatalf("unlogged %v, want %v", got, want)
		}
	}
}

func itemHex(h kernel.Hash) string { return itemName(h)[:2*len(h)] }

// An item of exactly maxSealed bytes is put and read back whole; a missing
// one is ErrItem, a linked one an error that says so, and a read leaves no
// descriptor open. Delete syncs the directory after the unlink.
func TestFileContentBoundsAndRefusals(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mail")
	f, _, err := openFileContent(dir)
	if err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte{7}, maxSealed)
	h := kernel.Hash(sha256.Sum256(big))
	if err := f.Put(h, big); err != nil {
		t.Fatalf("put of %d bytes: %v", maxSealed, err)
	}
	if got, err := f.Get(h); err != nil || !bytes.Equal(got, big) {
		t.Fatalf("get of a %d-byte item: %d bytes, %v", maxSealed, len(got), err)
	}
	over := kernel.Hash{3}
	if err := os.WriteFile(filepath.Join(dir, itemName(over)), append(big, 7), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := f.Get(over); !errors.Is(err, kernel.ErrItem) || got != nil {
		t.Fatalf("get of a %d-byte item: %d bytes, %v; want ErrItem", maxSealed+1, len(got), err)
	}
	small := kernel.Hash(sha256.Sum256([]byte("s")))
	if err := f.Put(small, []byte("s")); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		if _, err := f.Get(small); err != nil {
			t.Fatal(err)
		}
		if n := openFDsTo(t, filepath.Join(dir, itemName(small))); n != 0 {
			t.Fatalf("%d descriptors to the item stay open after a get", n)
		}
	}
	if _, err := f.Get(kernel.Hash{1}); !errors.Is(err, kernel.ErrItem) {
		t.Fatalf("get of a missing item: %v, want ErrItem", err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(dir, itemName(kernel.Hash{2}))); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Get(kernel.Hash{2}); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("get of a linked item: %v, want ELOOP", err)
	}
	synced := 0
	was := privfile.SyncFile
	privfile.SyncFile = func(d *os.File) error { synced++; return was(d) }
	defer func() { privfile.SyncFile = was }()
	if err := f.Delete(h); err != nil || synced != 1 {
		t.Fatalf("delete: %v, %d syncs; want one", err, synced)
	}
}
