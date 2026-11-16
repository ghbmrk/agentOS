package seal

// REQ: STO-2, A8

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

func rewrite(t *testing.T, path string, edit func(f *file)) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := parse(b)
	if err != nil {
		t.Fatal(err)
	}
	edit(f)
	if b, err = json.Marshal(f); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Someone with the drive but not the store key can write a well-formed slot
// for this store's ID that wraps a key of their own under a factor they
// know. The store then refuses to open, for them and for the owner, rather
// than open a store they chose; dropping a slot is refused the same way.
func TestSlotsChangedWithoutTheKeyAreRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store")
	mine, theirs := Recovery{Key: make([]byte, RecoveryLen)}, Recovery{Key: make([]byte, RecoveryLen)}
	mine.Key[0], theirs.Key[0] = 1, 2
	s, err := Create(path, mine)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddSlot(Recovery{Key: make([]byte, RecoveryLen)}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	orig, _ := os.ReadFile(path)

	rewrite(t, path, func(f *file) {
		forged, err := makeSlot(f.ID, make([]byte, keyLen), theirs)
		if err != nil {
			t.Fatal(err)
		}
		f.Slots = append(f.Slots, forged)
	})
	for name, r := range map[string]Recovery{"theirs": theirs, "mine": mine} {
		if _, err := Unlock(path, r); !errors.Is(err, ErrTampered) {
			t.Errorf("a forged slot, unlocked with %s: got %v, want ErrTampered", name, err)
		}
	}

	os.WriteFile(path, orig, 0o600)
	rewrite(t, path, func(f *file) { f.Slots = slices.Delete(f.Slots, 1, 2) })
	if _, err := Unlock(path, mine); !errors.Is(err, ErrTampered) {
		t.Errorf("a dropped slot: got %v, want ErrTampered", err)
	}
}

// A wrap moved into another store does not open there: the store's ID is in
// every wrap's associated data.
func TestAWrapIsBoundToItsStore(t *testing.T) {
	dir := t.TempDir()
	r := Recovery{Key: make([]byte, RecoveryLen)}
	a, err := Create(filepath.Join(dir, "a"), r)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	b, err := Create(filepath.Join(dir, "b"), Recovery{Key: append([]byte{9}, make([]byte, RecoveryLen-1)...)})
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	ab, _ := os.ReadFile(filepath.Join(dir, "a"))
	fa, _ := parse(ab)
	rewrite(t, filepath.Join(dir, "b"), func(f *file) { f.Slots = append(f.Slots, fa.Slots[0]) })
	if _, err := Unlock(filepath.Join(dir, "b"), r); !errors.Is(err, ErrWrongFactor) {
		t.Fatalf("a wrap from another store: got %v, want ErrWrongFactor", err)
	}
}

// A tpm slot planted first in the file that unseals to a key of the wrong
// length (SealTo needs only the box's public policy key and the SRK's
// public area) makes Unlock return an error, not panic.
func TestAPlantedShortTPMKeyIsAnError(t *testing.T) {
	sw := swtpm.Start(t)
	sw.Reboot()
	sw.Measure(9, "initrd-A")
	key, err := tpmseal.NewPolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := tpmseal.SignCurrent(sw.TPM(), key, []uint{9})
	if err != nil {
		t.Fatal(err)
	}
	f := TPM{TPM: sw.TPM(), PolicyKey: &key.PublicKey, Policies: []tpmseal.Policy{p}}
	path := filepath.Join(t.TempDir(), "store")
	s, err := Create(path, f)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := s.Anchor()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	rewrite(t, path, func(fl *file) {
		planted := fl.Slots[0]
		planted.ID = "00000000000000ff"
		if planted.Sealed, err = tpmseal.SealTo(planted.Sealed.SRKPublic, []byte("short"), &key.PublicKey, ""); err != nil {
			t.Fatal(err)
		}
		fl.Slots = append([]slot{planted}, fl.Slots...)
	})
	_, err = Unlock(path, TPM{TPM: sw.TPM(), PolicyKey: &key.PublicKey, Anchor: anchor})
	if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrTampered) {
		t.Fatalf("a planted short tpm key: got %v, want the store refused", err)
	}
}

// refusalStore is a store file with one recovery slot over key and the
// entries blob that entries gives, MAC'd under key, built as Create and
// encode build one but without them.
func refusalStore(t *testing.T, key []byte, sl slot, entries func(id []byte) []byte) file {
	t.Helper()
	f := file{V: version, ID: make([]byte, idLen), Slots: []slot{sl}}
	f.Entries = entries(f.ID)
	f.MAC = mac(key, f)
	return f
}

func refusalWrite(t *testing.T, f file) string {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "store")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// refusalEntries seals set as the entries blob under key.
func refusalEntries(t *testing.T, key []byte, set map[string]any) func(id []byte) []byte {
	return func(id []byte) []byte {
		plain, err := json.Marshal(set)
		if err != nil {
			t.Fatal(err)
		}
		b, err := seal(derive(key, id, "entries", keyLen), plain, entriesAAD(id))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
}

// refusalWipes records what each wipe held, until the test ends.
func refusalWipes(t *testing.T) *[]string {
	var held []string
	w := wipe
	t.Cleanup(func() { wipe = w })
	wipe = func(b []byte) {
		held = append(held, string(b))
		clear(b)
	}
	return &held
}

func refusalCount(held []string, v []byte) int {
	n := 0
	for _, h := range held {
		if h == string(v) {
			n++
		}
	}
	return n
}

// An entry set the store refuses (a bad name, a value past MaxEntry, a value
// that is no byte string, one entry too many) had its values decoded before
// the refusal; Unlock wipes each of them, the slot, MAC and entries keys and
// the store key's clone before it returns ErrCorrupt, and leaves the file
// closed (CLK-1, STO-2).
func TestARefusedEntrySetIsWiped(t *testing.T) {
	canary := []byte("refused-entry-canary")
	many := map[string]any{"x/a": canary}
	for i := range MaxEntries {
		many[string([]byte{'y', '/', byte('a' + i%26), byte('a' + i/26)})] = []byte{}
	}
	r, key, id := Recovery{Key: make([]byte, RecoveryLen)}, slices.Repeat([]byte{0x5a}, keyLen), make([]byte, idLen)
	sl, err := makeSlot(id, key, r)
	if err != nil {
		t.Fatal(err)
	}
	k, err := slotKey(&sl, r)
	if err != nil {
		t.Fatal(err)
	}
	for name, set := range map[string]map[string]any{
		"bad name":     {"x/a": canary, "Bad Name": []byte{}},
		"too long":     {"x/a": canary, "x/b": make([]byte, MaxEntry+1)},
		"not bytes":    {"x/a": canary, "x/b": 1},
		"past the cap": many,
	} {
		t.Run(name, func(t *testing.T) {
			path := refusalWrite(t, refusalStore(t, key, sl, refusalEntries(t, key, set)))
			held := refusalWipes(t)
			if _, err := Unlock(path, r); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("got %v, want ErrCorrupt", err)
			}
			for what, v := range map[string][]byte{
				"the decoded canary": canary, "the slot key": k,
				"the MAC key": derive(key, id, "mac", 32), "the entries key": derive(key, id, "entries", keyLen),
				"the store key's clone": key, // Close drops it; a refusal that skips Close keeps it (#5898)
			} {
				if n := refusalCount(*held, v); n != 1 {
					t.Errorf("wiped %s %d times, want once", what, n)
				}
			}
			fds, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Skip("no /proc/self/fd")
			}
			for _, fd := range fds {
				if l, _ := os.Readlink(filepath.Join("/proc/self/fd", fd.Name())); l == path {
					t.Fatalf("Unlock left %s open", path)
				}
			}
		})
	}
}

// refusalTPM is a TPM no command reaches: Unlock must refuse before it.
type refusalTPM struct{}

func (refusalTPM) Send([]byte) ([]byte, error) { return nil, errors.New("no TPM here") }

// Each bound of the store file and each refusal on the way to its entries,
// and a set at the bounds that opens.
func TestEachBoundOfTheStoreFile(t *testing.T) {
	r, key, id := Recovery{Key: make([]byte, RecoveryLen)}, make([]byte, keyLen), make([]byte, idLen)
	if _, err := makeSlot(id, key, Recovery{Key: r.Key[1:]}); err == nil || errors.Is(err, ErrWrongFactor) {
		t.Fatalf("a short recovery key's slot: got %v, want refused before any unwrap", err)
	}
	held := refusalWipes(t)
	sl, err := makeSlot(id, key, r)
	if err != nil {
		t.Fatal(err)
	}
	if k, _ := slotKey(&sl, r); refusalCount(*held, k) != 1 {
		t.Error("makeSlot left the slot key unwiped")
	}
	short := func([]byte) []byte { return make([]byte, 12+16) }
	path := refusalWrite(t, refusalStore(t, key, sl, short))
	if _, err := Unlock(path, r); !errors.Is(err, ErrTampered) {
		t.Errorf("entries that do not open under a key that MACs the file: got %v, want ErrTampered", err)
	}
	if _, err := Unlock(path, Recovery{Key: r.Key[1:]}); !errors.Is(err, ErrWrongFactor) {
		t.Errorf("a short recovery key: got %v, want ErrWrongFactor", err)
	}
	if _, err := Unlock(path, TPM{}); !errors.Is(err, ErrNoSlot) {
		t.Errorf("a TPM factor with no TPM: got %v, want ErrNoSlot", err)
	}
	if _, err := Unlock(path, TPM{TPM: refusalTPM{}}); !errors.Is(err, ErrNoPolicyKey) {
		t.Errorf("a TPM factor with no policy key: got %v, want ErrNoPolicyKey", err)
	}
	if _, err := Unlock(path+".missing", r); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no file: got %v, want ErrNotExist", err)
	}
	if _, err := ReadID(path + ".missing"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no file to read the ID of: got %v, want ErrNotExist", err)
	}
	if _, err := Unlock(t.TempDir(), r); err == nil || errors.Is(err, ErrCorrupt) {
		t.Errorf("a directory: got %v, want the read's own error", err)
	}

	edge := map[string]any{"x/a": make([]byte, MaxEntry)}
	for i := range MaxEntries - 1 {
		edge[string([]byte{'y', '/', byte('a' + i%26), byte('a' + i/26)})] = []byte{}
	}
	s, err := Unlock(refusalWrite(t, refusalStore(t, key, sl, refusalEntries(t, key, edge))), r)
	if err != nil {
		t.Fatalf("MaxEntries entries, one MaxEntry long: %v", err)
	}
	s.Close()

	for name, edit := range map[string]func(f *file){
		"past MaxFile":  func(f *file) { f.Entries = make([]byte, MaxFile) },
		"version":       func(f *file) { f.V++ },
		"short entries": func(f *file) { f.Entries = f.Entries[1:] },
		"slot id":       func(f *file) { f.Slots[0].ID = "not-hex" },
		"same slot id":  func(f *file) { f.Slots = append(f.Slots, f.Slots[0]) },
	} {
		f := refusalStore(t, key, sl, short)
		edit(&f)
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parse(b); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: got %v, want ErrCorrupt", name, err)
		}
	}

	// MaxSlots slots, one a passphrase slot at the Argon bounds, parse.
	f := refusalStore(t, key, sl, short)
	for len(f.Slots) < MaxSlots-1 {
		next := sl
		next.ID = "00000000000000e" + "0123456789abcdef"[len(f.Slots):len(f.Slots)+1]
		f.Slots = append(f.Slots, next)
	}
	edges := Argon{Time: argonCapTime, MemKiB: argonCapKiB, Threads: 1}
	f.Slots = append(f.Slots, slot{ID: "00000000000000f1", Kind: KindPassphrase, Salt: make([]byte, saltLen), Argon: &edges, Wrap: make([]byte, wrapLen)})
	if b, err := json.Marshal(f); err != nil {
		t.Fatal(err)
	} else if _, err := parse(b); err != nil {
		t.Errorf("MaxSlots slots, Argon at its caps: %v", err)
	}

	// A file of exactly MaxFile bytes is read whole: pad the entries in
	// base64's steps of 4, after a passphrase slot whose Argon digits take
	// up the rest (parse checks no wrap).
	f = refusalStore(t, key, sl, short)
	f.Slots = append(f.Slots, slot{ID: "00000000000000f1", Kind: KindPassphrase, Salt: make([]byte, saltLen), Wrap: make([]byte, wrapLen)})
	for n := range 4 {
		f.Slots[1].Argon = &Argon{Time: 1, MemKiB: ArgonFloorKiB, Threads: []uint8{1, 10, 100, 100}[n]}
		if n == 3 {
			f.Slots[1].Argon.Time = 10
		}
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if gap := MaxFile - len(b); gap%4 == 0 {
			f.Entries = make([]byte, len(f.Entries)+gap/4*3)
			break
		}
	}
	if b, _ := json.Marshal(f); len(b) != MaxFile {
		t.Fatalf("the padded file is %d bytes, want MaxFile", len(b))
	}
	if id, err := ReadID(refusalWrite(t, f)); err != nil || len(id) != idLen {
		t.Fatalf("a store file of exactly MaxFile bytes: %v", err)
	}
}
