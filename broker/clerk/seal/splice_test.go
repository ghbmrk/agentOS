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

// An authenticated entry set encode never writes (#5897; CLK-1, STO-2): a
// name given twice opens with its last value, and the value it displaced is
// never decoded, so a displaced value that is no base64 does not refuse the
// set; a value that is no base64 has its part-decoded buffer wiped once; a
// value that is no string, and a set of null, are ErrCorrupt.
func TestAnEntrySetEncodeNeverWrites(t *testing.T) {
	r, key, id := Recovery{Key: make([]byte, RecoveryLen)}, slices.Repeat([]byte{0x3c}, keyLen), make([]byte, idLen)
	sl, err := makeSlot(id, key, r)
	if err != nil {
		t.Fatal(err)
	}
	raw := func(plain string) string {
		return refusalWrite(t, refusalStore(t, key, sl, func(id []byte) []byte {
			b, err := seal(derive(key, id, "entries", keyLen), []byte(plain), entriesAAD(id))
			if err != nil {
				t.Fatal(err)
			}
			return b
		}))
	}
	kept := []byte("kept-entry-canary")
	q, err := json.Marshal(kept) // the quoted base64 encode writes
	if err != nil {
		t.Fatal(err)
	}
	held := refusalWipes(t)
	s, err := Unlock(raw(`{"x/a":"ZGlzcGxhY2Vk","x/a":"!!!!","x/a":`+string(q)+`}`), r)
	if err != nil {
		t.Fatalf("a repeated name: %v", err)
	}
	if v, _, _ := s.Get("x/a"); string(v) != string(kept) || len(Entries(s)) != 1 {
		t.Fatalf("a repeated name opened as %q, %d entries; want its last value only", v, len(Entries(s)))
	}
	// The derived keys' buffers are wiped once each.
	s.LogKey()
	s.ClerkRoot()
	for _, purpose := range []string{"log", "clerks"} {
		if n := refusalCount(*held, derive(key, id, purpose, keyLen)); n != 1 {
			t.Errorf("wiped the %s key's buffer %d times, want once", purpose, n)
		}
	}
	s.Close()
	if n := refusalCount(*held, kept); n != 1 {
		t.Errorf("wiped the kept value %d times, want once", n)
	}
	if _, _, err := s.Get("x/a"); !errors.Is(err, ErrClosed) {
		t.Errorf("Get after Close: got %v, want ErrClosed", err)
	}
	// "QUJDREVG!!!!" decodes to ABCDEF before its bad quantum; the buffer is
	// DecodedLen(len of the quoted value) = 9 bytes long.
	part := []byte("ABCDEF\x00\x00\x00")
	for name, plain := range map[string]string{
		"no base64": `{"x/a":` + string(q) + `,"x/b":"QUJDREVG!!!!"}`,
		"a number":  `{"x/a":` + string(q) + `,"x/b":1234}`,
		"null":      `{"x/a":` + string(q) + `,"x/b":null}`,
		"null set":  `null`,
	} {
		t.Run(name, func(t *testing.T) {
			held := refusalWipes(t)
			if _, err := Unlock(raw(plain), r); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("got %v, want ErrCorrupt", err)
			}
			want := map[bool]int{true: 1}
			if n := refusalCount(*held, part); n != want[name == "no base64"] {
				t.Errorf("wiped the part-decoded value %d times", n)
			}
			if n := refusalCount(*held, kept); n != want[name != "null set"] {
				t.Errorf("wiped the decoded canary %d times", n)
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

// A write wipes each value it displaces once the rename is done, and only
// then: a Put or ReplaceAndPut over a name and a Delete each wipe the old
// value once, and a write that fails before the rename wipes nothing the
// store still holds (#5913; CLK-1, STO-2).
func TestADisplacedValueIsWipedOnce(t *testing.T) {
	r := Recovery{Key: make([]byte, RecoveryLen)}
	s, err := Create(filepath.Join(t.TempDir(), "store"), r)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, b, c, d := []byte("displaced-a-canary"), []byte("displaced-b-canary"), []byte("kept-c-canary"), []byte("tried-d-canary")
	for _, v := range [][]byte{a, nil, c} {
		if err := s.Put("x/c", v); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Put("x/a", a); err != nil {
		t.Fatal(err)
	}
	old := Entries(s)["x/a"]
	held := refusalWipes(t)
	if err := s.Put("x/a", b); err != nil {
		t.Fatal(err)
	}
	if n := refusalCount(*held, a); n != 1 || string(old) != string(make([]byte, len(a))) {
		t.Errorf("a Put over a name wiped the old value %d times, left %q; want once", n, old)
	}
	restore := FailWrite(errors.New("disk full"))
	_, err = s.ReplaceAndPut("x/a", d, Swap{ID: "none", F: r})
	err2, err3 := s.Put("x/a", d), s.Delete("x/a")
	restore()
	if err == nil || err2 == nil || err3 == nil || refusalCount(*held, b) != 0 || refusalCount(*held, d) != 1 {
		t.Fatalf("failed writes (%v, %v, %v) wiped b %d times, d %d times; want 0, 1",
			err, err2, err3, refusalCount(*held, b), refusalCount(*held, d))
	}
	if v, _, _ := s.Get("x/a"); string(v) != string(b) {
		t.Fatalf("after failed writes x/a is %q, want %q", v, b)
	}
	if _, err := s.ReplaceAndPut("x/a", a, Swap{ID: s.Slots()[0].ID, F: r}); err != nil || refusalCount(*held, b) != 1 {
		t.Fatalf("ReplaceAndPut over a name: %v, wiped the old value %d times; want once", err, refusalCount(*held, b))
	}
	if err := s.Delete("x/a"); err != nil || refusalCount(*held, a) != 2 || refusalCount(*held, c) != 0 {
		t.Fatalf("Delete: %v, wiped the dropped value %d times, the kept one %d; want 1, 0", err, refusalCount(*held, a)-1, refusalCount(*held, c))
	}
	if err := s.Put("x/c", nil); err != nil || refusalCount(*held, c) != 1 {
		t.Fatalf("a Put of nothing over a name: %v, wiped the old value %d times; want once", err, refusalCount(*held, c))
	}
}

// entriesJSON writes json.Marshal's bytes in a buffer of exactly their
// length, so encode leaves no grown-out or pooled copy of a value (#5913).
func TestEntriesJSONIsMarshalInOneBuffer(t *testing.T) {
	big := map[string][]byte{}
	for i := range MaxEntries {
		big[string([]byte{'y', '/', byte('a' + i%26), byte('a' + i/26)})] = slices.Repeat([]byte{byte(i)}, i*61)
	}
	for _, e := range []map[string][]byte{{}, {"a": {}}, {"a": {1}, "b/c": []byte("xy"), "0.z": []byte("abc")}, big} {
		got := entriesJSON(e)
		want, err := json.Marshal(e)
		if err != nil || string(got) != string(want) || cap(got) != len(got) {
			t.Errorf("entriesJSON = %s (cap %d), want %s", got, cap(got), want)
		}
	}
	if got := entriesJSON(map[string][]byte{"a": nil}); string(got) != `{"a":""}` { // json.Marshal's null, which Unlock refuses
		t.Errorf("a nil value is written as %s", got)
	}
}

// Unlock's decode leaves every value a slice of the plaintext, which its
// defer wipes: no copy (#5915). Pins the toolchain's encoding/json.
func TestEntriesDecodeCopiesNoValue(t *testing.T) {
	plain := []byte(`{"x/a":"ZGlzcGxhY2Vk","x/b":"","x/c":"QUJD"}`)
	var set map[string]inPlain
	if err := json.Unmarshal(plain, &set); err != nil || len(set) != 3 {
		t.Fatal(err, len(set))
	}
	clear(plain)
	for k, v := range set {
		if string(v) != string(make([]byte, len(v))) {
			t.Errorf("%s decoded to a copy %q", k, v)
		}
	}
}
