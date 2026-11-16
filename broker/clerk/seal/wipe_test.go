package seal

// REQ: CLK-1, STO-2

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/secret"
)

// A write wipes each value it displaces once the rename is done, and only
// then: a Put or ReplaceAndPut over a name and a Delete each wipe the old
// value once, and a write that fails before the rename wipes nothing the
// store still holds, only its own clone (#5913; CLK-1, STO-2). Each write
// wipes its entries key and its plaintext once. The store is built here and
// the file write stubbed, so the test reaches no more of the package than
// the write.
func TestADisplacedValueIsWipedOnce(t *testing.T) {
	r, key, id := Recovery{Key: make([]byte, RecoveryLen)}, slices.Repeat([]byte{0x6b}, keyLen), make([]byte, idLen)
	sl, err := makeSlot(id, key, r)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "store")
	s := &Store{path: path, key: secret.Hide(slices.Clone(key)), f: file{V: version, ID: id, Slots: []slot{sl}}, entries: secret.Hide(map[string][]byte{})}
	w, d := writeTemp, syncDir
	t.Cleanup(func() { writeTemp, syncDir = w, d })
	writeTemp = func(path string, b []byte) (string, error) { return path + ".new", os.WriteFile(path+".new", b, 0o600) }
	syncDir = func(string) error { return nil }
	held := refusalWipes(t)
	a, b, c, dd := []byte("displaced-a-canary"), []byte("displaced-b-canary"), []byte("kept-c-canary"), []byte("tried-d-canary")
	for _, err := range []error{s.Put("x/c", nil), s.Put("x/c", c), s.Put("x/a", a)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	old := Entries(s)["x/a"]
	if err := s.Put("x/a", b); err != nil {
		t.Fatal(err)
	}
	if n := refusalCount(*held, a); n != 1 || string(old) != string(make([]byte, len(a))) {
		t.Errorf("a Put over a name wiped the old value %d times, left %q; want once", n, old)
	}
	if n := refusalCount(*held, entriesJSON(Entries(s))); n != 1 {
		t.Errorf("the Put's plaintext was wiped %d times, want once", n)
	}
	fail := errors.New("disk full")
	restore := FailWrite(fail)
	_, err1 := s.ReplaceAndPut("x/a", dd, Swap{ID: "none", F: r})
	ids, err2 := s.ReplaceAndPut("x/a", dd, Swap{ID: sl.ID, F: r})
	err3, err4, err5 := s.Put("x/a", dd), s.Delete("x/a"), s.Delete("x/none")
	restore()
	if !errors.Is(err1, ErrNoSlot) || ids != nil || !errors.Is(err2, fail) || !errors.Is(err3, fail) || !errors.Is(err4, fail) || err5 != nil {
		t.Fatalf("failed writes: %v, %v %v, %v, %v; a missing name's Delete: %v", err1, ids, err2, err3, err4, err5)
	}
	if v, _, _ := s.Get("x/a"); string(v) != string(b) || refusalCount(*held, b) != 0 || refusalCount(*held, dd) != 2 {
		t.Fatalf("after failed writes x/a is %q, b wiped %d times, d %d; want %q, 0, 2", v, refusalCount(*held, b), refusalCount(*held, dd), b)
	}
	if _, err := s.ReplaceAndPut("x/a", dd, Swap{ID: sl.ID, F: Recovery{Key: []byte("short")}}); err == nil {
		t.Fatal("ReplaceAndPut with a short recovery key wrote")
	}
	if _, err := s.ReplaceAndPut("Bad Name", dd, Swap{ID: sl.ID, F: r}); err == nil {
		t.Fatal("ReplaceAndPut of a bad name wrote")
	}
	restore = FailDirSync(fail)
	ids, err = s.ReplaceAndPut("x/a", a, Swap{ID: sl.ID, F: r})
	restore()
	if len(ids) != 1 || !errors.Is(err, fail) || refusalCount(*held, b) != 1 {
		t.Fatalf("ReplaceAndPut over a name: %v %v, wiped the old value %d times; want once", ids, err, refusalCount(*held, b))
	}
	if err := s.Delete("x/a"); err != nil || refusalCount(*held, a) != 2 || refusalCount(*held, c) != 0 {
		t.Fatalf("Delete: %v, wiped the dropped value %d times, the kept one %d; want 1, 0", err, refusalCount(*held, a)-1, refusalCount(*held, c))
	}
	if err := s.Put("x/c", nil); err != nil || refusalCount(*held, c) != 1 {
		t.Fatalf("a Put of nothing over a name: %v, wiped the old value %d times; want once", err, refusalCount(*held, c))
	}
	if n := refusalCount(*held, derive(key, id, "entries", keyLen)); n != 10 {
		t.Errorf("wiped the entries key %d times, want once for each of 10 encodes", n)
	}
	if got := s.Entries(); !slices.Equal(got, []string{"x/c"}) {
		t.Errorf("Entries = %v", got)
	}
	// The bounds withEntry checks before it clones: a value of MaxEntry
	// bytes, and a name already held when the store is full, are taken.
	if s.Put("x/m", make([]byte, MaxEntry)) != nil || s.Put("x/m", make([]byte, MaxEntry+1)) == nil || s.Put("Bad Name", nil) == nil {
		t.Fatal("the MaxEntry bound or the name pattern is off")
	}
	for i := len(s.Entries()); i < MaxEntries; i++ {
		if err := s.Put(string([]byte{'y', '/', byte('a' + i%26), byte('a' + i/26)}), nil); err != nil {
			t.Fatal(err)
		}
	}
	if s.Put("x/c", c) != nil || s.Put("x/new", nil) == nil {
		t.Fatal("a full store refused a held name, or took a new one")
	}
	s.Close()
	_, err = s.ReplaceAndPut("x/a", a, Swap{ID: sl.ID, F: r})
	for _, err := range []error{err, s.Put("x/a", a), s.Delete("x/c")} {
		if !errors.Is(err, ErrClosed) {
			t.Errorf("a write after Close: %v, want ErrClosed", err)
		}
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
