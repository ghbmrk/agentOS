package main

// Mutant kills for #6000 (KRN-keys-print-factors): main_test.go's
// secret.Hide edit made every line its tests run a mutation target, and
// these statements had no test that failed when they were deleted. Each
// test here fails on one or more such deletions (named by line at
// 32b378b3).

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/kernel/secret"
)

// REQ: A8, STO-2

// A clean scan says each check it passed, by name (main.go:132, :152,
// :180).
func TestCleanScanReportsEachCheck(t *testing.T) {
	d := newDrive(t)
	var out bytes.Buffer
	n, err := run(d.store, d.rk, d.rkText, "", shippedClerks, []string{d.esp()}, &out)
	if err != nil || n != 0 {
		t.Fatalf("clean drive: %d, %v\n%s", n, err, out.String())
	}
	for _, want := range []string{
		"ok   store slots: only TPM, passphrase and recovery\n",
		"ok   control: all ",
		"ok   " + d.esp() + ": nothing found\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q\n%s", want, out.String())
		}
	}
}

// A needle list that cannot be built is the scan's error, not a later
// one: a clerk name clerkkey refuses stops the scan with ErrKey, naming the
// clerk (main.go:142, :243, :312).
func TestBadClerkNameStopsTheScan(t *testing.T) {
	d := newDrive(t)
	_, err := run(d.store, d.rk, d.rkText, "", []string{"Not A Clerk!"}, []string{d.esp()}, &bytes.Buffer{})
	if !errors.Is(err, clerkkey.ErrKey) || !strings.Contains(err.Error(), `clerk "Not A Clerk!"`) {
		t.Fatalf("bad clerk name: %v, want clerkkey.ErrKey naming the clerk", err)
	}
}

// Targets that cannot be scanned are errors, never a clean result: a
// missing path, and a file whose reads fail (/proc/self/mem at offset 0
// is unmapped, so its first read is EIO) (main.go:156, :173). A directory
// target lists what it skipped (main.go:163).
func TestTargetsThatCannotBeScanned(t *testing.T) {
	d := newDrive(t)
	missing := filepath.Join(d.dir, "missing")
	if _, err := run(d.store, d.rk, d.rkText, "", nil, []string{missing}, &bytes.Buffer{}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing target: %v", err)
	}
	var out bytes.Buffer
	if _, err := run(d.store, d.rk, d.rkText, "", nil, []string{"/proc/self/mem"}, &out); err == nil || !strings.Contains(err.Error(), "/proc/self/mem: ") {
		t.Errorf("unreadable target: %v, want its read error\n%s", err, out.String())
	}
	sock := filepath.Join(d.esp(), "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("no unix socket here:", err)
	}
	defer l.Close()
	out.Reset()
	if _, err := run(d.store, d.rk, d.rkText, "", nil, []string{d.esp()}, &out); err != nil || !strings.Contains(out.String(), "skip "+sock+" (not a regular file)\n") {
		t.Errorf("socket in a directory target: %v\n%s", err, out.String())
	}
}

// storeNeedles refuses, with its own error, a store file it cannot read, a
// recovery key that opens no slot of the file, a closed store, a file whose
// recovery slot unwraps to a key the open store does not use, and card
// text that is not a recovery key (main.go:196, :200, :204, :209, :266).
func TestStoreNeedlesRefusals(t *testing.T) {
	d, other := newDrive(t), newDrive(t)
	st := mustUnlock(t, d)
	closed, err := seal.Unlock(d.store, seal.Recovery{Key: secret.Hide(d.rk)})
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	for _, c := range []struct {
		name   string
		sp     string
		st     *seal.Store
		rk     []byte
		rkText string
		is     error
		want   string
	}{
		{"unreadable file", filepath.Join(d.dir, "missing"), st, d.rk, d.rkText, fs.ErrNotExist, ""},
		{"key for no slot", d.store, st, other.rk, other.rkText, nil, "no recovery slot this factor opens"},
		{"closed store", d.store, closed, d.rk, d.rkText, seal.ErrClosed, ""},
		{"another store's file", other.store, st, other.rk, other.rkText, nil, "the store does not use; refusing to scan"},
		{"card text not a key", d.store, st, d.rk, "not a recovery key", nil, "not the card's 40 symbols"},
	} {
		ns, err := storeNeedles(c.sp, c.st, c.rk, c.rkText, "", nil, &bytes.Buffer{})
		switch {
		case err == nil:
			t.Errorf("%s: %d needles, want a refusal", c.name, len(ns))
		case c.is != nil && !errors.Is(err, c.is):
			t.Errorf("%s: %v, want %v", c.name, err, c.is)
		case c.want != "" && !strings.Contains(err.Error(), c.want):
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// A clerk named twice gets one set of needles (main.go:238, :241), and an
// entry shorter than the scan's shortest pattern is said to be skipped and
// is no needle (main.go:256).
func TestDuplicateClerkAndShortEntry(t *testing.T) {
	d := newDrive(t)
	st, err := seal.Unlock(d.store, seal.Recovery{Key: secret.Hide(d.rk)})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put("canary/short", []byte("abc")); err != nil {
		t.Fatal(err)
	}
	st.Close()
	var out bytes.Buffer
	ns, err := storeNeedles(d.store, mustUnlock(t, d), d.rk, d.rkText, "", []string{"mail", "bank", "mail"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, n := range ns {
		count[n.Name]++
	}
	if count["key of clerk mail"] != 1 || count["key of clerk bank"] != 1 {
		t.Errorf("clerk needles: mail %d, bank %d; want one each", count["key of clerk mail"], count["key of clerk bank"])
	}
	if count["store entry canary/short"] != 0 || !strings.Contains(out.String(), "skip store entry canary/short (shorter than 8 bytes)\n") {
		t.Errorf("short entry: %d needles\n%s", count["store entry canary/short"], out.String())
	}
}

// A symbol off the card's alphabet is refused even where the check symbol
// would pass for the value it is read as: 'I' read as index -1 is byte
// 255, and this group's check symbol is the one cardCheck gives for 255
// (main.go:382).
func TestCardKeyRefusesSymbolOffTheAlphabet(t *testing.T) {
	grp := []byte{255, 0, 0, 0}
	g := "I" + cardAlphabet[:1] + cardAlphabet[:1] + cardAlphabet[:1] + string(cardAlphabet[cardCheck(grp)])
	good := strings.Split(newDrive(t).rkText, "-")
	text := strings.Join(append([]string{g}, good[1:]...), "-")
	if p, bits, err := cardKey(text); err == nil || !strings.Contains(err.Error(), "group 1 ") {
		t.Fatalf("cardKey(%q) = %q, %x, %v; want group 1 refused", text, p, bits, err)
	}
}

// printable is false for bytes that are not UTF-8 and for control
// characters other than tab, newline and carriage return (main.go:477,
// :478, :480, :481).
func TestPrintable(t *testing.T) {
	for v, want := range map[string]bool{
		"plain text\twith\r\nbreaks": true,
		"bad \xff\xfe utf-8 bytes":   false,
		"a bell \x07 inside":         false,
		"a nul \x00 inside":          false,
	} {
		if got := printable([]byte(v)); got != want {
			t.Errorf("printable(%q) = %v, want %v", v, got, want)
		}
	}
}

// The passphrase slot's Argon2id cost is checked before it is used: a
// missing cost, no rounds, too little memory and no threads are refused
// (main.go:529).
func TestPassphraseKEKRefusesCostOutOfRange(t *testing.T) {
	kek := passphraseKEK([]byte("correct horse battery staple"))
	for name, a := range map[string]*argonCost{
		"no cost":     nil,
		"no rounds":   {Time: 0, MemKiB: seal.ArgonFloorKiB, Threads: 1},
		"too little":  {Time: 1, MemKiB: 8, Threads: 1},
		"no threads":  {Time: 1, MemKiB: seal.ArgonFloorKiB, Threads: 0},
		"many rounds": {Time: 65, MemKiB: 8, Threads: 1},
	} {
		if k, err := kek(fileSlot{Salt: make([]byte, 16), Argon: a}); err == nil {
			t.Errorf("%s: a %d-byte key, want a refusal", name, len(k))
		}
	}
}

// unwrapSlot says the store has no slot the factor opens when no slot of
// the kind is there, when the slot's wrap is too short to hold a nonce,
// and when the slot's key cannot be made; it never reads a short wrap or
// a key it did not make (main.go:556, :560, :570).
func TestUnwrapSlotRefusals(t *testing.T) {
	file := func(slots ...fileSlot) []byte {
		var f struct {
			ID    []byte     `json:"id"`
			Slots []fileSlot `json:"slots"`
		}
		f.ID, f.Slots = []byte("store-id-0123456"), slots
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	rk := make([]byte, 32)
	salt := make([]byte, 16)
	for _, c := range []struct {
		name string
		raw  []byte
		kind seal.Kind
		kek  func(fileSlot) ([]byte, error)
	}{
		{"no slots", file(), seal.KindRecovery, recoveryKEK(rk)},
		{"short wrap", file(fileSlot{ID: "r", Kind: "recovery", Salt: salt, Wrap: []byte("short")}), seal.KindRecovery, recoveryKEK(rk)},
		{"no key", file(fileSlot{ID: "p", Kind: "passphrase", Salt: salt, Wrap: make([]byte, 60)}), seal.KindPassphrase, passphraseKEK([]byte("x"))},
	} {
		key, id, kek, err := unwrapSlot(c.raw, c.kind, c.kek)
		if err == nil || !strings.Contains(err.Error(), "the store has no "+string(c.kind)+" slot this factor opens") {
			t.Errorf("%s: (%x, %x, %x, %v), want the no-slot refusal", c.name, key, id, kek, err)
		}
	}
}

// The self-check plants each needle in random data: a scanner whose only
// pattern is zeros, under the same name, must not pass it by finding the
// pad (main.go:589).
func TestControlPadIsNotZeros(t *testing.T) {
	s, err := NewScanner([]Needle{{Name: "n", Value: make([]byte, 16)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := control(s, []Needle{{Name: "n", Value: []byte("needle-not-zeros-0123")}}); err == nil {
		t.Fatal("a scanner that cannot see the planted value passed the self-check")
	}
}

// Tree: a missing root is an error; directories and symlinks are walked
// past, not listed as skipped or followed; a socket is skipped and
// listed; findings come sorted by path, not in walk order; and each file
// is closed once scanned (scan.go:201, :204, :205, :207, :215, :220).
func TestTreeWalk(t *testing.T) {
	needle := []byte("tree-needle-0123456789")
	s, err := NewScanner([]Needle{{Name: "n", Value: needle}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Tree(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing root: %v", err)
	}
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "a"), 0o700)
	os.WriteFile(filepath.Join(root, "a", "x"), needle, 0o600)
	os.WriteFile(filepath.Join(root, "a.txt"), needle, 0o600)
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, needle, 0o600)
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	got, skipped, err := s.Tree(root)
	if err != nil || len(skipped) != 0 {
		t.Fatalf("Tree: %v, skipped %v", err, skipped)
	}
	var order []string
	for _, g := range got {
		if len(order) == 0 || order[len(order)-1] != g.Source {
			order = append(order, g.Source)
		}
	}
	if want := []string{filepath.Join(root, "a.txt"), filepath.Join(root, "a", "x")}; strings.Join(order, "|") != strings.Join(want, "|") {
		t.Fatalf("findings in %v, want %v: sorted by path, the link not followed", order, want)
	}

	if l, err := net.Listen("unix", filepath.Join(root, "sock")); err == nil {
		_, skipped, err := s.Tree(root)
		l.Close()
		if err != nil || len(skipped) != 1 || skipped[0] != filepath.Join(root, "sock") {
			t.Errorf("socket: %v, skipped %v", err, skipped)
		}
	}

	many := t.TempDir()
	for i := 0; i < 64; i++ {
		os.WriteFile(filepath.Join(many, strings.Repeat("f", i+1)), []byte("nothing here"), 0o600)
	}
	before := noGC(t)
	if _, _, err := s.Tree(many); err != nil {
		t.Fatal(err)
	}
	if after := openFDs(t); after > before {
		t.Errorf("Tree over 64 files left %d more descriptors open", after-before)
	}
}

// Each file target is closed once scanned (main.go:170).
func TestRunClosesFileTargets(t *testing.T) {
	d := newDrive(t)
	var targets []string
	for i := 0; i < 16; i++ {
		p := filepath.Join(d.esp(), strings.Repeat("t", i+1))
		os.WriteFile(p, []byte("nothing here"), 0o600)
		targets = append(targets, p)
	}
	before := noGC(t)
	if n, err := run(d.store, d.rk, d.rkText, "", nil, targets, &bytes.Buffer{}); err != nil || n != 0 {
		t.Fatalf("run: %d, %v", n, err)
	}
	if after := openFDs(t); after > before {
		t.Errorf("run over 16 file targets left %d more descriptors open", after-before)
	}
}

// noGC stops the collector for the rest of the test, so no finalizer
// closes a leaked file behind the count, and returns the open descriptors.
func noGC(t *testing.T) int {
	t.Helper()
	runtime.GC()
	old := debug.SetGCPercent(-1)
	t.Cleanup(func() { debug.SetGCPercent(old) })
	return openFDs(t)
}

// A file Tree cannot open is the walk's error, as itself (scan.go:212).
// Root opens every file, so this needs a user without that power.
func TestTreeOpenError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a file of mode 000")
	}
	s, err := NewScanner([]Needle{{Name: "n", Value: []byte("tree-needle-0123456789")}})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	p := filepath.Join(root, "locked")
	os.WriteFile(p, []byte("x"), 0o000)
	if _, _, err := s.Tree(root); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("unopenable file: %v, want its permission error", err)
	}
}

func openFDs(t *testing.T) int {
	t.Helper()
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd:", err)
	}
	return len(es)
}
