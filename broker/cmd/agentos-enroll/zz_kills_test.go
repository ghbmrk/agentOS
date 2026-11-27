package main

// Mutant kills for #6000 (KRN-keys-print-factors): main_test.go's
// secret.Hide edits in shared helpers (b.who, b.enrolled, newRotBox) made
// every line those tests run a mutation target, and these statements had
// no test that failed when they were deleted. Each test here fails on one
// or more such deletions (named by line at fed59085). The rest are proved
// equivalent in MUTANTS-EQUIVALENT.

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/pageca"
)

// REQ: HW-1, CH-9

// pathOp is err's *fs.PathError Op, or "" when err holds none: which
// system call refused tells the check that refused from a later one.
func pathOp(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Op
	}
	return ""
}

func absent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s: got %v, want nothing there", path, err)
	}
}

// notADir is a path whose parent is a regular file, so Lstat of it fails
// with ENOTDIR rather than ErrNotExist.
func notADir(t *testing.T) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "file")
	noErr(t, os.WriteFile(f, nil, 0o600))
	return filepath.Join(f, "x")
}

// A staged or published path whose check fails stops staging at that
// check: nothing is made (stage.go:46, :50).
func stagePageCAStopsWhenAPathDoesNotCheck(t *testing.T) {
	s := newStaging(t)
	bad := notADir(t)
	err := stagePageCA(bad, s.published, testBuilt)
	if pathOp(err) != "lstat" || !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("an unreadable staged path: got %v, want its lstat error", err)
	}
	absent(t, s.published)
	err = stagePageCA(s.staged, bad, testBuilt)
	if pathOp(err) != "lstat" || !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("an unreadable published path: got %v, want its lstat error", err)
	}
	absent(t, s.staged)
}

// An authority that cannot be made (no build time) is an error, and
// nothing is written (stage.go:71).
func stagePageCAWithNoBuildTime(t *testing.T) {
	s := newStaging(t)
	if err := stagePageCA(s.staged, s.published, time.Time{}); err == nil {
		t.Fatal("staged with no build time")
	}
	absent(t, s.staged)
	absent(t, s.published)
}

// An empty or oversized published certificate is refused (stage.go:146).
func readPublishedRefusesEmptyAndOversized(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []int{0, maxPublished + 1} {
		p := filepath.Join(dir, "cert")
		os.Remove(p)
		noErr(t, os.WriteFile(p, bytes.Repeat([]byte{1}, n), 0o644))
		if b, err := readPublished(p); !errors.Is(err, errPublished) || b != nil {
			t.Fatalf("%d bytes: got %d bytes, %v; want errPublished", n, len(b), err)
		}
	}
	p := filepath.Join(dir, "cert")
	os.Remove(p)
	noErr(t, os.WriteFile(p, bytes.Repeat([]byte{1}, maxPublished), 0o644))
	if b, err := readPublished(p); err != nil || len(b) != maxPublished {
		t.Fatalf("%d bytes: got %d, %v", maxPublished, len(b), err)
	}
}

// readSecretMax refuses a secret file one byte over its bound and returns
// none of it (main.go:782); a file of exactly the bound reads whole.
func readSecretMaxRefusesOversized(t *testing.T) {
	const max = 16
	p := filepath.Join(t.TempDir(), "secret")
	noErr(t, os.WriteFile(p, bytes.Repeat([]byte{1}, max+1), 0o600))
	if b, err := readSecretMax(p, max); err == nil || b != nil || !strings.Contains(err.Error(), "is over") {
		t.Fatalf("%d bytes: got %d bytes, %v; want the over-size refusal", max+1, len(b), err)
	}
	noErr(t, os.Truncate(p, max))
	if b, err := readSecretMax(p, max); err != nil || len(b) != max {
		t.Fatalf("%d bytes: got %d, %v", max, len(b), err)
	}
}

// writeOnce stops at the call that refused, and leaves nothing at path:
// a missing directory at its open (stage.go:160, :161), a temporary name
// too long to create at its create (:170).
func writeOnceStopsAtTheRefusingCall(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone", "f")
	if err := writeOnce(missing, []byte("x"), 0o600); pathOp(err) != "open" || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("a missing directory: got %v, want its open error", err)
	}
	long := filepath.Join(t.TempDir(), strings.Repeat("a", 240))
	if err := writeOnce(long, []byte("x"), 0o600); pathOp(err) != "create" || !errors.Is(err, syscall.ENAMETOOLONG) {
		t.Fatalf("a too-long temporary name: got %v, want its create error", err)
	}
}

// A write that fails (the file-size limit) is a write error and links
// nothing at path, so path never holds part of data (stage.go:186).
func writeOnceFailedWriteLeavesNothing(t *testing.T) {
	var old syscall.Rlimit
	noErr(t, syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old))
	signal.Ignore(syscall.SIGXFSZ)
	lim := old
	lim.Cur = 4
	noErr(t, syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lim))
	path := filepath.Join(t.TempDir(), "f")
	err := writeOnce(path, bytes.Repeat([]byte{1}, 64), 0o600)
	noErr(t, syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old))
	signal.Reset(syscall.SIGXFSZ)
	if pathOp(err) != "write" || !errors.Is(err, syscall.EFBIG) {
		t.Fatalf("a write past the size limit: got %v, want its write error", err)
	}
	absent(t, path)
	es := get(os.ReadDir(filepath.Dir(path)))
	if len(es) != 0 {
		t.Fatalf("the temporary file was left: %v", es)
	}
}

// The file readers and writeOnce close every descriptor they open, so a
// long-running unit does not leak them (stage.go:136, :163, :183;
// main.go:769). The GC is off, so no finalizer closes a leaked *os.File.
func fileHelpersCloseTheirDescriptors(t *testing.T) {
	dir := t.TempDir()
	cert, sec := filepath.Join(dir, "cert"), filepath.Join(dir, "secret")
	noErr(t, os.WriteFile(cert, []byte("der"), 0o644))
	noErr(t, os.WriteFile(sec, []byte("s"), 0o600))
	runtime.GC()
	old := debug.SetGCPercent(-1)
	t.Cleanup(func() { debug.SetGCPercent(old) })
	before := enrollFDs(t)
	for i := range 8 {
		get(readPublished(cert))
		get(readSecretMax(sec, 16))
		noErr(t, writeOnce(filepath.Join(dir, "w"+string(rune('a'+i))), []byte("x"), 0o600))
	}
	if after := enrollFDs(t); after != before {
		t.Fatalf("open descriptors went from %d to %d", before, after)
	}
}

func enrollFDs(t *testing.T) int {
	t.Helper()
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd:", err)
	}
	return len(es)
}

// A refused request exits 1 and its reason goes to the journal
// (take.go:107, :108, :109); a good one exits 0.
func takeFactorsMainExitStatus(t *testing.T) {
	b := newSetupBox(t)
	var out, errw bytes.Buffer
	if code := takeFactorsMain(b.c, strings.NewReader("{"), &out, &errw); code != 1 || out.String() != "bad\n" || !strings.Contains(errw.String(), errBad.Error()) {
		t.Fatalf("a bad request: exit %d, answer %q, journal %q", code, out.String(), errw.String())
	}
	out.Reset()
	errw.Reset()
	if code := takeFactorsMain(b.c, bytes.NewReader(setupRequestFor(newCard(t), b.fp)), &out, &errw); code != 0 || out.String() != "ok\n" || errw.Len() != 0 {
		t.Fatalf("a good request: exit %d, answer %q, journal %q", code, out.String(), errw.String())
	}
}

// wipe zeroes both factors in place (take.go:95, :96).
func setupRequestWipe(t *testing.T) {
	r := setupRequest{Passphrase: cardText("abc def"), RecoveryKey: cardText("ABCD-EFGH")}
	p, k := r.Passphrase, r.RecoveryKey
	r.wipe()
	if bytes.ContainsFunc(p, func(c rune) bool { return c != 0 }) || bytes.ContainsFunc(k, func(c rune) bool { return c != 0 }) {
		t.Fatalf("after wipe: %q, %q", p, k)
	}
}

// With no store, a published certificate others may write is its own
// error, not an authority mismatch (take.go:152, :153); a missing one is
// authority. Neither writes a factor.
func takeFactorsWithABadCertificate(t *testing.T) {
	b := newSetupBox(t)
	noErr(t, os.Chmod(b.s.published, 0o666))
	if err := takeFactors(b.c, bytes.NewReader(setupRequestFor(newCard(t), b.fp))); !errors.Is(err, errPublished) {
		t.Fatalf("a certificate others may write: got %v, want errPublished", err)
	}
	noErr(t, os.Remove(b.s.published))
	// The fingerprint of no bytes, so a missing certificate is refused
	// as missing and never read as an empty one that matches (:153).
	if w, _ := b.ask(setupRequestFor(newCard(t), pageca.Fingerprint(nil))); w != "authority" {
		t.Fatalf("no published certificate answered %q", w)
	}
	absent(t, filepath.Join(b.c.setupDir, passphraseFile))
}

// putFactors stops at a file it cannot check or read, writing nothing:
// a path whose check fails returns that check's error (take.go:181), and a
// factor file it may not read is its read error, not taken (:187).
func putFactorsStopsAtAFileItCannotRead(t *testing.T) {
	bad := filepath.Dir(notADir(t))
	if err := putFactors(bad, []byte("p"), []byte("r")); pathOp(err) != "lstat" || !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("a setup path that is a file: got %v, want its lstat error", err)
	}
	dir := t.TempDir()
	noErr(t, os.WriteFile(filepath.Join(dir, passphraseFile), []byte("p"), 0o644))
	err := putFactors(dir, []byte("p"), []byte("r"))
	if err == nil || errors.Is(err, errTaken) || !strings.Contains(err.Error(), "only I can read") {
		t.Fatalf("a passphrase file others can read: got %v, want its read error", err)
	}
	absent(t, filepath.Join(dir, recoveryFile))
}

// Each word's length and hyphen rules hold on their own (take.go:233).
func validPassphraseWordRules(t *testing.T) {
	good := []string{"abc", "defgh", "ijk", "lmn", "opq", "rst", "uvw"}
	if !validPassphrase([]byte(strings.Join(good, " "))) {
		t.Fatal("the good passphrase is refused")
	}
	for _, w := range []string{"ab", "abcdefghij", "-ab", "ab-"} {
		p := append([]string{w}, good[1:]...)
		if validPassphrase([]byte(strings.Join(p, " "))) {
			t.Fatalf("a passphrase with the word %q passed", w)
		}
	}
}

// A symbol outside the alphabet is refused even where the group's check
// symbol would hold for the value an unread symbol becomes (take.go:276).
func storeRecoveryKeyRefusesASymbolOutsideTheAlphabet(t *testing.T) {
	// Group 0 is "I" (not in the alphabet) and three symbols, with the check
	// that a mis-read 0xff gives; the other seven groups are all-A with
	// their check.
	grp := []byte{0xff, 0, 0, 0}
	text := []byte("I" + "AAA" + string(cardAlphabet[cardCheck(grp)]))
	zero := "AAAA" + string(cardAlphabet[cardCheck([]byte{0, 0, 0, 0})])
	text = append(text, strings.Repeat(zero, cardGroups-1)...)
	if _, err := storeRecoveryKey(text); !errors.Is(err, errBad) {
		t.Fatalf("got %v, want errBad", err)
	}
	// The same text with a real symbol there reads, so the test is not
	// refused for some other reason.
	ok := append([]byte("AAAA"+string(cardAlphabet[cardCheck([]byte{0, 0, 0, 0})])), text[5:]...)
	if _, err := storeRecoveryKey(ok); err != nil {
		t.Fatalf("the all-A key: %v", err)
	}
}

// mutgateKills runs, as subtests of TestFactorFilesMustBePrivate, the checks this PR adds here.
// mutgate reads an init or package var of this package, or of one it
// imports, as order-dependent, so a new top-level test changes the run list
// and makes every test of the package a changed test (#6000). These run as
// subtests of TestFactorFilesMustBePrivate instead.
func mutgateKills(t *testing.T) {
	t.Run("StagePageCAStopsWhenAPathDoesNotCheck", stagePageCAStopsWhenAPathDoesNotCheck)
	t.Run("StagePageCAWithNoBuildTime", stagePageCAWithNoBuildTime)
	t.Run("ReadPublishedRefusesEmptyAndOversized", readPublishedRefusesEmptyAndOversized)
	t.Run("ReadSecretMaxRefusesOversized", readSecretMaxRefusesOversized)
	t.Run("WriteOnceStopsAtTheRefusingCall", writeOnceStopsAtTheRefusingCall)
	t.Run("WriteOnceFailedWriteLeavesNothing", writeOnceFailedWriteLeavesNothing)
	t.Run("FileHelpersCloseTheirDescriptors", fileHelpersCloseTheirDescriptors)
	t.Run("TakeFactorsMainExitStatus", takeFactorsMainExitStatus)
	t.Run("SetupRequestWipe", setupRequestWipe)
	t.Run("TakeFactorsWithABadCertificate", takeFactorsWithABadCertificate)
	t.Run("PutFactorsStopsAtAFileItCannotRead", putFactorsStopsAtAFileItCannotRead)
	t.Run("ValidPassphraseWordRules", validPassphraseWordRules)
	t.Run("StoreRecoveryKeyRefusesASymbolOutsideTheAlphabet", storeRecoveryKeyRefusesASymbolOutsideTheAlphabet)
	mutgateKills2(t)
}
