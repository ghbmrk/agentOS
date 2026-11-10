package main

// The state files' own failure paths (#5207): each write is synced and
// closed whether it lands or fails, a failed Save leaves the old file and
// no temporary one, and an unreadable or malformed key file stops the
// start rather than being replaced.

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/channel"
	"github.com/ghbmrk/agentos/broker/enforcer/page"
)

// openUnder is the files under dir this process holds open.
func openUnder(t *testing.T, dir string) []string {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var open []string
	for _, fd := range fds {
		if p, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name())); err == nil && (p == dir || strings.HasPrefix(p, dir+"/")) {
			open = append(open, p)
		}
	}
	return open
}

var errSync = errors.New("disk: sync failed")

// syncs records each fsync's file for the test, failing those fail names.
func syncs(t *testing.T, fail func(name string) bool) *[]string {
	var got []string
	t.Cleanup(func() { syncFile = (*os.File).Sync })
	syncFile = func(f *os.File) error {
		got = append(got, f.Name())
		if fail != nil && fail(f.Name()) {
			return errSync
		}
		return f.Sync()
	}
	return &got
}

// TestSaveSyncsFileAndDirectory: Save syncs the new file before the
// rename and the directory after it, closes both, and leaves the file
// readable by its owner only.
func TestSaveSyncsFileAndDirectory(t *testing.T) {
	dir := t.TempDir()
	got := syncs(t, nil)
	path := filepath.Join(dir, fileCut)
	if err := (fileStore{path: path}).Save([]byte("v1")); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 2 || !strings.HasPrefix(filepath.Base((*got)[0]), "."+fileCut+".") || (*got)[1] != dir {
		t.Fatalf("syncs %q: want the temporary file, then the directory", *got)
	}
	if b, _ := os.ReadFile(path); string(b) != "v1" {
		t.Fatalf("saved %q", b)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v", fi.Mode(), err)
	}
	if open := openUnder(t, dir); len(open) != 0 {
		t.Fatalf("left open: %q", open)
	}
}

// TestSaveFailureKeepsOldFile: a Save whose sync, rename or directory
// sync fails returns the error, closes what it opened, and leaves no
// temporary file; until the rename, the old file stands.
func TestSaveFailureKeepsOldFile(t *testing.T) {
	for _, c := range []struct {
		name string
		fail func(dir, name string) bool
		old  bool // the old file still stands
	}{
		{"file sync", func(dir, name string) bool { return name != dir }, true},
		{"directory sync", func(dir, name string) bool { return name == dir }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, fileCut)
			if err := (fileStore{path: path}).Save([]byte("old")); err != nil {
				t.Fatal(err)
			}
			syncs(t, func(name string) bool { return c.fail(dir, name) })
			if err := (fileStore{path: path}).Save([]byte("new")); !errors.Is(err, errSync) {
				t.Fatalf("a failed sync: %v", err)
			}
			if b, _ := os.ReadFile(path); (string(b) == "old") != c.old {
				t.Fatalf("after the failure the file holds %q", b)
			}
			left, _ := filepath.Glob(filepath.Join(dir, ".*"))
			if open := openUnder(t, dir); len(left) != 0 || len(open) != 0 {
				t.Fatalf("left behind %q, open %q", left, open)
			}
		})
	}
	// A rename over a directory fails after the temporary file is written.
	dir := t.TempDir()
	path := filepath.Join(dir, fileCut)
	if err := os.MkdirAll(filepath.Join(path, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (fileStore{path: path}).Save([]byte("new")); err == nil {
		t.Fatal("a rename over a directory was taken as saved")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*")); len(left) != 0 {
		t.Fatalf("left behind %q", left)
	}
	// A directory that is gone fails the Save and the directory sync as
	// itself, not as a later read of a nil file.
	gone := filepath.Join(dir, "gone")
	if err := (fileStore{path: filepath.Join(gone, fileCut)}).Save([]byte("x")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Save into a missing directory: %v", err)
	}
	if err := syncDir(gone); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("syncDir of a missing directory: %v", err)
	}
	if err := checkStateDir(gone); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("checkStateDir of a missing directory: %v", err)
	}
}

// TestJournalSyncsAndTruncates: Append and Truncate each sync the
// journal's file and close it, landed or failed; Truncate cuts the file
// to its length; a missing directory fails both as itself.
func TestJournalSyncsAndTruncates(t *testing.T) {
	dir := t.TempDir()
	j := fileJournal{filepath.Join(dir, fileAlerts)}
	fail := false
	got := syncs(t, func(string) bool { return fail })
	if err := j.Append([]byte("one\ntwo\n")); err != nil {
		t.Fatal(err)
	}
	if err := j.Truncate(4); err != nil {
		t.Fatal(err)
	}
	if b, _ := j.Load(); string(b) != "one\n" {
		t.Fatalf("after Truncate(4) the journal holds %q", b)
	}
	if !slices.Equal(*got, []string{j.path, j.path}) {
		t.Fatalf("syncs %q: want the journal's file for Append and for Truncate", *got)
	}
	fail = true
	if err := j.Append([]byte("x\n")); !errors.Is(err, errSync) {
		t.Fatalf("an Append whose sync failed: %v", err)
	}
	if err := j.Truncate(0); !errors.Is(err, errSync) {
		t.Fatalf("a Truncate whose sync failed: %v", err)
	}
	if open := openUnder(t, dir); len(open) != 0 {
		t.Fatalf("left open: %q", open)
	}
	gone := fileJournal{filepath.Join(dir, "gone", fileAlerts)}
	if err := gone.Append([]byte("x\n")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Append into a missing directory: %v", err)
	}
	if err := gone.Truncate(0); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Truncate in a missing directory: %v", err)
	}
}

// unreadable is a store whose Load fails: its path is a directory.
func unreadable(t *testing.T) fileStore {
	p := filepath.Join(t.TempDir(), "d")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return fileStore{path: p}
}

// failReader is a random source that has run dry.
type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("entropy: none") }

// TestKeyFilesRefused: an unreadable key file, or one that does not
// hold a key, stops the start; nothing makes a new key over it.
func TestKeyFilesRefused(t *testing.T) {
	if _, err := channelKey(unreadable(t), rand.Reader); !errors.Is(err, syscall.EISDIR) {
		t.Errorf("channelKey of an unreadable file: %v", err)
	}
	if _, err := coreKey(unreadable(t)); err == nil {
		t.Error("coreKey took an unreadable file")
	}
	store := fileStore{path: filepath.Join(t.TempDir(), fileChannelKey)}
	if _, err := channelKey(store, failReader{}); err == nil {
		t.Error("channelKey made a key with no randomness")
	}
	if b, _ := store.Load(); b != nil {
		t.Errorf("a failed key generation wrote %q", b)
	}
	for _, bad := range []string{"not base64!", base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		if err := store.Save([]byte(bad)); err != nil {
			t.Fatal(err)
		}
		if _, err := channelKey(store, rand.Reader); !errors.Is(err, errKeyFile) {
			t.Errorf("channel key %q: %v", bad, err)
		}
		if _, err := coreKey(store); !errors.Is(err, errKeyFile) {
			t.Errorf("core key %q: %v", bad, err)
		}
	}
}

// TestPageCertFile: the page's certificate is saved when made and when
// renewed, an unreadable or malformed file stops the start, and a save
// that fails is the start's error.
func TestPageCertFile(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000)
	path := filepath.Join(t.TempDir(), fileCert)
	store := fileStore{path: path}
	c, err := pageCert(store, rp, now)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := store.Load()
	if d, err := decodeCert(b); err != nil || !leafEqual(d, c) {
		t.Fatalf("the made certificate was not saved: %v", err)
	}
	// A leaf near its end is renewed, and the renewal saved.
	later := now.Add(page.LeafLife - 24*time.Hour)
	r, err := pageCert(store, rp, later)
	if err != nil || leafEqual(r, c) {
		t.Fatalf("no renewal near the leaf's end: %v", err)
	}
	b, _ = store.Load()
	if d, _ := decodeCert(b); !leafEqual(d, r) {
		t.Fatal("the renewed leaf was not saved")
	}
	failing := fileStore{path: path, fault: func(string) error { return errors.New("disk: no space left") }}
	if _, err := pageCert(failing, rp, later.Add(page.LeafLife)); err == nil {
		t.Error("a renewal that was not saved was taken")
	}
	if _, err := pageCert(fileStore{path: filepath.Join(t.TempDir(), fileCert), fault: failing.fault}, rp, now); err == nil {
		t.Error("a made certificate that was not saved was taken")
	}
	if _, err := pageCert(unreadable(t), rp, now); !errors.Is(err, syscall.EISDIR) {
		t.Errorf("pageCert of an unreadable file: %v", err)
	}
	// A leaf that does not parse cannot be renewed.
	var f certFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	f.Leaf = [][]byte{[]byte("not a certificate")}
	bad, _ := json.Marshal(f)
	if err := store.Save(bad); err != nil {
		t.Fatal(err)
	}
	if _, err := pageCert(store, rp, now); err == nil {
		t.Error("pageCert took a leaf that does not parse")
	}
}

// TestCertFileRefused: each malformed part of the certificate file is
// refused as errKeyFile.
func TestCertFileRefused(t *testing.T) {
	c, err := page.NewCert(rp, time.UnixMilli(1_800_000_000_000))
	if err != nil {
		t.Fatal(err)
	}
	store := fileStore{path: filepath.Join(t.TempDir(), fileCert)}
	if err := saveCert(store, c); err != nil {
		t.Fatal(err)
	}
	good, _ := store.Load()
	if _, err := decodeCert(good); err != nil {
		t.Fatal(err)
	}
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notSigner, err := x509.MarshalPKCS8PrivateKey(x)
	if err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func(*certFile){
		"no leaf":           func(f *certFile) { f.Leaf = nil },
		"root key garbage":  func(f *certFile) { f.RootKey = []byte("x") },
		"leaf key garbage":  func(f *certFile) { f.LeafKey = []byte("x") },
		"root key no sign":  func(f *certFile) { f.RootKey = notSigner },
		"leaf key no sign":  func(f *certFile) { f.LeafKey = notSigner },
		"root not parsable": func(f *certFile) { f.Root = []byte("x") },
	} {
		var cf certFile
		if err := json.Unmarshal(good, &cf); err != nil {
			t.Fatal(err)
		}
		f(&cf)
		b, _ := json.Marshal(cf)
		if _, err := decodeCert(b); !errors.Is(err, errKeyFile) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A key the file cannot hold is refused before anything is written.
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	for name, f := range map[string]func(*page.Cert){
		"root key": func(c *page.Cert) { c.RootKey = otherSigner{edKey} },
		"leaf key": func(c *page.Cert) { c.Leaf.PrivateKey = otherSigner{edKey} },
	} {
		bc := c
		f(&bc)
		empty := fileStore{path: filepath.Join(t.TempDir(), fileCert)}
		if err := saveCert(empty, bc); err == nil {
			t.Errorf("%s of a type PKCS #8 cannot hold was saved", name)
		}
		if b, _ := empty.Load(); b != nil {
			t.Errorf("%s: a refused certificate wrote %q", name, b)
		}
	}
}

// otherSigner is a signer of a type x509 cannot marshal.
type otherSigner struct{ ed25519.PrivateKey }

// TestCutStateFile: an unreadable cut file stops the start; a core
// already cut takes no second write, and one not cut no resume's write;
// a lift that is not saved does not happen.
func TestCutStateFile(t *testing.T) {
	if _, err := openCut(unreadable(t), nil, func(string) {}); !errors.Is(err, syscall.EISDIR) {
		t.Errorf("openCut of an unreadable file: %v", err)
	}
	x := newBox(t, true)
	x.fail(fileCut, true)
	if err := x.d.cut.Resume(); err != nil {
		t.Fatalf("a resume with no cut wrote the cut file: %v", err)
	}
	x.fail(fileCut, false)
	x.d.cut.Trip("first")
	x.fail(fileCut, true)
	x.d.cut.Trip("second")
	if x.d.cut.Unsaved() || x.d.cut.Stage() != channel.Tripped {
		t.Fatal("a second trip wrote the cut file again")
	}
	if err := x.d.cut.Resume(); err == nil || x.d.cut.Stage() != channel.Tripped {
		t.Fatalf("a lift that was not saved: %v, stage %v", err, x.d.cut.Stage())
	}
}
