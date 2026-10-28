package main

// REQ: HW-1, CH-9

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ghbmrk/agentos/broker/pageca"
)

// staging is the two tmpfs directories at first boot: the keeper's setup
// directory for the staged pair and the public one for its certificate.
type staging struct {
	t                 *testing.T
	staged, published string
}

func newStaging(t *testing.T) staging {
	dir := t.TempDir()
	s := staging{t: t, staged: filepath.Join(dir, "setup", "page-ca"), published: filepath.Join(dir, "pub", "authority.der")}
	noErr(t, os.Mkdir(filepath.Dir(s.staged), 0o700))
	noErr(t, os.Mkdir(filepath.Dir(s.published), 0o755))
	return s
}

func (s staging) stage() error { return stagePageCA(s.staged, s.published, testBuilt) }

// dirs reads both directories, names (hidden ones too), modes and bytes, so
// a test can say nothing changed and no temporary file was left.
func (s staging) dirs() map[string]string {
	s.t.Helper()
	out := map[string]string{}
	for _, d := range []string{filepath.Dir(s.staged), filepath.Dir(s.published)} {
		es, err := os.ReadDir(d)
		noErr(s.t, err)
		for _, e := range es {
			p := filepath.Join(d, e.Name())
			fi, err := os.Lstat(p)
			noErr(s.t, err)
			v := fi.Mode().String()
			if fi.Mode().IsRegular() {
				v += ":" + string(get(os.ReadFile(p)))
			} else if fi.Mode()&os.ModeSymlink != 0 {
				v += ":" + get(os.Readlink(p))
			}
			out[p] = v
		}
	}
	return out
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	noErr(t, err)
	return fi.Mode()
}

// HW-1, CH-9: staging writes the sealed pair (root's alone) and its
// certificate (public), and the certificate is the pair's. A second run
// changes nothing: no overwrite, no second authority.
func TestStageWritesPairAndCertificateOnce(t *testing.T) {
	s := newStaging(t)
	old := syscall.Umask(0o077) // the unit's UMask=0077
	defer syscall.Umask(old)
	noErr(t, s.stage())
	if m := mode(t, s.staged); m != 0o600 {
		t.Fatalf("staged pair mode %v", m)
	}
	if m := mode(t, s.published); m != 0o644 {
		t.Fatalf("published certificate mode %v", m)
	}
	a, err := pageca.Unmarshal(get(os.ReadFile(s.staged)))
	if err != nil || a.Name() != pageca.DefaultName {
		t.Fatalf("the staged pair does not open: %v", err)
	}
	if !bytes.Equal(a.Certificate(), get(os.ReadFile(s.published))) {
		t.Fatal("the published certificate is not the staged pair's")
	}
	before := s.dirs()
	if len(before) != 2 {
		t.Fatalf("staging left %d files: %v", len(before), before)
	}
	noErr(t, s.stage())
	if !sameMap(before, s.dirs()) {
		t.Fatal("a second staging changed the files")
	}
}

// A crash between the two writes leaves the pair alone, and the rerun
// publishes its certificate. A certificate alone is refused, unchanged, so
// it never gets a second key. A symlink at either name, or two files that
// are not one pair, is refused, and nothing is written through a link.
func TestStageRecoversAndRefuses(t *testing.T) {
	s := newStaging(t)
	noErr(t, s.stage())
	pair, cert := get(os.ReadFile(s.staged)), get(os.ReadFile(s.published))

	noErr(t, os.Remove(s.published))
	noErr(t, s.stage())
	if !bytes.Equal(get(os.ReadFile(s.published)), cert) || !bytes.Equal(get(os.ReadFile(s.staged)), pair) {
		t.Fatal("the rerun did not publish the staged pair's certificate")
	}

	refused := func(want error) {
		t.Helper()
		before := s.dirs()
		if err := s.stage(); !errors.Is(err, want) {
			t.Fatalf("got %v, want %v", err, want)
		}
		if !sameMap(before, s.dirs()) {
			t.Fatal("a refused staging changed the files")
		}
	}
	noErr(t, os.Remove(s.staged))
	refused(errPublishedAlone)

	// Another authority's pair beside this certificate.
	other := newStaging(t)
	noErr(t, other.stage())
	noErr(t, os.WriteFile(s.staged, get(os.ReadFile(other.staged)), 0o600))
	refused(errPageCAPair)

	// Links: at the pair's name (alone, and beside the certificate), and at
	// the certificate's name beside the pair and alone.
	away := filepath.Join(t.TempDir(), "away")
	noErr(t, os.WriteFile(away, pair, 0o600))
	noErr(t, os.Remove(s.staged))
	noErr(t, os.Symlink(away, s.staged))
	refused(errPageCARead)
	noErr(t, os.Remove(s.published))
	refused(errPageCARead)
	if _, err := os.Lstat(s.published); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a certificate was published from a linked pair")
	}
	noErr(t, os.Remove(s.staged))
	noErr(t, os.WriteFile(s.staged, pair, 0o600))
	awayCert := filepath.Join(t.TempDir(), "cert")
	noErr(t, os.WriteFile(awayCert, cert, 0o644))
	noErr(t, os.Symlink(awayCert, s.published))
	refused(errPublished)
	noErr(t, os.Remove(s.staged))
	gone := filepath.Join(t.TempDir(), "never")
	noErr(t, os.Remove(s.published))
	noErr(t, os.Symlink(gone, s.published))
	refused(errPublishedAlone)
	if _, err := os.Lstat(gone); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("staging wrote through a link")
	}
}

// writeOnce never replaces a file, and leaves no temporary name.
func TestWriteOnceNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	noErr(t, writeOnce(p, []byte("one"), 0o600))
	if err := writeOnce(p, []byte("two"), 0o600); err == nil {
		t.Fatal("writeOnce replaced a file")
	}
	if got := string(get(os.ReadFile(p))); got != "one" {
		t.Fatalf("the file holds %q", got)
	}
	es := get(os.ReadDir(dir))
	if len(es) != 1 || strings.HasPrefix(es[0].Name(), ".") {
		t.Fatalf("writeOnce left %v", es)
	}
}
