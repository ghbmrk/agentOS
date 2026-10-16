package main

// REQ: CAP-11, CRED-5, ONB-3

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/provagent"
)

// pinnedImage is an image root whose pin file holds content.
func pinnedImage(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, cliPinPath)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The pin is the version line build-rootfs.sh writes.
func TestImagePinReadsTheVersionLine(t *testing.T) {
	for _, v := range []string{"0.162.1", "1.2", "0.162.1-alpha.3", "2.0.0+build.7"} {
		got, err := readCLIPin(pinnedImage(t, v+"\n"))
		if err != nil || got != v {
			t.Errorf("%q = %q, %v", v, got, err)
		}
	}
}

// Anything but one version line pins nothing (fails closed).
func TestImagePinRefusesWhatIsNotAVersion(t *testing.T) {
	for name, content := range map[string]string{
		"empty":      "",
		"newline":    "\n",
		"garbage":    "latest\n",
		"two lines":  "0.162.1\n0.162.2\n",
		"padded":     " 0.162.1\n",
		"crlf":       "0.162.1\r\n",
		"one number": "1\n",
		"too long":   "0.162.1-" + strings.Repeat("a", cliPinMax) + "\n",
	} {
		if v, err := readCLIPin(pinnedImage(t, content)); err == nil || v != "" {
			t.Errorf("%s: %q, %v", name, v, err)
		}
	}
	if v, err := readCLIPin(t.TempDir()); err == nil || v != "" {
		t.Errorf("missing file: %q, %v", v, err)
	}
	if v, err := readCLIPin(filepath.Join(t.TempDir(), "nosuch")); err == nil || v != "" {
		t.Errorf("missing image: %q, %v", v, err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, cliPinPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if v, err := readCLIPin(dir); err == nil || v != "" {
		t.Errorf("directory: %q, %v", v, err)
	}
}

// A symlink in the image cannot point the read at a host file: the pin
// resolves inside the image root only.
func TestImagePinStaysInsideTheImage(t *testing.T) {
	host := filepath.Join(t.TempDir(), "host-file")
	if err := os.WriteFile(host, []byte("9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"absolute": host, "relative": "../../../../" + host} {
		dir := t.TempDir()
		p := filepath.Join(dir, cliPinPath)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		if v, err := readCLIPin(dir); err == nil || v != "" {
			t.Errorf("%s symlink out of the image read %q, %v", name, v, err)
		}
	}
	// A directory symlink out of the image is refused too.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := pinnedImage(t, "9.9.9\n")
	if err := os.Symlink(filepath.Join(out, "usr/lib/agentos"), filepath.Join(dir, "usr/lib/agentos")); err != nil {
		t.Fatal(err)
	}
	if v, err := readCLIPin(dir); err == nil || v != "" {
		t.Errorf("directory symlink out of the image read %q, %v", v, err)
	}
}

// A FIFO at the pin path neither hangs the read nor pins what is written
// to it: the open does not block and only a regular file is read.
func TestImagePinRefusesAFIFO(t *testing.T) {
	for _, written := range []string{"", "0.162.1\n"} {
		dir := t.TempDir()
		p := filepath.Join(dir, cliPinPath)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(p, 0o644); err != nil {
			t.Fatal(err)
		}
		if written != "" {
			// O_RDWR opens a FIFO without a reader; the writer stays open,
			// so a read past the data would wait for more.
			w, err := os.OpenFile(p, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if _, err := w.WriteString(written); err != nil {
				t.Fatal(err)
			}
		}
		type res struct {
			v   string
			err error
		}
		done := make(chan res, 1)
		go func() { v, err := readCLIPin(dir); done <- res{v, err} }()
		select {
		case r := <-done:
			if r.err == nil || r.v != "" {
				t.Errorf("FIFO holding %q read %q, %v", written, r.v, r.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("FIFO holding %q hung the read", written)
		}
	}
}

// Only images a declaration runs on are read; an unregistered image pins
// nothing, and an image that pins nothing reads as "".
func TestImagePinsReadDeclaredImagesOnly(t *testing.T) {
	imgs := images{"codex": pinnedImage(t, "0.162.1\n"), "other": pinnedImage(t, "1.0.0\n"), "claude": t.TempDir()}
	p := readImagePins(imgs, provagent.Builtins())
	if p.version("codex") != "0.162.1" {
		t.Fatalf("codex = %q", p.version("codex"))
	}
	if p.version("other") != "" || p.version("claude") != "" || p.version("nosuch") != "" {
		t.Fatalf("pins = %v", p)
	}
	if got := readImagePins(images{}, provagent.Builtins()); len(got) != 0 {
		t.Fatalf("no images pinned %v", got)
	}
	var none imagePins
	if none.version("codex") != "" {
		t.Fatal("nil pins pinned a version")
	}
}

// At start, a provider image that pins nothing or pins another version
// than its record is logged by name with both versions, and nothing else
// the file holds.
func TestImagePinsLogAMismatchAtStart(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	decls := provagent.Builtins()
	qualifiedOn(decls, "0.162.1")
	readImagePins(images{"codex": pinnedImage(t, "0.162.1\n")}, decls)
	if buf.Len() != 0 {
		t.Fatalf("a matching pin logged %q", buf.String())
	}
	readImagePins(images{"codex": pinnedImage(t, "0.163.0\n")}, decls)
	if got := buf.String(); !strings.Contains(got, `image "codex" pins CLI 0.163.0`) || !strings.Contains(got, `record is for "0.162.1"`) {
		t.Fatalf("mismatch logged %q", got)
	}
	buf.Reset()
	readImagePins(images{"codex": pinnedImage(t, "canary-not-a-version\n")}, decls)
	if got := buf.String(); !strings.Contains(got, `image "codex" pins no CLI version`) || strings.Contains(got, "canary") {
		t.Fatalf("bad pin logged %q", got)
	}
}

// qualifiedOn fills codex's record as #809 would, taken on version.
func qualifiedOn(decls map[string]provagent.Declaration, version string) {
	d := decls["codex"]
	d.Q = provagent.Qualification{CLIVersion: version, Evidence: "e", TermsURL: "https://t.test", TermsRead: "2026-10-01", Verdict: provagent.Allowed}
	decls["codex"] = d
}

// The gate opens only when the image's pin equals the version the record
// was taken on: a changed pin makes the run unqualified, and the daemon's
// runner and setup's sign-in read the same pin, so they agree (#1877).
func TestAChangedImagePinMakesTheRunUnqualified(t *testing.T) {
	dir := pinnedImage(t, "0.162.1\n")
	imgs := images{"codex": dir}
	check := func(want bool) {
		t.Helper()
		pins := readImagePins(imgs, provagent.Builtins())
		r := providerRunner(nil, nil, nil, pins)
		qualifiedOn(r.Decls, "0.162.1")
		r.Granted = func(string) bool { return true }
		if got := runCodex(r); (got != provagent.Unqualified) != want {
			t.Fatalf("run = %q, gate open want %v", got, want)
		}
		s := newSetupSignIn(newSetupRig(0).s, modelroute.NewRouteControl(t.TempDir()+"/none.sock"), pins)
		qualifiedOn(s.r.Decls, "0.162.1")
		if s.Ready("codex") != want {
			t.Fatalf("setup sign-in ready = %v, want %v", !want, want)
		}
	}
	check(true)
	if err := os.WriteFile(filepath.Join(dir, cliPinPath), []byte("0.163.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	check(false)
	if err := os.Remove(filepath.Join(dir, cliPinPath)); err != nil {
		t.Fatal(err)
	}
	check(false)
	// No registered codex image (#1721 not landed) leaves the gate closed.
	imgs = images{}
	check(false)
}

// The pin is re-read from the registered image directory at every check,
// the directory vm creates the machine from: an image swapped after start
// closes the gate without a restart, and the image swapped back reopens it.
func TestASwappedImageClosesTheGate(t *testing.T) {
	dir := pinnedImage(t, "0.162.1\n")
	pins := readImagePins(images{"codex": dir}, provagent.Builtins())
	r := providerRunner(nil, nil, nil, pins)
	qualifiedOn(r.Decls, "0.162.1")
	r.Granted = func(string) bool { return true }
	s := newSetupSignIn(newSetupRig(0).s, modelroute.NewRouteControl(t.TempDir()+"/none.sock"), pins)
	qualifiedOn(s.r.Decls, "0.162.1")
	open := func() bool { return runCodex(r) != provagent.Unqualified && s.Ready("codex") }
	if !open() {
		t.Fatal("gate closed on the qualified image")
	}
	kept := dir + ".kept"
	if err := os.Rename(dir, kept); err != nil {
		t.Fatal(err)
	}
	other := pinnedImage(t, "0.163.0\n")
	if err := os.Rename(other, dir); err != nil {
		t.Fatal(err)
	}
	if runCodex(r) != provagent.Unqualified || s.Ready("codex") {
		t.Fatal("the gate stayed open on a swapped image")
	}
	if err := os.Rename(dir, other); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(kept, dir); err != nil {
		t.Fatal(err)
	}
	if !open() {
		t.Fatal("gate stayed closed on the image swapped back")
	}
}
