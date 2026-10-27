package proc

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel"
)

// REQ: LOG-4, KRN-erase

// MIG-4-run-keys (#2682): the kernel process opens its subject-key table at
// start, so content opens in the real process, not only in the sim.
func contentKernel(t *testing.T, logPath, keyDir string) *Kernel {
	t.Helper()
	h, err := OpenKernel(KernelConfig{
		Log: logPath, Anchor: anchor(t, logPath), Key: [32]byte{7},
		Pub: headPub, Sign: headPriv, Anchors: anchors, KeyDir: keyDir,
	}, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// anchor keeps one MemAnchor per log across the test's restarts, as the
// real anchor outlives the process.
var memAnchors = map[string]*kernel.MemAnchor{}

func anchor(t *testing.T, logPath string) *kernel.MemAnchor {
	a := memAnchors[logPath]
	if a == nil {
		a = &kernel.MemAnchor{}
		memAnchors[logPath] = a
		t.Cleanup(func() { delete(memAnchors, logPath) })
	}
	return a
}

func openSubject(t *testing.T, h *Kernel) string {
	t.Helper()
	var sub string
	if err := h.With(func(k *kernel.Kernel) (err error) {
		sub, err = k.OpenSubject(1000)
		return err
	}); err != nil {
		t.Fatalf("open a subject: %v", err)
	}
	return sub
}

func TestTheKernelProcessOpensContent(t *testing.T) {
	dir := t.TempDir()
	logPath, keyDir := filepath.Join(dir, "log"), filepath.Join(dir, "keys")
	h := contentKernel(t, logPath, keyDir)
	sub := openSubject(t, h)
	if r := h.Content(); len(r.Missing)+len(r.Unnamed) != 0 {
		t.Fatalf("a fresh table reports %+v", r)
	}
	h.Close()
	// The key is on the drive, sealed, and the next start finds it.
	if _, err := os.Stat(filepath.Join(keyDir, sub+keyExt)); err != nil {
		t.Fatalf("the subject's key file: %v", err)
	}
	h = contentKernel(t, logPath, keyDir)
	defer h.Close()
	if r := h.Content(); len(r.Missing)+len(r.Unnamed) != 0 {
		t.Fatalf("a restart reports %+v", r)
	}
	if _, err := h.Erase(1000, sub); err != nil {
		t.Fatalf("erase after a restart: %v", err)
	}
	if _, err := os.Stat(filepath.Join(keyDir, sub+keyExt)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an erased subject's key file is still there: %v", err)
	}
}

// Without a table the kernel's content stays closed: that is the gap on
// main this slice closes, and what a test-only kernel still gets.
func TestNoKeyTableKeepsContentClosed(t *testing.T) {
	h, err := OpenKernel(KernelConfig{
		Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7},
		Pub: headPub, Sign: headPriv, Anchors: anchors,
	}, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	err = h.With(func(k *kernel.Kernel) error { _, err := k.OpenSubject(1000); return err })
	if !errors.Is(err, kernel.ErrContentClosed) {
		t.Fatalf("got %v, want ErrContentClosed", err)
	}
}

// Every start re-applies the erases: a key file back after its erase (a
// restore, or a delete the drive lost) is deleted again at start, and a
// key no subject names, or a subject whose key is gone, is reported.
func TestAStartReappliesErasesAndReports(t *testing.T) {
	dir := t.TempDir()
	logPath, keyDir := filepath.Join(dir, "log"), filepath.Join(dir, "keys")
	h := contentKernel(t, logPath, keyDir)
	gone, lost := openSubject(t, h), openSubject(t, h)
	saved, err := os.ReadFile(filepath.Join(keyDir, gone+keyExt))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Erase(1000, gone); err != nil {
		t.Fatal(err)
	}
	h.Close()
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(keyDir, name+keyExt), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(gone, saved)
	stray := "0123456789abcdef0123456789abcdef"
	write(stray, saved)
	if err := os.Remove(filepath.Join(keyDir, lost+keyExt)); err != nil {
		t.Fatal(err)
	}
	h = contentKernel(t, logPath, keyDir)
	defer h.Close()
	if _, err := os.Stat(filepath.Join(keyDir, gone+keyExt)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an erased subject's key came back and stayed: %v", err)
	}
	r := h.Content()
	if !slices.Equal(r.Missing, []string{lost}) || !slices.Equal(r.Unnamed, []string{stray}) {
		t.Fatalf("report %+v, want missing [%s] and unnamed [%s]", r, lost, stray)
	}
}

// A table open to another uid is refused, so the kernel does not start on
// keys someone else could have placed (privfile).
func TestALooseKeyTableStopsTheStart(t *testing.T) {
	dir := t.TempDir()
	keyDir := filepath.Join(dir, "keys")
	if err := os.Mkdir(keyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := OpenKernel(KernelConfig{
		Log: filepath.Join(dir, "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7},
		Pub: headPub, Sign: headPriv, Anchors: anchors, KeyDir: keyDir,
	}, 1000)
	if err == nil {
		t.Fatal("a kernel started on a key table open to other uids")
	}
}

// The real process never starts without a table: RunKernel refuses an
// empty KeyDir before anything else.
func TestRunKernelNeedsAKeyTable(t *testing.T) {
	err := RunKernel(t.Context(), MainConfig{Log: filepath.Join(t.TempDir(), "log")}, handoff.KernelKeys{Head: headPriv}, &kernel.MemAnchor{})
	if err == nil || !errors.Is(err, ErrNoKeyTable) {
		t.Fatalf("got %v, want ErrNoKeyTable", err)
	}
}
