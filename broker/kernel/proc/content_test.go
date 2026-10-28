package proc

import (
	"errors"
	"fmt"
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

// refusing is a content store that refuses every delete.
type refusing struct{ *kernel.MemContent }

func (refusing) Delete(kernel.Hash) error { return errors.New("store down") }

// The owner finds a subject by name, sees its items, and erases it over
// the owner socket: then nothing is left unerased, the item is unreadable
// and the lineage that read it is named; a store that refuses its delete
// stays listed in unerased (LOG-4).
func TestEraseOverTheOwnerSocket(t *testing.T) {
	dir := t.TempDir()
	h := contentKernel(t, filepath.Join(dir, "log"), filepath.Join(dir, "keys"))
	defer h.Close()
	o := Owner{serveSide(t, &box{t: t, h: h}, OwnerSide, os.Getuid())}
	var alice, bob string
	var item kernel.Hash
	if err := h.With(func(k *kernel.Kernel) (err error) {
		stores := map[string]kernel.ContentStore{"mail": kernel.NewMemContent(), "notes": refusing{kernel.NewMemContent()}}
		if _, err = k.OpenContent(kernel.NewMemKeys(), stores, 1000); err != nil {
			return err
		}
		if alice, err = k.OpenSubject(1000); err != nil {
			return err
		}
		if bob, err = k.OpenSubject(1000); err != nil {
			return err
		}
		k.Seal(1000, alice, "mail", kernel.ClassLabel, []byte("Alice"))
		if item, err = k.Seal(1000, alice, "mail", "message", []byte("lunch")); err != nil {
			return err
		}
		k.Seal(1000, bob, "notes", kernel.ClassLabel, []byte("Bob"))
		_, err = k.ReadFor(1001, item, "lin-1")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	found, unread, err := o.Named("alice")
	if err != nil || !slices.Equal(found, []string{alice}) || unread != nil {
		t.Fatalf("named: %v %v %v", found, unread, err)
	}
	if r, ok, err := o.Recall(alice); err != nil || !ok || len(r.Items) != 2 {
		t.Fatalf("recall: %+v %v %v", r, ok, err)
	}
	if _, ok, err := o.Recall("0123456789abcdef0123456789abcdef"); err != nil || ok {
		t.Fatalf("recall of no subject: %v %v", ok, err)
	}
	c, err := o.Erase(alice)
	if err != nil || c.Subject != alice || len(c.Unconfirmed) != 0 {
		t.Fatalf("erase: %+v %v", c, err)
	}
	if u, err := o.Unerased(); err != nil || u != nil {
		t.Fatalf("unerased after the erase: %+v %v", u, err)
	}
	if err := h.With(func(k *kernel.Kernel) error { _, err := k.Read(item); return err }); !errors.Is(err, kernel.ErrErased) {
		t.Fatalf("read after the erase: %v", err)
	}
	if rs, err := o.ErasedReads(); err != nil || len(rs) != 1 || rs[0].Subject != alice || rs[0].Lineage != "lin-1" {
		t.Fatalf("erased reads: %+v %v", rs, err)
	}
	if _, err := o.Erase(alice); !errors.Is(err, kernel.ErrErased) {
		t.Fatalf("a second erase: %v", err)
	}
	if _, err := o.Erase("0123456789abcdef0123456789abcdef"); !errors.Is(err, kernel.ErrSubject) {
		t.Fatalf("an erase of no subject: %v", err)
	}
	c, err = o.Erase(bob)
	if err != nil || !slices.Equal(c.Unconfirmed, []string{"notes"}) {
		t.Fatalf("erase with a store down: %+v %v", c, err)
	}
	if u, err := o.Unerased(); err != nil || len(u) != 1 || u[0].Subject != bob || !slices.Equal(u[0].Stores, []string{"notes"}) {
		t.Fatalf("unerased with a store down: %+v %v", u, err)
	}
}

// Before content opens, named says so over the socket, by the sentinel.
func TestNamedOverTheSocketBeforeContentOpens(t *testing.T) {
	b := newBox(t, filepath.Join(shortDir(t), "web.sock"))
	o := Owner{serveSide(t, b, OwnerSide, os.Getuid())}
	if _, _, err := o.Named("Alice"); !errors.Is(err, kernel.ErrContentClosed) {
		t.Fatalf("named before content opens: %v", err)
	}
}

// downKeys is a key table whose delete fails with err.
type downKeys struct {
	*kernel.MemKeys
	err error
}

func (d downKeys) Delete(string) error { return d.err }

// KRN-forget-erase-err-test (#3525): when the key delete after a logged
// erase fails, the owner socket still answers the Confirmation with the
// error, and Owner.Erase gives the sentinel back by its text, or the text
// alone for any other error, so the forget flow neither retries the erase
// nor reports it unlogged (LOG-4).
func TestEraseOverTheOwnerSocketWhenAStepAfterTheLogFails(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		is   error // the sentinel errors.Is finds across the socket; nil: none
	}{
		{"sentinel", kernel.ErrStore, kernel.ErrStore},
		{"wrapped sentinel", fmt.Errorf("%w: key file", kernel.ErrStore), nil},
		{"plain text", errors.New("key table down"), nil},
		{"joined", errors.Join(kernel.ErrStore, errors.New("key table down")), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			h := contentKernel(t, filepath.Join(dir, "log"), filepath.Join(dir, "keys"))
			defer h.Close()
			o := Owner{serveSide(t, &box{t: t, h: h}, OwnerSide, os.Getuid())}
			var sub string
			if err := h.With(func(k *kernel.Kernel) (err error) {
				if _, err = k.OpenContent(downKeys{kernel.NewMemKeys(), tc.err}, map[string]kernel.ContentStore{"mail": kernel.NewMemContent()}, 1000); err != nil {
					return err
				}
				if sub, err = k.OpenSubject(1000); err != nil {
					return err
				}
				_, err = k.Seal(1000, sub, "mail", "message", []byte("lunch"))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			c, err := o.Erase(sub)
			if c.Subject != sub || !slices.Equal(c.Unconfirmed, []string{kernel.KeyTable}) {
				t.Fatalf("the Confirmation did not cross with the error: %+v %v", c, err)
			}
			if err == nil || err.Error() != tc.err.Error() {
				t.Fatalf("got error %v, want %q", err, tc.err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("errors.Is(%v, %v) is false across the socket", err, tc.is)
			}
			if u, err := o.Unerased(); err != nil || len(u) != 1 || u[0].Subject != sub || !slices.Equal(u[0].Stores, []string{kernel.KeyTable}) {
				t.Fatalf("unerased after the failed key delete: %+v %v", u, err)
			}
			if _, err := o.Erase(sub); !errors.Is(err, kernel.ErrErased) {
				t.Fatalf("the erase is not logged: a second erase got %v", err)
			}
		})
	}
}
