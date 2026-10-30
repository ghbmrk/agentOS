package bootab_test

// REQ: UPD-1, UPD-1a

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/apply"
	"github.com/ghbmrk/agentos/broker/apply/activatortest"
	"github.com/ghbmrk/agentos/broker/apply/bootab"
	"github.com/ghbmrk/agentos/broker/update"
	"github.com/ghbmrk/agentos/broker/update/updatetest"
)

func newActivator(t *testing.T) func(*activatortest.Disk, update.Source) apply.Activator {
	return func(d *activatortest.Disk, src update.Source) apply.Activator {
		return bootab.New(d, bootab.Config{Source: src, Staging: t.TempDir()})
	}
}

// TestCheck (A12(3), (4); #2094): the activator passes the cut sweep
// under each LoaderEntryDefault pin.
func TestCheck(t *testing.T) {
	activatortest.Check(t, newActivator(t))
}

// alter serves one release file with its bytes changed.
type alter struct {
	src  update.Source
	file string
	f    func([]byte) []byte
}

func (a alter) Open(name string) (io.ReadCloser, error) {
	rc, err := a.src.Open(name)
	if err != nil || !strings.HasSuffix(name, "."+filepath.Base(a.file)) {
		return rc, err
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(a.f(b))), nil
}

// noEntry checks a failed Install left no N+1 entry, N-1 the effective
// next boot when the slot was touched, and slot a unwritten.
func noEntry(t *testing.T, d *activatortest.Disk) {
	t.Helper()
	es, _, err := d.Entries()
	if err != nil {
		t.Fatal(err)
	}
	for id, e := range es {
		if e.UsrHash == updatetest.UsrHash(3) {
			t.Errorf("entry %q for N+1 exists: %+v", id, e)
		}
	}
	if eff := es[d.Effective()]; eff.UsrHash == updatetest.UsrHash(3) || eff.Slot == "b" && d.Touched("b") {
		t.Errorf("effective next boot %q is %+v", d.Effective(), eff)
	}
	if d.Touched("a") {
		t.Error("the booted slot was written")
	}
}

// TestNoEntryWithoutVerify (A4): a slot that fails veritysetup verify, or
// a fetched file whose length or hash differs from the signed one, gets
// no counted entry and is not the next boot. A bad fetch writes nothing.
func TestNoEntryWithoutVerify(t *testing.T) {
	rel, src := activatortest.NextRelease(t)
	t.Run("verify fails", func(t *testing.T) {
		d := activatortest.Scenario()
		d.BreakVerify()
		err := newActivator(t)(d, src).Install(t.Context(), rel)
		if err == nil || !strings.Contains(err.Error(), "does not verify") {
			t.Fatalf("Install: %v", err)
		}
		noEntry(t, d)
	})
	for name, f := range map[string]func([]byte) []byte{
		"short":   func(b []byte) []byte { return b[:len(b)-1] },
		"altered": func(b []byte) []byte { c := bytes.Clone(b); c[0] ^= 1; return c },
		"long":    func(b []byte) []byte { return append(bytes.Clone(b), 'x') },
	} {
		for _, file := range []string{bootab.DataFile, bootab.VerityFile} {
			t.Run(name+" "+file, func(t *testing.T) {
				d := activatortest.Scenario()
				if err := newActivator(t)(d, alter{src, file, f}).Install(t.Context(), rel); !errors.Is(err, update.ErrBadRepository) {
					t.Fatalf("Install: %v", err)
				}
				noEntry(t, d)
				if d.Touched("b") || d.Effective() != "agentos_2.conf" {
					t.Errorf("a failed fetch changed the disk: slot b touched %v, default %q", d.Touched("b"), d.Effective())
				}
			})
		}
	}
}

// TestStagingRefusesALink: a staging directory that is a symlink, or that
// others may write, is refused before anything is fetched or written.
func TestStagingRefusesALink(t *testing.T) {
	rel, src := activatortest.NextRelease(t)
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "staging")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	open := t.TempDir()
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	for name, dir := range map[string]string{"symlink": link, "world-writable": open, "missing": filepath.Join(real, "none")} {
		t.Run(name, func(t *testing.T) {
			d := activatortest.Scenario()
			if err := bootab.New(d, bootab.Config{Source: src, Staging: dir}).Install(t.Context(), rel); err == nil {
				t.Fatal("Install accepted the staging directory")
			}
			if d.Touched("b") || d.Effective() != "agentos_2.conf" {
				t.Error("the disk changed")
			}
			if es, _ := os.ReadDir(real); len(es) != 0 {
				t.Errorf("staged through the link: %v", es)
			}
		})
	}
}

// TestStagingRefusesAnotherOwner: a staging directory owned by another
// user, though not group- or world-writable, is refused: its owner could
// swap the fetched files before they are written (Security finding 4).
func TestStagingRefusesAnotherOwner(t *testing.T) {
	rel, src := activatortest.NextRelease(t)
	dir := "/usr" // root-owned and 0755: another owner unless this runs as root
	if os.Getuid() == 0 {
		dir = t.TempDir()
		if err := os.Chown(dir, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	d := activatortest.Scenario()
	if err := bootab.New(d, bootab.Config{Source: src, Staging: dir}).Install(t.Context(), rel); err == nil || !strings.Contains(err.Error(), "owns") {
		t.Fatalf("Install: %v", err)
	}
	if d.Touched("b") {
		t.Error("the disk changed")
	}
}

// TestRefusesTheRunningEntryID: a release whose entry ID is already the
// booted slot's entry is refused before any write, so Install never
// rewrites the running entry to boot the other slot (Security finding 3).
func TestRefusesTheRunningEntryID(t *testing.T) {
	rel, src := activatortest.NextRelease(t)
	d := activatortest.NewDisk("a", map[string]string{"a": updatetest.UsrHash(1), "b": updatetest.UsrHash(2)},
		map[string]activatortest.Entry{
			bootab.EntryID(3): {Slot: "a", UsrHash: updatetest.UsrHash(1), Tries: activatortest.Blessed},
			bootab.EntryID(2): {Slot: "b", UsrHash: updatetest.UsrHash(2), Tries: activatortest.Blessed},
		}, "", updatetest.UsrHash(3))
	if err := newActivator(t)(d, src).Install(t.Context(), rel); err == nil {
		t.Fatal("Install accepted")
	}
	if es, _, _ := d.Entries(); es[bootab.EntryID(3)].Slot != "a" || d.Touched("b") {
		t.Errorf("the disk changed: %v", es)
	}
}

// TestRefusesAnIncompleteRelease: a release without its verity file, a
// disk without exactly the booted slot and one other, and a booted slot
// with no blessed entry are each refused before any write.
func TestRefusesAnIncompleteRelease(t *testing.T) {
	src := updatetest.NewMirror(t)
	src.Add(3, update.ChannelStable, false)
	res, err := src.Box(2).Check(src.Source(), update.Options{})
	if err != nil || res.Release == nil {
		t.Fatalf("check: %v %v", res, err)
	}
	d := activatortest.Scenario()
	if err := bootab.New(d, bootab.Config{Source: src.Source(), Staging: t.TempDir()}).Install(t.Context(), res.Release); err == nil {
		t.Error("Install of a release with no verity file")
	}
	rel, s := activatortest.NextRelease(t)
	for name, d := range map[string]*activatortest.Disk{
		"one slot": activatortest.NewDisk("a", map[string]string{"a": updatetest.UsrHash(1)},
			map[string]activatortest.Entry{"agentos_1.conf": {Slot: "a", UsrHash: updatetest.UsrHash(1), Tries: activatortest.Blessed}}, "agentos_1.conf"),
		"booted entry counted": activatortest.NewDisk("a", map[string]string{"a": updatetest.UsrHash(1), "b": updatetest.UsrHash(2)},
			map[string]activatortest.Entry{
				"agentos_1.conf": {Slot: "a", UsrHash: updatetest.UsrHash(1), Tries: 2},
				"agentos_2.conf": {Slot: "b", UsrHash: updatetest.UsrHash(2), Tries: activatortest.Blessed},
			}, "agentos_2.conf"),
	} {
		if err := bootab.New(d, bootab.Config{Source: s, Staging: t.TempDir()}).Install(t.Context(), rel); err == nil {
			t.Errorf("%s: Install accepted", name)
		}
		if d.Touched("b") || d.Touched("a") {
			t.Errorf("%s: a slot was written", name)
		}
	}
	if err := bootab.New(activatortest.Scenario(), bootab.Config{Staging: t.TempDir()}).Install(t.Context(), rel); err == nil {
		t.Error("Install with no source")
	}
}

// TestAbandonRestoresTheRunningRoot: Abandon after an Install makes N-1
// the effective next boot again and removes N+1's counted entry; on a
// disk where nothing was installed it changes nothing, so a blessed
// default stays the default (A12(2)).
func TestAbandonRestoresTheRunningRoot(t *testing.T) {
	rel, src := activatortest.NextRelease(t)
	d := activatortest.Scenario()
	a := newActivator(t)(d, src)
	if err := a.Abandon(t.Context()); err != nil {
		t.Fatal(err)
	}
	if d.Effective() != "agentos_2.conf" {
		t.Errorf("Abandon with nothing installed moved the default to %q", d.Effective())
	}
	if err := a.Install(t.Context(), rel); err != nil {
		t.Fatal(err)
	}
	if d.Effective() != bootab.EntryID(3) {
		t.Fatalf("after Install the default is %q", d.Effective())
	}
	if err := a.Abandon(t.Context()); err != nil {
		t.Fatal(err)
	}
	es, _, _ := d.Entries()
	if d.Effective() != "agentos_1.conf" {
		t.Errorf("after Abandon the default is %q", d.Effective())
	}
	if _, ok := es[bootab.EntryID(3)]; ok {
		t.Error("N+1's counted entry is still in the menu")
	}
	if _, ok := es["agentos_1.conf"]; !ok {
		t.Error("N-1's entry is gone")
	}
}

// TestBootedReadsTheLoader: Booted reports the boot ID, the usrhash= on
// the command line and whether the selected entry is blessed and boots
// that hash, so the applier's Resume never commits a boot that fell back
// or still counts tries. A missing or doubled usrhash= is an error.
func TestBootedReadsTheLoader(t *testing.T) {
	h1, h2 := updatetest.UsrHash(1), updatetest.UsrHash(2)
	for _, c := range []struct {
		name, cmdline, selected string
		want                    apply.Boot
		err                     bool
	}{
		{"blessed N-1", "ro usrhash=" + h1, "agentos_1.conf", apply.Boot{ID: "boot-9", UsrRootHash: h1, Blessed: true}, false},
		{"counted entry", "usrhash=" + h2 + " quiet", "agentos_3.conf", apply.Boot{ID: "boot-9", UsrRootHash: h2}, false},
		{"selected names another root", "usrhash=" + h1, "agentos_2.conf", apply.Boot{ID: "boot-9", UsrRootHash: h1}, false},
		{"selected unset", "usrhash=" + h1, "", apply.Boot{ID: "boot-9", UsrRootHash: h1}, false},
		{"no usrhash", "ro quiet", "agentos_1.conf", apply.Boot{}, true},
		{"two usrhash", "usrhash=" + h1 + " usrhash=" + h2, "agentos_1.conf", apply.Boot{}, true},
		{"bad usrhash", "usrhash=xyz", "agentos_1.conf", apply.Boot{}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := activatortest.Scenario()
			if err := d.WriteEntry("agentos_3.conf", activatortest.Entry{Slot: "b", UsrHash: h2, Tries: 2}); err != nil {
				t.Fatal(err)
			}
			d.SetBoot("boot-9", c.cmdline, c.selected)
			got, err := bootab.New(d, bootab.Config{}).Booted(context.Background())
			if (err != nil) != c.err || got != c.want {
				t.Errorf("Booted = %+v, %v; want %+v, error %v", got, err, c.want, c.err)
			}
		})
	}
}

// TestRestartRunsTheHook: Restart is the configured hook, and an absent
// hook is an error rather than a silent no-op.
func TestRestartRunsTheHook(t *testing.T) {
	called := 0
	a := bootab.New(activatortest.Scenario(), bootab.Config{Restart: func(context.Context) error { called++; return nil }})
	if err := a.Restart(t.Context()); err != nil || called != 1 {
		t.Errorf("Restart: %v, hook called %d", err, called)
	}
	if err := bootab.New(activatortest.Scenario(), bootab.Config{}).Restart(t.Context()); err == nil {
		t.Error("Restart with no hook")
	}
}

// TestPartitionUUIDs: the data UUID is the first 128 bits of the root
// hash and the verity UUID the last 128, in UUID form.
func TestPartitionUUIDs(t *testing.T) {
	h := "00112233445566778899aabbccddeeff0123456789abcdef0fedcba987654321"
	d, v, err := bootab.PartitionUUIDs(h)
	if err != nil || d != "00112233-4455-6677-8899-aabbccddeeff" || v != "01234567-89ab-cdef-0fed-cba987654321" {
		t.Errorf("PartitionUUIDs = %q, %q, %v", d, v, err)
	}
	for _, bad := range []string{"", "00", strings.Repeat("g", 64), strings.Repeat("0", 66)} {
		if _, _, err := bootab.PartitionUUIDs(bad); err == nil {
			t.Errorf("PartitionUUIDs(%q) accepted", bad)
		}
	}
}
