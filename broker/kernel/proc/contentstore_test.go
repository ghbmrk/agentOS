package proc

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// REQ: LOG-4, KRN-erase, CLK-1

// KRN-content (#3550): the kernel process keeps sealed items in file
// stores under ContentDir, and a content clerk opens subjects, seals and
// reads them for a lineage over its own socket.

// canary is a synthetic plaintext no store file may ever hold.
const canary = "face-template-canary-5b1d"

// storeKernel is contentKernel with the content stores in dir/content,
// stores named.
func storeKernel(t *testing.T, dir string, stores ...string) *Kernel {
	t.Helper()
	logPath := filepath.Join(dir, "log")
	h, err := OpenKernel(KernelConfig{
		Log: logPath, Anchor: anchor(t, logPath), Key: [32]byte{7},
		Pub: headPub, Sign: headPriv, Anchors: anchors,
		KeyDir: filepath.Join(dir, "keys"), ContentDir: filepath.Join(dir, "content"), Stores: stores,
	}, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// contentConn serves store's ContentSide of h to this uid.
func contentConn(t *testing.T, h *Kernel, store string) Content {
	t.Helper()
	return Content{serveSide(t, &box{t: t, h: h}, ContentSide(store), os.Getuid())}
}

// noCanary fails if any file under dir holds the canary.
func noCanary(t *testing.T, dir string) {
	t.Helper()
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(canary)) {
			t.Errorf("%s holds the plaintext", p)
		}
		return nil
	})
}

// itemFiles lists the item files of store.
func itemFiles(t *testing.T, dir, store string) []string {
	t.Helper()
	des, err := os.ReadDir(filepath.Join(dir, "content", store))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, de := range des {
		out = append(out, de.Name())
	}
	return out
}

// A sealed item written through the socket survives a restart, and readfor
// returns it and logs the read; an erase then refuses it, its file is gone,
// the lineage is named for rewinding, and no plaintext was ever on the
// drive. Revert mutants: OpenKernel passing an empty store map (the seal
// is ErrStore); FileContent.Delete not removing the file.
func TestASealedItemLivesUntilItsErase(t *testing.T) {
	dir := t.TempDir()
	h := storeKernel(t, dir, "vision")
	c := contentConn(t, h, "vision")
	sub, err := c.OpenSubject()
	if err != nil || !kernel.ValidSubject(sub) {
		t.Fatalf("opensubject: %q %v", sub, err)
	}
	item, err := c.Seal(sub, "wrap-key", []byte(canary))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if f := itemFiles(t, dir, "vision"); len(f) != 1 {
		t.Fatalf("the store holds %q, want one item", f)
	}
	noCanary(t, dir)
	h.Close()

	h = storeKernel(t, dir, "vision")
	defer h.Close()
	c = contentConn(t, h, "vision")
	got, err := c.ReadFor(item, "vision-lin")
	if err != nil || string(got) != canary {
		t.Fatalf("readfor after a restart: %q %v", got, err)
	}
	conf, err := h.Erase(time.Now().UnixMilli(), sub)
	if err != nil || len(conf.Unconfirmed) != 0 {
		t.Fatalf("erase: %+v %v", conf, err)
	}
	if _, err := c.ReadFor(item, "vision-lin"); !errors.Is(err, kernel.ErrErased) {
		t.Fatalf("readfor after the erase: %v, want ErrErased", err)
	}
	if f := itemFiles(t, dir, "vision"); len(f) != 0 {
		t.Fatalf("the store still holds %q after the erase", f)
	}
	if _, err := c.Seal(sub, "wrap-key", []byte("more")); !errors.Is(err, kernel.ErrErased) {
		t.Fatalf("seal into an erased subject: %v, want ErrErased", err)
	}
	var reads []kernel.ErasedRead
	h.With(func(k *kernel.Kernel) error { reads = k.State().ErasedReads(); return nil })
	if len(reads) != 1 || reads[0].Subject != sub || reads[0].Lineage != "vision-lin" {
		t.Fatalf("erased reads: %+v", reads)
	}
	noCanary(t, dir)
}

// A write stopped after its temporary, before the rename, leaves a store
// that opens whole: the temporary is gone at the next start and every
// logged item still reads. Revert mutant: openFileContent not removing
// temporaries.
func TestATornWriteLeavesAWholeStore(t *testing.T) {
	dir := t.TempDir()
	h := storeKernel(t, dir, "vision")
	c := contentConn(t, h, "vision")
	sub, _ := c.OpenSubject()
	item, err := c.Seal(sub, "wrap-key", []byte("kept"))
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
	store := filepath.Join(dir, "content", "vision")
	torn := strings.Repeat("ab", 32) + itemExt
	if err := privfile.WriteAtomic(store, torn, []byte("sealed bytes"), func(i int) bool { return i == 3 }); !errors.Is(err, privfile.ErrStopped) {
		t.Fatalf("the torn write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store, torn+tmpExt)); err != nil {
		t.Fatalf("no temporary to test with: %v", err)
	}
	h = storeKernel(t, dir, "vision")
	defer h.Close()
	if f := itemFiles(t, dir, "vision"); len(f) != 1 || strings.HasSuffix(f[0], tmpExt) {
		t.Fatalf("after the start the store holds %q", f)
	}
	if got, err := contentConn(t, h, "vision").ReadFor(item, "lin"); err != nil || string(got) != "kept" {
		t.Fatalf("the logged item after a torn write: %q %v", got, err)
	}
}

// Only a content socket seals or reads, and only its own store's items:
// the owner, meter and link sides have no such call, a content socket for
// another uid takes nothing, and another store's item reads as no item.
// None of these refusals logs anything. Revert mutants: readfor without the
// ItemStore check; opensubject or seal on OwnerSide.
func TestOnlyAContentClerkSealsAndReads(t *testing.T) {
	dir := t.TempDir()
	h := storeKernel(t, dir, "vision", "mail")
	defer h.Close()
	b := &box{t: t, h: h}
	vision, mail := contentConn(t, h, "vision"), contentConn(t, h, "mail")
	sub, _ := vision.OpenSubject()
	item, err := mail.Seal(sub, "message", []byte("mail's"))
	if err != nil {
		t.Fatal(err)
	}
	before := b.entries()
	for _, side := range []Side{OwnerSide, MeterSide, LinkSide} {
		conn := serveSide(t, b, side, os.Getuid())
		for _, op := range []string{"opensubject", "seal", "readfor"} {
			if err := conn.Call(op, readForArgs{item, "lin"}, nil); err == nil || !strings.Contains(err.Error(), "no call") {
				t.Errorf("%s on the %s socket: %v", op, side.name, err)
			}
		}
	}
	other := Content{serveSide(t, b, ContentSide("vision"), os.Getuid()+1)}
	if _, err := other.OpenSubject(); err == nil {
		t.Error("a content socket for another uid opened a subject")
	}
	if _, err := vision.ReadFor(item, "lin"); !errors.Is(err, kernel.ErrItem) {
		t.Errorf("vision reading mail's item: %v, want ErrItem", err)
	}
	// Another store's item answers as an unknown hash does, even with a bad
	// lineage, so its existence does not show (#3560 Security finding 1).
	for _, lin := range []string{"", strings.Repeat("l", 129)} {
		_, mine := vision.ReadFor(item, lin)
		_, none := vision.ReadFor(kernel.Hash{9}, lin)
		if fmt.Sprint(mine) != fmt.Sprint(none) {
			t.Errorf("lineage %d bytes: another store's item %v, no item %v", len(lin), mine, none)
		}
	}
	if n := b.entries(); n != before {
		t.Fatalf("refused calls logged %d entries", n-before)
	}
	if got, err := mail.ReadFor(item, "lin"); err != nil || string(got) != "mail's" {
		t.Fatalf("mail reading its own item: %q %v", got, err)
	}
}

// The socket bounds an item, and the kernel's own refusals cross as its
// sentinels: an unknown subject or store, a bad lineage, an unknown item.
func TestContentRefusalsCrossTheSocket(t *testing.T) {
	dir := t.TempDir()
	h := storeKernel(t, dir, "vision")
	defer h.Close()
	c := contentConn(t, h, "vision")
	sub, _ := c.OpenSubject()
	if _, err := c.Seal(sub, "big", make([]byte, MaxItem+1)); !errors.Is(err, ErrArgs) {
		t.Errorf("an item past MaxItem: %v", err)
	}
	if err := c.Call("seal", sealArgs{sub, "big", make([]byte, MaxItem+1)}, nil); !errors.Is(err, ErrArgs) {
		t.Errorf("an item past MaxItem sent anyway: %v", err)
	}
	if _, err := c.Seal(sub, "whole", make([]byte, MaxItem)); err != nil {
		t.Errorf("an item of MaxItem: %v", err)
	}
	if _, err := c.Seal("0123456789abcdef0123456789abcdef", "x", []byte("x")); !errors.Is(err, kernel.ErrSubject) {
		t.Errorf("seal into no subject: %v", err)
	}
	if _, err := c.Seal(sub, "", []byte("x")); !errors.Is(err, kernel.ErrStore) {
		t.Errorf("seal with no class: %v", err)
	}
	item, _ := c.Seal(sub, "x", []byte("x"))
	if _, err := c.ReadFor(item, ""); !errors.Is(err, kernel.ErrLineage) {
		t.Errorf("readfor with no lineage: %v", err)
	}
	if _, err := c.ReadFor(kernel.Hash{1}, "lin"); !errors.Is(err, kernel.ErrItem) {
		t.Errorf("readfor of no item: %v", err)
	}
	// A content socket for a store the kernel never opened seals nothing.
	if _, err := contentConn(t, h, "photos").Seal(sub, "x", []byte("x")); !errors.Is(err, kernel.ErrStore) {
		t.Errorf("seal into an unopened store: %v", err)
	}
}

// A kernel with no KeyDir keeps content closed, over the socket too.
func TestNoKeyTableRefusesSeal(t *testing.T) {
	h, err := OpenKernel(KernelConfig{
		Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7},
		Pub: headPub, Sign: headPriv, Anchors: anchors,
	}, 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	c := contentConn(t, h, "vision")
	if _, err := c.OpenSubject(); !errors.Is(err, kernel.ErrContentClosed) {
		t.Errorf("opensubject: %v, want ErrContentClosed", err)
	}
	if _, err := c.Seal("0123456789abcdef0123456789abcdef", "x", []byte("x")); !errors.Is(err, kernel.ErrContentClosed) {
		t.Errorf("seal: %v, want ErrContentClosed", err)
	}
	if _, err := OpenKernel(KernelConfig{
		Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7},
		Pub: headPub, Sign: headPriv, Anchors: anchors, ContentDir: t.TempDir(),
	}, 1000); err == nil {
		t.Error("content stores opened with no key table")
	}
}

// A store no longer named at start is opened from its directory, so its
// items are still erased. Revert mutant: OpenContentStores opening only
// the names it is given (the erase stays unconfirmed).
func TestAStoreDroppedFromTheConfigIsStillErased(t *testing.T) {
	dir := t.TempDir()
	h := storeKernel(t, dir, "vision")
	c := contentConn(t, h, "vision")
	sub, _ := c.OpenSubject()
	if _, err := c.Seal(sub, "x", []byte(canary)); err != nil {
		t.Fatal(err)
	}
	h.Close()
	h = storeKernel(t, dir)
	defer h.Close()
	conf, err := h.Erase(time.Now().UnixMilli(), sub)
	if err != nil || len(conf.Unconfirmed) != 0 {
		t.Fatalf("erase: %+v %v", conf, err)
	}
	if f := itemFiles(t, dir, "vision"); len(f) != 0 {
		t.Fatalf("the store still holds %q", f)
	}
}

// Store directories open to another uid stop the start, as a loose key
// table does, and a name a store cannot take is refused.
func TestALooseContentStoreStopsTheStart(t *testing.T) {
	for _, loose := range []string{"content", "content/vision"} {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, loose), 0o755); err != nil {
			t.Fatal(err)
		}
		// Only the directory under test is loose (#3560 L3 point 1).
		if loose != "content" {
			if err := os.Chmod(filepath.Join(dir, "content"), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		logPath := filepath.Join(dir, "log")
		if _, err := OpenKernel(KernelConfig{
			Log: logPath, Anchor: &kernel.MemAnchor{}, Key: [32]byte{7}, Pub: headPub, Sign: headPriv, Anchors: anchors,
			KeyDir: filepath.Join(dir, "keys"), ContentDir: filepath.Join(dir, "content"), Stores: []string{"vision"},
		}, 1000); err == nil {
			t.Errorf("a kernel started with %s open to other uids", loose)
		}
	}
	for _, bad := range []string{"", "Vision", "../keys", "a/b", strings.Repeat("a", 33), kernel.KeyTable} {
		if _, _, err := OpenContentStores(filepath.Join(t.TempDir(), "c"), []string{bad}); !errors.Is(err, ErrStoreName) {
			t.Errorf("store %q: %v, want ErrStoreName", bad, err)
		}
	}
}

// The real process never starts without its content directory.
func TestRunKernelNeedsAContentDir(t *testing.T) {
	err := RunKernel(t.Context(), MainConfig{Log: filepath.Join(t.TempDir(), "log"), KeyDir: t.TempDir(), BackupDir: t.TempDir()}, handoff.KernelKeys{Head: headPriv}, &kernel.MemAnchor{})
	if !errors.Is(err, ErrNoContentDir) {
		t.Fatalf("got %v, want ErrNoContentDir", err)
	}
}

// RunKernel serves each content clerk's socket, behind setup like every
// other side's, and keeps its items in ContentDir. Revert mutant: the
// Content loop in RunKernel dropped (the socket is unreachable).
func TestTheKernelServesTheContentSockets(t *testing.T) {
	m := newMainBox(t)
	m.cfg.Content = map[string]Remote{"vision": {Socket: filepath.Join(m.dir, "v.sock"), UID: os.Getuid()}}
	o, stop := m.boot(handoff.SlotTPM, nil)
	defer stop()
	c := Content{Conn{Socket: m.cfg.Content["vision"].Socket, UID: os.Getuid(), Timeout: 10 * time.Second}}
	if _, err := c.OpenSubject(); !errors.Is(err, ErrSetupOnly) {
		t.Fatalf("opensubject before setup: %v, want ErrSetupOnly", err)
	}
	if err := o.Setup(setupAnchors()); err != nil {
		t.Fatal(err)
	}
	sub, err := c.OpenSubject()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Seal(sub, "x", []byte(canary)); err != nil {
		t.Fatal(err)
	}
	des, err := os.ReadDir(filepath.Join(m.cfg.ContentDir, "vision"))
	if err != nil || len(des) != 1 {
		t.Fatalf("the vision store: %v %v", des, err)
	}
	noCanary(t, m.dir)
}

// An item file open to another uid is never read: readfor refuses it
// (#3560 L3 point 1). Revert mutant: Get without privfile.CheckFile.
func TestALooseItemFileIsNotRead(t *testing.T) {
	dir := t.TempDir()
	h := storeKernel(t, dir, "vision")
	defer h.Close()
	c := contentConn(t, h, "vision")
	sub, _ := c.OpenSubject()
	item, err := c.Seal(sub, "x", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "content", "vision", itemName(item)), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := c.ReadFor(item, "lin"); err == nil {
		t.Fatalf("readfor of a loose item file: %q", got)
	}
}

// A store an erase names that is neither configured nor on the drive
// stays unconfirmed, in Unerased (LOG-4 fails closed; #3560 L3 point 2).
func TestAMissingStoreKeepsTheEraseUnconfirmed(t *testing.T) {
	dir := t.TempDir()
	h := storeKernel(t, dir, "vision")
	c := contentConn(t, h, "vision")
	sub, _ := c.OpenSubject()
	if _, err := c.Seal(sub, "x", []byte("x")); err != nil {
		t.Fatal(err)
	}
	h.Close()
	if err := os.RemoveAll(filepath.Join(dir, "content", "vision")); err != nil {
		t.Fatal(err)
	}
	h = storeKernel(t, dir)
	defer h.Close()
	conf, _ := h.Erase(time.Now().UnixMilli(), sub)
	if len(conf.Unconfirmed) != 1 || conf.Unconfirmed[0] != "vision" {
		t.Fatalf("erase with its store missing: %+v", conf)
	}
	var u []kernel.Unerased
	h.With(func(k *kernel.Kernel) error { u = k.State().Unerased(); return nil })
	if len(u) != 1 || u[0].Subject != sub {
		t.Fatalf("unerased: %+v", u)
	}
}
