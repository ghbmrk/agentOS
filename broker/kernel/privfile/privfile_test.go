package privfile

// REQ: KRN-2

import (
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// WriteAtomic refuses a directory another uid can write, since that uid
// could swap the closed name.tmp for a link that the rename installs at name
// (#3954); a directory only this uid can write passes, readable or not.
func TestWriteAtomicRefusesADirOtherUidsCanWrite(t *testing.T) {
	for _, mode := range []os.FileMode{0o770, 0o720, 0o702, 0o777, 0o777 | os.ModeSticky} {
		dir := t.TempDir()
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := WriteAtomic(dir, "f", []byte("canary"), nil); err == nil {
			t.Errorf("a %v directory was written", mode)
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Errorf("a refused %v directory holds %d entries", mode, len(ents))
		}
	}
	for _, mode := range []os.FileMode{0o700, 0o750, 0o755} {
		dir := t.TempDir()
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := WriteAtomic(dir, "f", []byte("canary"), nil); err != nil {
			t.Errorf("a %v directory: %v", mode, err)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "f")); string(b) != "canary" {
			t.Errorf("a %v directory holds %q", mode, b)
		}
	}
}

// A directory owned by another uid is refused: that uid can chmod it open.
func TestWriteAtomicRefusesADirOfAnotherUid(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown to another uid needs root")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 12345, 12345); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(dir, "f", []byte("canary"), nil); err == nil {
		t.Fatal("a directory of uid 12345 was written")
	}
}

// A link planted at dir is not followed, by WriteAtomic or by SyncDir.
func TestWriteAtomicRefusesALinkedDir(t *testing.T) {
	target, link := t.TempDir(), filepath.Join(t.TempDir(), "d")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(link, "f", []byte("canary"), nil); err == nil {
		t.Fatal("WriteAtomic followed a link at dir")
	}
	if ents, _ := os.ReadDir(target); len(ents) != 0 {
		t.Fatalf("the link's target holds %d entries", len(ents))
	}
	if err := SyncDir(link); err == nil {
		t.Fatal("SyncDir followed a link at dir")
	}
}

// WriteAtomic works in the directory it opened: dir swapped for a link
// after name.tmp is closed (as another uid that can write dir's parent
// could) still gets the rename and the sync, and the link's target gets
// nothing.
func TestWriteAtomicStaysInTheDirItOpened(t *testing.T) {
	parent, decoy := t.TempDir(), t.TempDir()
	dir, moved := filepath.Join(parent, "d"), filepath.Join(parent, "moved")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nonexistent-canary", filepath.Join(decoy, "f.tmp")); err != nil {
		t.Fatal(err)
	}
	swap := func(i int) bool {
		if i == 3 { // after Close, before Rename
			if err := os.Rename(dir, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(decoy, dir); err != nil {
				t.Fatal(err)
			}
		}
		return false
	}
	err := WriteAtomic(dir, "f", []byte("canary"), swap)
	if err != nil {
		t.Errorf("a write whose dir was swapped mid-way: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(moved, "f")); string(b) != "canary" {
		t.Errorf("the opened directory holds %q", b)
	}
	if _, err := os.Lstat(filepath.Join(decoy, "f")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the decoy got f: %v", err)
	}
}

// Neither WriteAtomic nor SyncDir hangs on a FIFO at dir or follows a link
// to one (#3954 comment; #3991 Security 1).
func TestSyncDirRefusesAFIFO(t *testing.T) {
	d := t.TempDir()
	fifo, link := filepath.Join(d, "fifo"), filepath.Join(d, "link")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	calls := map[string]func(string) error{
		"SyncDir":     SyncDir,
		"WriteAtomic": func(dir string) error { return WriteAtomic(dir, "f", []byte("canary"), nil) },
	}
	for name, call := range calls {
		for _, p := range []string{fifo, link} {
			done := make(chan error, 1)
			go func() { done <- call(p) }()
			select {
			case err := <-done:
				if err == nil {
					t.Errorf("%s(%s) took a FIFO for a directory", name, filepath.Base(p))
				}
			case <-time.After(5 * time.Second):
				t.Errorf("%s(%s) hangs on a FIFO", name, filepath.Base(p))
			}
		}
	}
}

// A name.tmp left by a write that stopped before its rename is replaced, not
// taken for a race: the next write removes it before its O_EXCL create.
func TestWriteAtomicReplacesAStaleTmp(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.tmp"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(dir, "f", []byte("canary"), nil); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "f")); err != nil || string(b) != "canary" {
		t.Fatalf("f = %q, %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "f.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("f.tmp left behind: %v", err)
	}
}

// A failed directory sync after the rename is ErrUnsynced, never success:
// the new form is in place but may not survive a crash (#2742 item 7).
func TestWriteAtomicReportsAFailedDirSync(t *testing.T) {
	sync := SyncFile
	t.Cleanup(func() { SyncFile = sync })
	dir, synced := t.TempDir(), ""
	SyncFile = func(d *os.File) error { synced = d.Name(); return errors.New("synthetic sync failure") }
	if err := WriteAtomic(dir, "f", []byte("canary"), nil); !errors.Is(err, ErrUnsynced) {
		t.Fatalf("WriteAtomic = %v, want ErrUnsynced", err)
	}
	if synced != dir {
		t.Errorf("synced %q, want the directory %q", synced, dir)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "f")); err != nil || string(b) != "canary" {
		t.Errorf("f = %q, %v", b, err)
	}
}

// A missing directory is reported as missing, from the open itself.
func TestMissingDirIsNotExist(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gone")
	if err := WriteAtomic(missing, "f", []byte("canary"), nil); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("WriteAtomic = %v, want ErrNotExist", err)
	}
	if err := SyncDir(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("SyncDir = %v, want ErrNotExist", err)
	}
}

// WriteAtomic closes every descriptor it opens, on success and on a refused
// directory: root runs it for every state write, so a leak would run the
// process out of descriptors.
func TestWriteAtomicLeaksNoDescriptor(t *testing.T) {
	open := func() int {
		ents, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skip("no /proc/self/fd")
		}
		return len(ents)
	}
	ok, shared := t.TempDir(), t.TempDir()
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	before := open()
	for i := 0; i < 8; i++ {
		if err := WriteAtomic(ok, "f", []byte("canary"), nil); err != nil {
			t.Fatal(err)
		}
		if err := WriteAtomic(shared, "f", []byte("canary"), nil); err == nil {
			t.Fatal("a 0777 directory was written")
		}
	}
	if after := open(); after != before {
		t.Errorf("%d descriptors open after 16 writes, %d before", after, before)
	}
}

// A write that fails or is stopped before its rename closes name.tmp too:
// the write step fails here with EFBIG, under a one-byte file size limit
// whose SIGXFSZ is ignored, and the stop hook stops after each step that
// leaves the file open.
func TestWriteAtomicClosesTheTmpOnAFailedOrStoppedStep(t *testing.T) {
	dir := t.TempDir()
	before := openFDs(t)
	for i := 0; i < 3; i++ {
		stopAt := i
		if err := WriteAtomic(dir, "f", []byte("canary"), func(i int) bool { return i == stopAt }); !errors.Is(err, ErrStopped) {
			t.Fatalf("stop after step %d: %v", stopAt, err)
		}
	}
	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &lim); err != nil {
		t.Fatal(err)
	}
	low := lim
	low.Cur = 1
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &low); err != nil {
		t.Skip(err)
	}
	var failed []error
	for i := 0; i < 4; i++ {
		failed = append(failed, WriteAtomic(dir, "g", []byte("canary"), nil))
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lim); err != nil {
		t.Fatal(err)
	}
	for _, err := range failed {
		if !errors.Is(err, syscall.EFBIG) {
			t.Fatalf("WriteAtomic under a 1-byte limit = %v, want EFBIG", err)
		}
	}
	if after := openFDs(t); after != before {
		t.Errorf("%d descriptors open after 7 failed or stopped writes, %d before", after, before)
	}
}

func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	return len(ents)
}
