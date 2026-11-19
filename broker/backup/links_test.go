package backup

// A link planted at a file this package reads is refused, not followed
// (REV-CHK-links, #3945).

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// plantLink makes p a link to a real file holding b, as another uid that could
// write p's directory would.
func plantLink(t *testing.T, p string, b []byte) {
	t.Helper()
	real := p + ".real"
	if err := os.WriteFile(real, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, p); err != nil {
		t.Fatal(err)
	}
}

func TestPlantedLinksAreRefused(t *testing.T) {
	dir := t.TempDir()
	d := DirTarget{Dir: dir}
	id := "00112233445566778899aabbccddeeff"
	p, err := d.path(id, 1)
	if err != nil {
		t.Fatal(err)
	}
	plantLink(t, p, []byte("table"))
	if _, err := d.GetTable(id, 1); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("GetTable of a linked table: %v, want ELOOP", err)
	}
	if err := d.PutTable(id, 1, []byte("new")); !errors.Is(err, ErrExists) {
		t.Fatalf("PutTable over a planted name: %v, want ErrExists", err)
	}
	link := filepath.Join(t.TempDir(), "dir")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := (DirTarget{Dir: link}).DeleteTable(id, 1); !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("a target directory that is a link: %v, want ENOTDIR from its sync (O_DIRECTORY|O_NOFOLLOW)", err)
	}
}

// REQ: BAK-1
// MUT-backup-names (#5036): DirTarget refuses an id that is not a backup
// id on every call, reports a directory it cannot write, a missing
// generation and a delete that fails, leaves no temporary file, and closes
// every file it opens.
func TestDirTargetReportsEachFailure(t *testing.T) {
	d := DirTarget{Dir: t.TempDir()}
	id := strings.Repeat("ab", idLen)
	for _, bad := range []string{"../" + id[3:], "zz"} {
		errs := map[string]error{"put": d.PutTable(bad, 1, []byte("t")), "delete": d.DeleteTable(bad, 1)}
		_, errs["get"] = d.GetTable(bad, 1)
		_, errs["tables"] = d.Tables(bad)
		for op, err := range errs {
			if err == nil || !strings.Contains(err.Error(), "is not a backup id") {
				t.Errorf("%s %q: %v, want the id refused", op, bad, err)
			}
		}
	}
	if des, _ := os.ReadDir(filepath.Dir(d.Dir)); len(des) != 1 {
		t.Errorf("a refused id wrote beside the directory: %d entries", len(des))
	}

	must(t, d.PutTable(id, 1, []byte("t1")))
	if des, _ := os.ReadDir(d.Dir); len(des) != 1 || des[0].Name() != id+tableExt+"1" {
		t.Errorf("after a put the directory holds %v, want only the table", des)
	}
	if _, err := d.GetTable(id, 2); !errors.Is(err, ErrNoTable) {
		t.Errorf("a missing generation: %v, want ErrNoTable", err)
	}
	if err := (DirTarget{Dir: filepath.Join(d.Dir, "missing")}).PutTable(id, 1, []byte("t")); err == nil {
		t.Error("a put into a missing directory succeeded")
	}
	full := filepath.Join(d.Dir, id+tableExt+"3")
	must(t, os.Mkdir(full, 0o700))
	must(t, os.WriteFile(filepath.Join(full, "f"), nil, 0o600))
	if err := d.DeleteTable(id, 3); err == nil {
		t.Error("a delete that fails was reported done")
	}

	fds := func() int {
		des, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skip("no /proc/self/fd:", err)
		}
		return len(des)
	}
	before := fds()
	for g := uint64(10); g < 74; g++ {
		must(t, d.PutTable(id, g, []byte("t")))
		_, err := d.GetTable(id, g)
		must(t, err)
		must(t, d.DeleteTable(id, g))
	}
	if after := fds(); after-before > 16 {
		t.Errorf("%d files left open after 64 put, get and delete rounds", after-before)
	}
}

// BACKUP-table-fifo (#3998): the target directory is the owner's choice and
// the read runs as root, so a name there may be a FIFO, a socket, a device or
// an oversized file planted by another uid. Each is refused, promptly.

// getTableWithin runs GetTable and fails the test if it does not return in d.
func getTableWithin(t *testing.T, tg DirTarget, id string, gen uint64, d time.Duration) ([]byte, error) {
	t.Helper()
	type res struct {
		b   []byte
		err error
	}
	c := make(chan res, 1)
	go func() {
		b, err := tg.GetTable(id, gen)
		c <- res{b, err}
	}()
	select {
	case r := <-c:
		return r.b, r.err
	case <-time.After(d):
		t.Fatalf("GetTable did not return within %v", d)
		return nil, nil
	}
}

// REQ: STO-1
func TestGetTableRefusesFIFO(t *testing.T) {
	d := DirTarget{Dir: t.TempDir()}
	id := strings.Repeat("ab", idLen)
	p, err := d.path(id, 1)
	must(t, err)
	must(t, syscall.Mkfifo(p, 0o600))
	_, err = getTableWithin(t, d, id, 1, time.Second)
	if err == nil || !strings.Contains(err.Error(), "named pipe") {
		t.Fatalf("GetTable of a FIFO: %v, want refused naming a named pipe", err)
	}
}

// REQ: STO-1
func TestGetTableRefusesDeviceAndSocket(t *testing.T) {
	d := DirTarget{Dir: t.TempDir()}
	id := strings.Repeat("ab", idLen)
	p, err := d.path(id, 1)
	must(t, err)
	l, err := net.Listen("unix", p)
	must(t, err)
	defer l.Close()
	if _, err := getTableWithin(t, d, id, 1, time.Second); err == nil || !strings.Contains(err.Error(), "socket") {
		t.Errorf("GetTable of a socket: %v, want refused naming a socket", err)
	}

	must(t, os.Mkdir(filepath.Join(d.Dir, id+tableExt+"2"), 0o700))
	if _, err := getTableWithin(t, d, id, 2, time.Second); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Errorf("GetTable of a directory: %v, want refused naming a directory", err)
	}

	if os.Geteuid() != 0 {
		t.Skip("mknod of a character device needs root; the device case is skipped")
	}
	dev, err := d.path(id, 3)
	must(t, err)
	if err := syscall.Mknod(dev, syscall.S_IFCHR|0o600, 1<<8|3); err != nil {
		t.Skipf("mknod of a character device (/dev/null's 1,3) refused here: %v", err)
	}
	if _, err := getTableWithin(t, d, id, 3, time.Second); err == nil || !strings.Contains(err.Error(), "device") {
		t.Errorf("GetTable of a character device: %v, want refused naming a device", err)
	}
}

// countWriter counts bytes and keeps none.
type countWriter int64

func (c *countWriter) Write(p []byte) (int, error) { *c += countWriter(len(p)); return len(p), nil }

// REQ: STO-1
func TestGetTableBoundsRead(t *testing.T) {
	// The bound is the largest table UnwrapTable accepts, sealed.
	var n countWriter
	w, err := sealTo(&n, recipient(t, bytes.Repeat([]byte{7}, minRK)), header{kind: KindKeyTable})
	must(t, err)
	_, err = w.Write(make([]byte, maxTable))
	must(t, err)
	must(t, w.Close())
	maxSealedTable := sealedSize(maxTable)
	if int64(n) != maxSealedTable {
		t.Fatalf("a %d-byte table seals to %d bytes, sealedSize(maxTable) is %d", maxTable, n, maxSealedTable)
	}

	d := DirTarget{Dir: t.TempDir()}
	id := strings.Repeat("ab", idLen)
	for gen, size := range map[uint64]int64{1: maxSealedTable + 1, 2: 1 << 40} {
		p, err := d.path(id, gen)
		must(t, err)
		f, err := os.Create(p)
		must(t, err)
		must(t, f.Truncate(size)) // sparse: reading it whole would allocate size bytes
		must(t, f.Close())
		if _, err := getTableWithin(t, d, id, gen, 5*time.Second); err == nil || !strings.Contains(err.Error(), "over") {
			t.Errorf("GetTable of a %d-byte file: %v, want refused as over the bound", size, err)
		}
	}

	// A file at the bound is read whole; one that grows past it after the
	// size check is still cut at the bound (readBounded).
	p, err := d.path(id, 3)
	must(t, err)
	f, err := os.Create(p)
	must(t, err)
	must(t, f.Truncate(maxSealedTable))
	must(t, f.Close())
	b, err := getTableWithin(t, d, id, 3, 5*time.Second)
	if err != nil || int64(len(b)) != maxSealedTable {
		t.Errorf("GetTable of a file at the bound: %d bytes, %v; want it read whole", len(b), err)
	}
	if _, err := readBounded(strings.NewReader(strings.Repeat("x", 11)), 10); err == nil {
		t.Error("readBounded returned a reader one byte over its bound")
	}
	if b, err := readBounded(strings.NewReader(strings.Repeat("x", 10)), 10); err != nil || len(b) != 10 {
		t.Errorf("readBounded at its bound: %d bytes, %v", len(b), err)
	}
	// A file that keeps growing after its fstat: reading stops at n+1 bytes.
	r := &endless{t: t, limit: 11}
	if _, err := readBounded(r, 10); err == nil || r.n != 11 {
		t.Errorf("readBounded of an endless reader: %v after %d bytes, want refused after 11", err, r.n)
	}
}

// endless is a reader that never ends and fails the test once read past limit.
type endless struct {
	t        *testing.T
	n, limit int
}

func (e *endless) Read(p []byte) (int, error) {
	if e.n+len(p) > e.limit {
		e.t.Fatalf("read past %d bytes: the bound is not applied while reading", e.limit)
	}
	e.n += len(p)
	return len(p), nil
}
