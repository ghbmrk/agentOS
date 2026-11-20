package backup

// BACKUP-table-fifo (#3998): the key-table read refuses what a table is
// never, promptly, and reads at most sealedSize(maxTable) bytes; readTable's
// checks and failures are also run directly.

import (
	"bytes"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"
	"time"
)

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
	// size check is still cut at the bound (readTable).
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
	if _, err := readTable(strings.NewReader(strings.Repeat("x", 11)), 0, 10, "t"); err == nil {
		t.Error("readTable returned a reader one byte over its bound")
	}
	if b, err := readTable(strings.NewReader(strings.Repeat("x", 10)), 0, 10, "t"); err != nil || len(b) != 10 {
		t.Errorf("readTable at its bound: %d bytes, %v", len(b), err)
	}
	// A file that keeps growing after its fstat: reading stops at n+1 bytes.
	r := &endless{t: t, limit: 11}
	if _, err := readTable(r, 0, 10, "t"); err == nil || r.n != 11 {
		t.Errorf("readTable of an endless reader: %v after %d bytes, want refused after 11", err, r.n)
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

// REQ: STO-1
func TestReadTableRefusesUnread(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big")
	f, err := os.Create(p)
	must(t, err)
	must(t, f.Truncate(1<<40)) // sparse
	must(t, f.Close())
	f, err = os.Open(p)
	must(t, err)
	defer f.Close()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err = readTable(f, 1<<40, sealedSize(maxTable), p)
	runtime.ReadMemStats(&after)
	if err == nil || !strings.Contains(err.Error(), "1099511627776 bytes, over") {
		t.Errorf("readTable of a 1 TiB file: %v, want refused by its size", err)
	}
	// Reading up to the bound would allocate sealedSize(maxTable) bytes or more.
	if got := after.TotalAlloc - before.TotalAlloc; got > 1<<20 {
		t.Errorf("readTable of a 1 TiB file allocated %d bytes: it read before refusing", got)
	}
}

// REQ: STO-1
func TestReadTableReportsFailures(t *testing.T) {
	p := filepath.Join(t.TempDir(), "table")
	must(t, os.WriteFile(p, []byte("sealed"), 0o600))

	// A regular file whose read fails: opened for writing only.
	w, err := os.OpenFile(p, os.O_WRONLY, 0)
	must(t, err)
	defer w.Close()
	if b, err := readTable(w, 6, 10, p); err == nil || !strings.Contains(err.Error(), p) {
		t.Errorf("readTable of an unreadable file: %q, %v; want its read error, naming %s", b, err, p)
	}

	boom := errors.New("boom")
	if b, err := readTable(iotest.ErrReader(boom), 0, 10, "t"); !errors.Is(err, boom) {
		t.Errorf("readTable of a failing reader: %q, %v; want %v", b, err, boom)
	}
}

// REQ: STO-1
func TestTypeNameNamesEachType(t *testing.T) {
	for m, want := range map[fs.FileMode]string{
		fs.ModeNamedPipe:                  "named pipe",
		fs.ModeSocket:                     "socket",
		fs.ModeDevice | fs.ModeCharDevice: "character device",
		fs.ModeDevice:                     "block device",
		fs.ModeDir:                        "directory",
		fs.ModeIrregular:                  "non-regular file",
	} {
		if got := typeName(m); got != want {
			t.Errorf("typeName(%v) = %q, want %q", m, got, want)
		}
	}
}
