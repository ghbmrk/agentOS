package backup

// readTable's checks on the descriptor readFile opened, and readBounded's
// own failure (BACKUP-table-fifo, #3998), each run directly.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
)

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
	_, err = readTable(f, p)
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

	closed, err := os.Open(p)
	must(t, err)
	must(t, closed.Close())
	if b, err := readTable(closed, p); err == nil {
		t.Errorf("readTable of a closed file: %q, nil; want its fstat error", b)
	}

	// A regular file whose read fails: opened for writing only.
	w, err := os.OpenFile(p, os.O_WRONLY, 0)
	must(t, err)
	defer w.Close()
	if b, err := readTable(w, p); err == nil || !strings.Contains(err.Error(), p) {
		t.Errorf("readTable of an unreadable file: %q, %v; want its read error, naming %s", b, err, p)
	}

	boom := errors.New("boom")
	if b, err := readBounded(iotest.ErrReader(boom), 10); !errors.Is(err, boom) {
		t.Errorf("readBounded of a failing reader: %q, %v; want %v", b, err, boom)
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
