package proc

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/backup"
)

// REQ: STO-1, REC-1
// BACKUP-table-fifo-f1 (#6014): the content read-back reads only a regular
// file, so a FIFO planted at the content name cannot stall the run, and at
// most one byte past the size written, so a grown file is unverified.
func TestReadBackRefusesPlantedContent(t *testing.T) {
	dir := t.TempDir()
	tg := backup.DirTarget{Dir: dir}
	id := strings.Repeat("cd", 16)
	table, content := []byte("table"), []byte("content")
	if err := tg.PutTable(id, 1, table); err != nil {
		t.Fatal(err)
	}
	rec := backup.Record{BackupID: id, Generation: 1, TableSum: sumHex(table), ContentSum: sumHex(content)}
	p := filepath.Join(dir, id+contentExt)
	within := func(size int64) bool {
		t.Helper()
		c := make(chan bool, 1)
		go func() { c <- readBack(tg, dir, rec, size) }()
		select {
		case ok := <-c:
			return ok
		case <-time.After(5 * time.Second):
			t.Fatal("readBack did not return within 5s")
			return false
		}
	}
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if !within(int64(len(content))) {
		t.Fatal("readBack of the content as written: unverified")
	}
	// It closes the content it read.
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		if l, _ := os.Readlink(filepath.Join("/proc/self/fd", fd.Name())); l == p {
			t.Errorf("readBack left %s open (fd %s)", p, fd.Name())
		}
	}
	// One byte more than was written: the sum read is not the content's.
	if err := os.WriteFile(p, append(content, 'x'), 0o600); err != nil {
		t.Fatal(err)
	}
	if within(int64(len(content))) {
		t.Error("readBack of content one byte longer than written: verified")
	}
	// A 1 TiB sparse file is read no further than the size written.
	if err := os.Truncate(p, 1<<40); err != nil {
		t.Fatal(err)
	}
	if within(int64(len(content))) {
		t.Error("readBack of a 1 TiB content file: verified")
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if within(int64(len(content))) {
		t.Error("readBack of a FIFO at the content name: verified")
	}
}
