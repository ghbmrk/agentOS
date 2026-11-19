package backup

// BACKUP-table-fifo-f1 (#6014): OpenRegular refuses what is not a regular
// file without opening it, so a planted FIFO gains no reader and a planted
// device's driver never sees an open.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// REQ: STO-1, REC-1
func TestOpenRegularOpensNothingPlanted(t *testing.T) {
	if oPath != unix.O_PATH {
		t.Fatalf("oPath is %#x, O_PATH is %#x", oPath, unix.O_PATH)
	}
	d := DirTarget{Dir: t.TempDir()}
	id := strings.Repeat("ab", idLen)
	p, err := d.path(id, 1)
	must(t, err)
	must(t, syscall.Mkfifo(p, 0o600))
	// A writer's open of a FIFO waits for a reader: GetTable must not be one.
	opened := make(chan error, 1)
	go func() {
		w, err := os.OpenFile(p, os.O_WRONLY, 0)
		if err == nil {
			w.Close()
		}
		opened <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the writer block in its open
	if _, err := getTableWithin(t, d, id, 1, time.Second); err == nil || !strings.Contains(err.Error(), "named pipe") {
		t.Errorf("GetTable of a FIFO: %v, want refused naming a named pipe", err)
	}
	select {
	case err := <-opened:
		t.Errorf("GetTable opened the FIFO for reading: a writer's open returned (%v)", err)
	case <-time.After(200 * time.Millisecond):
	}
	r, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0) // release the writer, if still waiting
	must(t, err)
	select { // a writer already released has no reader to wait for
	case <-opened:
	case <-time.After(time.Second):
	}
	r.Close()

	q := filepath.Join(d.Dir, "regular")
	must(t, os.WriteFile(q, []byte("table"), 0o600))
	// A link is refused by its fstat, before any open of its target, with
	// the ELOOP O_NOFOLLOW alone gives, naming the link.
	l := filepath.Join(d.Dir, "link")
	must(t, os.Symlink(q, l))
	if _, _, err := OpenRegular(l); !errors.Is(err, syscall.ELOOP) || !strings.Contains(err.Error(), "open "+l+":") {
		t.Errorf("OpenRegular of a link: %v, want ELOOP naming %s", err, l)
	}

	// A regular file is read whole, through a new descriptor of its own, with its size.
	f, st, err := OpenRegular(q)
	must(t, err)
	b := make([]byte, 8)
	if n, err := f.Read(b); err != nil || string(b[:n]) != "table" || st.Size() != 5 {
		t.Errorf("OpenRegular of a regular file read %q, %v; fstat size %d", b[:n], err, st.Size())
	}
	must(t, f.Close())

	if os.Geteuid() != 0 {
		t.Skip("mknod of a character device needs root; the device case is skipped")
	}
	// A character major with no driver (none listed in /proc/devices): an
	// open of it fails (ENXIO), so a refusal naming its type shows none was made.
	dev, err := d.path(id, 2)
	must(t, err)
	major := freeCharMajor(t)
	if err := syscall.Mknod(dev, syscall.S_IFCHR|0o600, major<<8); err != nil {
		t.Skipf("mknod of a character device refused here: %v", err)
	}
	if f, err := os.OpenFile(dev, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
		f.Close()
		t.Fatalf("character device %d,0 opened: it has a driver", major)
	}
	if _, err := getTableWithin(t, d, id, 2, time.Second); err == nil || !strings.Contains(err.Error(), "character device") {
		t.Errorf("GetTable of a driverless character device: %v, want refused by its type, unopened", err)
	}
}

// freeCharMajor is a character major in the dynamic ranges (234-254,
// 384-511) that /proc/devices lists no driver for.
func freeCharMajor(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile("/proc/devices")
	must(t, err)
	chars, _, _ := strings.Cut(string(b), "Block devices:")
	used := map[int]bool{}
	for _, line := range strings.Split(chars, "\n") {
		var m int
		var name string
		if n, _ := fmt.Sscan(line, &m, &name); n == 2 {
			used[m] = true
		}
	}
	for m := 234; m < 512; m++ {
		if (m <= 254 || m >= 384) && !used[m] {
			return m
		}
	}
	t.Fatal("no free character major in /proc/devices")
	return 0
}
