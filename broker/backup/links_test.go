package backup

// A link planted at a file this package reads is refused, not followed
// (REV-CHK-links, #3945).

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
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
