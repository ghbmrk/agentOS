package quota

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/ghbmrk/agentos/broker/quota/quotatest"
)

// REQ: RES-4
//
// Security review 2, finding 3 (SR2-3): a directory tagged with a project
// has a hard limit that the file system enforces on every write beneath
// it, so a guest writing in its layer stops at its budget.

func TestAProjectStopsAtItsHardLimit(t *testing.T) {
	root := quotatest.Dir(t, 64)
	q, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	d := filepath.Join(root, "m1")
	must(t, os.Mkdir(d, 0o700))
	must(t, q.Limit(d, 4242, 1<<20, 100))
	// Files and directories made later inherit the project. The test runs
	// as root, so it writes as the broker's overlay mount does: without
	// CAP_SYS_RESOURCE, which ext4 lets past a hard limit.
	must(t, os.MkdirAll(filepath.Join(d, "upper", "deep"), 0o755))
	werr := Enforced(func() error { return fill(filepath.Join(d, "upper", "deep", "big"), 4<<20) })
	if !errors.Is(werr, syscall.EDQUOT) {
		t.Fatalf("wrote 4 MiB under a 1 MiB quota: %v", werr)
	}
	u, err := q.Usage(4242)
	must(t, err)
	if u.LimitBytes != 1<<20 || u.LimitInodes != 100 || u.Bytes > 1<<20 || u.Bytes == 0 {
		t.Fatalf("usage %+v", u)
	}
	// An untagged sibling is not limited by it.
	must(t, os.WriteFile(filepath.Join(root, "free"), make([]byte, 2<<20), 0o600))
	// Inodes are capped too.
	e := filepath.Join(root, "m2")
	must(t, os.Mkdir(e, 0o700))
	must(t, q.Limit(e, 4243, 0, 10))
	ierr := Enforced(func() (err error) {
		for i := 0; i < 20 && err == nil; i++ {
			err = os.WriteFile(filepath.Join(e, string(rune('a'+i))), nil, 0o600)
		}
		return err
	})
	if !errors.Is(ierr, syscall.EDQUOT) {
		t.Fatalf("made 20 files under a 10-inode quota: %v", ierr)
	}
	// Cleared, the project writes freely.
	must(t, q.Clear(4243))
	must(t, Enforced(func() error { return os.WriteFile(filepath.Join(e, "after-clear"), nil, 0o600) }))
}

// fill writes n bytes to path, synced as it goes so blocks are allocated.
func fill(path string, n int) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 64<<10)
	for i := 0; i < n; i += len(buf) {
		if _, err := f.Write(buf); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
	}
	return nil
}

// TestEnforcedDropsTheOverrideAndRestoresIt: inside Enforced the thread
// lacks CAP_SYS_RESOURCE in its effective set; afterwards it has what it
// had before.
func TestEnforcedDropsTheOverrideAndRestoresIt(t *testing.T) {
	before := effective(t)
	var inside uint64
	must(t, Enforced(func() error { inside = effective(t); return nil }))
	if inside&(1<<24) != 0 {
		t.Fatalf("CAP_SYS_RESOURCE still effective inside Enforced (%#x)", inside)
	}
	if inside != before&^(1<<24) {
		t.Fatalf("Enforced changed more than CAP_SYS_RESOURCE: %#x -> %#x", before, inside)
	}
	if after := effective(t); after != before {
		t.Fatalf("capabilities not restored: %#x -> %#x", before, after)
	}
	want := errors.New("x")
	if err := Enforced(func() error { return want }); err != want {
		t.Fatalf("fn's error lost: %v", err)
	}
}

// effective reads this thread's effective capabilities from /proc.
func effective(t *testing.T) uint64 {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	b, err := os.ReadFile(fmt.Sprintf("/proc/self/task/%d/status", syscall.Gettid()))
	if err != nil {
		t.Skip("no /proc:", err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "CapEff:"); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			must(t, err)
			return n
		}
	}
	t.Fatal("no CapEff")
	return 0
}

func TestProjectZeroIsRefused(t *testing.T) {
	root := quotatest.Dir(t, 16)
	q, err := Open(root)
	must(t, err)
	if err := q.Limit(root, 0, 1<<20, 0); err == nil {
		t.Fatal("tagged a directory with project 0")
	}
}

func TestOpenRefusesAFileSystemWithoutQuotas(t *testing.T) {
	// The test's temporary directory is on a file system mounted without
	// prjquota (tmpfs or the runner's root).
	if _, err := Open(t.TempDir()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Open on a plain file system: %v", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
