package quota

import (
	"errors"
	"os"
	"path/filepath"
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

// eachFS runs f on every file system with project quotas this host can
// mount, as subtests; with none, the test is skipped (or fails in CI).
func eachFS(t *testing.T, mb int64, f func(t *testing.T, root string)) {
	var why []string
	ran := false
	for _, k := range quotatest.Kinds {
		t.Run(k, func(t *testing.T) {
			root, err := quotatest.On(t, k, mb)
			if err != nil {
				why = append(why, err.Error())
				t.Skip(err)
			}
			ran = true
			f(t, root)
		})
	}
	if !ran {
		quotatest.Unavailable(t, strings.Join(why, "; "))
	}
}

func TestAProjectStopsAtItsHardLimit(t *testing.T) { eachFS(t, 64, projectStopsAtItsHardLimit) }

func projectStopsAtItsHardLimit(t *testing.T, root string) {
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

// TestTagTakesInATreeWrittenUntagged: a tree made before its directory was
// tagged (copied, restored, or written with quotas off) is project 0 all
// through; Tag brings every directory and file into the project, so the
// tree's use counts and nothing written in it later escapes the limit.
func TestTagTakesInATreeWrittenUntagged(t *testing.T) {
	eachFS(t, 64, func(t *testing.T, root string) {
		q, err := Open(root)
		must(t, err)
		d := filepath.Join(root, "m1")
		must(t, os.MkdirAll(filepath.Join(d, "upper", "deep"), 0o755))
		must(t, os.WriteFile(filepath.Join(d, "upper", "deep", "old"), make([]byte, 512<<10), 0o644))
		must(t, os.Symlink("deep/old", filepath.Join(d, "upper", "link")))
		must(t, q.Limit(d, 4250, 1<<20, 100))
		// Only d is tagged: its old subdirectory still is not.
		if p, err := Project(filepath.Join(d, "upper", "deep")); err != nil || p != 0 {
			t.Fatalf("existing subdirectory tagged %d (%v) by Limit alone", p, err)
		}
		must(t, q.Tag(d, 4250))
		for _, rel := range []string{"upper", "upper/deep", "upper/deep/old"} {
			if p, err := Project(filepath.Join(d, rel)); err != nil || p != 4250 {
				t.Fatalf("%s: project %d (%v)", rel, p, err)
			}
		}
		u, err := q.Usage(4250)
		must(t, err)
		if u.Bytes < 512<<10 {
			t.Fatalf("tagged tree's use not counted: %+v", u)
		}
		werr := Enforced(func() error { return fill(filepath.Join(d, "upper", "deep", "new"), 2<<20) })
		if !errors.Is(werr, syscall.EDQUOT) {
			t.Fatalf("wrote 2 MiB more under a 1 MiB quota holding 512 KiB: %v", werr)
		}
		if err := q.Tag(d, 0); err == nil {
			t.Fatal("tagged a tree with project 0")
		}
	})
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

func TestProjectZeroIsRefused(t *testing.T) {
	root := quotatest.Dir(t, 64)
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
