package update

// REQ: UPD-2

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// openFDs counts this process's open descriptors.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	return len(ents)
}

// DirSource.Open leaks no descriptor, neither the drive's directory handle
// nor a refused non-regular file's: a check that reads a drive many times
// would otherwise run out of descriptors.
func TestDirSourceOpenLeaksNoDescriptor(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "metadata", "snapshot.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "metadata", "root.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	const n = 64
	for _, tc := range []struct {
		name   string
		wantOK bool
	}{{"metadata/root.json", true}, {"metadata/snapshot.json", false}} {
		before := openFDs(t)
		for i := 0; i < n; i++ {
			rc, err := DirSource(root).Open(tc.name)
			if (err == nil) != tc.wantOK {
				t.Fatalf("Open(%q): %v", tc.name, err)
			}
			if err == nil {
				rc.Close()
			}
		}
		if grew := openFDs(t) - before; grew > n/2 {
			t.Errorf("%d opens of %q left %d more descriptors open", n, tc.name, grew)
		}
	}
}

// A drive root that cannot be opened is refused with the open's own error,
// before openat2 runs on a descriptor that does not exist.
func TestDirSourceMissingRootNamesTheOpen(t *testing.T) {
	_, err := DirSource(filepath.Join(t.TempDir(), "gone")).Open("metadata/root.json")
	var pe *os.PathError
	if !errors.Is(err, os.ErrNotExist) || !errors.As(err, &pe) || pe.Op != "open" {
		t.Fatalf("Open under a missing root: %v, want the root's open to fail with ENOENT", err)
	}
}

// openat2's EAGAIN (a rename raced the walk) and EINTR are retried a bounded
// number of times; any other error is returned at once.
func TestOpenBeneathRetriesEAGAIN(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "metadata"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "metadata", "root.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	real := openat2
	t.Cleanup(func() { openat2 = real })
	calls := 0
	failing := func(fails int, errno error) func(int, string, *unix.OpenHow) (int, error) {
		calls = 0
		return func(d int, name string, how *unix.OpenHow) (int, error) {
			calls++
			if calls <= fails {
				return -1, errno
			}
			return real(d, name, how)
		}
	}

	for _, errno := range []error{unix.EAGAIN, unix.EINTR} {
		openat2 = failing(3, errno)
		rc, err := DirSource(root).Open("metadata/root.json")
		if err != nil {
			t.Fatalf("Open after 3 %v: %v, want retried", errno, err)
		}
		rc.Close()
		if calls != 4 {
			t.Errorf("%v: %d openat2 calls, want 4", errno, calls)
		}
	}

	openat2 = failing(100, unix.EAGAIN)
	if _, err := DirSource(root).Open("metadata/root.json"); !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("Open under endless EAGAIN: %v, want EAGAIN", err)
	}
	if calls != 9 {
		t.Errorf("endless EAGAIN: %d openat2 calls, want 9 (bounded)", calls)
	}

	openat2 = failing(1, unix.EACCES)
	if _, err := DirSource(root).Open("metadata/root.json"); !errors.Is(err, syscall.EACCES) || calls != 1 {
		t.Fatalf("Open under EACCES: %v after %d calls, want EACCES at once", err, calls)
	}
}

// InitStore names a path component that is a file by the pre-check's own
// lstat error, and keeps the cleaned path as the store's directory.
func TestInitStorePreCheckAndCleanPath(t *testing.T) {
	f := newFixture(t)
	root, err := readFile(f.store.p("root.json"))
	f.must(err)
	base := t.TempDir()

	file := filepath.Join(base, "file")
	f.must(os.WriteFile(file, nil, 0o600))
	_, err = InitStore(filepath.Join(file, "box"), root, 1)
	if !errors.Is(err, ErrUnsafeStore) || !errors.Is(err, syscall.ENOTDIR) || !strings.Contains(err.Error(), "lstat") {
		t.Fatalf("InitStore through a file: %v, want the pre-check's lstat ENOTDIR", err)
	}

	f.must(os.Mkdir(filepath.Join(base, "a"), 0o700))
	st, err := InitStore(base+"/a/./b/../box/", root, 1)
	f.must(err)
	if want := filepath.Join(base, "a", "box"); st.Dir != want {
		t.Fatalf("store dir %q, want %q", st.Dir, want)
	}
}
