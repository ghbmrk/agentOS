//go:build linux

package kernelsock

// REQ: CLK-1, KRN-7

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
)

// testOwnerUID stands in for agentos-owner: a uid no test process runs as.
const testOwnerUID = 65534

func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: agentosd calls the kernel as the owner side's uid")
	}
}

// runDir stands in for /run/agentos-kernel (0711), in a directory the
// owner side's uid can search: t.TempDir's parent is root's alone.
func runDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kernel")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o711); err != nil {
		t.Fatal(err)
	}
	return dir
}

// setupKernel serves a real setup-only kernel's OwnerSide, as the kernel's
// process does, to the owner side's uid alone; this process stands in for
// the kernel's uid.
func setupKernel(t *testing.T) Owner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	h, err := proc.OpenKernel(proc.KernelConfig{
		Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7},
		Pub: pub, Sign: priv,
	}, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	path := filepath.Join(runDir(t), "owner.sock")
	ln, err := proc.ListenKernel(path, testOwnerUID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go proc.ServeKernel(ln, h, proc.OwnerSide, func() int64 { return time.Now().UnixMilli() })
	return Owner{Socket: path, UID: os.Getuid(), As: testOwnerUID}
}

// The kernel's own owner socket answers this client as the owner side: a
// setup-only kernel says setup is open, and its refusal of another call
// comes back in its own words. A call made as root, the broker's own uid,
// is refused (MIG-4-run-start-a).
func TestSpeaksTheKernelsWire(t *testing.T) {
	needRoot(t)
	o := setupKernel(t)
	ctx := context.Background()
	open, err := o.SetupOpen(ctx)
	if err != nil || !open {
		t.Fatalf("setup open %v, %v", open, err)
	}
	var r Refused
	if err := o.call(ctx, "stop", nil, nil); !errors.As(err, &r) || r.Text != proc.ErrSetupOnly.Error() {
		t.Fatalf("stop before setup: %v", err)
	}
	root := o
	root.As = 0
	if _, err := root.SetupOpen(ctx); err == nil {
		t.Fatal("the kernel's owner socket answered the broker's own uid")
	}
}

// A socket no kernel serves, or one served under another uid than the
// kernel's, is never sent the call.
func TestOnlyTheKernelsUIDIsCalled(t *testing.T) {
	needRoot(t)
	o := setupKernel(t)
	o.UID = testOwnerUID + 1
	if _, err := o.SetupOpen(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("a socket under another uid: %v", err)
	}
	o.Socket = filepath.Join(runDir(t), "none.sock")
	if _, err := o.SetupOpen(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("no kernel: %v", err)
	}
}

// Only the calling thread takes the owner side's uid, as its effective uid
// alone, and takes root back before the runtime has it again: after many
// calls, every thread of the broker is root, so no other goroutine ever
// runs as the owner side (MIG-4-run-start-a).
func TestNoThreadKeepsTheOwnerSidesUID(t *testing.T) {
	needRoot(t)
	o := setupKernel(t)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := o.SetupOpen(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if os.Geteuid() != 0 {
		t.Fatal("the process's own euid changed")
	}
	if left := threadsNotRoot(t); len(left) != 0 {
		t.Fatalf("threads still under another uid: %v", left)
	}
}

// threadsNotRoot lists this process's threads whose real, effective or
// saved uid is not 0.
func threadsNotRoot(t *testing.T) []string {
	t.Helper()
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, task := range tasks {
		f, err := os.Open(filepath.Join("/proc/self/task", task.Name(), "status"))
		if err != nil {
			continue // the thread ended
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if fs := strings.Fields(sc.Text()); len(fs) >= 4 && fs[0] == "Uid:" && (fs[1] != "0" || fs[2] != "0" || fs[3] != "0") {
				out = append(out, task.Name()+" "+sc.Text())
			}
		}
		f.Close()
	}
	return out
}

// A uid this process cannot take fails the call before anything is sent.
func TestAnOwnerUIDThatCannotBeTakenSendsNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can take any uid")
	}
	called := false
	err := asUID(os.Geteuid()+1, func() error { called = true; return nil })
	if !errors.Is(err, errNoSeat) || called {
		t.Fatalf("a call ran without the owner side's uid: %v", err)
	}
}
