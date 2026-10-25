package daemon

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
)

// REQ: CH-2, KRN-7

// fakeKernel is the kernel's owner seam: running, waiting for setup
// (every call but setupinfo refused), or not answering.
type fakeKernel struct {
	mu                    sync.Mutex
	stopped, setup, down  bool
	stops, resumes, reads int
}

var (
	errDown  = errors.New("unreachable")
	errSetup = errors.New("refused: waiting for setup")
)

func (k *fakeKernel) refuse() error {
	switch {
	case k.down:
		return errDown
	case k.setup:
		return errSetup
	}
	return nil
}

func (k *fakeKernel) Stop(context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.refuse(); err != nil {
		return err
	}
	k.stops++
	k.stopped = true
	return nil
}

func (k *fakeKernel) Resume(context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.refuse(); err != nil {
		return err
	}
	k.resumes++
	k.stopped = false
	return nil
}

func (k *fakeKernel) Stopped(context.Context) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.reads++
	return k.stopped, k.refuse()
}

func (k *fakeKernel) SetupOpen(context.Context) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.down {
		return false, errDown
	}
	return k.setup, nil
}

func (k *fakeKernel) set(f func(*fakeKernel)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f(k)
}

func withKernel(t *testing.T, k *fakeKernel) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	startWith(t, dir, func(c *Config) { c.Kernel = k })
	return dir
}

func resume(t *testing.T, dir string) string {
	t.Helper()
	r := text(t, dir, owner, "RESUME")
	if len(r) != 1 || !strings.Contains(r[0], "RESUME ") {
		t.Fatalf("RESUME: %q", r)
	}
	code := strings.Fields(strings.SplitN(r[0], "RESUME ", 2)[1])[0]
	return text(t, dir, owner, "RESUME "+code)[0]
}

// The owner's STOP reaches the kernel as well as the journal, and STATUS
// and RESUME read and lift both (#2783).
func TestSTOPReachesTheKernel(t *testing.T) {
	k := &fakeKernel{}
	dir := withKernel(t, k)
	if r := text(t, dir, owner, "STOP"); !strings.HasPrefix(r[0], "Stopped.") {
		t.Fatalf("STOP: %q", r)
	}
	if !k.stopped || k.stops != 1 {
		t.Fatalf("the kernel was not stopped: %+v", k)
	}
	if r := resume(t, dir); !strings.HasPrefix(r, "Resumed.") {
		t.Fatalf("RESUME: %q", r)
	}
	if k.stopped || k.resumes != 1 {
		t.Fatalf("the kernel was not resumed: %+v", k)
	}
	// A STOP on the kernel alone (another owner surface's) is STATUS's
	// stop, and RESUME lifts it.
	k.set(func(k *fakeKernel) { k.stopped = true })
	if r := text(t, dir, owner, "STATUS"); !strings.HasPrefix(r[0], "Stopped.") {
		t.Fatalf("STATUS with the kernel stopped: %q", r)
	}
	if r := resume(t, dir); !strings.HasPrefix(r, "Resumed.") || k.stopped {
		t.Fatalf("RESUME of the kernel's stop: %q, %+v", r, k)
	}
}

// A kernel that does not answer cannot have recorded the STOP: STOP says
// it failed (CH-2), though the journal's STOP holds. STATUS never reports
// that kernel stopped, and names it.
func TestSTOPFailsWhileTheKernelDoesNotAnswer(t *testing.T) {
	k := &fakeKernel{down: true}
	dir := withKernel(t, k)
	if r := text(t, dir, owner, "STOP"); !strings.HasPrefix(r[0], "STOP failed") {
		t.Fatalf("STOP with no kernel: %q", r)
	}
	r := text(t, dir, owner, "STATUS")[0]
	if !strings.HasPrefix(r, "Stopped.") {
		t.Fatalf("the journal's STOP did not hold: %q", r)
	}
	// RESUME fails whole: the journal stays stopped.
	if r := resume(t, dir); !strings.HasPrefix(r, "RESUME failed") {
		t.Fatalf("RESUME with no kernel: %q", r)
	}
	if r := text(t, dir, owner, "STATUS")[0]; !strings.HasPrefix(r, "Stopped.") {
		t.Fatalf("RESUME lifted the journal's STOP with no kernel: %q", r)
	}

	k2 := &fakeKernel{down: true}
	dir2 := withKernel(t, k2)
	r = text(t, dir2, owner, "STATUS")[0]
	if !strings.HasPrefix(r, "Running.") || !strings.Contains(r, kernelUnreached) {
		t.Fatalf("STATUS with no kernel: %q", r)
	}
	k2.set(func(k *fakeKernel) { k.down = false })
	if r := text(t, dir2, owner, "STATUS")[0]; strings.Contains(r, kernelUnreached) {
		t.Fatalf("the note outlived the kernel's answer: %q", r)
	}
}

// A kernel waiting for setup holds no plan and runs nothing: its refusal
// of STOP and RESUME is not a failure.
func TestAKernelWaitingForSetupHasNothingToStop(t *testing.T) {
	k := &fakeKernel{setup: true}
	dir := withKernel(t, k)
	if r := text(t, dir, owner, "STOP"); !strings.HasPrefix(r[0], "Stopped.") {
		t.Fatalf("STOP: %q", r)
	}
	if r := resume(t, dir); !strings.HasPrefix(r, "Resumed.") {
		t.Fatalf("RESUME: %q", r)
	}
	if r := text(t, dir, owner, "STATUS")[0]; !strings.HasPrefix(r, "Running.") || strings.Contains(r, kernelUnreached) {
		t.Fatalf("STATUS: %q", r)
	}
}
