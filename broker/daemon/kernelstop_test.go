package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/daemon/journalowner"
)

// REQ: CH-2, KRN-7

// fakeKernel is the kernel's owner seam: running, waiting for setup
// (every call but setupinfo refused), or not answering.
type fakeKernel struct {
	mu                    sync.Mutex
	stopped, setup, down  bool
	stops, resumes, reads int
	// lost: RESUME takes effect but its answer is lost.
	lost bool
	// hang: STOP and RESUME are taken and never answered.
	hang bool
	// steps are the unsettled steps; unlisted refuses their read alone.
	steps    []KernelStep
	unlisted bool
	// retried are the steps RETRY reached; retryErr is its answer.
	retried  []string
	retryErr error
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

func (k *fakeKernel) Stop(ctx context.Context) error {
	k.mu.Lock()
	if k.hang {
		k.mu.Unlock()
		<-ctx.Done()
		return ctx.Err()
	}
	defer k.mu.Unlock()
	if err := k.refuse(); err != nil {
		return err
	}
	k.stops++
	k.stopped = true
	return nil
}

func (k *fakeKernel) Resume(ctx context.Context) error {
	k.mu.Lock()
	if k.hang {
		k.mu.Unlock()
		<-ctx.Done()
		return ctx.Err()
	}
	defer k.mu.Unlock()
	if err := k.refuse(); err != nil {
		return err
	}
	k.resumes++
	k.stopped = false
	if k.lost {
		return errors.New("lost")
	}
	return nil
}

func (k *fakeKernel) Stopped(context.Context) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.reads++
	return k.stopped, k.refuse()
}

func (k *fakeKernel) Status(context.Context) ([]KernelStep, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case k.down:
		return nil, errDown
	case k.unlisted:
		return nil, errors.New("status refused")
	case k.setup:
		// As agentosd's kernel with no sealed store: the read fails, and
		// SetupOpen says the kernel waits for setup.
		return nil, errSetup
	}
	return slices.Clone(k.steps), nil
}

func (k *fakeKernel) Retry(_ context.Context, plan string, index int) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.refuse(); err != nil {
		return err
	}
	k.retried = append(k.retried, fmt.Sprintf("%s/%d", plan, index))
	return k.retryErr
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
	dir, _ := withKernelOwner(t, k, false)
	return dir
}

// withKernelOwner starts the daemon with the kernel; with channel, through
// the owner channel (-owner-state), as agentosd always runs it.
func withKernelOwner(t *testing.T, k KernelOwner, channel bool) (string, *Daemon) {
	t.Helper()
	dir, err := os.MkdirTemp("", "bk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	_, d := startWith(t, dir, func(c *Config) {
		c.Kernel = k
		if channel {
			c.Auth, c.OwnerState = nil, filepath.Join(dir, "owner.json")
		}
	})
	return dir, d
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

// The owner channel, which agentosd always runs (-owner-state), drives the
// kernel too: STOP by text and RESUME through its STOP-ordered resume
// (resumeUnlessStopped, here from a signed-in page).
func TestTheOwnerChannelsSTOPAndRESUMEReachTheKernel(t *testing.T) {
	k := &fakeKernel{}
	_, d := withKernelOwner(t, k, true)
	ch := d.Owner()
	if ch == nil {
		t.Fatal("no owner channel")
	}
	if err := ch.LocalStop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !k.stopped || k.stops != 1 {
		t.Fatalf("the page's STOP did not reach the kernel: %+v", k)
	}
	if msg, err := ch.LocalResume(ch.LocalStatus().Locks, ch.StopGen()); err != nil || !strings.HasPrefix(msg, "Resumed.") {
		t.Fatalf("RESUME: %q, %v", msg, err)
	}
	if k.stopped || k.resumes != 1 {
		t.Fatalf("the page's RESUME did not reach the kernel: %+v", k)
	}
	k.set(func(k *fakeKernel) { k.down = true })
	if err := ch.LocalStop(context.Background()); err == nil {
		t.Fatal("the page's STOP reported done with no kernel")
	}
}

// The owner's STOP by text through the owner channel reaches the kernel.
func TestTheOwnerChannelsTextedSTOPReachesTheKernel(t *testing.T) {
	k := &fakeKernel{}
	dir, _ := withKernelOwner(t, k, true)
	if r := text(t, dir, owner, "STOP"); len(r) == 0 || !strings.HasPrefix(r[0], "Stopped.") {
		t.Fatalf("STOP: %q", r)
	}
	if !k.stopped || k.stops != 1 {
		t.Fatalf("the texted STOP did not reach the kernel: %+v", k)
	}
}

// A kernel that takes a RESUME and never answers holds the owner's next
// STOP no longer than kernelFor per kernel call: RESUME fails, and the
// STOP behind it is answered (CH-2).
func TestAHungKernelHoldsSTOPOnlyBriefly(t *testing.T) {
	defer func(d time.Duration) { kernelFor = d }(kernelFor)
	kernelFor = 200 * time.Millisecond
	for _, channel := range []bool{false, true} {
		k := &fakeKernel{}
		dir, d := withKernelOwner(t, k, channel)
		if r := text(t, dir, owner, "STOP"); !strings.HasPrefix(r[0], "Stopped.") {
			t.Fatalf("STOP: %q", r)
		}
		k.set(func(k *fakeKernel) { k.hang = true })
		res := make(chan error, 1)
		if channel {
			go func() {
				_, err := d.Owner().LocalResume(d.Owner().LocalStatus().Locks, d.Owner().StopGen())
				res <- err
			}()
		} else {
			go func() {
				if r := resume(t, dir); !strings.HasPrefix(r, "RESUME failed") {
					res <- errors.New(r)
					return
				}
				res <- errors.New("failed")
			}()
		}
		time.Sleep(50 * time.Millisecond)
		start := time.Now()
		r := text(t, dir, owner, "STOP")
		if took := time.Since(start); took > 6*kernelFor {
			t.Fatalf("channel %v: STOP waited %v behind a hung kernel", channel, took)
		}
		if len(r) == 0 || !strings.HasPrefix(r[0], "STOP failed") {
			t.Fatalf("channel %v: STOP on a hung kernel: %q", channel, r)
		}
		if err := <-res; err == nil || strings.HasPrefix(err.Error(), "Resumed") {
			t.Fatalf("channel %v: RESUME on a hung kernel: %v", channel, err)
		}
	}
}

// failingResume is the daemon's journal engine with a RESUME that fails
// to record.
type failingResume struct{ control.Engine }

func (failingResume) Resume() error { return errors.New("fsync failed") }

// A RESUME that fails after the kernel took it leaves the kernel stopped
// again, so "Still stopped." holds for both: the journal's write failing,
// or the kernel's answer lost (#3077 Security release 1).
func TestAFailedRESUMELeavesTheKernelStopped(t *testing.T) {
	ctx := context.Background()
	k := &fakeKernel{}
	_, d := withKernelOwner(t, &fakeKernel{}, false)
	b := &bothStops{Engine: failingResume{journalowner.Engine{Engine: d.Engine()}}, k: k}
	if _, err := b.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Resume(); err == nil || !k.stopped {
		t.Fatalf("journal write failed: %v, kernel %+v", err, k)
	}
	k2 := &fakeKernel{lost: true}
	_, d = withKernelOwner(t, &fakeKernel{}, false)
	b = &bothStops{Engine: failingResume{journalowner.Engine{Engine: d.Engine()}}, k: k2}
	if _, err := b.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Resume(); err == nil || !k2.stopped || !b.Engine.Stopped() {
		t.Fatalf("kernel answer lost: %v, kernel %+v", err, k2)
	}
}
