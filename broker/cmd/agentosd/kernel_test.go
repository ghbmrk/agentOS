package main

// REQ: CLK-1

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
)

// fakeSetup answers SetupOpen from errs in turn, then with open.
type fakeSetup struct {
	errs []error
	open bool
}

func (f *fakeSetup) SetupOpen(context.Context) (bool, error) {
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		return false, err
	}
	return f.open, nil
}

// The start-up probe says once that the kernel is not reached, keeps
// trying through unreachable and lost calls, and says once whether setup
// is open when the kernel answers; a refusal ends it (MIG-4-run-start-b).
func TestTheBrokerSaysWhenItReachesTheKernel(t *testing.T) {
	refused := kernelsock.Refused{Text: "no"}
	for _, c := range []struct {
		f    *fakeSetup
		want []string
	}{
		{&fakeSetup{open: true}, []string{"kernel: reached; it is waiting for setup"}},
		{&fakeSetup{errs: []error{kernelsock.ErrUnreachable, kernelsock.ErrLost, kernelsock.ErrUnreachable}},
			[]string{"kernel: not reached yet; I keep trying (" + kernelsock.ErrUnreachable.Error() + ")", "kernel: reached; it is running"}},
		{&fakeSetup{errs: []error{fmt.Errorf("%w (x)", kernelsock.ErrUnreachable), refused}},
			[]string{"kernel: not reached yet; I keep trying (" + kernelsock.ErrUnreachable.Error() + " (x))", "kernel: reached, but it refused me: " + refused.Error()}},
	} {
		var lines []string
		reachKernel(context.Background(), c.f, time.Millisecond, func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) })
		if strings.Join(lines, "\n") != strings.Join(c.want, "\n") {
			t.Errorf("lines:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(c.want, "\n"))
		}
	}
	// Shutdown ends a probe that never reaches the kernel.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		reachKernel(ctx, &fakeSetup{errs: make([]error, 1<<20)}, time.Millisecond, func(string, ...any) {})
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the probe outlived shutdown")
	}
}

func TestKernelFlags(t *testing.T) {
	for _, c := range []struct {
		sock                string
		kernelUID, ownerUID int
		others              []int
		ok, on              bool
	}{
		{"", -1, -1, nil, true, false},
		{"/run/agentos-kernel/owner.sock", 900, 901, []int{902, -1}, true, true},
		{"/run/agentos-kernel/owner.sock", -1, 901, nil, false, false},
		{"/run/agentos-kernel/owner.sock", 900, -1, nil, false, false},
		{"", 900, 901, nil, false, false},
		{"owner.sock", 900, 901, nil, false, false},
		{"/run/agentos-kernel/owner.sock", 0, 901, nil, false, false},
		{"/run/agentos-kernel/owner.sock", 900, 0, nil, false, false},
		{"/run/agentos-kernel/owner.sock", 900, 900, nil, false, false},
		{"/run/agentos-kernel/owner.sock", 900, 901, []int{901}, false, false},
		{"/run/agentos-kernel/owner.sock", 900, 901, []int{900}, false, false},
	} {
		k, err := kernelFlags(c.sock, c.kernelUID, c.ownerUID, c.others...)
		if (err == nil) != c.ok || (k != nil) != c.on {
			t.Errorf("%+v: %v, %v", c, k, err)
		}
		if k != nil && (k.Socket != c.sock || k.UID != c.kernelUID || k.As != c.ownerUID) {
			t.Errorf("%+v: %+v", c, *k)
		}
	}
}

// With no sealed store no kernel can run, so the owner commands' kernel
// reads as waiting for setup and is never called; once the store exists
// the kernel itself answers, here not at all (#2783).
func TestNoSealedStoreIsAKernelWaitingForSetup(t *testing.T) {
	dir := t.TempDir()
	k := storedKernel{kernelsock.Owner{Socket: filepath.Join(dir, "none.sock"), UID: 1, As: 2}, filepath.Join(dir, "store")}
	if open, err := k.SetupOpen(context.Background()); err != nil || !open {
		t.Fatalf("no store: %v, %v", open, err)
	}
	if err := os.WriteFile(k.store, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := k.SetupOpen(context.Background()); !errors.Is(err, kernelsock.ErrUnreachable) {
		t.Fatalf("a store and no kernel: %v", err)
	}
}

// The kernel's answers reach the owner commands in their own terms (#2783
// b): a refusal keeps the kernel's words, a lost answer stays "may or may
// not have taken effect", and anything else passes as it is.
func TestTheKernelsAnswersInTheOwnerCommandsTerms(t *testing.T) {
	var r daemon.KernelRefused
	if err := kernelErr(kernelsock.Refused{Text: "kernel: no parked step"}); !errors.As(err, &r) || r.Text != "kernel: no parked step" {
		t.Fatalf("a refusal: %v", err)
	}
	if err := kernelErr(kernelsock.ErrLost); !errors.Is(err, daemon.ErrKernelLost) || errors.As(err, &r) {
		t.Fatalf("a lost answer: %v", err)
	}
	if err := kernelErr(kernelsock.ErrUnreachable); !errors.Is(err, kernelsock.ErrUnreachable) || errors.As(err, &r) || errors.Is(err, daemon.ErrKernelLost) {
		t.Fatalf("an unreached kernel: %v", err)
	}
	if kernelErr(nil) != nil {
		t.Fatal("success read as a failure")
	}
	// A RETRY's attempt crosses the conversion, and the kernel's refusal of
	// a moved one keeps the words daemon's kernelRefusal matches (CH-10).
	if s := daemon.KernelStep(kernelsock.Step{Plan: "p1", Attempt: 2}); s.Attempt != 2 {
		t.Fatalf("attempt %d after the conversion", s.Attempt)
	}
	if err := kernelErr(kernelsock.Refused{Text: kernel.ErrRetryMoved.Error()}); !errors.As(err, &r) || !strings.Contains(r.Text, "retried since that ask") {
		t.Fatalf("a moved retry: %v", err)
	}
}

// agentosd's RETRY sends the kernel the attempt the ask read, not another
// (CH-10). Revert mutant: storedKernel.Retry passes a constant attempt (1),
// and the kernel reads attempt 1 for an ask about attempt 3.
func TestRetrySendsTheAttemptTheAskRead(t *testing.T) {
	// The call is made as this process's own uid, which needs no root, and
	// only this process's uid is called.
	dir := t.TempDir()
	path := filepath.Join(dir, "owner.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	lines := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		l, _ := bufio.NewReader(c).ReadString('\n')
		lines <- l
		c.Write([]byte("{\"result\":null}\n"))
	}()
	k := storedKernel{kernelsock.Owner{Socket: path, UID: os.Getuid(), As: os.Geteuid()}, filepath.Join(dir, "store")}
	if err := k.Retry(context.Background(), "plan:7", 2, 3); err != nil {
		t.Fatal(err)
	}
	var call struct {
		Op   string
		Args struct {
			Plan    string
			Index   int
			Attempt int
		}
	}
	if err := json.Unmarshal([]byte(<-lines), &call); err != nil {
		t.Fatal(err)
	}
	if call.Op != "retry" || call.Args.Plan != "plan:7" || call.Args.Index != 2 || call.Args.Attempt != 3 {
		t.Fatalf("RETRY sent %+v, want retry of plan:7 step 2 at attempt 3", call)
	}
}
