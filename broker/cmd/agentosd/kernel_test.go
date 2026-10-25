package main

// REQ: CLK-1

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
