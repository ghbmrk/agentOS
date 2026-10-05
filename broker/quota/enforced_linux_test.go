package quota

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// REQ: RES-4

// TestEnforcedDropsTheOverrideAndRestoresIt: inside Enforced the thread
// lacks CAP_SYS_RESOURCE in its effective set; afterwards it has what it
// had before.
func TestEnforcedDropsTheOverrideAndRestoresIt(t *testing.T) {
	before := effective(t)
	if before&(1<<24) == 0 {
		t.Skip("no CAP_SYS_RESOURCE to drop here")
	}
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
