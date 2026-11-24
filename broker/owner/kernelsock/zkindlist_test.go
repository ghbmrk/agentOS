package kernelsock

// REQ: OWN-6

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// KindList is the kernel's rendering unchanged, so the owner side's texts
// say kinds in the Forget ask's words (#5378).
func TestKindListIsTheKernels(t *testing.T) {
	for _, c := range []map[string]int{
		{"message": 2, "vision-wrap-key": 1},
		{"message": 1, kernel.ClassLabel: 1, "zz-other": 3},
		{},
	} {
		if got, want := KindList(c), kernel.KindList(c); got != want || (len(c) > 0 && got == "") {
			t.Fatalf("KindList(%v) = %q, want %q", c, got, want)
		}
	}
}
