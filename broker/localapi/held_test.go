package localapi

// REQ: CH-19, CH-8

import (
	"slices"
	"strings"
	"testing"
)

// The held-text op is a page op, distinct from every other.
func TestHeldOpIsAPageOp(t *testing.T) {
	all := slices.Concat(Ops, SetupOps, PasskeyOps, BackupOps, RecoveryOps, CameraOps)
	for _, op := range HeldOps {
		if !strings.HasPrefix(op, "page_") || slices.Contains(all, op) {
			t.Fatalf("%s", op)
		}
	}
}
