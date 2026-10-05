package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/quota"
	"github.com/ghbmrk/agentos/broker/quota/quotatest"
)

// REQ: RES-4
//
// Security review 2, finding 3 (SR2-3): agent machines run only under
// per-machine disk quotas, unless the operator declares them off.

func TestMachinesNeedADiskQuotaUnlessDeclaredOff(t *testing.T) {
	plain := t.TempDir() // no project quotas here
	q, off, err := machineQuota("on", plain)
	if !errors.Is(err, quota.ErrUnsupported) || !strings.Contains(err.Error(), "-disk-quota=off") || q != nil || off {
		t.Fatalf("on, without quotas: %v %v %v", q, off, err)
	}
	if q, off, err := machineQuota("off", plain); err != nil || q != nil || !off {
		t.Fatalf("declared off: %v %v %v", q, off, err)
	}
	if _, _, err := machineQuota("maybe", plain); err == nil {
		t.Fatal("accepted -disk-quota=maybe")
	}
}

func TestMachinesGetTheStateFileSystemsQuota(t *testing.T) {
	dir := quotatest.Dir(t, 16)
	q, off, err := machineQuota("on", dir+"/machines")
	if err != nil || q == nil || off {
		t.Fatalf("on, with quotas: %v %v %v", q, off, err)
	}
}

// Security R2 on #152 (SR2-3i): quotas off, declared or missing, is an
// owner-visible STATUS line, not only a log line; quotas on adds none.
func TestQuotasOffIsAStatusLine(t *testing.T) {
	if n := quotaNote(false, nil); n != "" {
		t.Fatalf("quotas on: %q", n)
	}
	if n := quotaNote(true, nil); !strings.Contains(n, "could fill the disk") {
		t.Fatalf("declared off: %q", n)
	}
	n := quotaNote(false, quota.ErrUnsupported)
	if !strings.Contains(n, "Agent machines are off") || strings.Contains(n, "/") {
		t.Fatalf("unavailable: %q", n)
	}
}
