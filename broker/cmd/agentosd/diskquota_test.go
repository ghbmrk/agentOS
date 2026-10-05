package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/quota"
	"github.com/ghbmrk/agentos/broker/quota/quotatest"
	"github.com/ghbmrk/agentos/broker/vm"
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
// owner-visible STATUS line, not only a log line; quotas on adds none. A
// bad flag value stops the broker instead (L3 S3 on #174).
func TestQuotasOffIsAStatusLine(t *testing.T) {
	if n := quotaNote(false, nil); n != "" {
		t.Fatalf("quotas on: %q", n)
	}
	if n := quotaNote(true, nil); !strings.Contains(n, "could fill the disk") {
		t.Fatalf("declared off: %q", n)
	}
	if n := quotaNote(false, quota.ErrUnsupported); !strings.Contains(n, "can't limit") {
		t.Fatalf("unavailable: %q", n)
	}
	if n := quotaNote(false, errors.New("mkdir /x: read-only file system")); !strings.Contains(n, "could not be set up") || strings.Contains(n, "/") {
		t.Fatalf("not set up: %q", n)
	}
	if checkDiskQuotaFlag("on") != nil || checkDiskQuotaFlag("off") != nil || checkDiskQuotaFlag("bogus") == nil {
		t.Fatal("-disk-quota values")
	}
}

// openMachineDisk is main's seam: what it opens reaches vm.Config, and
// its STATUS line reaches the notes (L3 S4 on #174).
func TestMachineDiskReachesConfigAndStatus(t *testing.T) {
	var notes []func() string
	var c vm.Config
	d := openMachineDisk("off", t.TempDir(), &notes)
	d.set(&c)
	if d.err != nil || !c.NoQuota || c.Quota != nil || len(notes) != 1 || !strings.Contains(notes[0](), "could fill") {
		t.Fatalf("declared off: %+v %+v %d notes", d, c, len(notes))
	}
	notes, c = nil, vm.Config{}
	d = openMachineDisk("on", t.TempDir(), &notes)
	d.set(&c)
	if d.err == nil || c.NoQuota || len(notes) != 1 || !strings.Contains(notes[0](), "can't limit") {
		t.Fatalf("on, without quotas: %+v %+v %d notes", d, c, len(notes))
	}
}

func TestMachineDiskWithQuotasAddsNoLine(t *testing.T) {
	dir := quotatest.Dir(t, 16)
	var notes []func() string
	var c vm.Config
	d := openMachineDisk("on", dir+"/machines", &notes)
	d.set(&c)
	if d.err != nil || c.NoQuota || c.Quota == nil || len(notes) != 0 {
		t.Fatalf("on, with quotas: %+v %+v %d notes", d, c, len(notes))
	}
}
