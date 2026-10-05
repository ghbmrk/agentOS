package gvisor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/quota"
	"github.com/ghbmrk/agentos/broker/quota/quotatest"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: RES-4
//
// Security review 2, finding 3 (SR2-3), end to end: a guest under gVisor
// writing past its machine's disk budget is stopped by the file system,
// and printing without end fills no more than its console allowance.

func TestIntegrationGuestStopsAtItsDiskQuota(t *testing.T) {
	if os.Getenv("AGENTOS_RUNSC") == "" || os.Geteuid() != 0 {
		t.Skip("set AGENTOS_RUNSC to a runsc binary and run as root (CI integration job)")
	}
	state := quotatest.Dir(t, 256)
	q, err := quota.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	const budget = 16 << 20
	r := newRigOn(t, 4096, nil, state, func(c *vm.Config) {
		c.NoQuota, c.Quota, c.MachineDiskBytes = false, q, budget
		c.DiskReserveBytes = 16 << 20
	})
	r.create("m1", admission.Accepted)
	r.ask("m1", "token") // serving
	out := r.ask("m1", "fill", "/work/big", "64")
	// gVisor may report the host's EDQUOT as either errno.
	if !strings.HasPrefix(out, "ERR") || !(strings.Contains(out, "quota") || strings.Contains(out, "no space")) {
		t.Fatalf("guest wrote 64 MiB under a 16 MiB budget: %s", out)
	}
	mc, err := r.m.Get("m1")
	if err != nil {
		t.Fatal(err)
	}
	u, err := q.Usage(mc.Project)
	if err != nil {
		t.Fatal(err)
	}
	if u.Bytes > budget || u.Bytes < budget/2 {
		t.Fatalf("project use %d bytes, budget %d", u.Bytes, budget)
	}
	t.Logf("guest stopped: %s (project use %d bytes)", out, u.Bytes)
	// Deleting files frees the guest's budget again.
	if got := r.ask("m1", "remove", "/work/big"); got != "ok" {
		t.Fatal(got)
	}
	if got := r.ask("m1", "fill", "/work/again", "4"); got != "ok" {
		t.Fatalf("guest cannot write after freeing space: %s", got)
	}

	// The console: 3 times the allowance printed, at most the allowance kept.
	if got := r.ask("m1", "spam", "24"); got != "ok" {
		t.Fatal(got)
	}
	var kept int64
	for _, n := range []string{"console.log", "console.log.1"} {
		if fi, err := os.Stat(filepath.Join(state, "broker", "machines", "m1", n)); err == nil {
			kept += fi.Size()
		}
	}
	if kept > vm.ConsoleMaxBytes || kept < vm.ConsoleMaxBytes/2 {
		t.Fatalf("console keeps %d bytes, allowance %d", kept, vm.ConsoleMaxBytes)
	}
	if err := r.m.Destroy(context.Background(), "m1"); err != nil {
		t.Fatal(err)
	}
}
