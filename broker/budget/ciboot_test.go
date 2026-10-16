package budget

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// REQ: RES-2, CAP-11

// guestReserveMB is what a QEMU guest's kernel keeps out of MemTotal:
// about 146 MB of -m 4096 on CI's boot (3950 MB MemTotal, #1896), read as
// 4% of -m so a larger guest's page tables are covered too.
func guestMemTotalMB(m int64) int64 { return m - m/25 }

// TestCIBootVMHoldsTheAgentAndOneWorker is #1896: image/ci_boot.sh boots
// the image QEMU guest that runs G1's e2e, whose model-backed task runs
// provider_run. The pool ForHost leaves on that guest must hold the agent
// machine and one provider worker at once, which reserves its caller's
// budget (an OpenClaw machine's). A sign-in worker runs alone at setup, so
// it is not counted beside both.
func TestCIBootVMHoldsTheAgentAndOneWorker(t *testing.T) {
	src, err := os.ReadFile("../../image/ci_boot.sh")
	if err != nil {
		t.Fatal(err)
	}
	q := regexp.MustCompile(`qemu-system-x86_64 .*-smp (\d+) -m (\d+) `).FindSubmatch(src)
	if q == nil {
		t.Fatal("image/ci_boot.sh: no qemu-system-x86_64 line with -smp N -m MB")
	}
	cores, _ := strconv.Atoi(string(q[1]))
	mb, _ := strconv.ParseInt(string(q[2]), 10, 64)
	m, err := ForHost(guestMemTotalMB(mb), cores, Floor())
	if err != nil {
		t.Fatalf("-m %d -smp %d: %v", mb, cores, err)
	}
	if need := 2 * int64(OpenClawMB); m.PoolMB < need {
		t.Fatalf("ci_boot.sh's -m %d -smp %d leaves a pool of %d MB; the agent and one provider worker need %d", mb, cores, m.PoolMB, need)
	}
}
