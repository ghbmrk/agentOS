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

// ext4Usable is the share of a grown ext4 root's added bytes that statfs
// reports available: 5% is reserved for root, and the inode tables,
// journal and group descriptors take about 2% more.
const ext4Usable = 0.93

// TestCIBootDriveHoldsTheAgentAndOneWorkerDisk is #1701: the e2e copy's
// root filesystem grows over what ci_boot.sh adds to the image, and vm
// admits a machine only when what its quota may still write fits above
// the RES-4 reserve beside every running machine's (vm.ErrDiskFull). The
// added bytes must hold the reserve, the agent machine and one provider
// worker, each at agentosd's -machine-disk-mb. With the image's +2G, the
// setup sign-in worker alone was refused. The image's own root partition
// is left as headroom for what the image writes there.
func TestCIBootDriveHoldsTheAgentAndOneWorkerDisk(t *testing.T) {
	src, err := os.ReadFile("../../image/ci_boot.sh")
	if err != nil {
		t.Fatal(err)
	}
	e := regexp.MustCompile(`(?m)^\s*copy "\$W/e2e\.raw" (\d+)G$`).FindSubmatch(src)
	if e == nil {
		t.Fatal(`image/ci_boot.sh: the e2e copy is not grown by "copy "$W/e2e.raw" NG"`)
	}
	main, err := os.ReadFile("../cmd/agentosd/main.go")
	if err != nil {
		t.Fatal(err)
	}
	d := regexp.MustCompile(`"machine-disk-mb", (\d+),`).FindSubmatch(main)
	if d == nil {
		t.Fatal("cmd/agentosd/main.go: no -machine-disk-mb default")
	}
	unit, err := os.ReadFile("../../image/mkosi/mkosi.extra/usr/lib/systemd/system/agentosd.service")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`-(machine-disk|disk-reserve)-mb`).Match(unit) {
		t.Fatal("agentosd.service sets a disk budget flag; read it here")
	}
	gb, _ := strconv.ParseInt(string(e[1]), 10, 64)
	machineMB, _ := strconv.ParseInt(string(d[1]), 10, 64)
	usable := int64(float64(gb<<10) * ext4Usable)
	if need := FloorDisk().ReserveBytes()>>20 + 2*machineMB; usable < need {
		t.Fatalf("ci_boot.sh grows the e2e copy by %dG, about %d MB usable; the reserve, the agent and one provider worker need %d", gb, usable, need)
	}
}
