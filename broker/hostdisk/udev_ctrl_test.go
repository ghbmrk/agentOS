package hostdisk

import "testing"

// REQ: HW-8, ONB-2

// Security, optional, on #172 (HOST-1a part 2): the block SCSI generic
// nodes (/dev/bsg/*) and the NVMe controller nodes (/dev/nvme0) send the
// same writing commands as sg and ng (SG_IO, NVMe admin and I/O
// passthrough) to any disk behind them, the drive's included, so every one
// is root:root 0600 with no uaccess, locked so no later rule widens it.
func TestUdevRuleClosesBsgAndNvmeControllerNodes(t *testing.T) {
	s := newUdevStack(t, testClassify(t))
	for _, c := range []struct{ kernel, subsystem string }{
		{"0:0:0:0", "bsg"},
		{"2:0:0:0", "bsg"},
		{"nvme0", "nvme"},
		{"nvme1", "nvme"},
	} {
		d := &udevDev{kernel: c.kernel, subsystem: c.subsystem, action: "add", owner: "root", group: "disk", mode: "0660",
			env: map[string]string{}}
		s.run(d, nil)
		if d.owner != "root" || d.group != "root" || d.mode != "0600" || !d.locked["OWNER"] || !d.locked["GROUP"] || !d.locked["MODE"] || d.tags["uaccess"] {
			t.Errorf("%s (%s): %+v", c.kernel, c.subsystem, d)
		}
	}
}

// The rule reaches only the storage passthrough subsystems: a character
// device of another subsystem keeps its stock owner and mode.
func TestUdevRuleLeavesOtherCharNodes(t *testing.T) {
	s := newUdevStack(t, testClassify(t))
	for _, c := range []struct{ kernel, subsystem string }{
		{"ttyS0", "tty"},
		{"hidraw0", "hidraw"},
		{"nvme-subsys0", "nvme-subsystem"},
	} {
		d := &udevDev{kernel: c.kernel, subsystem: c.subsystem, action: "add", owner: "root", group: "dialout", mode: "0660",
			env: map[string]string{}}
		s.run(d, nil)
		if d.group != "dialout" || d.mode != "0660" || d.locked["MODE"] {
			t.Errorf("%s (%s) changed: %+v", c.kernel, c.subsystem, d)
		}
	}
}
