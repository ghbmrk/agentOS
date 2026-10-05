package accel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
)

// REQ: RES-3

// sysfs builds a fake /sys with the given DRM render nodes and accel nodes.
type node struct{ class, name, vendor, driver, pci string }

func sysfs(t *testing.T, nodes ...node) string {
	t.Helper()
	root := t.TempDir()
	for _, n := range nodes {
		dev := filepath.Join(root, "devices", "pci0000:00", n.pci)
		drv := filepath.Join(root, "bus", "pci", "drivers", n.driver)
		if _, err := os.Stat(dev); err != nil {
			must(t, os.MkdirAll(dev, 0o755))
			must(t, os.WriteFile(filepath.Join(dev, "vendor"), []byte(n.vendor+"\n"), 0o644))
			must(t, os.MkdirAll(drv, 0o755))
			must(t, os.Symlink(drv, filepath.Join(dev, "driver")))
		}
		cls := filepath.Join(root, "class", n.class, n.name)
		must(t, os.MkdirAll(cls, 0o755))
		must(t, os.Symlink(dev, filepath.Join(cls, "device")))
	}
	return root
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRES3DiscoversIGPUAndNPU(t *testing.T) {
	root := sysfs(t,
		node{"drm", "renderD128", "0x8086", "i915", "0000:00:02.0"},
		node{"drm", "card0", "0x8086", "i915", "0000:00:02.0"}, // a display node, not for compute
		node{"accel", "accel0", "0x8086", "intel_vpu", "0000:00:0b.0"},
		node{"drm", "renderD129", "0x10de", "nvidia", "0000:01:00.0"},
	)
	devs, err := Discover(root)
	must(t, err)
	want := []Device{
		{Kind: NPU, Node: "/dev/accel/accel0", Vendor: "0x8086", Driver: "intel_vpu"},
		{Kind: IGPU, Node: "/dev/dri/renderD128", Vendor: "0x8086", Driver: "i915"},
		{Kind: GPU, Node: "/dev/dri/renderD129", Vendor: "0x10de", Driver: "nvidia"},
	}
	if len(devs) != len(want) {
		t.Fatalf("found %+v", devs)
	}
	for i := range want {
		if devs[i] != want[i] {
			t.Errorf("device %d = %+v, want %+v", i, devs[i], want[i])
		}
	}
}

// The floor has no accelerator: discovery finds nothing and is not an error.
func TestRES3NoAcceleratorIsNormal(t *testing.T) {
	devs, err := Discover(t.TempDir())
	if err != nil || len(devs) != 0 {
		t.Fatalf("Discover(empty) = %v, %v", devs, err)
	}
	p := NewPool(nil)
	l := p.Acquire("asr", admission.Foreground, Any)
	if !l.CPU() {
		t.Fatalf("lease without accelerators = %+v, want CPU", l)
	}
	l.Release()
}

func TestRES3LeasesAreAnAdmissionResourceAndFallBackToCPU(t *testing.T) {
	gpu := Device{Kind: IGPU, Node: "/dev/dri/renderD128"}
	p := NewPool([]Device{gpu})
	a := p.Acquire("embed", admission.Accepted, Any)
	if a.CPU() || a.Device() != gpu {
		t.Fatalf("first lease = %+v, want the iGPU", a)
	}
	// Same class: no taking. The second job runs on CPU, same service.
	b := p.Acquire("embed2", admission.Accepted, Any)
	if !b.CPU() {
		t.Fatalf("second lease = %+v, want CPU", b)
	}
	a.Release()
	b.Release()
	c := p.Acquire("embed3", admission.Accepted, Any)
	if c.CPU() {
		t.Fatal("released device not handed out again")
	}
	c.Release()
}

func TestRES1RES3ForegroundTakesTheAcceleratorFromAnExperiment(t *testing.T) {
	gpu := Device{Kind: IGPU, Node: "/dev/dri/renderD128"}
	p := NewPool([]Device{gpu})
	exp := p.Acquire("loop", admission.Experiment, Any)
	if exp.CPU() {
		t.Fatal("idle accelerator not lent to an experiment")
	}
	call := p.Acquire("asr", admission.Foreground, Any)
	if call.CPU() || call.Device() != gpu {
		t.Fatalf("foreground lease = %+v, want the iGPU", call)
	}
	select {
	case <-exp.Lost():
	default:
		t.Fatal("experiment not told it lost the device")
	}
	// Accepted work is never taken from by anything but foreground, and
	// foreground never loses a device.
	call2 := p.Acquire("asr2", admission.Foreground, Any)
	if !call2.CPU() {
		t.Fatal("foreground took a device from foreground")
	}
	select {
	case <-call.Lost():
		t.Fatal("foreground lost its device")
	default:
	}
	exp.Release() // releasing a lost lease frees nothing
	if p.Acquire("x", admission.Accepted, Any).CPU() == false {
		t.Fatal("a lost lease's release freed the device foreground holds")
	}
}

func TestRES3KindFilterAndDisabledPoolBehaveIdentically(t *testing.T) {
	npu := Device{Kind: NPU, Node: "/dev/accel/accel0"}
	p := NewPool([]Device{npu})
	if l := p.Acquire("gpu-only", admission.Accepted, IGPU|GPU); !l.CPU() {
		t.Fatalf("NPU handed to a GPU-only job: %+v", l)
	}
	// Disabled (A2: identical behavior when disabled): every lease is CPU.
	off := NewPool(nil)
	if l := off.Acquire("asr", admission.Foreground, Any); !l.CPU() {
		t.Fatal("disabled pool handed out a device")
	}
	if got := off.Summary(); got != "Accelerators: none; local inference on CPU." {
		t.Fatalf("summary = %q", got)
	}
	if got := p.Summary(); got != "Accelerators: 1 (npu), 0 in use." {
		t.Fatalf("summary = %q", got)
	}
}
