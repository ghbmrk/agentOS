// Package accel discovers accelerators (iGPU, GPU, NPU) and leases them as
// an admission resource to local inference (SPEC RES-3).
//
// Nothing depends on an accelerator: with none present, or with discovery
// turned off, every lease is a CPU lease and the same service runs on the
// CPU. A lease never blocks. Leases follow the admission classes (RES-1):
// foreground takes a device from an experiment, whose lease reports Lost
// so its next unit of work runs on the CPU; nothing else is taken from.
//
// Discovery reads sysfs only (render nodes under class/drm, compute
// accelerators under class/accel), so it can run on the broker's control
// path (ARC-2). Opening a device is the inference runtime's business.
package accel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/ghbmrk/agentos/broker/admission"
)

// Kind is an accelerator type; kinds combine as a filter.
type Kind uint8

const (
	IGPU Kind = 1 << iota // integrated GPU
	GPU                   // discrete GPU
	NPU                   // neural processing unit (class/accel)

	Any = IGPU | GPU | NPU
)

func (k Kind) String() string {
	switch k {
	case IGPU:
		return "igpu"
	case GPU:
		return "gpu"
	case NPU:
		return "npu"
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// Device is one discovered accelerator.
type Device struct {
	Kind   Kind
	Node   string // device node the inference runtime opens
	Vendor string // PCI vendor ID, e.g. 0x8086
	Driver string // kernel driver, e.g. i915, xe, amdgpu, intel_vpu
}

// Discover lists accelerators under sysRoot (normally /sys): NPUs first,
// then GPUs by node name. A missing class directory means none of that
// kind.
func Discover(sysRoot string) ([]Device, error) {
	var out []Device
	for _, c := range []struct {
		class, prefix, dev string
	}{
		{"accel", "accel", "/dev/accel/"},
		{"drm", "renderD", "/dev/dri/"},
	} {
		ents, err := os.ReadDir(filepath.Join(sysRoot, "class", c.class))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var names []string
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), c.prefix) {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			dev := filepath.Join(sysRoot, "class", c.class, name, "device")
			d := Device{Node: c.dev + name, Vendor: readTrim(filepath.Join(dev, "vendor"))}
			if drv, err := os.Readlink(filepath.Join(dev, "driver")); err == nil {
				d.Driver = filepath.Base(drv)
			}
			switch {
			case c.class == "accel":
				d.Kind = NPU
			case integrated(dev):
				d.Kind = IGPU
			default:
				d.Kind = GPU
			}
			out = append(out, d)
		}
	}
	return out, nil
}

// integrated reports a GPU on the root complex's bus 0: Intel iGPUs sit at
// 0000:00:02.0 and AMD APUs on bus 0 too, while discrete cards hang off a
// PCIe port on another bus.
func integrated(dev string) bool {
	p, err := filepath.EvalSymlinks(dev)
	if err != nil {
		return false
	}
	return strings.HasPrefix(filepath.Base(p), "0000:00:")
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Pool leases devices. It is safe for concurrent use.
type Pool struct {
	mu      sync.Mutex
	devs    []Device
	holders []*Lease // per device; nil when free
}

// NewPool leases devs. A nil or empty list (no accelerator, or discovery
// turned off) leases only the CPU.
func NewPool(devs []Device) *Pool {
	return &Pool{devs: devs, holders: make([]*Lease, len(devs))}
}

// Lease is one job's claim on a device, or on the CPU.
type Lease struct {
	p     *Pool
	idx   int // -1: CPU
	owner string
	class admission.Class
	lost  chan struct{}
}

// CPU reports a CPU lease: no device, or the device was taken.
func (l *Lease) CPU() bool {
	l.p.mu.Lock()
	defer l.p.mu.Unlock()
	return l.idx < 0
}

// Device is the leased device; zero for a CPU lease.
func (l *Lease) Device() Device {
	l.p.mu.Lock()
	defer l.p.mu.Unlock()
	if l.idx < 0 {
		return Device{}
	}
	return l.p.devs[l.idx]
}

// Lost is closed when a higher class takes the device. The holder finishes
// its current unit and runs the next on the CPU.
func (l *Lease) Lost() <-chan struct{} { return l.lost }

// Release gives the device back; the lease is a CPU lease afterwards.
// Releasing a lost or CPU lease frees nothing.
func (l *Lease) Release() {
	l.p.mu.Lock()
	defer l.p.mu.Unlock()
	if l.idx >= 0 && l.p.holders[l.idx] == l {
		l.p.holders[l.idx] = nil
	}
	l.idx = -1
}

// Acquire leases a device of one of kinds for owner. It prefers a free
// device; foreground may take one from an experiment; otherwise the lease
// is on the CPU. It never blocks or fails.
func (p *Pool) Acquire(owner string, class admission.Class, kinds Kind) *Lease {
	l := &Lease{p: p, idx: -1, owner: owner, class: class, lost: make(chan struct{})}
	p.mu.Lock()
	defer p.mu.Unlock()
	victim := -1
	for i, d := range p.devs {
		if d.Kind&kinds == 0 {
			continue
		}
		h := p.holders[i]
		if h == nil {
			l.idx = i
			break
		}
		if victim < 0 && class == admission.Foreground && h.class == admission.Experiment {
			victim = i
		}
	}
	if l.idx < 0 && victim >= 0 {
		close(p.holders[victim].lost)
		p.holders[victim].idx = -1
		l.idx = victim
	}
	if l.idx >= 0 {
		p.holders[l.idx] = l
	}
	return l
}

// Summary is STATUS's one line about accelerators.
func (p *Pool) Summary() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.devs) == 0 {
		return "Accelerators: none; local inference on CPU."
	}
	kinds := map[string]bool{}
	var names []string
	busy := 0
	for i, d := range p.devs {
		if !kinds[d.Kind.String()] {
			kinds[d.Kind.String()] = true
			names = append(names, d.Kind.String())
		}
		if p.holders[i] != nil {
			busy++
		}
	}
	return fmt.Sprintf("Accelerators: %d (%s), %d in use.", len(p.devs), strings.Join(names, ", "), busy)
}
