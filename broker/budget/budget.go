// Package budget declares the host's per-component memory budget (SPEC
// RES-2) and its storage reserve (RES-4), and applies the memory budget
// with one cgroup v2 group per component.
//
// The floor figures are SPEC RES-2's table (from S3 and S4, still to be
// checked on the N95). A larger host keeps every component's budget and
// gives the rest to the agent-machine pool, so it adds throughput and
// changes nothing else (HW-4). All figures are MiB.
package budget

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/cgroup"
)

// OpenClawMB is one OpenClaw machine: about 1.6 GB (S4, summed RSS) plus
// 16 MiB of gVisor overhead (S3).
const OpenClawMB = 1536 + 16

// Memory is the declared per-component budget, MiB.
type Memory struct {
	HostMB      int64 // host image, broker, journal: protected, never capped
	InferenceMB int64 // local inference (small model, speech, embeddings)
	BrowserMB   int64 // one credentialed browser
	HeadroomMB  int64 // never admitted into: S3's no-stall margin
	PoolMB      int64 // agent machines; set by ForHost
}

// Floor is RES-2's floor budget, without the pool: 1.0, 2.0 and 0.5 GB
// read as GiB, the figures agentosd (PE6) and the S1 test kit's floor_fit
// use too.
func Floor() Memory {
	return Memory{HostMB: 1024, InferenceMB: 2048, BrowserMB: 512, HeadroomMB: 600}
}

// MaxCapacityMB caps admission's capacity (the pool plus headroom) on a
// large host: agentosd's 4500 MB default before PE6, kept as the cap by
// PE6 (R1 on #114). HW-4 would let a larger host grow the pool instead;
// lifting the cap is left to a measured rule (budget R2).
const MaxCapacityMB = 4500

// ForHost sizes the pool for a host with totalMB of memory: what the
// declared components leave, with capacity (pool plus headroom) at most
// MaxCapacityMB. A pool too small for an agent machine is returned as is:
// the caller turns the agent off and says so (agentosd planMemory).
func ForHost(totalMB int64, c Memory) (Memory, error) {
	if c.HostMB <= 0 || c.InferenceMB < 0 || c.BrowserMB < 0 || c.HeadroomMB <= 0 {
		return Memory{}, fmt.Errorf("budget: every component needs a budget and headroom must be positive: %+v", c)
	}
	c.PoolMB = min(totalMB-c.HostMB-c.InferenceMB-c.BrowserMB, MaxCapacityMB) - c.HeadroomMB
	return c, nil
}

// Total is the sum of every component and the headroom.
func (m Memory) Total() int64 {
	return m.HostMB + m.InferenceMB + m.BrowserMB + m.HeadroomMB + m.PoolMB
}

// Admission is the admission controller's configuration for the pool: it
// admits machines into exactly PoolMB and holds the headroom back.
func (m Memory) Admission() admission.Config {
	return admission.Config{CapacityMB: m.PoolMB + m.HeadroomMB, HeadroomMB: m.HeadroomMB}
}

// Groups are the component groups Apply made.
type Groups struct {
	Broker, Inference, Browser *cgroup.Group
	// Machines is opened as a parent: per-machine groups go beneath it.
	Machines *cgroup.Group
}

// Apply creates one group per component under root. Inference, the browser
// and the pool get hard limits; the broker gets its budget as protected
// memory and no hard limit, so it is never OOM-killed by its own group and
// its pages are not reclaimed for others. With every other component capped
// and the headroom left over, the host's own OOM killer has nothing to do.
func (m Memory) Apply(root *cgroup.Group) (Groups, error) {
	var g Groups
	var err error
	mib := func(n int64) int64 { return n << 20 }
	if g.Broker, err = root.Component("broker", cgroup.Limits{MinBytes: mib(m.HostMB)}); err != nil {
		return Groups{}, err
	}
	if m.InferenceMB > 0 {
		if g.Inference, err = root.Component("inference", cgroup.Limits{MaxBytes: mib(m.InferenceMB)}); err != nil {
			return Groups{}, err
		}
	}
	if m.BrowserMB > 0 {
		if g.Browser, err = root.Component("browser", cgroup.Limits{MaxBytes: mib(m.BrowserMB)}); err != nil {
			return Groups{}, err
		}
	}
	// The pool's own memory.high would throttle every machine together
	// before any one reached its limit, so it is set at the hard limit:
	// per-machine groups carry the throttle.
	pool, err := root.Component("machines", cgroup.Limits{MaxBytes: mib(m.PoolMB), HighBytes: mib(m.PoolMB)})
	if err != nil {
		return Groups{}, err
	}
	if g.Machines, err = cgroup.Open(pool.Path); err != nil {
		return Groups{}, err
	}
	return g, nil
}

// MemTotalMB reads MemTotal from a meminfo file (/proc/meminfo), in MiB.
func MemTotalMB(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), "MemTotal:"); ok {
			kb, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
			if err != nil {
				return 0, fmt.Errorf("budget: %s: %w", path, err)
			}
			return kb >> 10, nil
		}
	}
	if err := s.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("budget: no MemTotal in %s", filepath.Clean(path))
}

// Disk is the state disk's RES-4 reserve, MiB: what must stay free before
// any discretionary download or snapshot.
type Disk struct {
	ReleaseMB int64 // one healthy release staged before install (S7: 1.0 GiB erofs + 69 MiB verity)
	JournalMB int64 // journal growth
	RecallMB  int64 // recall index growth
}

// FloorDisk is the floor's reserve. Only the release figure is measured
// (S7); the journal and recall figures are placeholders until P3 sizes them.
func FloorDisk() Disk {
	return Disk{ReleaseMB: 1280, JournalMB: 512, RecallMB: 1024}
}

// ReserveBytes is the whole reserve in bytes.
func (d Disk) ReserveBytes() int64 { return (d.ReleaseMB + d.JournalMB + d.RecallMB) << 20 }
