// Command agentosd runs the AgentOS broker.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/accel"
	"github.com/ghbmrk/agentos/broker/budget"
	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
)

// images collects -image name=dir flags.
type images map[string]string

func (i images) String() string { return "" }
func (i images) Set(v string) error {
	name, dir, ok := strings.Cut(v, "=")
	if !ok || name == "" || dir == "" {
		return errors.New("want name=dir")
	}
	i[name] = dir
	return nil
}

// preempter forwards to the machine manager once it is open.
type preempter struct{ m atomic.Pointer[vm.Manager] }

func (p *preempter) Preempt(id string) error {
	m := p.m.Load()
	if m == nil {
		return errors.New("machine manager not open")
	}
	return m.Preempt(id)
}

func main() {
	var cfg daemon.Config
	imgs := images{}
	var stateDir, runsc, cgroupParent, cgroupRoot, accelMode string
	var diskReserveMB int64
	mem := budget.Floor()
	flag.StringVar(&cfg.JournalPath, "journal", "/var/lib/agentos/journal.log", "journal file")
	flag.StringVar(&cfg.SocketDir, "sockets", "/run/agentos", "socket directory (created 0700)")
	flag.StringVar(&cfg.OwnerNumber, "owner", "", "owner's phone number, E.164")
	flag.IntVar(&cfg.ModemUID, "modem-uid", -1, "uid of the modem bridge, the only peer allowed on the owner socket")
	flag.Int64Var(&mem.HostMB, "host-mb", mem.HostMB, "budget: host image, broker and journal (protected), MiB")
	flag.Int64Var(&mem.InferenceMB, "inference-mb", mem.InferenceMB, "budget: local inference, MiB")
	flag.Int64Var(&mem.BrowserMB, "browser-mb", mem.BrowserMB, "budget: one credentialed browser, MiB")
	flag.Int64Var(&mem.HeadroomMB, "headroom-mb", mem.HeadroomMB, "memory never admitted into, MiB")
	flag.StringVar(&cgroupRoot, "cgroup-root", "/sys/fs/cgroup/agentos.slice", "cgroup v2 group for the broker's components (RES-2); empty uses -cgroup alone")
	flag.StringVar(&accelMode, "accel", "auto", "accelerator discovery: auto or off (RES-3)")
	flag.Float64Var(&cfg.MaxPressure, "max-pressure", 10, "memory PSI (some avg10, %) above which only foreground is admitted")
	flag.StringVar(&stateDir, "machines", "/var/lib/agentos/machines", "agent-machine layers and snapshots (created 0700)")
	flag.StringVar(&runsc, "runsc", "", "gVisor runsc binary; empty runs no agent machines")
	flag.StringVar(&cgroupParent, "cgroup", "/sys/fs/cgroup/agentos.slice/machines", "cgroup v2 parent for agent machines")
	flag.Int64Var(&diskReserveMB, "disk-reserve-mb", budget.FloorDisk().ReserveBytes()>>20, "state-disk space snapshots never use (RES-4 reserve), MiB")
	flag.Var(imgs, "image", "agent-machine image, name=dir (repeatable)")
	flag.Parse()
	if cfg.ModemUID < 0 || cfg.ModemUID == os.Getuid() {
		log.Fatal("-modem-uid must name the modem bridge's own uid, distinct from the broker's")
	}

	// RES-2: the pool is what the declared components leave of this host.
	total, err := budget.MemTotalMB("/proc/meminfo")
	if err == nil {
		mem, err = budget.ForHost(total, mem)
	}
	if err != nil {
		log.Printf("agent machines disabled: %v", err)
		runsc = ""
		mem.PoolMB = 1 // admission needs capacity > headroom; no machine fits
	}
	cfg.Admission = mem.Admission()
	log.Printf("memory budget (MiB): host %d, inference %d, browser %d, headroom %d, machines %d",
		mem.HostMB, mem.InferenceMB, mem.BrowserMB, mem.HeadroomMB, mem.PoolMB)

	// RES-3: nothing below depends on what is found here.
	var devs []accel.Device
	if accelMode != "off" {
		if devs, err = accel.Discover("/sys"); err != nil {
			log.Printf("accelerator discovery failed, using CPU: %v", err)
			devs = nil
		}
	}
	accels := accel.NewPool(devs)
	log.Print(accels.Summary())

	// The machine plane failing must not take the owner channel down with
	// it: STOP and STATUS keep working, and no machines run.
	var cg *cgroup.Group
	psiPath := "/proc/pressure/memory"
	if runsc != "" {
		g, err := openPool(cgroupRoot, cgroupParent, mem)
		if err != nil {
			log.Printf("agent machines disabled: %v", err)
			runsc = ""
		} else {
			cg, psiPath = g, filepath.Join(g.Path, "memory.pressure")
		}
	}
	if read, ok := cgroup.PressureSource(psiPath); ok {
		cfg.Pressure = read
	} else {
		log.Printf("no PSI at %s: admission uses the memory budget alone", psiPath)
	}
	pre := &preempter{}
	cfg.Preempter = pre

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	if runsc != "" {
		m, err := vm.Open(ctx, vm.Config{
			StateDir: stateDir,
			Images:   imgs,
			Runtime:  &gvisor.Runtime{Bin: runsc, StateDir: filepath.Join(stateDir, "runsc")},
			Admit:    d.Admission(),
			Cgroups:  cg,

			DiskReserveBytes: diskReserveMB << 20,
		})
		if err != nil {
			log.Printf("agent machines disabled: %v", err)
		} else {
			pre.m.Store(m)
			go m.RunPruner(vm.PrunePolicy{LowWaterBytes: 1 << 30}, time.Minute, ctx.Done())
		}
	}
	log.Printf("broker up; owner socket %s/%s", cfg.SocketDir, daemon.OwnerSocket)
	d.Wait()
}

// openPool applies the component budget under root and returns the
// machine pool's group, with the broker in its protected group. With no
// root, machines go under parent with no component groups. The broker
// moves first: cgroup v2 will not enable controllers for the children of
// a group that still holds a process (systemd Delegate=yes starts the
// broker in root itself).
func openPool(root, parent string, mem budget.Memory) (*cgroup.Group, error) {
	if root == "" {
		return openCgroup(parent)
	}
	b := &cgroup.Group{Path: filepath.Join(root, "broker")}
	if err := os.MkdirAll(b.Path, 0o755); err != nil {
		return nil, err
	}
	if err := b.Join(os.Getpid()); err != nil {
		return nil, err
	}
	r, err := cgroup.Open(root)
	if err != nil {
		return nil, err
	}
	gs, err := mem.Apply(r)
	if err != nil {
		return nil, err
	}
	return gs.Machines, nil
}

func openCgroup(path string) (*cgroup.Group, error) {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, err
	}
	return cgroup.Open(path)
}
