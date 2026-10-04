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
	var stateDir, runsc, cgroupParent string
	var diskReserveMB int64
	flag.StringVar(&cfg.JournalPath, "journal", "/var/lib/agentos/journal.log", "journal file")
	flag.StringVar(&cfg.SocketDir, "sockets", "/run/agentos", "socket directory (created 0700)")
	flag.StringVar(&cfg.OwnerNumber, "owner", "", "owner's phone number, E.164")
	flag.IntVar(&cfg.ModemUID, "modem-uid", -1, "uid of the modem bridge, the only peer allowed on the owner socket")
	flag.Int64Var(&cfg.Admission.CapacityMB, "capacity-mb", 4500, "memory for agent machines, MB")
	flag.Int64Var(&cfg.Admission.HeadroomMB, "headroom-mb", 600, "memory never admitted into, MB")
	flag.Float64Var(&cfg.MaxPressure, "max-pressure", 10, "memory PSI (some avg10, %) above which only foreground is admitted")
	flag.StringVar(&stateDir, "machines", "/var/lib/agentos/machines", "agent-machine layers and snapshots (created 0700)")
	flag.StringVar(&runsc, "runsc", "", "gVisor runsc binary; empty runs no agent machines")
	flag.StringVar(&cgroupParent, "cgroup", "/sys/fs/cgroup/agentos.slice/machines", "cgroup v2 parent for agent machines")
	flag.Int64Var(&diskReserveMB, "disk-reserve-mb", 2048, "state-disk space snapshots never use (RES-4 reserve), MB")
	flag.Var(imgs, "image", "agent-machine image, name=dir (repeatable)")
	flag.Parse()
	if cfg.ModemUID < 0 || cfg.ModemUID == os.Getuid() {
		log.Fatal("-modem-uid must name the modem bridge's own uid, distinct from the broker's")
	}

	// The machine plane failing must not take the owner channel down with
	// it: STOP and STATUS keep working, and no machines run.
	var cg *cgroup.Group
	psiPath := "/proc/pressure/memory"
	if runsc != "" {
		g, err := openCgroup(cgroupParent)
		if err != nil {
			log.Printf("agent machines disabled: %v", err)
			runsc = ""
		} else {
			cg, psiPath = g, filepath.Join(cgroupParent, "memory.pressure")
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
		}
	}
	log.Printf("broker up; owner socket %s/%s", cfg.SocketDir, daemon.OwnerSocket)
	d.Wait()
}

func openCgroup(path string) (*cgroup.Group, error) {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, err
	}
	return cgroup.Open(path)
}
