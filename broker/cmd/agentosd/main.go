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
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/meter"
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

// machines adapts the machine manager to the guest plane.
type machines struct{ m *vm.Manager }

func (a machines) Step(ctx context.Context, id string) error {
	_, err := a.m.Step(ctx, id)
	return err
}

func (a machines) RaisePrivate(id string) error { return a.m.RaiseLabel(id, vm.Private) }

func (a machines) Lineage(id string) (string, error) {
	mc, err := a.m.Get(id)
	return mc.Lineage, err
}

// lateServices forwards to the guest plane, which needs the manager and so
// is built after it; machines start only once both exist.
type lateServices struct{ p atomic.Pointer[guest.Plane] }

func (l *lateServices) Open(id string) (string, error) {
	p := l.p.Load()
	if p == nil {
		return "", errors.New("guest plane not open")
	}
	return p.Open(id)
}

func (l *lateServices) Close(id string) {
	if p := l.p.Load(); p != nil {
		p.Close(id)
	}
}

// lateAgent hands owner chat to the guest plane once it exists.
type lateAgent struct {
	a atomic.Pointer[guest.OwnerAgent]
}

func (l *lateAgent) Deliver(ctx context.Context, text string, public bool) error {
	a := l.a.Load()
	if a == nil {
		return errors.New("no agent machine is running")
	}
	return a.Deliver(ctx, text, public)
}

func main() {
	var cfg daemon.Config
	imgs := images{}
	var stateDir, runsc, cgroupParent, meterPath, agentMachine string
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
	flag.Var(imgs, "image", "agent-machine image, name=dir (repeatable)")
	flag.StringVar(&meterPath, "meter", "/var/lib/agentos/meter.json", "model-spend meter state (OP-8)")
	flag.StringVar(&cfg.OwnerState, "owner-state", "/var/lib/agentos/owner.json", "owner channel state (P1-5)")
	flag.StringVar(&agentMachine, "agent-machine", "agent", "machine whose guest receives the owner's task chat")
	flag.Parse()
	if cfg.ModemUID < 0 || cfg.ModemUID == os.Getuid() {
		log.Fatal("-modem-uid must name the modem bridge's own uid, distinct from the broker's")
	}

	var cg *cgroup.Group
	psiPath := "/proc/pressure/memory"
	if runsc != "" {
		if err := os.MkdirAll(cgroupParent, 0o755); err != nil {
			log.Fatal(err)
		}
		g, err := cgroup.Open(cgroupParent)
		if err != nil {
			log.Fatal(err)
		}
		cg, psiPath = g, filepath.Join(cgroupParent, "memory.pressure")
	}
	if read, ok := cgroup.PressureSource(psiPath); ok {
		cfg.Pressure = read
	} else {
		log.Printf("no PSI at %s: admission uses the memory budget alone", psiPath)
	}
	pre := &preempter{}
	cfg.Preempter = pre
	agent := &lateAgent{}
	cfg.Agent = agent
	// The high-tier code seeds come from the vault, which no process may
	// unlock before P2-4; until then the channel refuses high-tier codes.
	// No modem driver exists before P2-3, so texts arrive only through the
	// owner socket and the channel's own outbound texts are not sent.

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	if runsc != "" {
		svc := &lateServices{}
		m, err := vm.Open(ctx, vm.Config{
			StateDir: stateDir,
			Images:   imgs,
			Runtime:  &gvisor.Runtime{Bin: runsc, StateDir: filepath.Join(stateDir, "runsc")},
			Admit:    d.Admission(),
			Cgroups:  cg,
			Services: svc,
		})
		if err != nil {
			log.Fatal(err)
		}
		pre.m.Store(m)
		eng := d.Engine()
		mtr, err := meter.Open(meter.Config{
			Path:           meterPath,
			MachineCap:     meter.DefaultMachineCap,
			OverallCap:     meter.DefaultOverallCap,
			DailyExtension: meter.DefaultDailyExtension,
			Notify: func(e meter.Exhausted) {
				// The owner channel (P1-5) renders this for the owner;
				// until it is wired, the journal holds it.
				if err := eng.RecordEgress(guest.SpendNote(e)); err != nil {
					log.Printf("journal spend limit for %s: %v", e.Machine, err)
				}
			},
		})
		if err != nil {
			log.Fatal(err)
		}
		// ARC-6: each machine gets its own guest socket. Model egress
		// needs the vault, which no process may unlock before P2-4, so
		// model calls answer 503 until then; broker tools, per-step
		// snapshots, and the owner inbox work now.
		plane, err := guest.New(guest.Config{
			Dir:      filepath.Join(cfg.SocketDir, "guests"),
			Machines: machines{m},
			Effects:  eng,
			Meter:    mtr,
			OwnerReply: func(machine, _, text string) {
				if err := d.Owner().Notify(text); err != nil {
					log.Printf("reply from %s not sent: %v", machine, err)
				}
			},
			Logf: log.Printf,
		})
		if err != nil {
			log.Fatal(err)
		}
		svc.p.Store(plane)
		agent.a.Store(&guest.OwnerAgent{Plane: plane, Machine: agentMachine})
		defer plane.Shutdown()
	}
	log.Printf("broker up; owner socket %s/%s", cfg.SocketDir, daemon.OwnerSocket)
	d.Wait()
}
