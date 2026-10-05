// Command agentosd runs the AgentOS broker.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/recall"
	"github.com/ghbmrk/agentos/broker/recalltool"
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

// lateStatus is STATUS's agent line: the keeper's once it runs, and "not
// set up" before that or when no keeper could start.
type lateStatus struct{ k atomic.Pointer[keeper] }

func (l *lateStatus) Status() string {
	if k := l.k.Load(); k != nil {
		return k.Status()
	}
	return agentNotSet
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

// recallLabels gives the recall index the machine manager's REV-5 labels.
// Raise returns once the label is private, which model egress and the
// guest plane read per request.
type recallLabels struct{ m *vm.Manager }

func (r recallLabels) Label(id string) recall.Label {
	if r.m.DataLabel(id) == vm.Public.String() {
		return recall.Public
	}
	return recall.Private
}

func (r recallLabels) Raise(id string) error { return r.m.RaiseLabel(id, vm.Private) }

// openRecall waits for the owner to unlock the vault, takes the recall
// identity key from the vault process (recall K5), and opens recall, its
// event bus and provenance record, then serves the recall tools. Until then
// the tools answer that recall opens after the unlock. STOP and STATUS
// never wait on any of it. sc carries the labels and where deletions reach
// (the journal and, when machines run, the machine manager).
func openRecall(ctx context.Context, v *modelroute.Verifier, sc recalltool.ServiceConfig, late *recalltool.Late, exec *recalltool.LateExecutor) {
	var key []byte
	for {
		k, err := v.RecallKey()
		if err == nil {
			key = k
			break
		}
		if !errors.Is(err, modelroute.ErrVaultLocked) {
			log.Printf("recall: waiting for the vault process: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
	sc.Key, sc.Logf = key, log.Printf
	svc, err := recalltool.OpenService(sc)
	clear(key)
	if err != nil {
		log.Printf("recall disabled: %v", err)
		return
	}
	late.Set(svc.Tools)
	exec.Set(svc.Reach)
	log.Printf("recall open: %d items", svc.Index.Len())
	svc.Run(ctx, log.Printf)
	svc.Close()
}

func main() {
	var cfg daemon.Config
	imgs := images{}
	var stateDir, runsc, cgroupParent, meterPath, agentMachine, inboxPath, egressSocket, verifySocket, recallDir string
	var agentImage, agentLaunch string
	var diskReserveMB, agentMemMB int64
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
	flag.StringVar(&meterPath, "meter", "/var/lib/agentos/meter.json", "model-spend meter state (OP-8)")
	flag.StringVar(&cfg.OwnerState, "owner-state", "/var/lib/agentos/owner.json", "owner channel state (P1-5)")
	flag.StringVar(&agentMachine, "agent-machine", "agent", "machine whose guest receives the owner's task chat")
	flag.StringVar(&agentImage, "agent-image", "openclaw", "image the agent machine is created from on first start; empty keeps no agent machine")
	flag.StringVar(&agentLaunch, "agent-launch", "/usr/lib/agentos/guest/launch.json", "how the agent machine starts: argv and env (guest/openclaw/launch.json)")
	flag.Int64Var(&agentMemMB, "agent-mem-mb", 1536, "the agent machine's memory budget, MB")
	flag.StringVar(&inboxPath, "guest-inbox", "/var/lib/agentos/guest-inbox.json", "unanswered owner messages to guests, kept across restarts")
	flag.StringVar(&egressSocket, "egress", "/run/agentos-egress/model.sock", "the vault process's model socket (agentos-egress); empty serves no model route")
	flag.StringVar(&recallDir, "recall", "/var/lib/agentos/recall", "recall index, event bus and provenance (created 0700); empty runs no recall")
	flag.StringVar(&verifySocket, "owner-verify", "/run/agentos-egress/verify.sock", "the vault process's verify socket, which checks the owner's code-generator codes; empty refuses high-tier codes")
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
	agent := &lateAgent{}
	cfg.Agent = agent
	// Until the keeper runs, STATUS says the agent is not set up; it says
	// so for good if the machine plane or the agent's setup fails.
	agentStatus := &lateStatus{}
	cfg.AgentStatus = agentStatus.Status
	// The code-generator seed lives in the vault, which only the vault
	// process holds (P2-4a); the channel asks it to check high-tier codes
	// (egress K7). While the vault is locked those checks fail and count
	// nothing.
	var verifier *modelroute.Verifier
	if verifySocket != "" {
		verifier = modelroute.NewVerifier(verifySocket)
		cfg.OwnerVerifier = ownerVerifier{verifier}
	}
	recallTools := &recalltool.Late{}
	// Rollbacks the owner approves run here (recalltool W10).
	recallExec := &recalltool.LateExecutor{}
	cfg.Recall = recallExec
	cfg.Grants.Contained = recallExec.Contained
	// No modem driver exists before P2-3, so texts arrive only through the
	// owner socket and the channel's own outbound texts are not sent.

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	// Deletions reach the journal's guest intents (CAP-3). The change
	// pipeline is not run by the broker yet; whoever wires it sets Cases.
	recallCfg := recalltool.ServiceConfig{Dir: recallDir, Journal: d.Engine(), Ask: d.Gate(), Location: time.Local}
	if runsc != "" {
		svc := &lateServices{}
		m, err := vm.Open(ctx, vm.Config{
			StateDir: stateDir,
			Images:   imgs,
			Runtime:  &gvisor.Runtime{Bin: runsc, StateDir: filepath.Join(stateDir, "runsc")},
			Admit:    d.Admission(),
			Cgroups:  cg,
			Services: svc,

			DiskReserveBytes: diskReserveMB << 20,
		})
		if err != nil {
			log.Printf("agent machines disabled: %v", err)
		} else {
			pre.m.Store(m)
			recallCfg.Labeler, recallCfg.Machines = recallLabels{m}, m
			if plane, err := openGuestPlane(m, d, cfg.SocketDir, meterPath, inboxPath, egressSocket, recallTools); err != nil {
				// Machines cannot start without their guest sockets.
				log.Printf("agent machines disabled: %v", err)
			} else {
				svc.p.Store(plane)
				agent.a.Store(&guest.OwnerAgent{Plane: plane, Machine: agentMachine})
				defer plane.Shutdown()
				spec, err := agentSpec(imgs, agentImage, agentLaunch, agentMemMB)
				if err != nil {
					log.Printf("no agent machine kept running: %v", err)
				} else {
					k := &keeper{m: m, id: agentMachine, spec: spec, every: 30 * time.Second, logf: log.Printf, status: agentWaiting}
					agentStatus.k.Store(k)
					go k.run(ctx)
				}
			}
		}
	}
	// The recall identity key is vault-held (recall K5): recall opens once
	// the vault process can hand it over.
	if recallDir != "" && verifier != nil {
		go openRecall(ctx, verifier, recallCfg, recallTools, recallExec)
	}
	log.Printf("broker up; owner socket %s/%s", cfg.SocketDir, daemon.OwnerSocket)
	d.Wait()
}

// agentSpec is how the owner's agent machine starts, from the image flags
// and the guest rig's launch file.
func agentSpec(imgs images, image, launch string, memMB int64) (vm.Spec, error) {
	if image == "" {
		return vm.Spec{}, errors.New("-agent-image is empty")
	}
	if _, ok := imgs[image]; !ok {
		return vm.Spec{}, fmt.Errorf("image %q is not registered with -image", image)
	}
	argv, env, err := launchSpec(launch)
	if err != nil {
		return vm.Spec{}, err
	}
	return vm.Spec{Image: image, Class: admission.Foreground, MemMB: memMB, Argv: argv, Env: env, Label: vm.Public}, nil
}

func openCgroup(path string) (*cgroup.Group, error) {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, err
	}
	return cgroup.Open(path)
}

// openGuestPlane opens the OP-8 meter and the guest plane (ARC-6) over the
// machine manager. Without them no agent machine can start.
func openGuestPlane(m *vm.Manager, d *daemon.Daemon, socketDir, meterPath, inboxPath, egressSocket string, tools guest.Tools) (*guest.Plane, error) {
	eng := d.Engine()
	mtr, err := meter.Open(meter.Config{
		Path:           meterPath,
		MachineCap:     meter.DefaultMachineCap,
		OverallCap:     meter.DefaultOverallCap,
		DailyExtension: meter.DefaultDailyExtension,
		Notify: func(e meter.Exhausted) {
			// The journal holds it; the owner sees it in STATUS and
			// the digest once those render egress records.
			if err := eng.RecordEgress(guest.SpendNote(e)); err != nil {
				log.Printf("journal spend limit for %s: %v", e.Machine, err)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	// ARC-6: each machine gets its own guest socket. Its model route is
	// metered here, then forwarded to the vault process (P2-4a), which
	// holds the vault and runs the router and egress proxy; this process
	// links neither. Labels come from m.DataLabel, which reads private
	// for any machine it cannot vouch for (REV-5, E10). Until the owner
	// unlocks the vault, model calls answer 503.
	gcfg := guest.Config{
		Dir:       filepath.Join(socketDir, "guests"),
		InboxPath: inboxPath,
		Machines:  machines{m},
		// The grants gate decides every effect (OP-5, REV-2) and routes
		// only accounts a grant connects.
		Effects: d.Gate(),
		Route:   d.Gate().Route,
		Label: func(id string) string {
			if l, err := m.Label(id); err == nil && l == vm.Public {
				return "public"
			}
			return "private"
		},
		Meter: mtr,
		OwnerReply: func(machine, _, text string) {
			ch := d.Owner()
			if ch == nil {
				log.Printf("reply from %s not sent: no owner channel", machine)
				return
			}
			if err := ch.Notify(text); err != nil {
				log.Printf("reply from %s not sent: %v", machine, err)
			}
		},
		Logf: log.Printf,
		// The recall tools (CAP-3), live once the vault is unlocked.
		Tools: tools,
	}
	if egressSocket != "" {
		gcfg.Model = modelroute.Forward(modelroute.Config{
			Socket: egressSocket,
			Label:  m.DataLabel,
			Denied: func(machine string, x modelroute.Denial) {
				n := journal.EgressNote{Machine: machine, Adapter: x.Adapter, Operation: x.Operation, Method: x.Method, Status: x.Status, Reason: x.Reason}
				if n.Reason == "" {
					n.Reason = "denied"
				}
				if err := eng.RecordEgress(n); err != nil {
					log.Printf("journal egress denial for %s: %v", machine, err)
				}
			},
			Logf: log.Printf,
		})
	}
	return guest.New(gcfg)
}

// ownerVerifier gives the owner channel the vault process's verify
// operation, translating why a check did not run into the channel's terms.
type ownerVerifier struct{ v *modelroute.Verifier }

func (o ownerVerifier) VerifyTOTP(code string, after int64, counted bool) (int64, bool, error) {
	step, ok, err := o.v.VerifyTOTP(code, after, counted)
	return step, ok, ownerVerifyErr(err)
}

func ownerVerifyErr(err error) error {
	var ve *modelroute.VerifyError
	if err == nil || !errors.As(err, &ve) {
		return err
	}
	kind := map[modelroute.VerifyFailure]owner.VerifyFailure{
		modelroute.VerifyDown:   owner.VaultDown,
		modelroute.VerifyLocked: owner.VaultLocked,
		modelroute.VerifyPaused: owner.VerifyPaused,
		modelroute.VerifyLost:   owner.VerifyLost,
	}[ve.Kind]
	return &owner.VerifyError{Kind: kind, Until: ve.Until}
}
