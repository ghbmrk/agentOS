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
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/replay"
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

// lateServices routes each machine to its guest services, which need the
// manager and so are built after it; machines start only once they exist.
// Replay machines (vm.EvalPrefix) go only to the evaluator's plane, never
// the live one with its journal, executors and owner (replay R7); every
// other machine goes to the live guest plane.
type lateServices struct{ live, eval atomic.Pointer[svc] }

type svc struct{ vm.Services }

func (l *lateServices) pick(id string) *svc {
	if strings.HasPrefix(id, vm.EvalPrefix) {
		return l.eval.Load()
	}
	return l.live.Load()
}

func (l *lateServices) Open(id string) (string, error) {
	s := l.pick(id)
	if s == nil {
		return "", fmt.Errorf("no guest services for %s yet", id)
	}
	return s.Open(id)
}

func (l *lateServices) Close(id string) {
	if s := l.pick(id); s != nil {
		s.Close(id)
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

func main() {
	var cfg daemon.Config
	imgs := images{}
	var stateDir, runsc, cgroupParent, meterPath, agentMachine, inboxPath, egressSocket, verifySocket string
	var agentImage, agentLaunch string
	var diskReserveMB, agentMemMB, replayMemMB int64
	var learn learnPaths
	flag.StringVar(&cfg.JournalPath, "journal", "/var/lib/agentos/journal.log", "journal file")
	flag.StringVar(&cfg.SocketDir, "sockets", "/run/agentos", "socket directory (created 0700)")
	flag.StringVar(&cfg.OwnerNumber, "owner", "", "owner's phone number, E.164")
	flag.IntVar(&cfg.ModemUID, "modem-uid", -1, "uid of the modem bridge, the only peer allowed on the owner socket")
	flag.Int64Var(&cfg.Admission.CapacityMB, "capacity-mb", defaultCapacityMB, "memory for agent machines, MB; unset, MemTotal less the floor budget outside the pool, at most the default (PE6)")
	flag.Int64Var(&cfg.Admission.HeadroomMB, "headroom-mb", defaultHeadroomMB, "memory never admitted into, MB")
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
	flag.Int64Var(&agentMemMB, "agent-mem-mb", defaultAgentMemMB, "the agent machine's memory budget, MB")
	flag.StringVar(&inboxPath, "guest-inbox", "/var/lib/agentos/guest-inbox.json", "unanswered owner messages to guests, kept across restarts")
	flag.StringVar(&egressSocket, "egress", "/run/agentos-egress/model.sock", "the vault process's model socket (agentos-egress); empty serves no model route")
	flag.StringVar(&verifySocket, "owner-verify", "/run/agentos-egress/verify.sock", "the vault process's verify socket, which checks the owner's code-generator codes; empty refuses high-tier codes")
	flag.StringVar(&learn.Dir, "learn", "/var/lib/agentos/learn", "change pipeline and loop scheduler state (W3)")
	flag.StringVar(&learn.Spare, "spare-meter", "/var/lib/agentos/spare-meter.json", "spare-time model budget state (LOOP-2), apart from -meter")
	flag.StringVar(&learn.Routing, "routing", "/run/agentos-egress/routing.sock", "the vault process's routing socket, through which routing changes are read and adopted (W3); empty holds routing changes")
	flag.Int64Var(&replayMemMB, "replay-mem-mb", defaultReplayMemMB, "a replay machine's memory budget, MB (LOOP-5); with -agent-mem-mb it must fit in -capacity-mb less -headroom-mb")
	qcfg := defaultQuestionConfig("/var/lib/agentos")
	flag.StringVar(&qcfg.Path, "questions", qcfg.Path, "agents' questions to the owner, kept across restarts (P3-8)")
	flag.StringVar(&qcfg.ClockPath, "clock-state", qcfg.ClockPath, "the box clock check's state (P2-9)")
	flag.Parse()
	capacitySet := false
	flag.Visit(func(f *flag.Flag) { capacitySet = capacitySet || f.Name == "capacity-mb" })
	meminfo, _ := os.ReadFile("/proc/meminfo")
	var why string
	cfg.Admission.CapacityMB, why = capacityFor(string(meminfo), capacitySet, cfg.Admission.CapacityMB)
	log.Printf("admission capacity: %d MB (%s)", cfg.Admission.CapacityMB, why)
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
	// Agents' questions (W9): owner replies are answered before task chat
	// reaches the agent.
	qs := &questions{}
	// STATUS notes read in wiring order: the time check, then spare-time
	// work not running (learningOff, below). Keep the clock first.
	qs.wire(&cfg)
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
	if verifySocket != "" {
		cfg.OwnerVerifier = ownerVerifier{modelroute.NewVerifier(verifySocket)}
	}
	// No modem driver exists before P2-3, so texts arrive only through the
	// owner socket and the channel's own outbound texts are not sent.

	// The learning plane failing must not take the owner channel down
	// either: without it loop settings are refused and nothing adopts.
	var lp *learning
	if err := os.MkdirAll(learn.Dir, 0o700); err != nil {
		log.Printf("learning disabled: %v", err)
	} else if lp, err = openLearning(learn, runsc != "" && egressSocket != "", &cfg); err != nil {
		log.Printf("learning disabled: %v", err)
	}
	if lp == nil {
		learningOff(&cfg)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	if lp != nil {
		lp.attach(ctx, d)
	}
	// The owner channel failing to take questions must not take it down:
	// the tools are then not offered and replies are task chat.
	if err := qs.open(ctx, d, pre, qcfg); err != nil {
		log.Printf("owner questions disabled: %v", err)
	}
	// At exit the question loops stop before the guard's notices flush.
	defer func() { stop(); qs.wait() }()
	if runsc != "" {
		services := &lateServices{}
		m, err := vm.Open(ctx, vm.Config{
			StateDir: stateDir,
			Images:   imgs,
			Runtime:  &gvisor.Runtime{Bin: runsc, StateDir: filepath.Join(stateDir, "runsc")},
			Admit:    d.Admission(),
			Cgroups:  cg,
			Services: services,

			DiskReserveBytes: diskReserveMB << 20,
		})
		if err != nil {
			log.Printf("agent machines disabled: %v", err)
		} else {
			pre.m.Store(m)
			if plane, err := openGuestPlane(m, d, cfg.SocketDir, meterPath, inboxPath, egressSocket, qs.tools()); err != nil {
				// Machines cannot start without their guest sockets.
				log.Printf("agent machines disabled: %v", err)
			} else {
				services.live.Store(&svc{plane})
				oa := &guest.OwnerAgent{Plane: plane, Machine: agentMachine}
				if lp != nil {
					oa.Delivered = lp.delivered
				}
				agent.a.Store(oa)
				defer plane.Shutdown()
				if lp != nil {
					// Replay machines run the agent's image and launch.
					spec, err := agentSpec(imgs, agentImage, agentLaunch, replayMemMB)
					if err == nil {
						if err = replayFits(cfg.Admission.CapacityMB, cfg.Admission.HeadroomMB, agentMemMB, replayMemMB); err != nil {
							lp.noRoom.Store(true) // STATUS and LEARNING ON say so
						}
					}
					if err == nil {
						var ev *replay.Evaluator
						if ev, err = lp.openEvaluator(m, services, evalConfig{Dir: filepath.Join(cfg.SocketDir, "replay"), Spec: spec, Egress: egressSocket}); err == nil {
							defer ev.Shutdown()
						}
					}
					if err != nil {
						log.Printf("replay evaluation disabled: %v", err)
					}
				}
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
	log.Printf("broker up; owner socket %s/%s", cfg.SocketDir, daemon.OwnerSocket)
	d.Wait()
}

// Memory defaults, MB, from the RES-2 floor budget: an agent-machine pool
// of about 3.9 GB (capacity less headroom) on the N95. A replay machine
// gets its own budget, smaller than the agent's (PE2).
const (
	defaultCapacityMB  = 4500
	defaultHeadroomMB  = 600
	defaultAgentMemMB  = 1536
	defaultReplayMemMB = 1024
)

// The rest of the RES-2 floor budget, MB: what the box keeps outside the
// agent-machine pool. The S1 test kit's floor_fit uses the same figures.
const (
	floorHostMB      = 1024 // host, broker and journal
	floorInferenceMB = 2048 // local inference
	floorBrowserMB   = 512  // one credentialed browser
)

// capacityFor is PE6: unless -capacity-mb was given, admission's capacity
// is MemTotal less the floor budget outside the pool, at most
// defaultCapacityMB, so a box smaller than the budget assumed (the N95 has
// about 7.5 GB usable, not 8) is not over-committed. It returns the
// capacity and why, for the log.
func capacityFor(meminfo string, explicit bool, flagMB int64) (int64, string) {
	if explicit {
		return flagMB, "set by -capacity-mb"
	}
	var kb int64
	for _, line := range strings.Split(meminfo, "\n") {
		if v, ok := strings.CutPrefix(line, "MemTotal:"); ok {
			kb, _ = strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
		}
	}
	if kb <= 0 {
		return flagMB, "MemTotal unreadable; the default"
	}
	total := kb >> 10
	n := min(total-floorHostMB-floorInferenceMB-floorBrowserMB, defaultCapacityMB)
	return n, fmt.Sprintf("MemTotal %d MB less host %d, inference %d and browser %d, at most %d",
		total, floorHostMB, floorInferenceMB, floorBrowserMB, defaultCapacityMB)
}

// replayFits is PE2: the agent machine and one replay machine must fit in
// the pool admission hands out (capacity less headroom) at once. If they
// do not, admission refuses or preempts every evaluation while the agent
// runs (replay R6) and learning stalls without a word, so replay
// evaluation is not opened and the log says why.
func replayFits(capacityMB, headroomMB, agentMB, replayMB int64) error {
	if replayMB <= 0 {
		return fmt.Errorf("-replay-mem-mb is %d", replayMB)
	}
	if pool := capacityMB - headroomMB; agentMB+replayMB > pool {
		return fmt.Errorf("the agent machine (%d MB) and one replay machine (%d MB) do not fit in the %d MB pool (-capacity-mb less -headroom-mb)", agentMB, replayMB, pool)
	}
	return nil
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
		// Further broker tools: the owner-question tools (W9).
		Tools: tools,
		Logf:  log.Printf,
	}
	if egressSocket != "" {
		gcfg.Model = modelroute.Forward(modelroute.Config{
			Socket: egressSocket,
			Label:  m.DataLabel,
			Denied: modelroute.Journal(eng, log.Printf),
			Logf:   log.Printf,
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
