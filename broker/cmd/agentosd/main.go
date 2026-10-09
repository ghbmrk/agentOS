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
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/accel"
	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/budget"
	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/loopbuild"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/recall"
	"github.com/ghbmrk/agentos/broker/recalltool"
	"github.com/ghbmrk/agentos/broker/replay"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/vm/gvisor"
	"github.com/ghbmrk/agentos/broker/workers"
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
	return stepErr(err)
}

// stepErr marks a failed step snapshot's reason for the guest plane,
// which tells the agent and STATUS a fixed text for it (SR2-3s). A layer
// too deep to measure is checked first: the manager reports it as a
// disk budget too.
func stepErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, vm.ErrTooDeep):
		return fmt.Errorf("%w: %w", guest.ErrStepTooDeep, err)
	case errors.Is(err, vm.ErrQuota):
		return fmt.Errorf("%w: %w", guest.ErrStepNoRoom, err)
	}
	return err
}

// stepSource is the guest plane's view of failing step snapshots.
type stepSource interface {
	StepNote() string
	StepLine() (string, time.Time)
}

type stepSrc struct{ stepSource }

// stepNotes is STATUS's line while the agent's step snapshots keep
// failing, once the guest plane is open (SR2-3s).
type stepNotes struct{ p atomic.Pointer[stepSrc] }

// newStepNotes adds the line to STATUS's notes; it stays empty until open.
func newStepNotes(notes *[]func() string) *stepNotes {
	n := &stepNotes{}
	*notes = append(*notes, n.Note)
	return n
}

// open points the line at src and, with a digest to tell, starts telling
// it there.
func (n *stepNotes) open(ctx context.Context, src stepSource, notice func(key, line string) error) {
	n.p.Store(&stepSrc{src})
	if notice != nil {
		go n.digest(ctx, notice)
	}
}

func (n *stepNotes) Note() string {
	if p := n.p.Load(); p != nil {
		return p.StepNote()
	}
	return ""
}

// digestPeriod is how long the Rollback line stands before the digest
// carries it too (security R1, UX on SR2-3s).
const digestPeriod = 24 * time.Hour

// stepDigestKey is the digest notice key for the Rollback line STATUS has
// carried since shown, at now: none in the first digest period, then one
// a day for 7 days, then one a week (W5's cadence). The key holds the
// line, so a new reason or since-time is told at once; a success clears
// the line, and with it any further key.
func stepDigestKey(line string, shown, now time.Time) (string, bool) {
	if line == "" || now.Sub(shown) < digestPeriod {
		return "", false
	}
	d := int(now.Sub(shown) / digestPeriod)
	if d > 7 {
		d = 8 + (d-8)/7
	}
	return fmt.Sprintf("sr2-3s:%d:%s", d, line), true
}

// digest queues the Rollback line for the owner's digest on stepDigestKey's
// cadence, each minute until ctx ends. The line is the STATUS line,
// verbatim: the digest adds no wording of its own.
func (n *stepNotes) digest(ctx context.Context, notice func(key, line string) error) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		p := n.p.Load()
		if p == nil {
			continue
		}
		line, shown := p.StepLine()
		if key, ok := stepDigestKey(line, shown, time.Now()); ok {
			if err := notice(key, line); err != nil {
				log.Printf("rollback digest line: %v", err)
			}
		}
	}
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
type lateServices struct{ live, eval, build atomic.Pointer[svc] }

type svc struct{ vm.Services }

func (l *lateServices) pick(id string) *svc {
	switch {
	case strings.HasPrefix(id, vm.EvalPrefix):
		return l.eval.Load()
	case strings.HasPrefix(id, loopbuild.Prefix):
		// Loop 1's builder machines get the builder's socket or nothing,
		// never the live plane with managed_tree (C-3c-2).
		return l.build.Load()
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
type lateStatus struct {
	k   atomic.Pointer[keeper]
	off string // set before the daemon runs: why the agent is off (PE6)
	// caps is the capability-off registry's state: when its line names
	// the agent, this line says nothing, so STATUS has one (OP-9).
	caps *capState
}

func (l *lateStatus) Status() string {
	if k := l.k.Load(); k != nil {
		return k.Status()
	}
	if l.off != "" {
		return l.off
	}
	if l.caps != nil && l.caps.agentNamed() {
		return ""
	}
	return agentNotSet
}

// lateAgent hands owner chat to the guest plane once it exists. A
// message delivered while the agent sleeps wakes it (PE7): the message
// waits in the agent's inbox meanwhile, and its start hands it over, warm
// or cold alike (UX P2-c).
type lateAgent struct {
	a     atomic.Pointer[ownerAgent]
	sleep atomic.Pointer[sleeper]
	last  atomic.Int64 // unix nanoseconds of the last delivery
}

func (l *lateAgent) Deliver(ctx context.Context, text string, public bool) error {
	a := l.a.Load()
	if a == nil {
		return errors.New("no agent machine is running")
	}
	err := (*a).Deliver(ctx, text, public)
	if err == nil {
		now := time.Now
		if s := l.sleep.Load(); s != nil {
			now = s.cfg.Now // the clock the sleeper measures the hold on
		}
		l.delivered(now())
	}
	return err
}

// ownerAgent is where owner chat goes (guest.OwnerAgent).
type ownerAgent interface {
	Deliver(ctx context.Context, text string, public bool) error
}

// delivered notes an owner message that reached the agent's inbox at t,
// and wakes the agent if it sleeps.
func (l *lateAgent) delivered(t time.Time) {
	l.last.Store(t.UnixNano())
	if s := l.sleep.Load(); s != nil && s.Asleep() {
		go s.OwnerMessage(t)
	}
}

// lastDelivered is when an owner message last reached the agent.
func (l *lateAgent) lastDelivered() time.Time {
	if n := l.last.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
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

// recallMachines is where a recall deletion reaches the machines.
type recallMachines struct{ *vm.Manager }

func (r recallMachines) Plan(lineage string, since time.Time) (recalltool.Plan, error) {
	p, err := r.ResetPlan(lineage, since)
	return recalltool.Plan{To: p.To, Changes: p.Changes}, err
}

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
		log.Printf("recall disabled: %v; agents stay contained", err)
		exec.Failed()
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
	var stateDir, runsc, cgroupRoot, accelMode, meterPath, agentMachine, inboxPath, egressSocket, verifySocket, recallDir string
	var agentImage, agentLaunch string
	var diskReserveMB, machineDiskMB, agentMemMB, replayMemMB, builderMemMB int64
	var diskQuota, sleepHoursFlag string
	var builderImage, builderLaunch, keptPath, setupRecord string
	var learn learnPaths
	var cgroupVouched, modemBridge, ownerMessage bool
	localUIUID := -1
	floor := budget.Floor()
	flag.StringVar(&cfg.JournalPath, "journal", "/var/lib/agentos/journal.log", "journal file")
	flag.StringVar(&cfg.SocketDir, "sockets", "/run/agentos", "socket directory (created 0700; 0711 once owner.sock, 0660 to the modem bridge's group, is up)")
	flag.StringVar(&cfg.OwnerNumber, "owner", "", "owner's phone number, E.164")
	flag.IntVar(&cfg.ModemUID, "modem-uid", -1, "uid of the modem bridge, the only peer allowed on the owner socket")
	flag.IntVar(&localUIUID, "localui-uid", -1, "uid of the local UI (agentos-localui), the only peer allowed on localui.sock; unset, the socket is not served (P2-2w)")
	var updateStore, shippedRoot string
	flag.StringVar(&updateStore, "update-store", "", "the box's update store, already trusting a root; with -shipped-root and the local page, the owner can change where updates come from (OSS-10)")
	flag.StringVar(&shippedRoot, "shipped-root", "", "the root of trust this image ships (switching back needs its keys, WF1)")
	flag.BoolVar(&modemBridge, "modem-bridge", true, "serve the modem bridge's ops on the owner socket and send the owner channel's texts through it")
	modemRoles := flag.String("modem-roles", "/var/lib/agentos/modem/roles.json", "agentos-modem's roles file, where a SIM the owner adopts on the local page is recorded")
	flag.BoolVar(&ownerMessage, "owner-message", false, "also serve the raw \"message\" op on the owner socket with the bridge on (simulator and test builds only; it skips the bridge's checks)")
	flag.Int64Var(&cfg.Admission.CapacityMB, "capacity-mb", defaultCapacityMB, "memory for agent machines, MB; unset, MemTotal less the floor budget outside the pool, at most 4500 or one OpenClaw machine per two cores, whichever is more (PE6, RES-2c)")
	flag.Int64Var(&floor.HeadroomMB, "headroom-mb", floor.HeadroomMB, "memory never admitted into, MB")
	flag.Int64Var(&floor.HostMB, "host-mb", floor.HostMB, "budget: host image, broker and journal (protected), MB (RES-2)")
	flag.Int64Var(&floor.InferenceMB, "inference-mb", floor.InferenceMB, "budget: local inference, MB (RES-2)")
	flag.Int64Var(&floor.BrowserMB, "browser-mb", floor.BrowserMB, "budget: one credentialed browser, MB (RES-2)")
	flag.StringVar(&cgroupRoot, "cgroup-root", "", "cgroup v2 group for the broker's components (RES-2): its own group or below; empty is the broker's own group")
	flag.BoolVar(&cgroupVouched, "cgroup-delegated", false, "-cgroup-root is delegated to the broker (without it, systemd's delegate mark is required)")
	flag.StringVar(&accelMode, "accel", "auto", "accelerator discovery: auto or off (RES-3)")
	flag.Float64Var(&cfg.MaxPressure, "max-pressure", 10, "memory PSI (some avg10, %) above which only foreground is admitted")
	flag.StringVar(&stateDir, "machines", "/var/lib/agentos/machines", "agent-machine layers and snapshots (created 0700)")
	flag.StringVar(&runsc, "runsc", "", "gVisor runsc binary; empty runs no agent machines")
	flag.Int64Var(&diskReserveMB, "disk-reserve-mb", budget.FloorDisk().ReserveBytes()>>20, "state-disk space snapshots never use (RES-4 reserve), MB")
	flag.StringVar(&diskQuota, "disk-quota", "on", "per-machine disk quotas (RES-4): on needs -machines on a file system mounted with prjquota; off lets a guest fill the disk")
	flag.Int64Var(&machineDiskMB, "machine-disk-mb", 8192, "each agent machine's disk budget: its hard quota and largest snapshot, MB (RES-4)")
	flag.Var(imgs, "image", "agent-machine image, name=dir (repeatable)")
	flag.StringVar(&meterPath, "meter", "/var/lib/agentos/meter.json", "model-spend meter state (OP-8)")
	flag.StringVar(&cfg.OwnerState, "owner-state", "/var/lib/agentos/owner.json", "owner channel state (P1-5)")
	flag.StringVar(&setupRecord, "setup-record", "/var/lib/agentos/setup.json", "setup's record (P2-2w c2): with -owner unset, the local UI's setup is served on localui.sock until it records the owner's number here, then never again")
	flag.StringVar(&agentMachine, "agent-machine", "agent", "machine whose guest receives the owner's task chat")
	flag.StringVar(&agentImage, "agent-image", "openclaw", "image the agent machine is created from on first start; empty keeps no agent machine")
	flag.StringVar(&agentLaunch, "agent-launch", "/usr/lib/agentos/guest/launch.json", "how the agent machine starts: argv and env (guest/openclaw/launch.json)")
	flag.Int64Var(&agentMemMB, "agent-mem-mb", defaultAgentMemMB, "the agent machine's memory budget, MB")
	flag.StringVar(&inboxPath, "guest-inbox", "/var/lib/agentos/guest-inbox.json", "unanswered owner messages to guests, kept across restarts")
	flag.StringVar(&egressSocket, "egress", "/run/agentos-egress/model.sock", "the vault process's model socket (agentos-egress); empty serves no model route")
	flag.StringVar(&recallDir, "recall", "/var/lib/agentos/recall", "recall index, event bus and provenance (created 0700); empty runs no recall")
	flag.StringVar(&verifySocket, "owner-verify", "/run/agentos-egress/verify.sock", "the vault process's verify socket, which checks the owner's code-generator codes; empty refuses high-tier codes")
	flag.StringVar(&learn.Dir, "learn", "/var/lib/agentos/learn", "change pipeline and loop scheduler state (W3)")
	flag.StringVar(&learn.Loop7, "loop7", "/var/lib/agentos/loop7", "LOOP-7's fuzz corpora, with crash inputs found on this box, and the fuzz cache (P3-4b-3a)")
	learn.Fuzz = fuzzRelease
	flag.StringVar(&learn.Spare, "spare-meter", "/var/lib/agentos/spare-meter.json", "spare-time model budget state (LOOP-2), apart from -meter")
	flag.StringVar(&learn.Routing, "routing", "/run/agentos-egress/routing.sock", "the vault process's routing socket, through which routing changes are read and adopted (W3); empty holds routing changes")
	flag.StringVar(&builderImage, "builder-image", defaultBuilderImage, "the minimal image Loop 1's builder machines run (W3-builder), registered with -image; empty, or the default not registered, runs no model-backed builder")
	flag.StringVar(&builderLaunch, "builder-launch", defaultBuilderLaunch, "how a builder machine starts: argv and env (guest/builder/launch.json); empty uses the image's own")
	flag.Int64Var(&builderMemMB, "builder-mem-mb", loopbuild.DefaultMemMB, "a builder machine's memory budget, MB")
	flag.StringVar(&sleepHoursFlag, "sleep-hours", "", "on a box where the agent and a replay machine do not fit together, the hours the agent may sleep while the box tests changes, HH:MM-HH:MM box time (PE7); empty is 01:00-06:00")
	var workerImage, workerArgv string
	var workerMaxMB, workerLayerMB int64
	flag.StringVar(&workerImage, "worker-image", "", "the base image worker machines are built from (CAP-8), registered with -image; empty offers guests no worker tools")
	flag.StringVar(&workerArgv, "worker-argv", "sleep infinity", "what a worker machine runs while the guest drives it, space-separated")
	flag.Int64Var(&workerLayerMB, "worker-layer-mb", 4096, "the most one worker's files may hold, MB; over it the worker takes no command or snapshot until it shrinks; 0 is no cap beyond the disk reserve")
	flag.Int64Var(&workerMaxMB, "worker-max-mb", 2048, "the largest memory budget one worker may ask for, MB; admission still decides (RES-2)")
	flag.Int64Var(&replayMemMB, "replay-mem-mb", defaultReplayMemMB, "a replay machine's memory budget, MB (LOOP-5); with -agent-mem-mb it must fit in -capacity-mb less -headroom-mb")
	flag.StringVar(&keptPath, "kept-replies", "/var/lib/agentos/kept-replies.json", "private agent replies that could not be emailed, kept for the local page (CH-20)")
	qcfg := defaultQuestionConfig("/var/lib/agentos")
	flag.StringVar(&qcfg.Path, "questions", qcfg.Path, "agents' questions to the owner, kept across restarts (P3-8)")
	flag.StringVar(&qcfg.ClockPath, "clock-state", qcfg.ClockPath, "the box clock check's state (P2-9)")
	flag.Parse()
	sleepHours, err := parseSleepHours(sleepHoursFlag)
	if err != nil {
		log.Fatal(err)
	}
	if err := checkDiskQuotaFlag(diskQuota); err != nil {
		log.Fatal(err)
	}
	meminfo, _ := os.ReadFile("/proc/meminfo")
	mem := planMemory(string(meminfo), runtime.NumCPU(), flagSet(flag.CommandLine, "capacity-mb"), cfg.Admission.CapacityMB, floor, agentMemMB)
	cfg.Admission = mem.Budget.Admission()
	log.Printf("admission capacity: %d MB (%s); budget MB: host %d, inference %d, browser %d, headroom %d, machines %d",
		mem.CapacityMB, mem.Why, mem.Budget.HostMB, mem.Budget.InferenceMB, mem.Budget.BrowserMB, mem.Budget.HeadroomMB, mem.Budget.PoolMB)
	namedAgentImage := agentImage // the builder never runs it, agent or not
	if mem.AgentOff != "" {
		// The broker stays up, STOP and STATUS included; no agent machine
		// is kept and no replay machine opened, and STATUS says why.
		log.Printf("agent machine disabled: %s", mem.AgentOff)
		agentImage = ""
	}
	if cfg.ModemUID < 0 || cfg.ModemUID == os.Getuid() {
		log.Fatal("-modem-uid must name the modem bridge's own uid, distinct from the broker's")
	}
	// The owner socket is the bridge user's primary group's, 0660 (R3).
	if u, err := user.LookupId(strconv.Itoa(cfg.ModemUID)); err != nil {
		log.Fatalf("-modem-uid %d: %v", cfg.ModemUID, err)
	} else if gid, err := strconv.Atoi(u.Gid); err != nil {
		log.Fatalf("-modem-uid %d: group %q: %v", cfg.ModemUID, u.Gid, err)
	} else {
		cfg.ModemGID = &gid
	}
	// localui.sock is the local UI user's primary group's, 0660, like the
	// owner socket (Security L3 on the P2-2w plan).
	if localUIUID >= 0 {
		if localUIUID == os.Getuid() || localUIUID == cfg.ModemUID {
			log.Fatal("-localui-uid must name the local UI's own uid, distinct from the broker's and the modem bridge's")
		}
		u, err := user.LookupId(strconv.Itoa(localUIUID))
		if err != nil {
			log.Fatalf("-localui-uid %d: %v", localUIUID, err)
		}
		gid, err := strconv.Atoi(u.Gid)
		if err != nil {
			log.Fatalf("-localui-uid %d: group %q: %v", localUIUID, u.Gid, err)
		}
		cfg.PageSocket = &daemon.PageSocket{UID: localUIUID, GID: &gid}
	}
	// A restore the forget log's check held opens nothing on the restored
	// tree: no recall, no agent machines (W3-forget-b1; security C3). The
	// held mode texts the owner why, takes their answer, and the start
	// goes on once it releases the restore (W3-forget-b1-7). With no owner
	// to text, agentosd does not start.
	if held := restoreHold(learn.Dir); held != nil {
		owner, err := heldOwner(cfg.OwnerNumber, localsrv.FileRecord{Path: setupRecord})
		if err != nil {
			log.Fatalf("%v; %v", held, err)
		}
		log.Print(held)
		m := heldMode{Learn: learn.Dir, Dir: cfg.SocketDir, Owner: owner, PeerUID: &cfg.ModemUID, PeerGID: cfg.ModemGID,
			Message: !modemBridge || ownerMessage, Logf: log.Printf}
		if modemBridge {
			m.Link = modemlink.New(modemlink.Config{Owner: owner})
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err = m.run(ctx)
		stop()
		if errors.Is(err, context.Canceled) {
			return
		}
		if err != nil {
			log.Fatal(err)
		}
		if err := restoreHold(learn.Dir); err != nil {
			log.Fatal(err)
		}
	}
	// A box with no -owner is set up by the local UI (P2-2w c2): only
	// setup's ops are served until its finish is recorded, and the owner's
	// number then comes from the record, on this start and every later one.
	if cfg.OwnerNumber == "" {
		m := setupMode{Dir: cfg.SocketDir, Page: cfg.PageSocket, Record: localsrv.FileRecord{Path: setupRecord},
			OwnerState: cfg.OwnerState, Progress: setupProgress}
		if verifySocket != "" {
			m.Enroll = enroller{modelroute.NewVerifier(verifySocket)}
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		owner, err := m.run(ctx)
		stop()
		if errors.Is(err, context.Canceled) {
			return
		}
		if err != nil {
			log.Fatal(err)
		}
		cfg.OwnerNumber = owner
	}

	// RES-3: nothing below depends on what is found here. No local
	// inference service exists yet to take leases (budget R8).
	var devs []accel.Device
	if accelMode != "off" {
		var err error
		if devs, err = accel.Discover("/sys"); err != nil {
			log.Printf("accelerator discovery failed, using CPU: %v", err)
			devs = nil
		}
	}
	log.Print(accel.NewPool(devs).Summary())

	// The machine plane failing must not take the owner channel down with
	// it: STOP and STATUS keep working, and no machines run.
	// Without a delegated group no machine may start: none runs outside
	// its budget (RES-2), and STATUS says why.
	var cg *cgroup.Group
	psiPath := "/proc/pressure/memory"
	agentOff := mem.AgentOff
	if runsc != "" {
		g, err := openMachines(liveCgroups, cgroupRoot, cgroupVouched, mem.Budget)
		if err != nil {
			log.Printf("agent machines disabled: %v", err)
			runsc = ""
			if agentOff == "" {
				agentOff = agentNoLimits
			}
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
	// Agents' questions (W9): owner replies are answered before task chat
	// reaches the agent.
	qs := &questions{}
	// STATUS notes read in wiring order: the time check, then the
	// capability-off lines (OP-9, capoff.go), then spare-time work not
	// running (learningOff, below), then recall's (an agent holding a
	// deleted record, or memory not open), then the second line's. Keep
	// the clock first.
	qs.wire(&cfg)
	// Each line reads live state set as the box opens below; the daemon
	// copies the notes, so they are wired now.
	caps := newCapState(egressSocket)
	caps.machinesUnset(runsc, agentOff)
	capLines := newCapLines(caps)
	capLines.wire(&cfg)
	// No update-check loop (Loop 3, W5b) is built yet: caps.updateChecks
	// is never called, and STATUS says update checks are not running.
	agent := &lateAgent{}
	cfg.Agent = agent
	// Until the keeper runs, STATUS says the agent is not set up; it says
	// so for good if the machine plane or the agent's setup fails.
	agentStatus := &lateStatus{off: agentOff, caps: caps}
	cfg.AgentStatus = agentStatus.Status
	// The code-generator seed lives in the vault, which only the vault
	// process holds (P2-4a); the channel asks it to check high-tier codes
	// (egress K7). While the vault is locked those checks fail and count
	// nothing.
	var verifier *modelroute.Verifier
	var line *secondLine
	if verifySocket != "" {
		verifier = modelroute.NewVerifier(verifySocket)
		cfg.OwnerVerifier = ownerVerifier{verifier}
		// The second line's STATUS line (potency R1 on #139); its digest
		// line waits for the digest's sender.
		line = &secondLine{get: verifier.SecondLine, texts: verifier.SecondLineTexts}
	}
	recallTools := &recalltool.Late{}
	// Rollbacks the owner approves run here (recalltool W10).
	recallExec := &recalltool.LateExecutor{}
	cfg.Recall = recallExec
	cfg.Grants.Contained = recallExec.Contained
	cfg.Notes = append(cfg.Notes, recallExec.Status)
	var md machineDisk
	if runsc != "" {
		md = openMachineDisk(diskQuota, stateDir, &cfg.Notes)
	}
	if line != nil {
		cfg.Notes = append(cfg.Notes, line.Note, line.TextsNote)
	}
	// The modem bridge (agentos-modem, P2-3w) hands owner texts in and
	// pulls the channel's own texts from the owner socket; until it
	// reports the owner line, sends fail as down and are counted for the
	// recovery text. Its note, last outage and counts are for the box's local page (U-B1).
	if modemBridge {
		// A SIM the owner adopts on the page, with a code (P2-2w d2b), is
		// recorded where the bridge reads it at its next open.
		link := modemlink.New(modemlink.Config{Owner: cfg.OwnerNumber, Record: recordOwnerSIM(*modemRoles)})
		cfg.Modem, cfg.OwnerOps = link, link.Ops()
		if cfg.PageSocket != nil {
			cfg.PageSocket.Line, cfg.PageSocket.AdoptSIM = pageLine(link), adoptSIM(link.Adopt)
		}
		cfg.BridgeOnly = !ownerMessage
	}

	// The learning plane failing must not take the owner channel down
	// either: without it loop settings are refused and nothing adopts.
	// The tree's procedures, skills and context reach the agent through
	// managed_tree, private machines only (W4).
	tree := newLiveTree(log.Printf)
	learn.Tree = tree
	asleep := sleepMode(cfg.Admission.CapacityMB, cfg.Admission.HeadroomMB, agentMemMB, replayMemMB)
	learn.ResumeFor = sleepResumeFor(asleep)
	var lp *learning
	if err := os.MkdirAll(learn.Dir, 0o700); err != nil {
		log.Printf("learning disabled: %v", err)
	} else if lp, err = openLearning(learn, runsc != "" && egressSocket != "", &cfg); err != nil {
		log.Printf("learning disabled: %v", err)
	}
	if lp == nil {
		learningOff(&cfg)
	} else {
		lp.forgetOwner.wirePage(&cfg)
		caps.learning(lp) // routing held while learning is on (C12)
	}
	// Evidence delivery (CH-20): with a destination set, private replies
	// are emailed to it. No mail account is connected in this process
	// yet, so none can be set (owns is nil) and replies go by text.
	ev := newEvidence(keptPath, cfg.PageSocket != nil, log.Printf)
	ev.wire(&cfg)
	// Changing where updates come from (OSS-10): on the clock guard's
	// Latest, which questions.open starts; until then nothing is followed.
	fs, err := newFollowSetting(updateStore, shippedRoot, qs.g.Load)
	if err != nil {
		log.Fatal(err)
	}
	if fs != nil && !fs.wire(&cfg) {
		log.Print("-update-store is set but the local page is not served (-localui-uid): updates keep their source")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	steps := newStepNotes(&cfg.Notes)
	if lp != nil && recallDir != "" && verifier != nil {
		// An approved item 2 that finds recall not open yet waits for it
		// (#327 L3 B-3); set before the daemon serves the owner.
		lp.forgetOwner.whenOpen = func() {
			recallExec.OnOpen(func() { go lp.forgetOwner.resumeAgent(ctx) })
		}
	}
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	ev.attach(ctx, d)
	fs.attach(ctx, d)
	// Deletions reach the journal's guest intents (CAP-3), when learning
	// runs what it keeps of them (change C19, learning.ForgetTasks),
	recallCfg := recalltool.ServiceConfig{Dir: recallDir, Journal: d.Engine(), Ask: d.Gate(), Location: time.Local,
		Notify: func(text string) error {
			if ch := d.Owner(); ch != nil {
				return ch.Notify(text)
			}
			return errors.New("no owner channel")
		}}
	// and every reply kept on the box (CH-20).
	fan := forgetFan{kept: ev.kept}
	if lp != nil {
		fan.cases = lp
	}
	recallCfg.Cases = fan
	if lp != nil {
		lp.attach(ctx, d)
	}
	// The owner channel failing to take questions must not take it down:
	// the tools are then not offered and replies are task chat.
	qs.start(ctx, d, pre, qcfg, caps)
	// At exit the question loops stop before the guard's notices flush.
	defer func() { stop(); qs.wait() }()
	if runsc != "" && md.err != nil {
		log.Printf("agent machines disabled: %v", md.err)
		caps.agentOff(agentNoMachines)
	} else if runsc != "" {
		services := &lateServices{}
		vmc := vm.Config{
			StateDir: stateDir,
			Images:   imgs,
			Runtime:  &gvisor.Runtime{Bin: runsc, StateDir: filepath.Join(stateDir, "runsc")},
			Admit:    d.Admission(),
			Cgroups:  cg,
			Services: services,

			DiskReserveBytes: diskReserveMB << 20,
			MachineDiskBytes: machineDiskMB << 20,
			WorkerLayerBytes: workerLayerBytes(workerLayerMB),
			// A lineage holding a record the owner deleted is not forked
			// or merged until that is settled (recall W10).
			Contained: recallExec.Contained,
		}
		md.set(&vmc)
		m, err := vm.Open(ctx, vmc)
		if err != nil {
			log.Printf("agent machines disabled: %v", err)
			caps.agentOff(agentNoMachines)
		} else {
			pre.m.Store(m)
			if lp != nil {
				// FORGET's item 2 (W3-forget-b2b): the agent machine's
				// work since a task, taken back by recall's Reach.
				lp.forgetOwner.agent.Store(&forgetAgent{work: recallExec,
					lineage: func() (string, error) { return machines{m}.Lineage(agentMachine) }})
				// Recall's Retry reports a take-back it finished here,
				// which tells item 2's done text (RCH-3, RCH-4).
				recallCfg.OnTakenBack = func(_ string, since time.Time) { lp.forgetOwner.agentTakenBack(ctx, since) }
			}
			recallCfg.Labeler, recallCfg.Machines = recallLabels{m}, recallMachines{m}
			go m.RunPruner(vm.PrunePolicy{LowWaterBytes: 1 << 30}, time.Minute, ctx.Done())
			tree.setMachines(m)
			wt := workerTools(m, imgs, workerImage, workerArgv, workerMaxMB, boxGates(d, "/proc/meminfo", cfg.Admission.HeadroomMB))
			caps.workers(wt != nil)
			tools := registeredTools(qs, tree, recallTools, wt)
			if wt != nil {
				go reapWorkers(ctx, wt, m, d.Engine().Stopped, 5*time.Second)
			}
			if plane, err := openGuestPlane(m, d, ev, cfg.SocketDir, meterPath, inboxPath, egressSocket, tools); err != nil {
				// Machines cannot start without their guest sockets.
				log.Printf("agent machines disabled: %v", err)
				caps.agentOff(agentNoMachines)
			} else {
				services.live.Store(&svc{plane})
				var notice func(key, line string) error
				if lp != nil {
					notice = lp.pipe.Notice
				}
				steps.open(ctx, plane, notice)
				oa := &guest.OwnerAgent{Plane: plane, Machine: agentMachine}
				if lp != nil {
					oa.Delivered = lp.delivered
				}
				var to ownerAgent = oa
				agent.a.Store(&to)
				defer plane.Shutdown()
				if lp != nil {
					// Replay machines run the agent's image and launch.
					spec, err := agentSpec(imgs, agentImage, agentLaunch, replayMemMB)
					if err == nil {
						if err = replayFits(cfg.Admission.CapacityMB, cfg.Admission.HeadroomMB, agentMemMB, replayMemMB); err != nil {
							lp.noRoom.Store(true) // STATUS and LEARNING ON say so
						}
						if asleep {
							// The agent sleeps while the box evaluates (PE7).
							sl := openSleeper(ctx, sleepDeps{d: d, m: m, plane: plane, qs: qs, agent: agent, id: agentMachine, hours: sleepHours, workers: wt})
							lp.sleep.Store(sl)
							agent.sleep.Store(sl)
							if nerr := lp.pipe.Notice("pe7:sleep-mode", sleepDigest); nerr != nil {
								log.Printf("sleep mode digest line: %v", nerr)
							}
							err = nil
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
					bc := builderFlags(flag.CommandLine, builderImage, builderLaunch)
					bc.Dir, bc.AgentImage, bc.MemMB, bc.Egress = filepath.Join(cfg.SocketDir, "build"), namedAgentImage, builderMemMB, egressSocket
					lp.startBuilder(m, imgs, services, bc)
				}
				spec, err := agentSpec(imgs, agentImage, agentLaunch, agentMemMB)
				if err != nil {
					log.Printf("no agent machine kept running: %v", err)
					caps.agentOff(agentNoSoftware)
				} else {
					k := agentKeeper(ctx, m, d.Engine().RecordSleep, agentMachine, spec, agent.sleep.Load())
					agentStatus.k.Store(k)
					go k.run(ctx)
				}
			}
		}
	}
	// The recall identity key is vault-held (recall K5): recall opens once
	// the vault process can hand it over.
	// FORGET's item 2s a restart interrupted resume once recall opens;
	// with recall off they cannot, and the owner is told so.
	if recallDir != "" && verifier != nil {
		if lp != nil {
			recallExec.OnOpen(func() { go lp.forgetOwner.resumeAgent(ctx) })
		}
		go openRecall(ctx, verifier, recallCfg, recallTools, recallExec)
	} else {
		recallExec.Off()
		caps.recallWired(false)
		if lp != nil {
			go lp.forgetOwner.resumeAgent(ctx)
		}
	}
	if line != nil {
		go line.run(ctx)
	}
	// What is off, in the box log too (OP-9); the digest's sender (DIG-1)
	// takes this list once it lands.
	logCapLines(capLines)
	log.Printf("digest sources: %d, not sent until the digest is", len(newDigestSources(capLines, lp, line)))
	log.Printf("broker up; owner socket %s/%s", cfg.SocketDir, daemon.OwnerSocket)
	d.Wait()
}

// Memory defaults, MB, from the RES-2 floor budget: an agent-machine pool
// of about 3.9 GB (capacity less headroom) on the N95. A replay machine
// gets its own budget, smaller than the agent's (PE2).
const (
	defaultCapacityMB  = budget.BaseCapMB
	defaultHeadroomMB  = 600 // budget.Floor's
	defaultAgentMemMB  = 1536
	defaultReplayMemMB = 1024
)

// capacityFor is PE6: unless -capacity-mb was given, admission's capacity
// is MemTotal less the floor budget outside the pool (budget.ForHost), at
// most budget.CapMB for the box's cores (RES-2c), so a box smaller than the
// budget assumed (the N95 has about 7.5 GB usable, not 8) is not
// over-committed. An unreadable MemTotal gives the N95's figure, the floor
// (HW-4). It returns the capacity, MemTotal in MB (0 if unreadable), and
// why, for the log.
func capacityFor(meminfo string, cores int, explicit bool, flagMB int64, floor budget.Memory) (capacity, totalMB int64, why string) {
	var kb int64
	for _, line := range strings.Split(meminfo, "\n") {
		if v, ok := strings.CutPrefix(line, "MemTotal:"); ok {
			kb, _ = strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
		}
	}
	totalMB = max(kb>>10, 0)
	switch {
	case explicit:
		return flagMB, totalMB, "set by -capacity-mb"
	case totalMB == 0:
		return n95CapacityMB, 0, fmt.Sprintf("MemTotal unreadable; the N95 floor's %d", n95CapacityMB)
	}
	m, err := budget.ForHost(totalMB, cores, floor)
	if err != nil {
		return n95CapacityMB, totalMB, fmt.Sprintf("%v; the N95 floor's %d", err, n95CapacityMB)
	}
	return m.PoolMB + m.HeadroomMB, totalMB, fmt.Sprintf("MemTotal %d MB less host %d, inference %d and browser %d, at most %d for %d cores",
		totalMB, floor.HostMB, floor.InferenceMB, floor.BrowserMB, budget.CapMB(cores, floor.HeadroomMB), cores)
}

// n95CapacityMB is capacityFor's figure on the N95 (about 7680 MB).
const n95CapacityMB = 4096

// memPlan is agentosd's start-time memory plan (PE6, P2-5r).
type memPlan struct {
	CapacityMB int64
	Why        string
	// Budget is the per-component budget, its pool what admission hands
	// out (capacity less headroom); agentosd applies it as cgroups (RES-2).
	Budget budget.Memory
	// AgentOff, when set, is STATUS's agent line: the agent machine does
	// not fit in the pool, so it is not started (potency C1 on #118).
	AgentOff string
}

// planMemory sets admission's capacity (capacityFor) and checks the agent
// machine fits in the pool it leaves. If not, the agent is off and the
// capacity is kept above headroom, so admission still opens and agentosd
// stays up (STOP, STATUS) instead of failing at start or refusing every
// launch without a word.
func planMemory(meminfo string, cores int, explicit bool, flagMB int64, floor budget.Memory, agentMB int64) memPlan {
	c, total, why := capacityFor(meminfo, cores, explicit, flagMB, floor)
	headroomMB := floor.HeadroomMB
	p := memPlan{CapacityMB: c, Why: why}
	if c-headroomMB < agentMB {
		need := agentMB + headroomMB
		if !explicit {
			need += floor.HostMB + floor.InferenceMB + floor.BrowserMB
		}
		if total > 0 && !explicit {
			p.AgentOff = fmt.Sprintf("Agent: off, this box has %s of memory and running the agent needs about %s.", gb(total), gb(need))
		} else {
			p.AgentOff = "Agent: off, the memory set aside for it is too small to run it."
		}
		p.CapacityMB = max(c, headroomMB+1)
	}
	p.Budget = floor
	p.Budget.PoolMB = p.CapacityMB - headroomMB
	return p
}

// gb renders MB as GB with one decimal.
func gb(mb int64) string { return fmt.Sprintf("%.1f GB", float64(mb)/1024) }

// flagSet reports whether flag name was given on fs's command line.
func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
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

// workerTools serves the worker-machine tools (CAP-8) on the live guest
// plane only: replay and builder machines never get them. Nil, offering
// none, when no worker image is registered.
func workerTools(m *vm.Manager, imgs images, image, argv string, maxMB int64, g workerGates) *workers.Tools {
	if image == "" {
		return nil
	}
	if _, ok := imgs[image]; !ok {
		log.Printf("worker tools off: image %q is not registered with -image", image)
		return nil
	}
	return &workers.Tools{M: m, Image: image, Argv: strings.Fields(argv), MaxMemMB: maxMB, Stopped: g.stopped, Free: g.room, Avail: g.avail}
}

// workerGates are what the worker tools read of the box: the owner's
// STOP, admission's room for a class, and measured free memory (CAP-1).
type workerGates struct {
	stopped func() bool
	room    func(admission.Class) int64
	avail   func() (int64, error)
}

// boxGates reads the worker gates from the running daemon: its STOP,
// its admission's room, and meminfo less admission's headroom.
func boxGates(d *daemon.Daemon, meminfo string, headroomMB int64) workerGates {
	return workerGates{stopped: d.Engine().Stopped, room: d.Admission().RoomFor, avail: measuredFree(meminfo, headroomMB)}
}

// measuredFree is MemAvailable in meminfo less the headroom admission
// never admits into, in MiB (CAP-1: N from measured free memory).
func measuredFree(meminfo string, headroomMB int64) func() (int64, error) {
	return func() (int64, error) {
		mb, err := budget.MemAvailableMB(meminfo)
		if err != nil {
			return 0, err
		}
		return max(mb-headroomMB, 0), nil
	}
}

// workerLayerBytes is -worker-layer-mb in bytes: 0 or less is no cap
// beyond the disk reserve, and a value past 1 PiB is clamped there
// rather than overflow.
func workerLayerBytes(mb int64) int64 {
	if mb <= 0 {
		return 0
	}
	return min(mb, 1<<30) << 20
}

// reapWorkers ends worker commands in flight while STOP holds, checked
// every 5 s (security R2 on #146), and parks idle and orphaned workers
// every minute (UX-146-1).
func reapWorkers(ctx context.Context, wt reaper, m commandEnder, stopped func() bool, tick time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if stopped() {
				if n := m.EndCommands(); n > 0 {
					log.Printf("STOP: ended %d worker commands", n)
				}
			}
			if time.Since(last) >= time.Minute {
				last = time.Now()
				if parked := wt.Reap(ctx); len(parked) > 0 {
					log.Printf("workers parked: %v", parked)
				}
			}
		}
	}
}

// reaper and commandEnder are what reapWorkers uses of the worker tools
// and the machine manager.
type reaper interface {
	Reap(context.Context) []string
}
type commandEnder interface{ EndCommands() int }

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

// openPool applies the component budget under root and returns the
// machine pool's group, with the broker in its protected group (budget
// R3). root must already be checked as delegated (openMachines).
// The broker moves first: cgroup v2 will not enable controllers for the
// children of a group that still holds a process (systemd Delegate=yes
// starts the broker in root itself).
func openPool(root string, mem budget.Memory) (*cgroup.Group, error) {
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

// openGuestPlane opens the OP-8 meter and the guest plane (ARC-6) over the
// machine manager. Without them no agent machine can start.
func openGuestPlane(m *vm.Manager, d *daemon.Daemon, ev *evidence, socketDir, meterPath, inboxPath, egressSocket string, tools guest.Tools) (*guest.Plane, error) {
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
	label := func(id string) string {
		if l, err := m.Label(id); err == nil && l == vm.Public {
			return "public"
		}
		return "private"
	}
	gcfg := guest.Config{
		Dir:       filepath.Join(socketDir, "guests"),
		InboxPath: inboxPath,
		Machines:  machines{m},
		// The grants gate decides every effect (OP-5, REV-2) and routes
		// only accounts a grant connects.
		Effects: d.Gate(),
		Route:   d.Gate().Route,
		Label:   label,
		Meter:   mtr,
		// A private machine's reply goes to the owner's evidence
		// destination when one is set (CH-20).
		OwnerReply: func(machine string, rep guest.Reply) {
			ev.enqueue(machine, label(machine) != "public", rep.Text, rep.Summary)
		},
		// Further broker tools: the owner-question tools (W9) and the
		// managed tree (W4).
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
