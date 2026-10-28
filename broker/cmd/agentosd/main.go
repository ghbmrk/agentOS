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
	"github.com/ghbmrk/agentos/broker/durable"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
	"github.com/ghbmrk/agentos/broker/owner/notice"
	"github.com/ghbmrk/agentos/broker/provagent"
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

// PreemptInstance forwards too, so admission preempts the life it picked
// and never a successor given its ID (#2144).
func (p *preempter) PreemptInstance(id, instance string) error {
	m := p.m.Load()
	if m == nil {
		return errors.New("machine manager not open")
	}
	return m.PreemptInstance(id, instance)
}

var _ admission.LifePreempter = (*preempter)(nil)

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

// open points the line at src. STATUS carries it; nothing else does,
// since the digest it was queued for went with the learning loop's
// pipeline (MIG-4-untrusted-learn; DRB-1: what waits on the owner is in
// STATUS).
func (n *stepNotes) open(src stepSource) { n.p.Store(&stepSrc{src}) }

func (n *stepNotes) Note() string {
	if p := n.p.Load(); p != nil {
		return p.StepNote()
	}
	return ""
}

func (a machines) RaisePrivate(id string) error { return a.m.RaiseLabel(id, vm.Private) }

func (a machines) Lineage(id string) (string, error) {
	mc, err := a.m.Get(id)
	return mc.Lineage, err
}

// lateServices routes each machine to its guest services, which need the
// manager and so are built after it; machines start only once they exist.
// agentosd runs no replay or builder machines (MIG-4-untrusted-learn): a
// machine named as one (vm.EvalPrefix, vm.BuilderPrefix) gets no
// services, never the live plane with its journal, executors and owner
// (replay R7, C-3c-2); every other machine goes to the live guest plane.
type lateServices struct{ live atomic.Pointer[svc] }

type svc struct{ vm.Services }

func (l *lateServices) pick(id string) *svc {
	switch {
	case strings.HasPrefix(id, vm.EvalPrefix), strings.HasPrefix(id, vm.BuilderPrefix):
		return nil
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

// Reset passes ForgetSince's reset notice on to the machine's services
// when they hold state derived from its memory (vm.Resetter, CAP-3): the
// live guest plane drops the tool results it held for the machine.
func (l *lateServices) Reset(id string) {
	if s := l.pick(id); s != nil {
		if r, ok := s.Services.(vm.Resetter); ok {
			r.Reset(id)
		}
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
	// replies is the guest plane once open: while its outbox refuses
	// replies, STATUS says so (DEL-1e).
	replies atomic.Pointer[replyWait]
}

type replyWait struct {
	p interface{ RepliesWaiting() bool }
}

func (l *lateStatus) Status() string {
	if w := l.replies.Load(); w != nil && w.p.RepliesWaiting() {
		return repliesWaiting
	}
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

// lateAgent hands owner chat to the guest plane once it exists.
type lateAgent struct {
	a atomic.Pointer[ownerAgent]
}

func (l *lateAgent) Deliver(ctx context.Context, text string, public bool) error {
	a := l.a.Load()
	if a == nil {
		return errors.New("no agent machine is running")
	}
	return (*a).Deliver(ctx, text, public)
}

// ownerAgent is where owner chat goes (guest.OwnerAgent).
type ownerAgent interface {
	Deliver(ctx context.Context, text string, public bool) error
}

func main() {
	var cfg daemon.Config
	imgs := images{}
	var stateDir, runsc, cgroupRoot, accelMode, meterPath, agentMachine, inboxPath, egressSocket, workerRoutes, verifySocket string
	var agentImage, agentLaunch string
	var diskReserveMB, machineDiskMB, agentMemMB int64
	var diskQuota string
	var keptPath, setupRecord string
	var learnDir, routingSocket string
	var cgroupVouched, modemBridge, ownerMessage bool
	var noticeSocket string
	localUIUID, mailUID := -1, -1
	var mailOwner string
	kernelUID, kernelOwnerUID := -1, -1
	var kernelOwner, kernelStore, passkeyRPID string
	var planHolder, planGrant string
	var signInSock, signInRoutes string
	planUID := -1
	floor := budget.Floor()
	flag.StringVar(&cfg.JournalPath, "journal", "/var/lib/agentos/journal.log", "journal file")
	flag.StringVar(&cfg.SocketDir, "sockets", "/run/agentos", "socket directory (created 0700; 0711 once owner.sock, 0660 to the modem bridge's group, is up)")
	flag.StringVar(&cfg.OwnerNumber, "owner", "", "owner's phone number, E.164")
	flag.StringVar(&cfg.Currency, "currency", "", "the household's one currency, an ISO 4217 code such as EUR, which a RETRY line names a kernel step's amount in; empty, in minor units (#3079)")
	flag.IntVar(&cfg.ModemUID, "modem-uid", -1, "uid of the modem bridge, the only peer allowed on the owner socket")
	flag.IntVar(&localUIUID, "localui-uid", -1, "uid of the local UI (agentos-localui), the only peer allowed on localui.sock; unset, the socket is not served (P2-2w)")
	flag.StringVar(&mailOwner, "mail-owner", "", "the mail clerk's owner socket (clerk/run MailOwnerSide), which the local UI's Connect page signs in to Gmail through (#3006); empty, the page's account ops are refused")
	flag.IntVar(&mailUID, "mail-uid", -1, "uid of the mail clerk's process, the only peer -mail-owner is called on")
	flag.StringVar(&kernelOwner, "kernel-owner", "", "the kernel's owner socket (agentos-kernel -owner-sock), which the broker calls the owner seam on (#2682); empty, there is no kernel to call")
	flag.IntVar(&kernelUID, "kernel-uid", -1, "uid of the kernel's process, the only peer -kernel-owner is called on")
	flag.IntVar(&kernelOwnerUID, "kernel-owner-uid", -1, "the owner side's uid (agentos-kernel -owner-uid), which every call on -kernel-owner is made as")
	flag.StringVar(&passkeyRPID, "passkey-rp-id", "", "the owner page's name as passkeys are bound to it (WebAuthn RP ID; agentos-localui -page-name): serves the page's passkey ops on the kernel's owner seam (#2779a), with -kernel-owner and -localui-uid; empty, they are not served")
	flag.StringVar(&kernelStore, "kernel-store", "/var/lib/agentos-store/store", "the kernel's sealed store (agentos-keeper-kernel.service ConditionPathExists): while it is absent no kernel can run, so STOP has nothing to reach there (#2783)")
	var updateStore, shippedRoot string
	flag.StringVar(&updateStore, "update-store", "", "the update store, already trusting a root; with -shipped-root and the local page, the owner can change where updates come from (OSS-10)")
	flag.StringVar(&shippedRoot, "shipped-root", "", "the root of trust this image ships (switching back needs its keys, WF1)")
	flag.BoolVar(&modemBridge, "modem-bridge", true, "serve the modem bridge's ops on the owner socket and send the owner channel's texts through it")
	modemRoles := flag.String("modem-roles", "/var/lib/agentos/modem/roles.json", "agentos-modem's roles file, where a SIM the owner adopts on the local page is recorded")
	flag.BoolVar(&ownerMessage, "owner-message", false, "also serve the raw \"message\" op on the owner socket with the bridge on (simulator and test builds only; it skips the bridge's checks)")
	flag.Int64Var(&cfg.Admission.CapacityMB, "capacity-mb", defaultCapacityMB, "memory for agent machines, MB; unset, MemTotal less the floor budget outside the pool, at most 4500 or one OpenClaw machine per two cores, whichever is more (PE6, RES-2c)")
	flag.Int64Var(&floor.HeadroomMB, "headroom-mb", floor.HeadroomMB, "memory never admitted into, MB")
	flag.Int64Var(&floor.HostMB, "host-mb", floor.HostMB, "budget: host image, broker and journal (protected), MB (RES-2)")
	flag.Int64Var(&floor.InferenceMB, "inference-mb", floor.InferenceMB, "budget: local inference, MB (RES-2)")
	var inf inferFlags
	inf.register(flag.CommandLine)
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
	flag.StringVar(&planHolder, "plan-holder", "/var/lib/agentos/plan-holder.key", "the key that holds the owner's clerk-key grant and signs guests' plans (#3087): made root-only at first start, kept across reboots; empty, no guest plan is signed")
	flag.StringVar(&signInSock, "signin-sock", "", "where the model clerk's process starts, reads and stops its plan sign-in CLIs, each in a machine whose only mount out is its own endpoint (MIG-4-untrusted-exit-b1), in a directory of its own (such as /run/agentos-signin/signin.sock); empty, it is not served")
	flag.StringVar(&signInRoutes, "signin-routes", "", "the directory agentosd makes each plan sign-in's route in, its own and writable by no other uid (such as /run/agentos-signin-routes); set with -signin-sock")
	flag.IntVar(&planUID, "plan-uid", -1, "uid of the model clerk's process, the only peer -signin-sock admits and the owner of every sign-in route")
	flag.StringVar(&planGrant, "plan-grant", "/var/lib/agentos/plan-grant.json", "the owner's clerk-key grant to -plan-holder, root-only; absent, every guest plan is refused for want of a key (KEY-4)")
	flag.StringVar(&meterPath, "meter", "/var/lib/agentos/meter.json", "model-spend meter state (OP-8)")
	flag.StringVar(&cfg.OwnerState, "owner-state", "/var/lib/agentos/owner.json", "owner channel state (P1-5)")
	flag.StringVar(&setupRecord, "setup-record", "/var/lib/agentos/setup.json", "setup's record (P2-2w c2): with -owner unset, the local UI's setup is served on localui.sock until it records the owner's number here, then never again")
	flag.StringVar(&agentMachine, "agent-machine", "agent", "machine whose guest receives the owner's task chat")
	flag.StringVar(&agentImage, "agent-image", "openclaw", "image the owner's agent machine is created from on first start; empty keeps no agent machine")
	flag.StringVar(&agentLaunch, "agent-launch", "/usr/lib/agentos/guest/launch.json", "how the owner's agent machine starts: argv and env (guest/openclaw/launch.json)")
	flag.Int64Var(&agentMemMB, "agent-mem-mb", defaultAgentMemMB, "the owner's agent machine's memory budget, MB")
	flag.StringVar(&inboxPath, "guest-inbox", "/var/lib/agentos/guest-inbox.json", "unanswered owner messages to guests, kept across restarts")
	flag.StringVar(&workerRoutes, "worker-routes", "/run/agentos-egress/provider.sock", "the vault process's provider control socket, which opens each provider worker's route socket (#1014); empty gives provider workers no route")
	flag.StringVar(&egressSocket, "egress", "/run/agentos-egress/model.sock", "the vault process's model socket (agentos-egress); empty serves no model route")
	flag.StringVar(&verifySocket, "owner-verify", "/run/agentos-egress/verify.sock", "the vault process's verify socket, which checks the owner's code-generator codes; empty refuses high-tier codes")
	flag.StringVar(&noticeSocket, "notice-socket", "/run/agentos-egress/"+notice.Socket, "the vault process's notice socket, whose owner notices are texted to the owner; empty texts none")
	flag.StringVar(&learnDir, "learn", "/var/lib/agentos/learn", "the old learning plane's directory: its state is erased at start, and a restore's forget log is checked here (W3-forget-b1)")
	flag.StringVar(&routingSocket, "routing", "/run/agentos-egress/routing.sock", "the vault process's routing socket, from which the model routes read how many attempts the owner's rule allows; empty holds MaxRetries")
	var workerImage, workerArgv string
	var workerMaxMB, workerLayerMB int64
	flag.StringVar(&workerImage, "worker-image", "", "the base image worker machines are built from (CAP-8), registered with -image; empty offers guests no worker tools")
	flag.StringVar(&workerArgv, "worker-argv", "sleep infinity", "what a worker machine runs while the guest drives it, space-separated")
	flag.Int64Var(&workerLayerMB, "worker-layer-mb", 4096, "the most one worker's files may hold, MB; over it the worker takes no command or snapshot until it shrinks; 0 is no cap beyond the disk reserve")
	flag.Int64Var(&workerMaxMB, "worker-max-mb", 2048, "the largest memory budget one worker may ask for, MB; admission still decides (RES-2)")
	flag.StringVar(&keptPath, "kept-replies", "/var/lib/agentos/kept-replies.json", "agent replies too long for a text or that could not be sent, kept for the local page (CH-20)")
	qcfg := defaultQuestionConfig("/var/lib/agentos")
	flag.StringVar(&qcfg.Path, "questions", qcfg.Path, "agents' questions to the owner, kept across restarts (P3-8)")
	flag.StringVar(&qcfg.ClockPath, "clock-state", qcfg.ClockPath, "the clock check's state (P2-9)")
	flag.Parse()
	// Before agentosd writes anything, so none of its own temps is in flight.
	sweepInboxTemps(inboxPath)
	// The removed digest's queue held private text (DRB-2).
	if removed, err := removeOldDigest(oldDigestDir); err != nil {
		log.Printf("old digest directory not removed: %v", err)
	} else if removed {
		log.Printf("old digest directory removed")
	}
	if err := checkDiskQuotaFlag(diskQuota); err != nil {
		log.Fatal(err)
	}
	// The provider images whose pinned CLI versions both provider runners
	// read at each gate check (#1877).
	pins := readImagePins(imgs, provagent.Builtins())
	meminfo, _ := os.ReadFile("/proc/meminfo")
	mem := planMemory(string(meminfo), runtime.NumCPU(), flagSet(flag.CommandLine, "capacity-mb"), cfg.Admission.CapacityMB, floor, agentMemMB)
	cfg.Admission = mem.Budget.Admission()
	// One opening serves setup's sign-in worker and the owner's plane:
	// the first moves the broker below the delegate mark (#1701).
	boxMachines := onceMachines(func() (*cgroup.Group, error) {
		return openMachines(liveCgroups, cgroupRoot, cgroupVouched, mem.Budget)
	})
	log.Printf("admission capacity: %d MB (%s); budget MB: host %d, inference %d, browser %d, headroom %d, machines %d",
		mem.CapacityMB, mem.Why, mem.Budget.HostMB, mem.Budget.InferenceMB, mem.Budget.BrowserMB, mem.Budget.HeadroomMB, mem.Budget.PoolMB)
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
		if cfg.PageSocket.Accounts, err = pageAccounts(mailOwner, mailUID, localUIUID, cfg.ModemUID); err != nil {
			log.Fatal(err)
		}
	}
	// A restore the forget log's check held opens nothing on the restored
	// tree: no agent machines (W3-forget-b1; security C3). The
	// held mode texts the owner why, takes their answer, and the start
	// goes on once it releases the restore (W3-forget-b1-7). With no owner
	// to text, agentosd does not start.
	if held := restoreHold(learnDir); held != nil {
		owner, err := heldOwner(cfg.OwnerNumber, localsrv.FileRecord{Path: setupRecord})
		if err != nil {
			log.Fatalf("%v; %v", held, err)
		}
		log.Print(held)
		m := heldMode{Learn: learnDir, Dir: cfg.SocketDir, Owner: owner, PeerUID: &cfg.ModemUID, PeerGID: cfg.ModemGID,
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
		if err := restoreHold(learnDir); err != nil {
			log.Fatal(err)
		}
	}
	// A lineage that read a record the owner deleted before the upgrade
	// gets no fork, merge or pre-allowance until its rollback is settled
	// below (VM-lineage-contained, LOG-4).
	recallHeld := openRecallHeld(recallAtRest, filepath.Join(stateDir, recallSettledFile), log.Printf)
	// So does a lineage that read content the owner had the box forget,
	// until it goes back (KRN-forget b, D-169); a kernel is attached below.
	eraseBack := openEraseRewind(filepath.Join(stateDir, eraseRewoundFile), log.Printf)
	var served atomic.Pointer[daemon.Daemon] // set once the daemon runs
	recallHeld.also = eraseBack.Contained
	// A box with no -owner is set up by the local UI (P2-2w c2): only
	// setup's ops are served until its finish is recorded, and the owner's
	// number then comes from the record, on this start and every later one.
	if cfg.OwnerNumber == "" {
		m := setupMode{Dir: cfg.SocketDir, Page: cfg.PageSocket, Record: localsrv.FileRecord{Path: setupRecord},
			OwnerState: cfg.OwnerState, Progress: progressOf(routeOnline),
			Card: pageCardStep}
		if modemBridge {
			// The box texts its setup and pairing texts on its own line
			// (P2-2w c4c), and records the SIM it finds as that line's.
			m.Line = modemlink.NewSetup(modemlink.SetupConfig{Record: recordOwnerSIM(*modemRoles)})
			m.ModemUID, m.ModemGID = &cfg.ModemUID, cfg.ModemGID
			// Once setup is finished the bridge learns the owner's number
			// from its environment file (P2-2w c4c r1).
			m.ModemEnv = modemEnvFile
		}
		if verifySocket != "" {
			m.Enroll = enroller{modelroute.NewVerifier(verifySocket)}
		}
		// "Use my plan" signs in through the provider's CLI in one private
		// worker (ONB-3, #1264 c4e2b), on machines opened only if it is used
		// and closed before agentosd opens its own below.
		var signInHost *setupHost
		if runsc != "" && workerRoutes != "" {
			signInHost, m.SignIn = newSetupPlane(setupMachines{
				runsc: runsc, stateDir: stateDir, rc: modelroute.NewRouteControl(workerRoutes), diskQuota: diskQuota,
				images: imgs, admit: cfg.Admission,
				cgroups:       boxMachines,
				diskReserveMB: diskReserveMB, machineDiskMB: machineDiskMB, workerLayerMB: workerLayerMB,
				contained: recallHeld.Contained,
			}, pins)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		owner, err := m.run(ctx)
		stop()
		if signInHost != nil {
			cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			signInHost.Close(cctx)
			cancel()
		}
		if errors.Is(err, context.Canceled) {
			return
		}
		if err != nil {
			log.Fatal(err)
		}
		cfg.OwnerNumber = owner
	}
	// RES-3: nothing below depends on what is found here. The local
	// inference service runs on CPU and takes no lease (INF-1); leases are a
	// later row (budget R8).
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
		g, err := boxMachines()
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
	// STATUS notes read in wiring order: the time check, then what waits
	// on the owner (unclear effects), then
	// the capability-off lines (OP-9, capoff.go), then spare-time work not
	// running (learningOff, below), then the second line's. The
	// texted STATUS leaves out whole notes that do not fit, from the
	// end, so keep the clock first and the waiting lines before the rest.
	qs.wire(&cfg)
	// No daily text (DRB-1): what waits on the owner is in STATUS, read
	// when asked.
	unclear := wireStatusNotes(&cfg)
	// Each line reads live state set as the box opens below; the daemon
	// copies the notes, so they are wired now.
	caps := newCapState(egressSocket)
	caps.machinesUnset(runsc, agentOff)
	capLines := newCapLines(caps)
	capLines.wire(&cfg)
	// No update-check loop (Loop 3, W5b) runs: STATUS says update checks
	// are not running.
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
		cfg.OwnerVerifier = ownerVerifier{v: verifier}
		// The second line's STATUS line (potency R1 on #139).
		line = &secondLine{get: verifier.SecondLine, texts: verifier.SecondLineTexts}
	}
	// Recall, FORGET and RENEW are deleted (#2781): memory across tasks is
	// off on every box, and STATUS says so (OP-9).
	caps.recallWired(false)
	recallHeld.wire(&cfg)
	// Approval requests follow the owner's pacing setting and spend its one
	// hourly budget; STATUS says what the pacer holds (W5-Dc-r1b QH-8,
	// QH-10). The channel is attached once the daemon runs.
	pacer := newOwnerPacer(&cfg)
	var md machineDisk
	if runsc != "" {
		md = openMachineDisk(diskQuota, stateDir, &cfg.Notes)
	}
	if line != nil {
		cfg.Notes = append(cfg.Notes, line.Note, line.TextsNote)
	}
	// ONB-9's plan sign-in line; the provider runner sets and clears it.
	planLine := &planNote{}
	cfg.Notes = append(cfg.Notes, planLine.Note)
	// #1264: the Wi-Fi page offers that sign-in again after setup, through
	// the provider runner once it exists (ONB-3, ONB-9).
	pageSI := &pageSignIn{note: planLine}
	if cfg.PageSocket != nil {
		cfg.PageSocket.PlanSignIn = pageSI
	}
	// The modem bridge (agentos-modem, P2-3w) hands owner texts in and
	// pulls the channel's own texts from the owner socket; until it
	// reports the owner line, sends fail as down and are counted for the
	// recovery text. Its note, last outage and counts are for the box's local page (U-B1).
	pictures := &pictureJournal{}
	if modemBridge {
		// A SIM the owner adopts on the page, with a code (P2-2w d2b), is
		// recorded where the bridge reads it at its next open. A picture
		// texted to the box is journaled and counted in STATUS (CH-12). A text
		// the down line drops is logged by kind and caller (#2170).
		link := modemlink.New(modemlink.Config{Owner: cfg.OwnerNumber, Record: recordOwnerSIM(*modemRoles), Picture: pictures.tell, Logf: log.Printf})
		cfg.Notes = append(cfg.Notes, link.PictureNote)
		cfg.Modem, cfg.OwnerOps, cfg.OwnerDrainOps, cfg.OwnerDrainLive = link, link.Ops(), modemlink.DrainOps(), link.Bridged
		if cfg.PageSocket != nil {
			cfg.PageSocket.Line, cfg.PageSocket.AdoptSIM = pageLine(link), adoptSIM(link.Adopt)
		}
		cfg.BridgeOnly = !ownerMessage
	}

	// The old learning plane's state is erased, and FORGET, RENEW and the
	// loop settings get fixed replies (#2781).
	openLearnState(learnDir, &cfg)
	// Intents left open for the deleted change, loops, forget and recall
	// executors settle as not applied (NL-8).
	registerRetired(&cfg)
	// One clock for the journal and the gate.
	cfg.Now = func() time.Time { return time.Now().UTC() }
	cfg.Grants.Now = cfg.Now
	// Agent replies (CH-20): texted, or kept for the local page when too
	// long. The mail clerk runs in its own process and has no share route
	// to an owner destination yet, so no destination can be set.
	ev := newEvidence(keptPath, log.Printf)
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

	seat, err := kernelFlags(kernelOwner, kernelUID, kernelOwnerUID, localUIUID, cfg.ModemUID, mailUID)
	if err != nil {
		log.Fatal(err)
	}
	signInGID, err := signInFlags(signInSock, signInRoutes, cfg.SocketDir, planUID, localUIUID, cfg.ModemUID, mailUID, kernelUID)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if passkeyRPID != "" {
		if !validRPID(passkeyRPID) || seat == nil || cfg.PageSocket == nil {
			log.Fatal("-passkey-rp-id must be the owner page's name, with -kernel-owner and -localui-uid")
		}
		cfg.PageSocket.Passkeys = newPasskeys(*seat, passkeyRPID)
	}
	if seat != nil {
		if cfg.PageSocket != nil {
			cfg.PageSocket.Certify = pageCertify{*seat}
		}
		cfg.Kernel = storedKernel{*seat, kernelStore}
		go reachKernel(ctx, *seat, 2*time.Second, log.Printf)
		// Erase by name (KRN-forget b): every agent is contained until the
		// kernel says which read erased content; the start-up pass below
		// takes those back. The owner page's Forget step (KRN-forget c,
		// #3414) calls newForgetFlow's find and confirm.
		eraseBack.attach(*seat, func() lineageForgetter {
			if m := pre.m.Load(); m != nil {
				return m
			}
			return nil
		}, func() error {
			held, err := ev.kept.forget()
			// The owner hears of held agent texts dropped (CAP3-F1).
			if d := served.Load(); d != nil {
				if terr := tellHeldDropped(d.Owner(), held); terr != nil {
					log.Printf("held agent texts dropped by a forget; owner not told: %v", terr)
				}
			}
			return err
		})
		cfg.Notes = append(cfg.Notes, eraseBack.Note, forgetStatus(*seat))
		// Backups (BAK-1, e4a): daily and at once, and STATUS's
		// only-copy notice until the kernel verifies one.
		bs := newBackupSchedule(*seat)
		bs.wire(&cfg)
		if cfg.PageSocket != nil {
			// The status page's notice, and the Backups page (e4b), whose
			// add is a tap on the passkey page's name.
			cfg.PageSocket.BackupNotes = bs.pageLines
			if cfg.PageSocket.Passkeys != nil {
				cfg.PageSocket.Backups = &backupChoice{K: *seat, S: bs}
				// The Recovery key page (REC-4, r4a): its tap is on the
				// same name, and a switch the kernel missed is retried.
				rf := newRecoveryFlow(*seat, bs)
				cfg.PageSocket.Recovery = rf
				go rf.run(ctx, backupCheckEvery)
			}
		}
		go bs.run(ctx, backupCheckEvery)
	}
	// The local inference service runs beside the broker, never in its
	// control path: it is started here and never waited on (INF-1, DEP-1).
	startInference(ctx, inf, inferenceLeaf(boxMachines, mem.Budget.InferenceMB), log.Writer())
	// The model routes hold only the attempts the owner's rule can spend,
	// read from the routing socket off the request path (SR3-7-f2); with
	// no routing socket they hold MaxRetries.
	var retries func() int
	if egressSocket != "" && routingSocket != "" {
		spare := &modelroute.Spare{}
		go spare.Run(ctx, modelroute.NewRouting(routingSocket).State, 30*time.Second)
		retries = spare.Retries
		// The line names other routes only when some class of the owner's
		// rule has a route past its first (#1264 item 3): a plan-only rule
		// has one route per class. Unknown reads as plan-only.
		planLine.others = func() bool { return spare.Retries() >= 1 }
	}
	steps := newStepNotes(&cfg.Notes)
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	pictures.open(d.Engine().RecordPicture)
	served.Store(d)
	pacer.attach(ctx, d.Owner(), time.Minute)
	if seat != nil {
		// Erased reads the start-up pass could not get are asked again, and
		// the owner told of each rewind that follows (D-169).
		go eraseBack.watch(ctx, eraseReadsEvery, informOwner(d.Owner))
	}
	ev.attach(ctx, d)
	fs.attach(ctx, d)
	if noticeSocket != "" {
		go newNoticePuller(noticeSocket, informOwner(d.Owner)).run(ctx)
	}
	unclear.set(d.RetryWaiting)
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
			// Lineages held at upgrade (VM-lineage-contained).
			Contained: recallHeld.Contained,

			DiskReserveBytes: diskReserveMB << 20,
			MachineDiskBytes: machineDiskMB << 20,
			WorkerLayerBytes: workerLayerBytes(workerLayerMB),
		}
		var planRoutes *modelroute.RouteControl
		signIns := &signInHost{Plan: signInPlans["codex"], UID: planUID, GID: signInGID, Routes: signInRoutes, NewID: func() string { return randHex(6) }}
		if workerRoutes != "" {
			planRoutes = modelroute.NewRouteControl(workerRoutes)
			signIns.Fall = planRoutes
		}
		vmc.ProviderRoutes = signIns
		md.set(&vmc)
		m, err := vm.Open(ctx, vmc)
		if err != nil {
			log.Printf("agent machines disabled: %v", err)
			caps.agentOff(agentNoMachines)
		} else {
			pre.m.Store(m)
			// Held lineages go back before any machine is served or
			// pruned; the journal has the owner's NOs by now.
			recallHeld.settle(ctx, m, func() ([]recallNo, error) { return ownerNos(d.Engine()) }, informOwner(d.Owner))
			// So do lineages that read content a crash left erased with no
			// rewind, or rewound with the owner untold (D-169).
			eraseBack.settle(ctx, informOwner(d.Owner))
			go m.RunPruner(vm.PrunePolicy{LowWaterBytes: 1 << 30}, time.Minute, ctx.Done())
			// Provider workers a crash left go first, served or not (#3249, #3308).
			signIns.M = m
			signIns.Sweep()
			if signInSock != "" {
				if err := prepareSignInRoutes(signInRoutes); err != nil {
					log.Printf("plan sign-ins not served: %v", err)
				} else if stop, err := serveSignIns(signInSock, signInGID, signIns); err != nil {
					log.Printf("plan sign-ins not served: %v", err)
				} else {
					defer stop()
				}
			}
			wt := workerTools(m, imgs, workerImage, workerArgv, workerMaxMB, boxGates(d.Engine(), d.Admission(), "/proc/meminfo", cfg.Admission.HeadroomMB))
			if wt != nil && planRoutes != nil {
				pr := providerRunner(m, planRoutes, planLine, pins)
				pr.Background = ctx   // a sign-in's wait ends at shutdown
				pr.Stops = d.Engine() // a stopped route stays stopped across a restart (OP-11)
				journalProviderRuns(pr, d.Engine())
				pageSI.r.Store(pr)
				// #1856: plan readings and the owner's reserve (RES-5).
				wirePlanUsage(pr, planRoutes)
				wt.Provider = providerTool{pr}
			}
			caps.workers(wt != nil)
			tools := registeredTools(qs, wt)
			if wt != nil {
				startReaper(ctx, wt, m, 5*time.Second)
			}
			keys := openPlanKeys(planHolder, planGrant)
			if plane, err := openGuestPlane(m, d, ev, seat, keys, cfg.SocketDir, meterPath, inboxPath, egressSocket, retries, tools); err != nil {
				// Machines cannot start without their guest sockets.
				log.Printf("agent machines disabled: %v", err)
				caps.agentOff(agentNoMachines)
			} else {
				services.live.Store(&svc{plane})
				ev.serve(plane)
				agentStatus.replies.Store(&replyWait{plane})
				steps.open(plane)
				var to ownerAgent = &guest.OwnerAgent{Plane: plane, Machine: agentMachine}
				agent.a.Store(&to)
				defer plane.Shutdown()
				spec, err := agentSpec(imgs, agentImage, agentLaunch, agentMemMB)
				if err != nil {
					log.Printf("no agent machine kept running: %v", err)
					caps.agentOff(agentNoSoftware)
				} else {
					k := agentKeeper(ctx, m, d.Engine().RecordSleep, agentMachine, spec)
					agentStatus.k.Store(k)
					go k.run(ctx)
				}
			}
		}
	}
	if line != nil {
		go line.run(ctx)
	}
	// What is off, in the box log too (OP-9).
	logCapLines(capLines)
	log.Printf("broker up; owner socket %s/%s", cfg.SocketDir, daemon.OwnerSocket)
	d.Wait()
}

// Memory defaults, MB, from the RES-2 floor budget: an agent-machine pool
// of about 3.9 GB (capacity less headroom) on the N95.
const (
	defaultCapacityMB = budget.BaseCapMB
	defaultHeadroomMB = 600 // budget.Floor's
	defaultAgentMemMB = 1536
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
			p.AgentOff = fmt.Sprintf("Your agent is off: I have %s of memory and running it needs about %s.", gb(total), gb(need))
		} else {
			p.AgentOff = "Your agent is off: the memory set aside for it is too small to run it."
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

// workerTools serves the worker-machine tools (CAP-8) on the live guest
// plane only. Nil, offering
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

// providerRunner serves provider_run (CAP-11) over the built-in
// declarations and the vault process's route control rc. The owner's grant
// and private mark are rc's plan state (#1264), and note carries ONB-9's
// sign-in line. Every other owner-side input is closed until its row lands:
// no consent. The image's pinned CLI version is read from the image by
// pins at each check (#1877), as setup's sign-in reads it; an image that
// pins none keeps the gate closed. Codex's qualification record is empty until S8-live (#809)
// fills it, so a run refuses with a closed reason and starts nothing. Pool readings and the reserve come from
// wirePlanUsage (#1856); without them admission refuses (RES-5 fails
// closed). Its Journal logs each run until journalProviderRuns wires it
// to the engine journal (OP-8). Nothing calls StartSignIn until the setup page does (#1264
// c4e2b). A nil rc or note leaves those inputs closed, as nil pins
// leave the gate.
func providerRunner(m *vm.Manager, rc *modelroute.RouteControl, note *planNote, pins imagePins) *provagent.Runner {
	r := &provagent.Runner{
		Host: m, Seeder: planSeeder{rc}, Decls: provagent.Builtins(),
		ImageVersion: pins.version,
		Granted:      func(string) bool { return false },
		PrivateOK:    func(string) bool { return false },
		Consent:      func(string) bool { return false },
		Logf:         log.Printf,
		Caps:         provagent.Caps{Wall: 30 * time.Minute, Result: 256 << 10, Brief: 256 << 10},
		// The page's busy text names this wait (CH-12, #1945).
		SignInTimes: provagent.SignInTimes{Wall: localapi.PlanSignInWait},
		NewID:       func() string { return vm.ProviderPrefix + randHex(6) },
	}
	r.Journal = providerJournal{}.journal // logged until journalProviderRuns (PJ-1)
	if rc != nil {
		r.Granted = func(p string) bool { return planGranted(rc, p) }
		r.PrivateOK = func(p string) bool { return planPrivateOK(rc, p) }
		r.SignInStored = func(id string) bool { return planSignInStored(rc, id) }
		r.SignInFor = rc.SignInFor
	}
	if note != nil {
		r.SignIn, r.OnSignedIn = note.set, note.clear
	}
	return r
}

// providerTool adapts the runner to the worker tools' ProviderRunner, so
// workers links neither provagent nor the model route (ARC-2). A refusal
// crosses as its closed reason only.
type providerTool struct{ r *provagent.Runner }

func (p providerTool) Run(ctx context.Context, q workers.ProviderRequest) (string, error) {
	out, err := p.r.Run(ctx, provagent.Request{Machine: q.Machine, Provider: q.Provider, Brief: q.Brief, TaskClass: q.TaskClass,
		Label: q.Label, Class: q.Class, MemMB: q.MemMB})
	var ref *provagent.Refusal
	if errors.As(err, &ref) {
		return "", &workers.ProviderRefusal{Reason: workers.ProviderReason(ref.Reason)}
	}
	return out, err
}

// planSeeder adapts the vault process's route control to provagent's
// Seeder, mapping its errors onto provagent's sentinels. The control socket
// mints Codex placeholders only (egress PlanLogins.Seed), so any other
// provider is refused before it is asked (#1378, #1379, #1380 add theirs).
type planSeeder struct{ rc *modelroute.RouteControl }

func (s planSeeder) Seed(provider, id string, private bool) (map[string][]byte, error) {
	if provider != "codex" {
		return nil, fmt.Errorf("no plan seed for provider %q", provider)
	}
	if s.rc == nil {
		return nil, errors.New("no plan route control")
	}
	seed, err := s.rc.Seed(id, private)
	switch {
	case err == nil:
		return seed, nil
	case errors.Is(err, modelroute.ErrNoPlanLogin):
		return nil, fmt.Errorf("%w: %v", provagent.ErrNoLogin, err)
	case errors.Is(err, modelroute.ErrRouteBusy):
		return nil, fmt.Errorf("%w: %v", provagent.ErrRouteBusy, err)
	case errors.Is(err, modelroute.ErrVaultLocked):
		return nil, fmt.Errorf("%w: %v", provagent.ErrVaultLocked, err)
	}
	return nil, err
}

func (s planSeeder) Close(id string) {
	if s.rc != nil {
		s.rc.Close(id)
	}
}

// workerGates are what the worker tools read of the box: the owner's
// STOP, admission's room for a class, and measured free memory (CAP-1).
type workerGates struct {
	stopped func() bool
	room    func(admission.Class) int64
	avail   func() (int64, error)
}

// boxGates reads the worker gates from the running daemon's engine and
// admission: the engine's halt (a recorded STOP, or a STOP or other write
// that failed and broke the engine, SEC-failed-stop-latch), admission's
// room, and meminfo less admission's headroom.
func boxGates(e *journal.Engine, adm *admission.Controller, meminfo string, headroomMB int64) workerGates {
	return workerGates{stopped: e.Halted, room: adm.RoomFor, avail: measuredFree(meminfo, headroomMB)}
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

// startReaper runs reapWorkers on the worker tools' own gate, so the
// reaper ends commands exactly when the tools refuse them
// (SEC-failed-stop-latch).
func startReaper(ctx context.Context, wt *workers.Tools, m commandEnder, tick time.Duration) {
	go reapWorkers(ctx, wt, m, wt.Stopped, tick)
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

// sweepInboxTemps removes the temporary files a crash left beside the guest
// inbox (#2373): one holds the outbox as it stood, reply text included, which
// a forget of the guest's replies would otherwise leave on disk (CAP-3). It
// runs first thing at start. A failed sweep is logged, not fatal.
func sweepInboxTemps(inboxPath string) {
	if inboxPath == "" {
		return
	}
	if err := durable.SweepTemp(filepath.Dir(inboxPath)); err != nil {
		log.Printf("guest inbox: removing crash-left temporary files: %v", err)
	}
}

// openGuestPlane opens the OP-8 meter and the guest plane (ARC-6) over the
// machine manager. Without them no agent machine can start. A guest's plan
// goes to the kernel on its owner socket (PLN-5 (b)); with no kernel to call
// (seat nil), or no key for a machine (keys nil, or no grant), every plan is
// refused.
func openGuestPlane(m *vm.Manager, d *daemon.Daemon, ev *evidence, seat *kernelsock.Owner, keys guest.Keys, socketDir, meterPath, inboxPath, egressSocket string, retries func() int, tools guest.Tools) (*guest.Plane, error) {
	eng := d.Engine()
	mtr, err := meter.Open(meter.Config{
		Path:           meterPath,
		MachineCap:     meter.DefaultMachineCap,
		OverallCap:     meter.DefaultOverallCap,
		DailyExtension: meter.DefaultDailyExtension,
		Notify: func(e meter.Exhausted) {
			// The journal holds it; the owner sees it in STATUS once
			// that renders egress records.
			if err := eng.RecordEgress(spendNote(e)); err != nil {
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
		// Each machine's key is the owner's clerk-key grant narrowed to it
		// (KEY-3, KEY-4); until the owner grants one, every plan is refused
		// with the plane's fixed reason (ASSUMPTIONS MIG-4-guest-keys-a).
		Keys:  keys,
		Label: label,
		// A guest's reply waits in the plane's outbox, on disk, until the
		// evidence worker has routed it (DEL-1b); a private machine's
		// goes to the owner's evidence destination when one is set
		// (CH-20).
		Replies: ev.poke,
		// Further broker tools: the owner-question tools (W9) and the
		// managed tree (W4).
		Tools: tools,
		Logf:  log.Printf,
	}
	if seat != nil {
		gcfg.Kernel = seat
	}
	if egressSocket != "" {
		gcfg.Meter, gcfg.WithGoal = mtr, meter.WithGoal
		gcfg.Model = modelroute.Forward(modelroute.Config{
			Socket:  egressSocket,
			Label:   m.DataLabel,
			Denied:  modelroute.Journal(eng, log.Printf),
			Logf:    log.Printf,
			Retries: retries,
		})
	}
	return guest.New(gcfg)
}

// spendNote is the journal record for a meter exhaustion (OP-8): the first
// refused call of each exhaustion, the one the owner is told about.
func spendNote(e meter.Exhausted) journal.EgressNote {
	reason := "model spend limit reached (" + e.Scope
	if e.Task != "" {
		reason += " " + e.Task
	}
	return journal.EgressNote{Machine: e.Machine, Status: 429, Reason: reason + ")"}
}

// ownerVerifier gives the owner channel the vault process's verify
// operation, translating why a check did not run into the channel's terms.
// The vault process records no acts (owner.Item.Act), so a code that
// carries acts is not checked at all and no act is approved: approvals of
// irreversible acts are the kernel's owner seam now (KRN-4, CH-10; the
// checker split went with #2780).
type ownerVerifier struct {
	v *modelroute.Verifier
}

func (o ownerVerifier) VerifyTOTP(code string, after int64, counted bool, acts ...owner.CheckerAct) (int64, bool, error) {
	if len(acts) > 0 {
		return 0, false, &owner.VerifyError{Kind: owner.VaultDown}
	}
	step, ok, err := o.v.VerifyTOTP(code, after, counted)
	return step, ok, ownerVerifyErr(err)
}

// RevokeActs has nothing to withdraw: no act was approved (REV-3).
func (o ownerVerifier) RevokeActs(...string) error { return nil }

// ReleaseActs has nothing to open: no act was approved (REV-3).
func (o ownerVerifier) ReleaseActs(...string) error { return nil }

// AllowActs cannot record an approval, so the channel approves nothing.
func (o ownerVerifier) AllowActs(...owner.CheckerAct) error {
	return &owner.VerifyError{Kind: owner.VaultDown}
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

// recallOwnerNo is the reason the journal records for the owner's NO to a
// recall rollback question (recalltool's ownerNo).
const recallOwnerNo = "not approved: owner"

// recallNos are the owner's NOs to recall rollback questions in the
// journal (VM-lineage-contained): denied with the owner's reason, not
// expired or voided. Here, not in recallheld.go, so the old journal is
// imported by no further file (old-core ratchet).
func recallNos(intents []journal.Status) []recallNo {
	var out []recallNo
	for _, st := range intents {
		if st.Intent.Action != journal.ActionRecallRollback || st.State != journal.Denied || st.Permission.Reason != recallOwnerNo {
			continue
		}
		l, _ := st.Intent.Params["lineage"].(string)
		items, _ := st.Intent.Params["items"].(string)
		out = append(out, recallNo{l, items})
	}
	return out
}

// ownerNos reads the owner's NOs once the journal is known readable.
// List cannot report a read failure: past the in-memory denials it
// replays the journal and, if that fails, answers from memory without the
// evicted ones, so an old NO would be missed and its lineage rolled back
// against it (LOG-4). An unreadable journal errs instead.
func ownerNos(e interface {
	ReadTrail() ([]journal.Record, error)
	List() []journal.Status
}) ([]recallNo, error) {
	if _, err := e.ReadTrail(); err != nil {
		return nil, err
	}
	return recallNos(e.List()), nil
}

// informOwner sends the broker's fixed-wording notices (owner.Inform)
// once the owner channel is up.
func informOwner(own func() *owner.Channel) func(string) error {
	return func(text string) error {
		if ch := own(); ch != nil {
			return ch.Inform(text)
		}
		return errors.New("no owner channel")
	}
}

// ownerPacer is agentosd's hold on the owner channel's pacer (CH-15,
// W5-Dc-r1b): the grants hooks read its setting, the minute
// tick releases what it holds, and STATUS says what waits. Until the
// channel is attached it is never quiet and has no allowance, so nothing
// paced goes.
type ownerPacer struct {
	ch atomic.Pointer[owner.Channel]

	retireLogged string // the unsaved-retire cause last logged; tick only
}

// newOwnerPacer is the pacer's part of the daemon config, set before the
// daemon runs: the grants hooks (QH-8), STATUS's held line (QH-10) and
// its line while an answered approval is unsaved (SM-AJ-4).
func newOwnerPacer(cfg *daemon.Config) *ownerPacer {
	p := &ownerPacer{}
	p.wire(&cfg.Grants)
	cfg.Notes = append(cfg.Notes, p.note, p.retireNote)
	return p
}

// attach binds the owner channel once the daemon runs and starts the tick
// that releases held texts (QH-10).
func (p *ownerPacer) attach(ctx context.Context, ch *owner.Channel, every time.Duration) {
	p.ch.Store(ch)
	go p.run(ctx, every)
}

// wire sets the grants pacing hooks to the owner's setting and its one
// hourly budget (QH-8).
func (p *ownerPacer) wire(g *grants.Config) {
	g.Quiet = p.quiet
	g.Urgent = func(owner.Item) bool { return p.urgent(owner.ClassApproval) }
	g.Allowance = p.allowance
	g.Spend, g.Refund = p.spend, p.refund
}

func (p *ownerPacer) quiet(t time.Time) bool {
	ch := p.ch.Load()
	return ch != nil && ch.Quiet(t)
}

func (p *ownerPacer) urgent(class owner.Class) bool {
	ch := p.ch.Load()
	return ch != nil && ch.Urgent(class)
}

func (p *ownerPacer) allowance(t time.Time) int {
	if ch := p.ch.Load(); ch != nil {
		return ch.Allowance(t)
	}
	return 0
}

// spend counts a request text on the owner's hour as grants grants it
// (#1685); until the channel is attached, nothing paced goes.
func (p *ownerPacer) spend(paced bool) (time.Time, bool) {
	if ch := p.ch.Load(); ch != nil {
		return ch.Spend(paced)
	}
	return time.Time{}, !paced
}

func (p *ownerPacer) refund(at time.Time) {
	if ch := p.ch.Load(); ch != nil {
		ch.Refund(at)
	}
}

// note is STATUS's held line (QH-10).
func (p *ownerPacer) note() string {
	if ch := p.ch.Load(); ch != nil {
		return ch.HeldNote()
	}
	return ""
}

// retireNote is STATUS's line while an answered approval is unsaved, so
// new requests fail (SM-AJ-4).
func (p *ownerPacer) retireNote() string {
	if ch := p.ch.Load(); ch != nil {
		return ch.RetireNote()
	}
	return ""
}

// tick releases held texts that may go now (QH-10) and logs the cause of
// an unsaved retirement once per distinct cause (SM-AJ-4).
func (p *ownerPacer) tick() {
	if ch := p.ch.Load(); ch != nil {
		if err := ch.Release(); err != nil {
			log.Printf("owner: held texts not sent: %v", err)
		}
		cause := ""
		if err := ch.RetireErr(); err != nil {
			cause = err.Error()
		}
		if cause != "" && cause != p.retireLogged {
			log.Printf("%s; new approval requests fail until a save works", cause)
		}
		p.retireLogged = cause
	}
}

// run ticks every interval until ctx ends.
func (p *ownerPacer) run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.tick()
		}
	}
}

// oldDigestDir is where the daily digest kept its queue and state (the
// -digest flag's default) before it was removed (DRB-1).
const oldDigestDir = "/var/lib/agentos/digest"

// removeOldDigest deletes the digest's old directory at dir once at start:
// its queue held private text no part of agentosd reads any more (DRB-2).
// It never follows a link: a link at dir is removed itself, and
// os.RemoveAll does not descend through links inside. Nothing there is
// not an error.
func removeOldDigest(dir string) (removed bool, err error) {
	fi, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if fi.IsDir() {
		err = os.RemoveAll(dir)
	} else {
		err = os.Remove(dir)
	}
	return err == nil, err
}
