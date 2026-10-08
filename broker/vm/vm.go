// Package vm manages agent machines: create, per-step file-system snapshots,
// full-state checkpoints, fork(n), diff, merge, rollback, rebuild, and
// destroy (SPEC REV-1, REV-4, ARC-4), under admission and cgroup memory
// budgets (RES-1, RES-2).
//
// A machine is a read-only image plus a writable overlay layer, run by a
// Runtime (gVisor at the floor, ARC-5). Everything the broker keeps about a
// machine, its layer and every snapshot, lives under the broker's state
// directory, which is never mounted into a guest: the guest sees only its
// merged root, so it cannot read, change, or delete its snapshots (REV-1).
//
// Locking: the manager never calls admission while holding a machine's
// lock, and Preempt takes only the victim's lock, so admission and the
// manager cannot deadlock whichever side starts.
package vm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/quota"
	"github.com/ghbmrk/agentos/broker/vm/overlay"
)

// Label is a machine's data label (REV-5). It only rises during a machine's
// life: no rollback, rebuild, or merge lowers it.
type Label uint8

const (
	Public  Label = iota // has received no owner data
	Private              // has received owner data
)

func (l Label) String() string { return [...]string{"public", "private"}[l] }

func maxLabel(a, b Label) Label {
	if a > b {
		return a
	}
	return b
}

// Tier is a snapshot's depth (REV-1).
type Tier uint8

const (
	FS   Tier = iota // file system only: taken at every step, tens of ms
	Full             // memory and file system: warm templates, risky steps, fork
)

func (t Tier) String() string { return [...]string{"fs", "full"}[t] }

// State is where a machine is in its life.
type State string

const (
	Running   State = "running"
	Stopped   State = "stopped"   // not running; layer kept (e.g. after a broker restart)
	Preempted State = "preempted" // stopped for a higher class (RES-1); resumable
)

// Spec describes a machine to create.
type Spec struct {
	Image string // name of a registered image
	Class admission.Class
	MemMB int64 // declared budget: admission and the cgroup limit (RES-2)
	Argv  []string
	Env   []string
	Label Label
}

// Machines are siblings in the pool's cgroup, weighed by admission class
// for CPU and I/O (cpu.weight, io.weight; RES-1, RES-2): foreground first,
// accepted work next, experiments least. The pool as a whole weighs less
// than the broker (budget.BrokerWeight).
const (
	ForegroundWeight = 1000
	AcceptedWeight   = 100
	ExperimentWeight = 1
)

// MachinePids caps one machine's tasks, threads included (pids.max). A
// gVisor sandbox's host tasks are the sentry's threads and, under
// systrap, stub threads for the guest's, so this bounds a fork bomb well
// below memory.max while leaving room for a parallel build in a worker
// (vm V29, unmeasured).
const MachinePids = 4096

// MachineLimits is machine id's cgroup limits: its declared memory budget,
// its class's weights and the process cap. Every machine kind gets them,
// workers included; a worker never weighs more than accepted work, so a
// foreground agent's builds cannot crowd out the agent itself. An unknown
// class weighs least.
func MachineLimits(id string, s Spec) cgroup.Limits {
	w := ExperimentWeight
	switch s.Class {
	case admission.Foreground:
		w = ForegroundWeight
	case admission.Accepted:
		w = AcceptedWeight
	}
	if strings.HasPrefix(id, WorkerPrefix) {
		w = min(w, AcceptedWeight)
	}
	return cgroup.Limits{MaxBytes: s.MemMB << 20, CPUWeight: w, IOWeight: w, Pids: MachinePids}
}

// Machine is a copy of a machine's record.
type Machine struct {
	ID       string
	Spec     Spec
	Label    Label
	State    State
	ForkBase string // snapshot this machine was forked from, if any; written under m.mu too (ForkSiblings)
	// Lineage names the creation this machine descends from by fork: the
	// root machine's ID plus a nonce drawn when it was created. Forks share their source's memory, so the broker treats a
	// lineage as one requester for idempotency (OP-1).
	Lineage string
	Last    string // newest snapshot of this machine
	// Starts counts the machine's starts (every startFrom), so a sleep
	// checkpoint taken at one start is refused after another (PE7).
	Starts uint64 `json:",omitempty"`
	// Project is the machine's disk quota project (RES-4); 0: none.
	Project uint32 `json:",omitempty"`
}

// Snapshot is a broker-held snapshot's record.
type Snapshot struct {
	ID      string
	Machine string
	Tier    Tier
	Label   Label // the machine's label when taken
	Image   string
	Taken   time.Time
	// Lineage is the machine's lineage when taken, so a snapshot outlives
	// its machine's destroy still traceable (ForgetSince). Empty on
	// snapshots taken before it was recorded.
	Lineage string `json:",omitempty"`
	// Sleep marks CheckpointAndStop's checkpoint, the only kind
	// ResumeFromCheckpoint restores (PE7). Starts is the machine's start
	// count when it was taken, and Hash the SHA-256 over its files and
	// memory image (treeHash), checked before the restore.
	Sleep  bool   `json:",omitempty"`
	Starts uint64 `json:",omitempty"`
	Hash   string `json:",omitempty"`
}

// Launch is what a Runtime needs to run a machine.
type Launch struct {
	ID    string // machine ID
	Dir   string // broker-held machine directory, for runtime files
	Lower string // image root, read only
	// Upper (the writable layer) and Work (overlayfs's work directory) lie
	// under the machine's disk quota (RES-4). A runtime mounts them inside
	// quota.Enforced, so the guest's writes through the mount stop at it.
	Upper  string
	Work   string
	Root   string // where the merged root is mounted
	Cgroup string // cgroup v2 directory to start the machine in; "" if none
	// Services is a broker-held host directory holding only this machine's
	// guest service socket (ARC-6), mounted read-only at ServicesMount; ""
	// if none. The runtime lets the guest connect to host sockets there and
	// nowhere else.
	Services string
	Argv     []string
	Env      []string
}

// ConsoleMaxBytes bounds the console output a Runtime keeps for one
// machine in Launch.Dir, old and current logs together (RES-4). It is
// outside the machine's quota, so the disk admission counts it for every
// running machine.
const ConsoleMaxBytes = 8 << 20

// Quota sets per-machine hard disk quotas (quota.FS). Limit tags the
// directory dir with project, so all later created beneath it counts
// against the project, and sets the project's hard limits. Tag tags every
// directory and file already in the tree at root with project.
type Quota interface {
	Limit(dir string, project uint32, bytes, inodes int64) error
	Tag(root string, project uint32) error
	Usage(project uint32) (quota.Usage, error)
	Clear(project uint32) error
}

// ServicesMount is where a machine sees its Launch.Services directory.
const ServicesMount = "/run/agentos"

// Services hands each machine its own guest service directory (ARC-6). Open
// is called before every start or restore of machine id and must return the
// same directory each time. Close is called when the machine is removed
// (destroyed, or its creation failed) and must be idempotent.
// Identity comes from the directory: only machine id's sandbox has it.
type Services interface {
	Open(id string) (dir string, err error)
	Close(id string)
}

// Runtime runs machines. Checkpoint is called on a paused machine and leaves
// it paused. Kill stops a machine, releases what Start set up, and is
// idempotent.
type Runtime interface {
	Start(ctx context.Context, l Launch) error
	Restore(ctx context.Context, l Launch, image string) error
	Pause(ctx context.Context, id string) error
	Resume(ctx context.Context, id string) error
	Checkpoint(ctx context.Context, id, image string) error
	Kill(ctx context.Context, l Launch) error
}

// Admitter is the broker's admission controller (admission.Controller).
type Admitter interface {
	Admit(admission.Request) (admission.Decision, error)
	Release(id string)
}

// Config configures a Manager.
type Config struct {
	StateDir string            // broker-held; created 0700
	Images   map[string]string // image name -> read-only root directory
	Runtime  Runtime
	Admit    Admitter
	// Cgroups is the parent group for per-machine groups. Nil is allowed
	// only with NoCgroups, for tests and hosts without cgroup v2.
	Cgroups   *cgroup.Group
	NoCgroups bool
	// KillTimeout bounds waiting for a machine's memory to be released.
	KillTimeout time.Duration
	// Services gives each machine its guest service socket (P1-7). Nil
	// runs machines with no broker services at all.
	Services Services
	// DiskReserveBytes is the state disk's RES-4 reserve (a healthy
	// release, the journal, the recall index). A snapshot is admitted only
	// if copying the layer leaves the reserve free, as memory admission
	// leaves its headroom (RES-2). Zero means 2 GiB.
	DiskReserveBytes int64
	// Quota gives every machine (workers, builders and replay machines
	// too) a hard disk quota of its own on what its guest writes, from
	// MachineDiskBytes and MaxLayerInodes (RES-4). What running guests may
	// still write under their quotas is held back from the disk above the
	// reserve: a machine starts, and a copy is admitted, only if it fits
	// beside that. Nil is allowed only with NoQuota, for tests and for a
	// state file system without project quotas, where guests can fill it.
	Quota   Quota
	NoQuota bool
	// MachineDiskBytes is each machine's declared disk budget: its quota,
	// and the default MaxLayerBytes. Zero means 8 GiB.
	MachineDiskBytes int64
	// MaxLayerBytes caps one machine's layer at a snapshot (zero:
	// MachineDiskBytes). MaxLayerInodes caps its inodes (zero: 200,000).
	MaxLayerBytes, MaxLayerInodes int64
	// WorkerLayerBytes caps one worker's layer (zero: MaxLayerBytes
	// alone). A worker over it takes no snapshot and no command until
	// files are deleted or it is rolled back (security R3 on #146).
	WorkerLayerBytes int64
	// FreeBytes reports the state disk's free space; nil measures it.
	FreeBytes func(path string) (int64, error)
	// Contained reports a lineage that holds a record the owner deleted
	// and has not been rolled back yet (recall W10): its machines are not
	// forked or merged, so what it holds spreads no further. Nil: none is.
	Contained func(lineage string) bool
}

var (
	ErrUnknown  = errors.New("vm: unknown machine or snapshot")
	ErrExists   = errors.New("vm: machine already exists")
	ErrState    = errors.New("vm: machine is not in a state that allows this")
	ErrLineage  = errors.New("vm: snapshot is not in this machine's lineage")
	ErrConflict = errors.New("vm: merge conflict")
	ErrImage    = errors.New("vm: snapshots are of different images")
	ErrRevoked  = errors.New("vm: admission was withdrawn before the machine started")
	// ErrExecNotStarted and ErrExecFailed are a command the runtime
	// failed to run: before it started, or after, so it may have run.
	// Neither names a path; the runtime's messages are in its own log
	// (SR2-3j).
	ErrExecNotStarted = errors.New("vm: the command did not start")
	ErrExecFailed     = errors.New("vm: the runtime failed after the command started; it may have run")
	// ErrPreempted: the machine was preempted while an operation held it,
	// and what it was writing is discarded.
	ErrPreempted = errors.New("vm: machine was preempted during the operation")
	ErrQuota     = errors.New("vm: disk budget exceeded: snapshot refused; free space in the machine (delete files) or roll back, then retry")
	// ErrTooDeep is a layer nested too deep to measure or copy
	// (overlay.ErrTooDeep), for callers outside the machine plane.
	ErrTooDeep = overlay.ErrTooDeep
	// ErrDiskFull refuses to start a machine when the state disk above
	// the reserve cannot hold what it and the running machines may write
	// under their quotas (RES-4).
	ErrDiskFull = errors.New("vm: not enough disk above the reserve for this machine's disk budget; stop or destroy a machine, or free space, then retry")
	// ErrSeedLabel refuses a seed for a machine not labelled private: seeds
	// are derived from owner data until their files carry a public mark
	// (REV-5, compile K7).
	ErrSeedLabel = errors.New("vm: a seeded machine must be labelled private")
	// ErrContained refuses a fork or merge of a lineage that holds a
	// record the owner deleted (Config.Contained).
	ErrContained = errors.New("vm: this agent holds a record the owner deleted; no fork or merge until that is settled")
)

// maxIDLen is the longest machine ID idRE allows.
const maxIDLen = 40

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

type machine struct {
	mu sync.Mutex // held for a machine's whole operation
	Machine
	// revoked: admission preempted the machine after admitting it but
	// before it started, so it must not start on that admission.
	revoked bool
	// seed is written into a fresh layer before the machine starts from its
	// image (CreateSeeded). Kept in memory only.
	seed map[string][]byte
	// preempting is set, without the lock, while a preemption is under way
	// (see Preempt); startFrom refuses to start the machine meanwhile.
	preempting atomic.Bool
	// execCancel ends a worker's command in flight (Exec), so erasure,
	// rollback and destroy never wait behind it for the lock.
	execCancel atomic.Pointer[context.CancelFunc]
	// label is Label as last saved, read without the lock. Labels only
	// rise, so it is never above Label: a check that refuses on it would
	// refuse under the lock too (DeleteFiles, L3 SHOULD-2 on #166).
	label atomic.Uint32
}

// lockEndingExec takes mc's lock, ending any worker command that holds or
// takes it meanwhile, so the caller never waits behind one.
func (mc *machine) lockEndingExec() {
	for !mc.mu.TryLock() {
		if c := mc.execCancel.Load(); c != nil {
			(*c)()
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Manager is safe for concurrent use.
type Manager struct {
	cfg Config

	mu       sync.Mutex // guards the maps and seq, never held across I/O
	machines map[string]*machine
	snaps    map[string]Snapshot
	seq      int

	diskMu   sync.Mutex // serializes disk reservations
	diskHeld int64      // bytes reserved for copies in progress
	// live holds the quota project of each guest that may write (started,
	// and not known dead), under diskMu. It is keyed by project, unique to
	// one machine's life, so a guest whose kill failed stays counted even
	// after its ID is taken again.
	live    map[uint32]int64 // project -> its disk budget
	project uint32           // highest quota project given out, under mu

	now func() time.Time // nil: time.Now (tests age snapshots for Prune)
}

// Open opens (or creates) the state directory. Machines recorded by an
// earlier run come back Stopped with their layers and snapshots intact; any
// runtime state they left is killed.
func Open(ctx context.Context, cfg Config) (*Manager, error) {
	if cfg.Runtime == nil || cfg.Admit == nil {
		return nil, errors.New("vm: Runtime and Admit are required")
	}
	if cfg.Cgroups == nil && !cfg.NoCgroups {
		return nil, errors.New("vm: a cgroup parent is required to enforce budgets (RES-2)")
	}
	if cfg.Quota == nil && !cfg.NoQuota {
		return nil, errors.New("vm: a disk quota is required so no guest can fill the state disk (RES-4)")
	}
	if cfg.MachineDiskBytes == 0 {
		cfg.MachineDiskBytes = 8 << 30
	}
	if cfg.MaxLayerBytes == 0 {
		cfg.MaxLayerBytes = cfg.MachineDiskBytes
	}
	if cfg.KillTimeout == 0 {
		cfg.KillTimeout = 10 * time.Second
	}
	if cfg.DiskReserveBytes == 0 {
		cfg.DiskReserveBytes = 2 << 30
	}
	if cfg.FreeBytes == nil {
		cfg.FreeBytes = overlay.FreeBytes
	}
	if cfg.MaxLayerInodes == 0 {
		cfg.MaxLayerInodes = 200_000
	}
	for _, d := range []string{cfg.StateDir, filepath.Join(cfg.StateDir, "machines"), filepath.Join(cfg.StateDir, "snapshots")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return nil, err
		}
	}
	m := &Manager{cfg: cfg, machines: map[string]*machine{}, snaps: map[string]Snapshot{}, live: map[uint32]int64{}}
	if err := m.load(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) machineDir(id string) string { return filepath.Join(m.cfg.StateDir, "machines", id) }
func (m *Manager) snapDir(id string) string    { return filepath.Join(m.cfg.StateDir, "snapshots", id) }

// diskDir holds everything machine id's guest writes, under its quota; the
// machine's record and runtime files stay outside it, so a full quota
// cannot stop the broker recording the machine.
func (m *Manager) diskDir(id string) string { return filepath.Join(m.machineDir(id), "disk") }

// projectBase starts the quota projects the manager gives machines, clear
// of small IDs an administrator may use.
const projectBase = 0x41470000

func (m *Manager) launch(mc *machine) Launch {
	d := m.machineDir(mc.ID)
	l := Launch{
		ID: mc.ID, Dir: d,
		Lower: m.cfg.Images[mc.Spec.Image],
		Upper: filepath.Join(m.diskDir(mc.ID), "upper"), Work: filepath.Join(m.diskDir(mc.ID), "work"), Root: filepath.Join(d, "root"),
		Argv: mc.Spec.Argv, Env: mc.Spec.Env,
	}
	if m.cfg.Cgroups != nil {
		l.Cgroup = filepath.Join(m.cfg.Cgroups.Path, mc.ID)
	}
	return l
}

// Create admits and starts a new machine from an image.
func (m *Manager) Create(ctx context.Context, id string, s Spec) (Machine, error) {
	if strings.HasPrefix(id, EvalPrefix) {
		return Machine{}, fmt.Errorf("vm: machine ids starting %q are kept for replay", EvalPrefix)
	}
	if strings.HasPrefix(id, WorkerPrefix) {
		return Machine{}, fmt.Errorf("vm: machine ids starting %q are kept for workers", WorkerPrefix)
	}
	return m.create(ctx, id, s, nil, "")
}

// EvalPrefix starts the IDs of replay machines (LOOP-5), whose guest
// services are replay's, never the live plane's. Only CreateSeeded makes
// them, and they cannot be forked or forked into.
const EvalPrefix = "eval-"

// BuilderPrefix starts the IDs of Loop 1's builder machines (W3-builder),
// to which the vault process gives the builder's grants. Only Create makes
// them: no fork or merge makes or touches one (security R1 on #126).
const BuilderPrefix = "lb-"

// CreateSeeded is Create with files written into the machine's fresh layer
// before its guest first runs, at paths relative to the guest's root: how
// the broker hands a machine read-only inputs, such as the managed tree a
// replay evaluates (LOOP-5). Paths must be local and clean; files are
// root-owned 0644 in 0755 directories. A non-empty seed needs s.Label
// Private: the managed tree is derived from owner tasks, and no file carries
// a public mark yet, so only a private machine may read it (REV-5, compile
// K7); forks inherit the label, so the seed stays private. A rebuild from the image writes the
// seed again; the seed is not persisted, so after a broker restart the
// machine has only its layer.
func (m *Manager) CreateSeeded(ctx context.Context, id string, s Spec, seed map[string][]byte) (Machine, error) {
	if len(seed) > 0 && s.Label != Private {
		return Machine{}, fmt.Errorf("%w: %s is %v", ErrSeedLabel, id, s.Label)
	}
	var size int64
	for p, b := range seed {
		if !filepath.IsLocal(p) || filepath.Clean(p) != p {
			return Machine{}, fmt.Errorf("vm: bad seed path %q", p)
		}
		size += int64(len(b))
	}
	// The seed lands on the state disk like a layer copy (RES-4); every
	// write of it (create, rebuild) reserves the disk first.
	if m.cfg.MaxLayerBytes > 0 && size > m.cfg.MaxLayerBytes {
		return Machine{}, fmt.Errorf("%w (seed %d bytes, cap %d)", ErrQuota, size, m.cfg.MaxLayerBytes)
	}
	if strings.HasPrefix(id, WorkerPrefix) {
		return Machine{}, fmt.Errorf("vm: machine ids starting %q are kept for workers", WorkerPrefix)
	}
	return m.create(ctx, id, s, seed, "")
}

func (m *Manager) create(ctx context.Context, id string, s Spec, seed map[string][]byte, lineage string) (Machine, error) {
	if !idRE.MatchString(id) {
		return Machine{}, fmt.Errorf("vm: bad machine id %q", id)
	}
	if _, ok := m.cfg.Images[s.Image]; !ok {
		return Machine{}, fmt.Errorf("%w: image %q", ErrUnknown, s.Image)
	}
	mc, err := m.reserve(id, s, s.Label, "", lineage)
	if err != nil {
		return Machine{}, err
	}
	mc.seed = seed
	if err := m.admit(mc); err != nil {
		m.unreserve(id)
		return Machine{}, err
	}
	mc.mu.Lock()
	err = claimLocked(mc)
	if err == nil {
		var h *diskHold
		if h, err = m.reserveSeed(mc); err == nil {
			err = m.startFrom(ctx, mc, nil)
			h.release()
		}
	}
	if err != nil {
		m.stopRuntime(ctx, mc)
		os.RemoveAll(m.machineDir(id))
	}
	out := mc.Machine
	mc.mu.Unlock()
	if err != nil {
		m.unreserve(id)
		m.cfg.Admit.Release(id)
		return Machine{}, err
	}
	return out, nil
}

// admit asks admission for mc's budget. It is called without mc's lock,
// because admission holds its own lock while it calls Preempt.
func (m *Manager) admit(mc *machine) error {
	mc.mu.Lock()
	mc.revoked = false
	r := admission.Request{ID: mc.ID, Class: mc.Spec.Class, MemMB: mc.Spec.MemMB}
	mc.mu.Unlock()
	_, err := m.cfg.Admit.Admit(r)
	return err
}

// claimLocked fails if admission was withdrawn between admit and now.
// Releasing a withdrawn admission is a no-op, so callers release as usual.
func claimLocked(mc *machine) error {
	if mc.revoked {
		mc.revoked = false
		return fmt.Errorf("%w: %s", ErrRevoked, mc.ID)
	}
	return nil
}

// reserve records a new machine in the table so no one else takes its ID.
// The returned machine is not yet persisted or started.
func (m *Manager) reserve(id string, s Spec, l Label, forkBase, lineage string) (*machine, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.machines[id]; ok {
		return nil, fmt.Errorf("%w: %s", ErrExists, id)
	}
	if _, err := os.Lstat(m.machineDir(id)); err == nil {
		return nil, fmt.Errorf("%w: %s (left on disk)", ErrExists, id)
	}
	if lineage == "" {
		// A new lineage per creation: an ID reused after destroy must not
		// inherit an old machine's intent namespace (OP-1).
		var b [6]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		lineage = id + "." + hex.EncodeToString(b[:])
	}
	mc := &machine{Machine: Machine{ID: id, Spec: s, Label: l, State: Stopped, ForkBase: forkBase, Lineage: lineage}}
	mc.label.Store(uint32(l))
	if m.cfg.Quota != nil {
		mc.Project = m.nextProjectLocked()
	}
	m.machines[id] = mc
	return mc, nil
}

// nextProjectLocked gives out a quota project no machine holds. Called
// with m.mu held.
func (m *Manager) nextProjectLocked() uint32 {
	if m.project < projectBase {
		m.project = projectBase
	}
	m.project++
	return m.project
}

func (m *Manager) unreserve(id string) {
	m.mu.Lock()
	delete(m.machines, id)
	m.mu.Unlock()
	if m.cfg.Services != nil {
		m.cfg.Services.Close(id)
	}
}

// keepLayer, passed to startFrom, restarts a machine on the layer it has.
var keepLayer = &Snapshot{}

// startFrom (re)builds a machine's layer from snapshot s (or empty when s is
// nil, or as it is when s is keepLayer) and runs it, restoring memory when s
// is a full checkpoint. Called with mc.mu held and the machine admitted.
func (m *Manager) startFrom(ctx context.Context, mc *machine, s *Snapshot) error {
	l := m.launch(mc)
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return err
	}
	keep := s == keepLayer
	if keep {
		s = nil
	}
	if err := m.limitDisk(mc, keep); err != nil {
		return err
	}
	if keep {
		if err := os.RemoveAll(l.Work); err != nil {
			return err
		}
		if fi, err := os.Lstat(l.Upper); err != nil || !fi.IsDir() {
			return fmt.Errorf("vm: %s has no layer to resume on", mc.ID)
		}
	} else if err := m.writeLayer(l, mc, s); err != nil {
		return err
	}
	if err := os.Mkdir(l.Work, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(l.Root, 0o755); err != nil {
		return err
	}
	if m.cfg.Cgroups != nil {
		if _, err := m.cfg.Cgroups.Child(mc.ID, MachineLimits(mc.ID, mc.Spec)); err != nil {
			return err
		}
	}
	if mc.preempting.Load() {
		return fmt.Errorf("%w: %s", ErrRevoked, mc.ID)
	}
	if err := m.commitDisk(mc); err != nil {
		return err
	}
	// Workers run no agent: no broker socket, so no tools, owner channel
	// or model egress (CAP-8).
	if m.cfg.Services != nil && !strings.HasPrefix(mc.ID, WorkerPrefix) {
		dir, err := m.cfg.Services.Open(mc.ID)
		if err != nil {
			return err
		}
		l.Services = dir
	}
	var err error
	if s != nil && s.Tier == Full {
		err = m.cfg.Runtime.Restore(ctx, l, filepath.Join(m.snapDir(s.ID), "mem"))
	} else {
		err = m.cfg.Runtime.Start(ctx, l)
	}
	if err != nil {
		return err
	}
	if mc.preempting.Load() {
		// Preempted while starting: the caller's failure path stops it.
		return fmt.Errorf("%w: %s", ErrRevoked, mc.ID)
	}
	mc.State = Running
	mc.Starts++
	return m.saveMachine(mc)
}

// limitDisk makes mc's quota directory and sets its quota there, before
// any layer is written into it: files made beneath it count against mc's
// project. When mc resumes on the layer it has (keep), every file of it is
// tagged again first: a layer copied, restored, or written with quotas off
// is untagged, and its directories would pass project 0, which no limit
// covers, to what the guest writes in them. A machine recorded without a
// project gets one.
func (m *Manager) limitDisk(mc *machine, keep bool) error {
	dir := m.diskDir(mc.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if m.cfg.Quota == nil {
		return nil
	}
	if mc.Project == 0 {
		m.mu.Lock()
		mc.Project = m.nextProjectLocked()
		m.mu.Unlock()
	}
	if err := m.cfg.Quota.Limit(dir, mc.Project, m.diskBudget(mc.ID), m.cfg.MaxLayerInodes); err != nil {
		return err
	}
	if keep {
		return m.cfg.Quota.Tag(dir, mc.Project)
	}
	return nil
}

// diskBudget is machine id's disk quota: MachineDiskBytes, or a worker's
// smaller layer cap.
func (m *Manager) diskBudget(id string) int64 {
	if strings.HasPrefix(id, WorkerPrefix) && m.cfg.WorkerLayerBytes > 0 {
		return min(m.cfg.MachineDiskBytes, m.cfg.WorkerLayerBytes)
	}
	return m.cfg.MachineDiskBytes
}

// commitDisk admits mc's guest to write: the disk above the reserve and
// every hold must cover what it may still write under its quota (and its
// console) beside what every other running guest may. Until it stops, the
// same counts against every copy and start (grow). A no-op without quotas.
func (m *Manager) commitDisk(mc *machine) error {
	if m.cfg.Quota == nil {
		return nil
	}
	m.diskMu.Lock()
	defer m.diskMu.Unlock()
	room, err := m.roomLocked()
	if err != nil {
		return err
	}
	need, err := m.unusedLocked(mc.Project, m.diskBudget(mc.ID))
	if err != nil {
		return err
	}
	if need > room {
		return fmt.Errorf("%w (%s may write %d bytes; %d free above the reserve and running machines)", ErrDiskFull, mc.ID, need, room)
	}
	m.live[mc.Project] = m.diskBudget(mc.ID)
	return nil
}

// uncommitDisk: mc's guest no longer runs, so it writes nothing more.
func (m *Manager) uncommitDisk(mc *machine) {
	m.diskMu.Lock()
	delete(m.live, mc.Project)
	m.diskMu.Unlock()
}

// unusedLocked is what a running guest of project p may still write: its
// budget less its use, plus its console. Called with diskMu held.
func (m *Manager) unusedLocked(p uint32, budget int64) (int64, error) {
	u, err := m.cfg.Quota.Usage(p)
	if err != nil {
		return 0, fmt.Errorf("vm: disk use of project %d: %w", p, err)
	}
	return max(0, budget-u.Bytes) + ConsoleMaxBytes, nil
}

// roomLocked is the state disk's free space less the reserve, every hold,
// and what running guests may still write. Called with diskMu held.
func (m *Manager) roomLocked() (int64, error) {
	free, err := m.cfg.FreeBytes(m.cfg.StateDir)
	if err != nil {
		return 0, err
	}
	room := free - m.cfg.DiskReserveBytes - m.diskHeld
	for p, budget := range m.live {
		n, err := m.unusedLocked(p, budget)
		if err != nil {
			return 0, err
		}
		room -= n
	}
	return room, nil
}

// writeLayer replaces mc's layer with snapshot s's file system, or with a
// fresh one holding mc's seed when s is nil. The work directory goes too.
func (m *Manager) writeLayer(l Launch, mc *machine, s *Snapshot) error {
	for _, p := range []string{l.Upper, l.Work} {
		if err := os.RemoveAll(p); err != nil {
			return err
		}
	}
	if s != nil {
		return overlay.Copy(filepath.Join(m.snapDir(s.ID), "fs"), l.Upper)
	}
	if err := os.Mkdir(l.Upper, 0o755); err != nil {
		return err
	}
	return writeSeed(l.Upper, mc.seed)
}

// reserveSeed reserves the disk for writing mc's seed into a fresh layer,
// before anything is stopped or removed, so a refusal changes nothing.
func (m *Manager) reserveSeed(mc *machine) (*diskHold, error) {
	var size int64
	for _, b := range mc.seed {
		size += int64(len(b))
	}
	h, err := m.reserveDisk(size)
	if err != nil {
		return nil, fmt.Errorf("%s: seed: %w", mc.ID, err)
	}
	return h, nil
}

// writeSeed writes seed files into a fresh, broker-only layer. Nothing else
// has written to upper yet, so no path in it can be a symlink; O_EXCL
// refuses one at the final component anyway.
func writeSeed(upper string, seed map[string][]byte) error {
	for p, b := range seed {
		dst := filepath.Join(upper, p)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		_, err = f.Write(b)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// stopRuntime kills the machine and waits until its memory is released.
// Called with mc.mu held.
func (m *Manager) stopRuntime(ctx context.Context, mc *machine) error {
	ctx, cancel := context.WithTimeout(ctx, m.cfg.KillTimeout)
	defer cancel()
	l := m.launch(mc)
	err := m.cfg.Runtime.Kill(ctx, l)
	if l.Cgroup != "" {
		g := &cgroup.Group{Path: l.Cgroup}
		if _, statErr := os.Stat(l.Cgroup); statErr == nil {
			// Backstop: anything the runtime left behind is killed, and
			// memory counts as released only once the group is empty.
			if kerr := g.Kill(ctx); kerr != nil && err == nil {
				err = kerr
			}
			if rerr := g.Remove(); rerr != nil && err == nil {
				err = rerr
			}
		}
	}
	if err == nil {
		// Only a guest known dead stops counting against the reserve.
		m.uncommitDisk(mc)
	}
	if mc.State == Running {
		mc.State = Stopped
	}
	return err
}

func (m *Manager) get(id string) (*machine, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mc, ok := m.machines[id]
	if !ok {
		return nil, fmt.Errorf("%w: machine %s", ErrUnknown, id)
	}
	return mc, nil
}

// Get returns a machine's record.
func (m *Manager) Get(id string) (Machine, error) {
	mc, err := m.get(id)
	if err != nil {
		return Machine{}, err
	}
	mc.mu.Lock()
	defer mc.mu.Unlock()
	return mc.Machine, nil
}

// Snapshot returns a snapshot's record.
func (m *Manager) Snapshot(id string) (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.snaps[id]
	if !ok {
		return Snapshot{}, fmt.Errorf("%w: snapshot %s", ErrUnknown, id)
	}
	return s, nil
}

// Snapshots lists a machine's snapshots, oldest first.
func (m *Manager) Snapshots(machineID string) []Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Snapshot
	for _, s := range m.snaps {
		if s.Machine == machineID {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RaiseLabel raises a machine's label (REV-5). Lowering is refused.
func (m *Manager) RaiseLabel(id string, l Label) error {
	mc, err := m.get(id)
	if err != nil {
		return err
	}
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if l < mc.Label {
		return fmt.Errorf("vm: %s: a label only rises (REV-5)", id)
	}
	mc.Label = l
	return m.saveMachine(mc)
}

// Label returns a machine's data label (REV-5).
func (m *Manager) Label(id string) (Label, error) {
	mc, err := m.get(id)
	if err != nil {
		return 0, err
	}
	mc.mu.Lock()
	defer mc.mu.Unlock()
	return mc.Label, nil
}

// DataLabel is machine id's REV-5 label as model egress reads it
// (egress.Config.Label): "public" only for a known machine labelled
// public. An unknown machine or any error reads "private", so a failed
// lookup never opens provider-side fetches.
func (m *Manager) DataLabel(id string) string {
	if l, err := m.Label(id); err == nil && l == Public {
		return Public.String()
	}
	return Private.String()
}

// Step takes the per-step file-system snapshot (REV-1).
func (m *Manager) Step(ctx context.Context, id string) (Snapshot, error) {
	return m.take(ctx, id, FS)
}

// Checkpoint takes a full-state checkpoint: memory and file system (REV-1,
// REV-4). The machine keeps running.
func (m *Manager) Checkpoint(ctx context.Context, id string) (Snapshot, error) {
	return m.take(ctx, id, Full)
}

func (m *Manager) take(ctx context.Context, id string, t Tier) (Snapshot, error) {
	mc, err := m.get(id)
	if err != nil {
		return Snapshot{}, err
	}
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if mc.State != Running {
		return Snapshot{}, fmt.Errorf("%w: %s is %s", ErrState, id, mc.State)
	}
	return m.takeLocked(ctx, mc, t)
}

// takeLocked pauses the machine so the layer copy is consistent with memory,
// copies it, checkpoints memory for Full, and resumes. A snapshot is
// published only when the whole operation succeeds: if the resume fails
// (a preemption that killed the sandbox after the image was whole, or any
// other cause), the snapshot just taken is withdrawn, so an error never
// leaves one behind (Security R2 on #124).
func (m *Manager) takeLocked(ctx context.Context, mc *machine, t Tier) (Snapshot, error) {
	if err := m.cfg.Runtime.Pause(ctx, mc.ID); err != nil {
		return Snapshot{}, err
	}
	prev := mc.Last
	s, err := m.capture(ctx, mc, t)
	// Resume even if the caller gave up, or the guest stays paused while
	// recorded as running.
	rerr := m.cfg.Runtime.Resume(context.WithoutCancel(ctx), mc.ID)
	if err != nil {
		if s.ID != "" {
			// Published, then the machine record failed to save (L3 on #137).
			m.withdrawLocked(mc, s.ID, prev)
		}
		return Snapshot{}, err
	}
	if rerr != nil {
		m.withdrawLocked(mc, s.ID, prev)
		return Snapshot{}, rerr
	}
	return s, nil
}

// withdrawLocked unpublishes snapshot id, just taken of mc, and deletes it;
// mc.mu is held. Like a prune, the record goes first, then meta.json, so a
// crash or a failed delete leaves a directory that load drops.
func (m *Manager) withdrawLocked(mc *machine, id, prev string) {
	if err := m.unpublishSnapshot(id); err != nil {
		log.Printf("vm: %s: withdrawing snapshot %s: %v", mc.ID, id, err)
	}
	if err := os.RemoveAll(m.snapDir(id)); err != nil {
		log.Printf("vm: %s: deleting withdrawn snapshot %s: %v", mc.ID, id, err)
	}
	if mc.Last == id {
		mc.Last = prev
		if err := m.saveMachine(mc); err != nil {
			log.Printf("vm: %s: %v", mc.ID, err)
		}
	}
}

// capture writes a snapshot of a paused (or stopped) machine.
func (m *Manager) capture(ctx context.Context, mc *machine, t Tier) (Snapshot, error) {
	return m.captureAs(ctx, mc, t, false)
}

// captureAs is capture; sleep marks a sleep checkpoint, with the
// machine's start count and the hash of what was written.
func (m *Manager) captureAs(ctx context.Context, mc *machine, t Tier, sleep bool) (Snapshot, error) {
	u, err := m.checkCaps(mc.ID, m.launch(mc).Upper)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%s: %w", mc.ID, err)
	}
	need := u.Bytes
	if t == Full {
		// The memory image is at most the machine's memory budget.
		need += mc.Spec.MemMB << 20
	}
	h, err := m.reserveDisk(need)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%s: %w", mc.ID, err)
	}
	defer h.release()
	s := Snapshot{ID: m.nextSnapID(), Machine: mc.ID, Tier: t, Label: mc.Label, Image: mc.Spec.Image, Lineage: mc.Lineage}
	dir := m.snapDir(s.ID)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Snapshot{}, err
	}
	fail := func(err error) (Snapshot, error) {
		os.RemoveAll(dir)
		return Snapshot{}, err
	}
	if err := overlay.Copy(m.launch(mc).Upper, filepath.Join(dir, "fs")); err != nil {
		return fail(err)
	}
	if t == Full {
		mem := filepath.Join(dir, "mem")
		if err := os.Mkdir(mem, 0o700); err != nil {
			return fail(err)
		}
		if err := m.cfg.Runtime.Checkpoint(ctx, mc.ID, mem); err != nil {
			return fail(err)
		}
	}
	// A preemption that began before the copy or checkpoint returned may
	// have killed the sandbox under it, and a runtime need not report that
	// as an error: the image may be cut short. Such a snapshot is never
	// published (Security R2 on #124). Preempt marks the machine before it
	// kills, so a mark not seen here means the kill came after the image
	// was whole.
	if mc.preempting.Load() {
		return fail(fmt.Errorf("%w: %s: snapshot discarded", ErrPreempted, mc.ID))
	}
	// Stamped once the capture is complete: a record handed to the machine
	// while it was being copied may be in it, so the snapshot must not
	// read as taken before that (CAP-3 restore points, V26).
	s.Taken = time.Now().UTC()
	if sleep {
		h, err := treeHash(dir)
		if err != nil {
			return fail(err)
		}
		s.Sleep, s.Starts, s.Hash = true, mc.Starts, h
	}
	if err := writeJSON(filepath.Join(dir, "meta.json"), s); err != nil {
		return fail(err)
	}
	m.mu.Lock()
	m.snaps[s.ID] = s
	m.mu.Unlock()
	mc.Last = s.ID
	return s, m.saveMachine(mc)
}

// measure is overlay.Measure, with a layer too deep or with paths too long
// for the broker to copy over the cap (security R4 on #166, L3 MUST-1 on
// #174): refused as a disk budget the guest can act on, never taken as no
// use. Every copy of a layer is measured against the longest root any copy
// of it can have, so a layer one step accepts no later restore or fork
// refuses (L3 MUST-A on #174).
func (m *Manager) measure(dir string) (overlay.Usage, error) {
	longest := max(len(filepath.Join(m.diskDir(strings.Repeat("x", maxIDLen)), "upper")),
		len(filepath.Join(m.snapDir(snapName(0)), "fs")))
	u, err := overlay.MeasureUnder(dir, longest)
	if errors.Is(err, overlay.ErrTooDeep) {
		err = fmt.Errorf("%w (%w)", ErrQuota, err)
	}
	return u, err
}

// checkCaps measures a layer about to be snapshotted and refuses it if it
// is over the per-layer caps. Copies keep holes and hardlinks, so a copy
// costs no more than this measure.
func (m *Manager) checkCaps(id, upper string) (overlay.Usage, error) {
	u, err := m.measure(upper)
	if err != nil {
		return u, err
	}
	switch {
	case strings.HasPrefix(id, WorkerPrefix) && m.cfg.WorkerLayerBytes > 0 && u.Bytes > m.cfg.WorkerLayerBytes:
		return u, &WorkerFull{ID: id, Bytes: u.Bytes, Cap: m.cfg.WorkerLayerBytes}
	case m.cfg.MaxLayerBytes > 0 && u.Bytes > m.cfg.MaxLayerBytes:
		return u, fmt.Errorf("%w (layer %d bytes, cap %d)", ErrQuota, u.Bytes, m.cfg.MaxLayerBytes)
	case u.Inodes > m.cfg.MaxLayerInodes:
		return u, fmt.Errorf("%w (layer %d inodes, cap %d)", ErrQuota, u.Inodes, m.cfg.MaxLayerInodes)
	}
	return u, nil
}

// diskHold is a reservation of state-disk bytes for copies in progress.
type diskHold struct {
	m *Manager
	n int64
}

// reserveDisk reserves need bytes for copies about to be made (RES-4). It
// is granted only if the measured free space, less the reserve and every
// other reservation still held, covers it. Reservations are serialized, so
// concurrent snapshots, forks, merges and rollbacks cannot each pass the
// check and together eat the reserve. While a copy runs its bytes count
// both as used and as held: an overestimate, never an under-one. Refusal
// changes nothing: no machine or snapshot is touched.
func (m *Manager) reserveDisk(need int64) (*diskHold, error) {
	h := &diskHold{m: m}
	if err := h.grow(need); err != nil {
		return nil, err
	}
	return h, nil
}

// reserveRestore reserves the disk for n copies of snapshot id's layer.
func (m *Manager) reserveRestore(n int64, id string) (*diskHold, error) {
	u, err := m.measure(filepath.Join(m.snapDir(id), "fs"))
	if err != nil {
		return nil, err
	}
	return m.reserveDisk(n * u.Bytes)
}

// grow adds need bytes to the reservation.
func (h *diskHold) grow(need int64) error {
	if need <= 0 {
		return nil
	}
	m := h.m
	m.diskMu.Lock()
	defer m.diskMu.Unlock()
	room, err := m.roomLocked()
	if err != nil {
		return err
	}
	if need > room {
		return fmt.Errorf("%w (need %d bytes; %d free above the reserve, holds and running machines)", ErrQuota, need, room)
	}
	m.diskHeld += need
	h.n += need
	return nil
}

// release returns the reservation; the copies made under it now show in
// the measured free space instead.
func (h *diskHold) release() {
	h.m.diskMu.Lock()
	h.m.diskHeld -= h.n
	h.n = 0
	h.m.diskMu.Unlock()
}

func (m *Manager) nextSnapID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	return snapName(m.seq)
}

// snapName is snapshot seq's ID: fixed width, so IDs sort by age and none
// is a prefix of another (S3).
func snapName(seq int) string { return fmt.Sprintf("s%010d", seq) }

// inLineage reports whether machine mc may use snapshot s: its own, or the
// one it was forked from.
func inLineage(mc *machine, s Snapshot) bool {
	return s.Machine == mc.ID || s.ID == mc.ForkBase
}

// Rollback returns a machine to snapshot snapID (REV-4). A full checkpoint
// restores memory too; a file-system snapshot restarts the guest on that
// file system. The machine's label does not fall (REV-5). A preempted or
// stopped machine is re-admitted first.
func (m *Manager) Rollback(ctx context.Context, id, snapID string) error {
	if strings.HasPrefix(id, EvalPrefix) {
		return fmt.Errorf("vm: replay machine %s cannot be rolled back", id)
	}
	mc, err := m.get(id)
	if err != nil {
		return err
	}
	s, err := m.Snapshot(snapID)
	if err != nil {
		return err
	}
	mc.lockEndingExec()
	if !inLineage(mc, s) {
		mc.mu.Unlock()
		return fmt.Errorf("%w: %s, %s", ErrLineage, id, snapID)
	}
	running := mc.State == Running
	mc.mu.Unlock()
	if !running {
		if err := m.admit(mc); err != nil {
			return err
		}
	}
	mc.mu.Lock()
	err = claimLocked(mc)
	if err == nil {
		mc.Label = maxLabel(mc.Label, s.Label)
		err = m.restartLocked(ctx, mc, &s)
	}
	mc.mu.Unlock()
	if err != nil {
		m.cfg.Admit.Release(id)
	}
	return err
}

// restartLocked stops a machine and starts it from s (nil: its image). The
// disk for restoring s is reserved before the machine is stopped, so a full
// disk refuses the restart and leaves the machine as it was. On other
// failures the machine is left Stopped and the caller releases admission.
func (m *Manager) restartLocked(ctx context.Context, mc *machine, s *Snapshot) error {
	if s == nil {
		h, err := m.reserveSeed(mc)
		if err != nil {
			return err
		}
		defer h.release()
	}
	if s != nil && s != keepLayer {
		h, err := m.reserveRestore(1, s.ID)
		if err != nil {
			return fmt.Errorf("%s: %w", mc.ID, err)
		}
		defer h.release()
	}
	return m.restartHeld(ctx, mc, s)
}

// restartHeld is restartLocked for a caller that already reserved the disk.
func (m *Manager) restartHeld(ctx context.Context, mc *machine, s *Snapshot) error {
	err := m.stopRuntime(ctx, mc)
	if err == nil {
		err = m.startFrom(ctx, mc, s)
	}
	if err != nil {
		m.stopRuntime(ctx, mc)
		mc.State = Stopped
		m.saveMachine(mc)
	}
	return err
}

// Resume restarts a preempted or stopped machine on the layer it had when
// it stopped (a cold start: memory is not kept), re-admitting it first. A
// machine with no layer left restarts from its image.
func (m *Manager) Resume(ctx context.Context, id string) error {
	mc, err := m.get(id)
	if err != nil {
		return err
	}
	mc.mu.Lock()
	st := mc.State
	mc.mu.Unlock()
	if st == Running {
		return fmt.Errorf("%w: %s is running", ErrState, id)
	}
	if _, err := os.Lstat(m.launch(mc).Upper); err != nil {
		return m.Rebuild(ctx, id)
	}
	if err := m.admit(mc); err != nil {
		return err
	}
	mc.mu.Lock()
	err = claimLocked(mc)
	if err == nil {
		err = m.restartLocked(ctx, mc, keepLayer)
	}
	mc.mu.Unlock()
	if err != nil {
		m.cfg.Admit.Release(id)
	}
	return err
}

// Fork checkpoints machine id and starts one new machine per entry of ids
// from that checkpoint, memory included (REV-4 fork(n), CAP-1). Each fork
// inherits the source's image, class, budget, and label (REV-5), and is
// admitted on its own budget, because forks share no memory (S3). Either all
// forks start or none do.
func (m *Manager) Fork(ctx context.Context, id string, ids []string) (Snapshot, error) {
	src, err := m.get(id)
	if err != nil {
		return Snapshot{}, err
	}
	if len(ids) == 0 {
		return Snapshot{}, errors.New("vm: fork needs at least one new machine")
	}
	if strings.HasPrefix(id, EvalPrefix) {
		return Snapshot{}, fmt.Errorf("vm: replay machine %s cannot be forked", id)
	}
	if strings.HasPrefix(id, BuilderPrefix) {
		return Snapshot{}, fmt.Errorf("vm: builder machine %s cannot be forked", id)
	}
	if m.contained(src) {
		return Snapshot{}, fmt.Errorf("%w (%s)", ErrContained, id)
	}
	worker := strings.HasPrefix(id, WorkerPrefix)
	for _, f := range ids {
		// A worker forks into workers only, and nothing else forks into
		// one: a worker's memory never runs with an agent's services, and
		// an agent's never runs without them (CAP-8).
		if strings.HasPrefix(f, WorkerPrefix) != worker {
			return Snapshot{}, fmt.Errorf("vm: a worker forks into workers only, and only a worker into ids starting %q", WorkerPrefix)
		}
		if strings.HasPrefix(f, EvalPrefix) {
			return Snapshot{}, fmt.Errorf("vm: machine ids starting %q are kept for replay", EvalPrefix)
		}
		if strings.HasPrefix(f, BuilderPrefix) {
			return Snapshot{}, fmt.Errorf("vm: machine ids starting %q are kept for Loop 1's builder", BuilderPrefix)
		}
		if !idRE.MatchString(f) {
			return Snapshot{}, fmt.Errorf("vm: bad machine id %q", f)
		}
	}
	src.mu.Lock()
	spec, label, lineage := src.Spec, src.Label, src.Lineage
	src.mu.Unlock()
	if lineage == "" {
		lineage = id
	}
	spec.Label = label

	var reserved []*machine
	undo := func() {
		for _, f := range reserved {
			m.unreserve(f.ID)
			m.cfg.Admit.Release(f.ID)
		}
	}
	for _, f := range ids {
		mc, err := m.reserve(f, spec, label, "", lineage)
		if err != nil {
			undo()
			return Snapshot{}, err
		}
		if err := m.admit(mc); err != nil {
			m.unreserve(f)
			undo()
			return Snapshot{}, err
		}
		reserved = append(reserved, mc)
	}

	// Reserve the disk for every fork's copy before checkpointing anything,
	// held until all have started, so a disk too small for n forks refuses
	// the fork outright instead of failing part-way.
	u, err := m.measure(m.launch(src).Upper)
	if err != nil {
		undo()
		return Snapshot{}, err
	}
	n := int64(len(ids))
	h, err := m.reserveDisk(n * u.Bytes)
	if err != nil {
		undo()
		return Snapshot{}, fmt.Errorf("%s: fork(%d): %w", id, n, err)
	}
	defer h.release()
	src.mu.Lock()
	prevLast := src.Last
	src.mu.Unlock()
	s, err := m.take(ctx, id, Full)
	if err != nil {
		undo()
		return Snapshot{}, err
	}
	// The guest ran until it was paused; cover any growth since.
	v, err := m.measure(filepath.Join(m.snapDir(s.ID), "fs"))
	if err == nil {
		err = h.grow(n*v.Bytes - h.n)
	}
	if err != nil {
		// No fork will use the checkpoint, so it goes too: a refused fork
		// leaves nothing behind.
		m.dropSnapshot(src, s.ID, prevLast)
		undo()
		return Snapshot{}, fmt.Errorf("%s: fork(%d): %w", id, n, err)
	}
	for i, mc := range reserved {
		mc.mu.Lock()
		m.setForkBase(mc, s.ID)
		mc.Label = maxLabel(mc.Label, s.Label)
		err := claimLocked(mc)
		if err == nil {
			err = m.startFrom(ctx, mc, &s)
		}
		if err != nil {
			m.stopRuntime(ctx, mc)
			os.RemoveAll(m.machineDir(mc.ID))
		}
		mc.mu.Unlock()
		if err != nil {
			for _, done := range reserved[:i] {
				m.Destroy(ctx, done.ID)
			}
			undo()
			return Snapshot{}, err
		}
	}
	return s, nil
}

// dropSnapshot deletes snapshot id, just taken of mc, that nothing uses;
// mc's newest snapshot goes back to prev.
func (m *Manager) dropSnapshot(mc *machine, id, prev string) {
	m.mu.Lock()
	delete(m.snaps, id)
	m.mu.Unlock()
	os.RemoveAll(m.snapDir(id))
	mc.mu.Lock()
	if mc.Last == id {
		mc.Last = prev
		m.saveMachine(mc)
	}
	mc.mu.Unlock()
}

// Diff lists file-system changes from snapshot a to snapshot b (REV-4).
// The requesting machine learns about both snapshots' contents, so its
// label rises to theirs (REV-5).
func (m *Manager) Diff(requester, a, b string) ([]overlay.Change, error) {
	sa, err := m.Snapshot(a)
	if err != nil {
		return nil, err
	}
	sb, err := m.Snapshot(b)
	if err != nil {
		return nil, err
	}
	if sa.Image != sb.Image {
		return nil, ErrImage
	}
	if requester != "" {
		if err := m.RaiseLabel(requester, maxLabel(m.labelOf(requester), maxLabel(sa.Label, sb.Label))); err != nil {
			return nil, err
		}
	}
	return overlay.Diff(m.view(sa), m.view(sb))
}

func (m *Manager) labelOf(id string) Label {
	mc, err := m.get(id)
	if err != nil {
		return Public
	}
	mc.mu.Lock()
	defer mc.mu.Unlock()
	return mc.Label
}

func (m *Manager) view(s Snapshot) overlay.View {
	return overlay.View{Lower: m.cfg.Images[s.Image], Upper: filepath.Join(m.snapDir(s.ID), "fs")}
}

// Merge brings a fork's file-system changes back into the machine it was
// forked from (REV-4): a three-way merge against the fork point. A path both
// sides changed differently is a conflict, and nothing is merged. On success
// dst restarts on the merged file system (a file-system rollback), and its
// label rises to the fork's (REV-5). Returns the merged snapshot.
func (m *Manager) Merge(ctx context.Context, dst, src string) (Snapshot, error) {
	if strings.HasPrefix(dst, EvalPrefix) || strings.HasPrefix(src, EvalPrefix) {
		return Snapshot{}, errors.New("vm: replay machines are not merged")
	}
	if strings.HasPrefix(dst, BuilderPrefix) || strings.HasPrefix(src, BuilderPrefix) {
		return Snapshot{}, errors.New("vm: builder machines are not merged")
	}
	if strings.HasPrefix(dst, WorkerPrefix) || strings.HasPrefix(src, WorkerPrefix) {
		return Snapshot{}, errors.New("vm: worker machines are not merged")
	}
	sm, err := m.get(src)
	if err != nil {
		return Snapshot{}, err
	}
	if m.contained(sm) {
		return Snapshot{}, fmt.Errorf("%w (%s)", ErrContained, src)
	}
	sm.mu.Lock()
	baseID := sm.ForkBase
	sm.mu.Unlock()
	base, err := m.Snapshot(baseID)
	if err != nil || base.Machine != dst {
		return Snapshot{}, fmt.Errorf("%w: %s was not forked from %s", ErrLineage, src, dst)
	}
	ss, err := m.Step(ctx, src)
	if err != nil {
		return Snapshot{}, err
	}
	dm, err := m.get(dst)
	if err != nil {
		return Snapshot{}, err
	}
	dm.mu.Lock()
	out, restarted, err := m.mergeLocked(ctx, dm, base, ss)
	dm.mu.Unlock()
	if err != nil && restarted {
		m.cfg.Admit.Release(dst)
	}
	return out, err
}

// mergeLocked does Merge's work with dst's lock held. restarted reports
// that dst was stopped, so a failure leaves it unadmitted.
func (m *Manager) mergeLocked(ctx context.Context, dm *machine, base, ss Snapshot) (out Snapshot, restarted bool, err error) {
	dst := dm.ID
	if dm.State != Running {
		return Snapshot{}, false, fmt.Errorf("%w: %s is %s", ErrState, dst, dm.State)
	}
	// Reserve the disk for the merged layer (at most dst's layer plus the
	// fork's) and for restarting dst on it, before touching dst.
	cost := func(dstUpper string) (int64, error) {
		d, err := m.measure(dstUpper)
		if err != nil {
			return 0, err
		}
		f, err := m.measure(m.view(ss).Upper)
		return 2 * (d.Bytes + f.Bytes), err
	}
	need, err := cost(m.launch(dm).Upper)
	if err != nil {
		return Snapshot{}, false, err
	}
	h, err := m.reserveDisk(need)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("merge into %s: %w", dst, err)
	}
	defer h.release()
	// A full checkpoint, so the owner can roll dst back to its pre-merge
	// memory as well as its files.
	ds, err := m.takeLocked(ctx, dm, Full)
	if err != nil {
		return Snapshot{}, false, err
	}
	// dst ran until it was paused; cover any growth since.
	if need, err = cost(m.view(ds).Upper); err == nil {
		err = h.grow(need - h.n)
	}
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("merge into %s: %w", dst, err)
	}
	changes, err := overlay.Diff(m.view(base), m.view(ss))
	if err != nil {
		return Snapshot{}, false, err
	}
	mine, err := overlay.Diff(m.view(base), m.view(ds))
	if err != nil {
		return Snapshot{}, false, err
	}
	conflicts := subtreeConflicts(changes, mine)
	conflicts = append(conflicts, subtreeConflicts(mine, changes)...)
	// Build the merged layer beside the snapshots, then publish it as one.
	out = Snapshot{ID: m.nextSnapID(), Machine: dst, Tier: FS, Label: maxLabel(dm.Label, ss.Label), Image: ds.Image, Taken: time.Now().UTC()}
	dir := m.snapDir(out.ID)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Snapshot{}, false, err
	}
	fail := func(err error) (Snapshot, bool, error) {
		os.RemoveAll(dir)
		return Snapshot{}, false, err
	}
	merged := overlay.View{Lower: m.cfg.Images[ds.Image], Upper: filepath.Join(dir, "fs")}
	if err := overlay.Copy(m.view(ds).Upper, merged.Upper); err != nil {
		return fail(err)
	}
	for _, c := range changes {
		mine, _, err := m.view(ds).Lookup(c.Path)
		if err != nil {
			return fail(err)
		}
		switch {
		case len(conflicts) > 0: // report only; merge nothing
			if !mine.Same(c.From) && !mine.Same(c.To) {
				conflicts = append(conflicts, c.Path)
			}
		case mine.Same(c.From): // dst left it alone: take the fork's
			if err := overlay.Put(merged, m.view(ss), c.Path); err != nil {
				return fail(err)
			}
		case mine.Same(c.To): // both made the same change
		default:
			conflicts = append(conflicts, c.Path)
		}
	}
	if len(conflicts) > 0 {
		sort.Strings(conflicts)
		return fail(fmt.Errorf("%w: %s", ErrConflict, strings.Join(conflicts, ", ")))
	}
	if err := writeJSON(filepath.Join(dir, "meta.json"), out); err != nil {
		return fail(err)
	}
	m.mu.Lock()
	m.snaps[out.ID] = out
	m.mu.Unlock()
	dm.Label = out.Label
	dm.Last = out.ID
	if err := m.restartHeld(ctx, dm, &out); err != nil {
		return Snapshot{}, true, err
	}
	return out, false, nil
}

// subtreeConflicts finds directories one side removed or turned into
// something else while the other side changed a path beneath them in a
// different way. A per-path comparison would let the removal silently win
// (or bring the directory back opaque), losing the other side's work.
func subtreeConflicts(side, other []overlay.Change) []string {
	otherTo := map[string]overlay.Entry{}
	for _, c := range other {
		otherTo[c.Path] = c.To
	}
	var out []string
	for _, c := range side {
		if c.From.Kind != overlay.Dir || c.To.Kind == overlay.Dir {
			continue
		}
		prefix := c.Path + string(filepath.Separator)
		for _, o := range other {
			if !strings.HasPrefix(o.Path, prefix) {
				continue
			}
			// Both sides removed it: the same change, not a conflict.
			if o.To.Kind == overlay.Absent && c.To.Kind != overlay.Dir {
				continue
			}
			out = append(out, c.Path)
			break
		}
	}
	return out
}

// Rebuild throws away a machine's layer and restarts it from its image
// (ARC-4). Durable state is in broker stores and is untouched: the journal,
// and every snapshot of the machine. The label stays (REV-5).
func (m *Manager) Rebuild(ctx context.Context, id string) error {
	mc, err := m.get(id)
	if err != nil {
		return err
	}
	mc.mu.Lock()
	running := mc.State == Running
	mc.mu.Unlock()
	if !running {
		if err := m.admit(mc); err != nil {
			return err
		}
	}
	mc.mu.Lock()
	err = claimLocked(mc)
	if err == nil {
		err = m.restartLocked(ctx, mc, nil)
	}
	mc.mu.Unlock()
	if err != nil {
		m.cfg.Admit.Release(id)
	}
	return err
}

// Destroy stops a machine, releases its admission, and deletes its layer.
// Its snapshots stay broker-held until pruned (RES-4).
func (m *Manager) Destroy(ctx context.Context, id string) error {
	mc, err := m.get(id)
	if err != nil {
		return err
	}
	mc.lockEndingExec()
	err = m.stopRuntime(ctx, mc)
	if err == nil {
		err = os.RemoveAll(m.machineDir(id))
	}
	if err == nil && m.cfg.Quota != nil && mc.Project != 0 {
		err = m.cfg.Quota.Clear(mc.Project)
	}
	mc.mu.Unlock()
	if err != nil {
		return err
	}
	m.unreserve(id)
	m.cfg.Admit.Release(id)
	return nil
}

// Preempt stops a running machine for a higher admission class (RES-1). It
// pauses the guest at once, kills it, and returns only once its memory is
// released, as admission.Preempter requires. Nothing is copied on this
// path, so its time does not grow with what the guest wrote: the machine's
// layer stays on disk and Resume restarts it there. Memory since the last
// full checkpoint is lost. Preempting a machine that is not running is a
// no-op.
//
// Preemption never waits for an operation already holding the machine (a
// checkpoint or a fork takes seconds, longer than the frozen target): it
// kills the sandbox under that operation, which then fails, and the
// machine is recorded as preempted once the operation lets go. While that
// is pending the machine cannot be started again.
func (m *Manager) Preempt(id string) error {
	mc, err := m.get(id)
	if err != nil {
		return nil // already gone: nothing holds memory
	}
	mc.preempting.Store(true)
	if mc.mu.TryLock() {
		defer mc.mu.Unlock()
		return m.preemptLocked(mc)
	}
	// The completion is scheduled even if the kill fails: once the holding
	// operation lets go, the machine is stopped under its lock and
	// recorded preempted, and preempting is cleared (L3 on #124). A
	// worker's command in flight is ended with it.
	if c := mc.execCancel.Load(); c != nil {
		(*c)()
	}
	kerr := m.kill(mc)
	go func() {
		mc.mu.Lock()
		defer mc.mu.Unlock()
		if err := m.preemptLocked(mc); err != nil {
			log.Printf("vm: %s: finishing preemption: %v", mc.ID, err)
		}
	}()
	return kerr
}

// preemptLocked stops mc and records it as preempted. Called with mc.mu
// held and mc.preempting set; it clears preempting.
func (m *Manager) preemptLocked(mc *machine) error {
	defer mc.preempting.Store(false)
	if mc.State != Running {
		// Admitted but not started yet: it must not start now.
		mc.revoked = true
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.KillTimeout)
	defer cancel()
	m.cfg.Runtime.Pause(ctx, mc.ID) // stop its CPU use now; the kill follows
	if err := m.stopRuntime(ctx, mc); err != nil {
		return err
	}
	mc.State = Preempted
	return m.saveMachine(mc)
}

// kill releases a machine's memory without its lock: it empties the
// machine's cgroup, or asks the runtime when there are no cgroups. Only
// fields fixed at creation are read. The runtime's own state is cleaned up
// later, under the lock, by stopRuntime.
func (m *Manager) kill(mc *machine) error {
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.KillTimeout)
	defer cancel()
	l := m.launch(mc)
	if l.Cgroup == "" {
		return m.cfg.Runtime.Kill(ctx, l)
	}
	if _, err := os.Stat(l.Cgroup); errors.Is(err, fs.ErrNotExist) {
		return nil // never started: nothing holds memory
	} else if err != nil {
		return err // unknown: memory may still be held
	}
	return (&cgroup.Group{Path: l.Cgroup}).Kill(ctx)
}

// Machines lists machine IDs, sorted.
func (m *Manager) Machines() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for id := range m.machines {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (m *Manager) saveMachine(mc *machine) error {
	mc.label.Store(uint32(mc.Label))
	return writeJSON(filepath.Join(m.machineDir(mc.ID), "meta.json"), mc.Machine)
}

func (m *Manager) load(ctx context.Context) error {
	snaps, err := os.ReadDir(filepath.Join(m.cfg.StateDir, "snapshots"))
	if err != nil {
		return err
	}
	for _, e := range snaps {
		var s Snapshot
		if err := readJSON(filepath.Join(m.snapDir(e.Name()), "meta.json"), &s); err != nil || s.ID != e.Name() {
			// A snapshot without metadata was never published: drop it.
			os.RemoveAll(m.snapDir(e.Name()))
			continue
		}
		m.snaps[s.ID] = s
		if n, err := strconv.Atoi(strings.TrimPrefix(s.ID, "s")); err == nil && n > m.seq {
			m.seq = n
		}
	}
	ms, err := os.ReadDir(filepath.Join(m.cfg.StateDir, "machines"))
	if err != nil {
		return err
	}
	for _, e := range ms {
		if m.cfg.Quota != nil {
			// A directory left by a creation cut short still holds files
			// of its project: no new machine is given that project.
			if p, err := quota.Project(m.diskDir(e.Name())); err == nil {
				m.project = max(m.project, p)
			}
		}
		mc := &machine{}
		if err := readJSON(filepath.Join(m.machineDir(e.Name()), "meta.json"), &mc.Machine); err != nil || mc.ID != e.Name() {
			continue
		}
		if mc.State == Running {
			mc.State = Stopped
		}
		if mc.Lineage == "" {
			mc.Lineage = mc.ID
		}
		m.project = max(m.project, mc.Project)
		if err := m.stopRuntime(ctx, mc); err != nil && m.cfg.Quota != nil && mc.Project != 0 {
			// Its guest may outlive the broker: it stays counted.
			m.live[mc.Project] = m.diskBudget(mc.ID)
		}
		m.machines[mc.ID] = mc
		if err := m.saveMachine(mc); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
