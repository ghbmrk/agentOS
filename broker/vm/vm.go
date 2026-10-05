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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/cgroup"
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

// Machine is a copy of a machine's record.
type Machine struct {
	ID       string
	Spec     Spec
	Label    Label
	State    State
	ForkBase string // snapshot this machine was forked from, if any
	Last     string // newest snapshot of this machine
}

// Snapshot is a broker-held snapshot's record.
type Snapshot struct {
	ID      string
	Machine string
	Tier    Tier
	Label   Label // the machine's label when taken
	Image   string
	Taken   time.Time
}

// Launch is what a Runtime needs to run a machine.
type Launch struct {
	ID     string // machine ID
	Dir    string // broker-held machine directory, for runtime files
	Lower  string // image root, read only
	Upper  string // writable layer
	Work   string // overlayfs work directory
	Root   string // where the merged root is mounted
	Cgroup string // cgroup v2 directory to start the machine in; "" if none
	Argv   []string
	Env    []string
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
	// DiskReserveBytes is the state disk's RES-4 reserve (a healthy
	// release, the journal, the recall index). A snapshot is admitted only
	// if copying the layer leaves the reserve free, as memory admission
	// leaves its headroom (RES-2). Zero means 2 GiB.
	DiskReserveBytes int64
	// MaxLayerBytes optionally caps one machine's layer on top of that
	// (zero: no fixed cap). MaxLayerInodes caps its inodes (zero: 200,000).
	MaxLayerBytes, MaxLayerInodes int64
	// FreeBytes reports the state disk's free space; nil measures it.
	FreeBytes func(path string) (int64, error)
}

var (
	ErrUnknown  = errors.New("vm: unknown machine or snapshot")
	ErrExists   = errors.New("vm: machine already exists")
	ErrState    = errors.New("vm: machine is not in a state that allows this")
	ErrLineage  = errors.New("vm: snapshot is not in this machine's lineage")
	ErrConflict = errors.New("vm: merge conflict")
	ErrImage    = errors.New("vm: snapshots are of different images")
	ErrRevoked  = errors.New("vm: admission was withdrawn before the machine started")
	ErrQuota    = errors.New("vm: disk budget exceeded: snapshot refused; free space in the machine (delete files) or roll back, then retry")
)

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

type machine struct {
	mu sync.Mutex // held for a machine's whole operation
	Machine
	// revoked: admission preempted the machine after admitting it but
	// before it started, so it must not start on that admission.
	revoked bool
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
	m := &Manager{cfg: cfg, machines: map[string]*machine{}, snaps: map[string]Snapshot{}}
	if err := m.load(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) machineDir(id string) string { return filepath.Join(m.cfg.StateDir, "machines", id) }
func (m *Manager) snapDir(id string) string    { return filepath.Join(m.cfg.StateDir, "snapshots", id) }

func (m *Manager) launch(mc *machine) Launch {
	d := m.machineDir(mc.ID)
	l := Launch{
		ID: mc.ID, Dir: d,
		Lower: m.cfg.Images[mc.Spec.Image],
		Upper: filepath.Join(d, "upper"), Work: filepath.Join(d, "work"), Root: filepath.Join(d, "root"),
		Argv: mc.Spec.Argv, Env: mc.Spec.Env,
	}
	if m.cfg.Cgroups != nil {
		l.Cgroup = filepath.Join(m.cfg.Cgroups.Path, mc.ID)
	}
	return l
}

// Create admits and starts a new machine from an image.
func (m *Manager) Create(ctx context.Context, id string, s Spec) (Machine, error) {
	if !idRE.MatchString(id) {
		return Machine{}, fmt.Errorf("vm: bad machine id %q", id)
	}
	if _, ok := m.cfg.Images[s.Image]; !ok {
		return Machine{}, fmt.Errorf("%w: image %q", ErrUnknown, s.Image)
	}
	mc, err := m.reserve(id, s, s.Label, "")
	if err != nil {
		return Machine{}, err
	}
	if err := m.admit(mc); err != nil {
		m.unreserve(id)
		return Machine{}, err
	}
	mc.mu.Lock()
	err = claimLocked(mc)
	if err == nil {
		err = m.startFrom(ctx, mc, nil)
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
func (m *Manager) reserve(id string, s Spec, l Label, forkBase string) (*machine, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.machines[id]; ok {
		return nil, fmt.Errorf("%w: %s", ErrExists, id)
	}
	if _, err := os.Lstat(m.machineDir(id)); err == nil {
		return nil, fmt.Errorf("%w: %s (left on disk)", ErrExists, id)
	}
	mc := &machine{Machine: Machine{ID: id, Spec: s, Label: l, State: Stopped, ForkBase: forkBase}}
	m.machines[id] = mc
	return mc, nil
}

func (m *Manager) unreserve(id string) {
	m.mu.Lock()
	delete(m.machines, id)
	m.mu.Unlock()
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
	for _, p := range []string{l.Upper, l.Work} {
		if keep && p == l.Upper {
			continue
		}
		if err := os.RemoveAll(p); err != nil {
			return err
		}
	}
	if keep {
		if fi, err := os.Lstat(l.Upper); err != nil || !fi.IsDir() {
			return fmt.Errorf("vm: %s has no layer to resume on", mc.ID)
		}
	} else if s == nil {
		if err := os.Mkdir(l.Upper, 0o755); err != nil {
			return err
		}
	} else if err := overlay.Copy(filepath.Join(m.snapDir(s.ID), "fs"), l.Upper); err != nil {
		return err
	}
	if err := os.Mkdir(l.Work, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(l.Root, 0o755); err != nil {
		return err
	}
	if m.cfg.Cgroups != nil {
		if _, err := m.cfg.Cgroups.Child(mc.ID, cgroup.Limits{MaxBytes: mc.Spec.MemMB << 20}); err != nil {
			return err
		}
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
	mc.State = Running
	return m.saveMachine(mc)
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
// copies it, checkpoints memory for Full, and resumes.
func (m *Manager) takeLocked(ctx context.Context, mc *machine, t Tier) (s Snapshot, err error) {
	if err := m.cfg.Runtime.Pause(ctx, mc.ID); err != nil {
		return Snapshot{}, err
	}
	defer func() {
		// Resume even if the caller gave up, or the guest stays paused while
		// recorded as running.
		if rerr := m.cfg.Runtime.Resume(context.WithoutCancel(ctx), mc.ID); rerr != nil && err == nil {
			err = rerr
		}
	}()
	return m.capture(ctx, mc, t)
}

// capture writes a snapshot of a paused (or stopped) machine.
func (m *Manager) capture(ctx context.Context, mc *machine, t Tier) (Snapshot, error) {
	u, err := m.checkCaps(m.launch(mc).Upper)
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
	s := Snapshot{ID: m.nextSnapID(), Machine: mc.ID, Tier: t, Label: mc.Label, Image: mc.Spec.Image, Taken: time.Now().UTC()}
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
	if err := writeJSON(filepath.Join(dir, "meta.json"), s); err != nil {
		return fail(err)
	}
	m.mu.Lock()
	m.snaps[s.ID] = s
	m.mu.Unlock()
	mc.Last = s.ID
	return s, m.saveMachine(mc)
}

// checkCaps measures a layer about to be snapshotted and refuses it if it
// is over the per-layer caps. Copies keep holes and hardlinks, so a copy
// costs no more than this measure.
func (m *Manager) checkCaps(upper string) (overlay.Usage, error) {
	u, err := overlay.Measure(upper)
	if err != nil {
		return u, err
	}
	switch {
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
	u, err := overlay.Measure(filepath.Join(m.snapDir(id), "fs"))
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
	free, err := m.cfg.FreeBytes(m.cfg.StateDir)
	if err != nil {
		return err
	}
	if need > free-m.cfg.DiskReserveBytes-m.diskHeld {
		return fmt.Errorf("%w (need %d bytes; %d free, %d reserved, %d held)", ErrQuota, need, free, m.cfg.DiskReserveBytes, m.diskHeld)
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
	// Fixed width, so IDs sort by age and none is a prefix of another (S3).
	return fmt.Sprintf("s%010d", m.seq)
}

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
	mc, err := m.get(id)
	if err != nil {
		return err
	}
	s, err := m.Snapshot(snapID)
	if err != nil {
		return err
	}
	mc.mu.Lock()
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
	for _, f := range ids {
		if !idRE.MatchString(f) {
			return Snapshot{}, fmt.Errorf("vm: bad machine id %q", f)
		}
	}
	src.mu.Lock()
	spec, label := src.Spec, src.Label
	src.mu.Unlock()
	spec.Label = label

	var reserved []*machine
	undo := func() {
		for _, f := range reserved {
			m.unreserve(f.ID)
			m.cfg.Admit.Release(f.ID)
		}
	}
	for _, f := range ids {
		mc, err := m.reserve(f, spec, label, "")
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
	u, err := overlay.Measure(m.launch(src).Upper)
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
	v, err := overlay.Measure(filepath.Join(m.snapDir(s.ID), "fs"))
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
		mc.ForkBase = s.ID
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
	sm, err := m.get(src)
	if err != nil {
		return Snapshot{}, err
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
		d, err := overlay.Measure(dstUpper)
		if err != nil {
			return 0, err
		}
		f, err := overlay.Measure(m.view(ss).Upper)
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
	mc.mu.Lock()
	err = m.stopRuntime(ctx, mc)
	if err == nil {
		err = os.RemoveAll(m.machineDir(id))
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
func (m *Manager) Preempt(id string) error {
	mc, err := m.get(id)
	if err != nil {
		return nil // already gone: nothing holds memory
	}
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if mc.State != Running {
		// Admitted but not started yet: it must not start now.
		mc.revoked = true
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.KillTimeout)
	defer cancel()
	m.cfg.Runtime.Pause(ctx, id) // stop its CPU use now; the kill follows
	if err := m.stopRuntime(ctx, mc); err != nil {
		return err
	}
	mc.State = Preempted
	return m.saveMachine(mc)
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
		mc := &machine{}
		if err := readJSON(filepath.Join(m.machineDir(e.Name()), "meta.json"), &mc.Machine); err != nil || mc.ID != e.Name() {
			continue
		}
		if mc.State == Running {
			mc.State = Stopped
		}
		m.stopRuntime(ctx, mc)
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
