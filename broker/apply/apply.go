// Package apply is the broker side of update apply (UPD-1, UPD-6): it
// hands a verified release the change pipeline staged to the image's A/B
// activator through a journaled intent with a rollback point, only when
// the box is free (no call, no accepted work, not in hours the owner
// excluded), and after the restart commits it once the new slot passed its
// health check or drops it when boot counting fell back.
//
// A fallback rewinds only the boot slot. Everything the broker keeps lives
// outside the image (the journal, grants and their revocations, budgets,
// deletions, the update store's root metadata), so this package never
// snapshots or restores it.
package apply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/update"
)

// Journal vocabulary. Activating a release is a broker-state intent
// (OP-5) that only the applier submits.
const (
	Executor = "update"
	Origin   = "update"
	Action   = journal.ActionReleaseActivate
)

// Activator is the image's A/B activator (P2-1: systemd-sysupdate and
// systemd-boot with boot counting).
type Activator interface {
	// Install writes the release's /usr image, its verity data and its
	// boot entry to the inactive slot together (UPD-1a) and makes that
	// entry the next boot, with counted tries. It does not restart.
	Install(ctx context.Context, v *update.Verified) error
	// Abandon undoes an Install the box did not restart into: the
	// inactive slot is no longer the next boot. It is safe to call when
	// nothing was installed.
	Abandon(ctx context.Context) error
	// Restart boots the next entry.
	Restart(ctx context.Context) error
	// Booted reports the running boot.
	Booted(ctx context.Context) (Boot, error)
}

// Boot is the running boot: its ID (new at every boot), the /usr root
// hash it runs, and whether it is blessed, meaning its health check
// passed (UPD-1).
type Boot struct {
	ID          string
	UsrRootHash string
	Blessed     bool
}

// Stager is the change pipeline's hook for a staged image adoption.
type Stager interface {
	ConfirmStaged(ref string) error
	StageFailed(ctx context.Context, ref string) error
}

// Journal is the part of the intent engine the applier uses.
type Journal interface {
	Submit(journal.Intent) (journal.Status, error)
	Authorize(ctx context.Context, id string) (journal.Status, error)
	Dispatch(ctx context.Context, id string) (journal.Status, error)
}

// Store persists the applier's state (change.MemStore, change.FileStore).
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// Config configures New. Every function field but Excluded, Rand and Now
// is required.
type Config struct {
	Journal   Journal
	Activator Activator
	// Store is the box's update store: the applier stages the release in
	// it before the restart and commits or drops it after.
	Store    *update.Store
	Pipeline Stager
	State    Store
	// InCall reports a call in progress; Working reports accepted work in
	// progress (UPD-6).
	InCall  func() bool
	Working func() bool
	// Excluded reports hours the owner excluded from updates (UPD-6).
	// Nil: none.
	Excluded func(time.Time) bool
	// Jitter is the most an ordinary release waits, at random, before its
	// quiet moment (UPD-5). Security fixes do not wait. Default 6 hours.
	Jitter time.Duration
	// Rand returns a number in [0, n). Default: crypto/rand.
	Rand func(n int64) int64
	Now  func() time.Time
}

// pending is a release waiting to be applied.
type pending struct {
	Version   int64     `json:"version"`
	Adoption  string    `json:"adoption"`
	Security  bool      `json:"security"`
	NotBefore time.Time `json:"not_before"`
}

// point is the rollback point of an apply in flight: what ran before, what
// was handed to the activator, and the boot it was handed over in.
type point struct {
	ID       string `json:"id"`
	From     int64  `json:"from"`
	FromUsr  string `json:"from_usr"`
	To       int64  `json:"to"`
	ToUsr    string `json:"to_usr"`
	Adoption string `json:"adoption"`
	BootID   string `json:"boot_id"`
	// Installed: the activator took the release. Unset, a later boot is
	// not a fallback: nothing was handed over.
	Installed bool `json:"installed"`
}

// Outcome kinds for Status.
const (
	doneInstalled = "installed"
	doneFellBack  = "fell_back"
	doneNotHanded = "not_handed"
)

type last struct {
	Version int64  `json:"version"`
	Kind    string `json:"kind"`
}

type state struct {
	Seq      int             `json:"seq"`
	Pending  *pending        `json:"pending,omitempty"`
	Applying *point          `json:"applying,omitempty"`
	Applied  map[string]bool `json:"applied"`
	Last     *last           `json:"last,omitempty"`
}

// Applier applies staged releases.
type Applier struct {
	cfg Config
	mu  sync.Mutex
	st  state
	rel *update.Verified // the pending release, held in memory only
	// executing: Execute is handing a release over, with the lock
	// released during the slot write.
	executing bool
}

// New loads the applier's state. A pending release is not kept across a
// restart (a *update.Verified is never persisted); Loop 3's next check
// schedules it again.
func New(cfg Config) (*Applier, error) {
	if cfg.Journal == nil || cfg.Activator == nil || cfg.Store == nil || cfg.Pipeline == nil || cfg.State == nil ||
		cfg.InCall == nil || cfg.Working == nil {
		return nil, errors.New("apply: Journal, Activator, Store, Pipeline, State, InCall and Working are required")
	}
	if cfg.Excluded == nil {
		cfg.Excluded = func(time.Time) bool { return false }
	}
	if cfg.Jitter <= 0 {
		cfg.Jitter = 6 * time.Hour
	}
	if cfg.Rand == nil {
		cfg.Rand = cryptoRand
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	a := &Applier{cfg: cfg}
	b, err := cfg.State.Load()
	if err != nil {
		return nil, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &a.st); err != nil {
			return nil, fmt.Errorf("apply: state: %w", err)
		}
	}
	if a.st.Applied == nil {
		a.st.Applied = map[string]bool{}
	}
	a.st.Pending = nil
	return a, nil
}

// Schedule queues a verified release the change pipeline adopted as
// staged (adoption is the pipeline's reference). A security fix is due at
// once; an ordinary release after a random jitter (UPD-5). A newer
// schedule replaces an older one.
func (a *Applier) Schedule(v *update.Verified, adoption string) error {
	if !v.OK() {
		return update.ErrNotChecked
	}
	m, err := v.Manifest()
	if err != nil {
		return err
	}
	in, err := a.cfg.Store.Installed()
	if err != nil {
		return err
	}
	if m.Version <= in.Version {
		return fmt.Errorf("%w: release %d is not newer than installed %d", update.ErrRollback, m.Version, in.Version)
	}
	if adoption == "" {
		return errors.New("apply: no adoption")
	}
	nb := a.cfg.Now()
	if !v.Security() {
		nb = nb.Add(time.Duration(a.cfg.Rand(int64(a.cfg.Jitter))))
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.st.Applying != nil {
		return errors.New("apply: a release is being applied")
	}
	if p := a.st.Pending; p != nil && p.Version == m.Version && p.Adoption == adoption {
		a.rel = v // the same release again: keep its moment
		return nil
	}
	a.st.Pending = &pending{Version: m.Version, Adoption: adoption, Security: v.Security(), NotBefore: nb}
	a.rel = v
	return a.saveLocked()
}

// busy reports why the box is not free now, or "".
func (a *Applier) busy(now time.Time) string {
	switch {
	case a.cfg.InCall():
		return "a call is in progress"
	case a.cfg.Working():
		return "accepted work is in progress"
	case a.cfg.Excluded(now):
		return "the owner excluded these hours from updates"
	}
	return ""
}

// Tick applies the pending release when it is due and the box is free:
// it journals the activation and, once the activator took the release,
// restarts. ok reports the restart.
func (a *Applier) Tick(ctx context.Context) (ok bool, err error) {
	now := a.cfg.Now()
	a.mu.Lock()
	p := a.st.Pending
	if p == nil || a.rel == nil || a.st.Applying != nil || now.Before(p.NotBefore) {
		a.mu.Unlock()
		return false, nil
	}
	a.mu.Unlock()
	if a.busy(now) != "" {
		return false, nil
	}
	id := a.nextID(p.Version)
	st, err := a.cfg.Journal.Submit(a.intent(id))
	if err != nil {
		return false, err
	}
	if st.State == journal.Pending {
		if st, err = a.cfg.Journal.Authorize(ctx, id); err != nil {
			return false, err
		}
	}
	if st.State == journal.Authorized {
		if st, err = a.cfg.Journal.Dispatch(ctx, id); err != nil {
			return false, err
		}
	}
	if st.State != journal.Succeeded {
		return false, nil // denied (busy at dispatch) or not applied: try again later
	}
	return true, a.cfg.Activator.Restart(ctx)
}

// nextID numbers an apply attempt: upd:apply:<version>:n<seq>.
func (a *Applier) nextID(version int64) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.st.Seq++
	return fmt.Sprintf("upd:apply:%d:n%d", version, a.st.Seq)
}

// intent is the activation intent for id, with the rollback point in its
// params: the release it replaces and the one it activates.
func (a *Applier) intent(id string) journal.Intent {
	a.mu.Lock()
	defer a.mu.Unlock()
	params := map[string]any{}
	if p := a.st.Pending; p != nil && a.rel != nil {
		m, _ := a.rel.Manifest()
		in, _ := a.cfg.Store.Installed()
		b, _ := a.cfg.Activator.Booted(context.Background())
		params = map[string]any{"from": in.Version, "from_usr": b.UsrRootHash, "to": m.Version, "to_usr": m.UsrRootHash,
			"adoption": p.Adoption, "security": p.Security}
	}
	return journal.Intent{ID: id, Origin: Origin, Account: journal.BrokerAccount, Action: Action,
		Executor: Executor, Params: params}
}

func parseID(id string) (int64, bool) {
	p := strings.Split(id, ":")
	if len(p) != 4 || p[0] != "upd" || p[1] != "apply" || !strings.HasPrefix(p[3], "n") {
		return 0, false
	}
	v, err := strconv.ParseInt(p[2], 10, 64)
	if err != nil || p[2] != strconv.FormatInt(v, 10) {
		return 0, false
	}
	if _, err := strconv.Atoi(p[3][1:]); err != nil {
		return 0, false
	}
	return v, true
}

// Check is the policy for release activation (OP-3), at authorize and
// again just before dispatch: only the applier's own intent, for the
// release it holds, while the box is free (UPD-6).
func (a *Applier) Check(_ context.Context, _ journal.Phase, in journal.Intent) error {
	if in.Account != journal.BrokerAccount || in.Executor != Executor || in.Action != Action {
		return errors.New("apply: not a release activation")
	}
	if in.Origin != Origin {
		return errors.New("apply: only the update applier activates a release")
	}
	v, ok := parseID(in.ID)
	if !ok {
		return errors.New("apply: malformed activation intent")
	}
	a.mu.Lock()
	p, held, applying := a.st.Pending, a.rel != nil, a.st.Applying != nil
	a.mu.Unlock()
	if p == nil || !held || p.Version != v || applying {
		return errors.New("apply: no release is waiting for this activation")
	}
	if why := a.busy(a.cfg.Now()); why != "" {
		return errors.New("apply: " + why)
	}
	return nil
}

// Execute hands the release to the activator. The rollback point is saved
// first, then the release is staged in the update store and installed in
// the inactive slot, without holding the lock, so STATUS answers during
// the slot write. A failed install is abandoned and drops the stage, and
// the release stays pending.
func (a *Applier) Execute(ctx context.Context, in journal.Intent, _ int) journal.Outcome {
	v, ok := parseID(in.ID)
	if !ok {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "malformed"}
	}
	a.mu.Lock()
	if a.st.Applied[in.ID] {
		a.mu.Unlock()
		return journal.Outcome{Result: journal.ResultSucceeded}
	}
	p, rel := a.st.Pending, a.rel
	if p == nil || rel == nil || p.Version != v || a.st.Applying != nil || a.executing {
		a.mu.Unlock()
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "no pending release"}
	}
	pt, err := a.pointLocked(ctx, in.ID, rel, p.Adoption)
	if err == nil {
		a.st.Applying = pt
		if err = a.saveLocked(); err != nil {
			a.st.Applying = nil
		}
	}
	if err != nil {
		a.mu.Unlock()
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "rollback point not saved: " + err.Error()}
	}
	a.executing = true
	a.mu.Unlock()

	err = a.cfg.Store.Stage(rel)
	if err == nil {
		err = a.cfg.Activator.Install(ctx, rel)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.executing = false
	if err != nil {
		_ = a.cfg.Activator.Abandon(ctx)
		_ = a.cfg.Store.DropStaged()
		a.st.Applying = nil
		_ = a.saveLocked()
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: err.Error()}
	}
	a.st.Applying.Installed = true
	if a.st.Pending == p {
		a.st.Pending, a.rel = nil, nil
	}
	a.st.Applied = map[string]bool{in.ID: true} // only the latest is ever reconciled
	if err := a.saveLocked(); err != nil {
		// The slot holds the release; Resume judges it by the boot that
		// follows, whatever the saved state says.
		return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "state not saved"}
	}
	return journal.Outcome{Result: journal.ResultSucceeded}
}

// pointLocked is the rollback point for handing rel over now.
func (a *Applier) pointLocked(ctx context.Context, id string, rel *update.Verified, adoption string) (*point, error) {
	m, err := rel.Manifest()
	if err != nil {
		return nil, err
	}
	installed, err := a.cfg.Store.Installed()
	if err != nil {
		return nil, err
	}
	boot, err := a.cfg.Activator.Booted(ctx)
	if err != nil {
		return nil, err
	}
	return &point{ID: id, From: installed.Version, FromUsr: boot.UsrRootHash, To: m.Version,
		ToUsr: m.UsrRootHash, Adoption: adoption, BootID: boot.ID}, nil
}

// Reconcile answers from saved state: an activation is applied only once
// the activator took the release.
func (a *Applier) Reconcile(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.st.Applied[in.ID] || (a.st.Applying != nil && a.st.Applying.ID == in.ID && a.st.Applying.Installed) {
		return journal.Outcome{Result: journal.ResultSucceeded}
	}
	return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "not handed to the activator"}
}

// Resume settles an apply in flight after a restart, and is safe to call
// again until it does. Once the box runs a new boot, a blessed boot of
// the new release commits it (the update store and the pipeline's staged
// adoption); any other release means boot counting fell back, so the
// stage is dropped and the adoption reverted with no owner action
// (UPD-1). A boot of the new release whose health check has not passed
// yet waits. In the same boot, an apply the activator never took (the
// broker stopped mid-handover) is abandoned.
func (a *Applier) Resume(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	pt := a.st.Applying
	if pt == nil || a.executing {
		return nil
	}
	b, err := a.cfg.Activator.Booted(ctx)
	if err != nil {
		return err
	}
	switch {
	case b.ID == pt.BootID && pt.Installed:
		return nil // not restarted yet
	case b.ID == pt.BootID:
		if err := a.cfg.Activator.Abandon(ctx); err != nil {
			return err
		}
		if err := a.cfg.Store.DropStaged(); err != nil {
			return err
		}
		a.st.Last = &last{Version: pt.To, Kind: doneNotHanded}
	case b.UsrRootHash == pt.ToUsr && !b.Blessed:
		return nil // the health check has not passed yet
	case b.UsrRootHash == pt.ToUsr:
		if err := a.cfg.Store.CommitStaged(pt.To); err != nil {
			return err
		}
		if err := a.cfg.Pipeline.ConfirmStaged(pt.Adoption); err != nil {
			return err
		}
		a.st.Last = &last{Version: pt.To, Kind: doneInstalled}
	default:
		if err := a.cfg.Store.DropStaged(); err != nil {
			return err
		}
		if err := a.cfg.Pipeline.StageFailed(ctx, pt.Adoption); err != nil {
			return err
		}
		a.st.Last = &last{Version: pt.To, Kind: doneFellBack}
	}
	a.st.Applying = nil
	return a.saveLocked()
}

// Status is the applier's one line for STATUS and the digest, or "".
func (a *Applier) Status() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.st.Applying != nil && a.st.Applying.Installed:
		return fmt.Sprintf("Update %d is installing; the box will restart and check it.", a.st.Applying.To)
	case a.st.Pending != nil && a.rel != nil:
		if a.busy(a.cfg.Now()) != "" || a.cfg.Now().Before(a.st.Pending.NotBefore) {
			return fmt.Sprintf("Update %d is ready and will install when the box is free.", a.st.Pending.Version)
		}
		return fmt.Sprintf("Update %d is ready to install.", a.st.Pending.Version)
	case a.st.Last == nil:
		return ""
	case a.st.Last.Kind == doneInstalled:
		return fmt.Sprintf("Update %d is installed.", a.st.Last.Version)
	case a.st.Last.Kind == doneFellBack:
		return fmt.Sprintf("Update %d did not start cleanly, so the box went back to the version it had.", a.st.Last.Version)
	}
	return fmt.Sprintf("Update %d was not installed; the box will try again.", a.st.Last.Version)
}

func (a *Applier) saveLocked() error {
	b, err := json.Marshal(a.st)
	if err != nil {
		return err
	}
	return a.cfg.State.Save(b)
}
