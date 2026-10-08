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
	"github.com/ghbmrk/agentos/broker/reversible"
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
	// entry the next boot, with counted tries. It does not restart. It
	// reads each file only through v.Fetch, which checks the signed length
	// and hash, never follows a symlink in the slot it writes, and verifies
	// the written slot against the manifest's /usr root hash before it
	// makes the entry the next boot (security C2 on #133).
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

// Config configures New. Every function field but Excluded, Held, Rand
// and Now is required.
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
	// Stopped reports STOP in force (CH-11): nothing is handed over and no
	// restart happens while it holds. Nil: the Journal's own Stopped, which
	// *journal.Engine has; New refuses a journal without one.
	Stopped func() bool
	// LastTalk is when the owner was last delivered a message or the
	// agent last replied. Within Quiet of it the box is not free, so a
	// restart never cuts a conversation off (UX-133-4). Nil: never.
	LastTalk func() time.Time
	// Quiet is how long after LastTalk the box waits. Default 10 minutes.
	Quiet time.Duration
	// Held is when the last effect the owner approved under an undo
	// window is released (grants.Gate.HeldUntil); zero when none is held.
	// A restart cancels every held effect (reversible RV6), so until then
	// the box is not free (UX-76-2). Nil: nothing is ever held.
	Held func() time.Time
	// HeldBound is the longest held effects hold an update, from when it
	// became due, so approvals that keep arriving cannot hold it for ever.
	// Default DefaultHeldBound.
	HeldBound time.Duration
	// TalkBound is the longest a security fix waits on talk, from when it
	// became due; after it only a call, accepted work or excluded hours
	// hold it, so an agent or a spoofed sender that keeps talking cannot
	// hold a fix for ever (security ruling on UX-133-4). Default 2 hours.
	TalkBound time.Duration
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
	// TalkUntil: after it, talk no longer holds the restart (zero: no
	// bound).
	TalkUntil time.Time `json:"talk_until,omitzero"`
	// HeldUntil: after it, held effects no longer hold the restart (zero:
	// they never do).
	HeldUntil time.Time `json:"held_until,omitzero"`
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
	// Told: the digest carried it (UX-133-1).
	Told bool `json:"told,omitempty"`
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
	if cfg.Stopped == nil {
		j, ok := cfg.Journal.(interface{ Stopped() bool })
		if !ok {
			return nil, errors.New("apply: Stopped is required")
		}
		cfg.Stopped = j.Stopped
	}
	if cfg.LastTalk == nil {
		cfg.LastTalk = func() time.Time { return time.Time{} }
	}
	if cfg.Quiet <= 0 {
		cfg.Quiet = 10 * time.Minute
	}
	if cfg.Held == nil {
		cfg.Held = func() time.Time { return time.Time{} }
	}
	if cfg.HeldBound <= 0 {
		cfg.HeldBound = DefaultHeldBound
	}
	if cfg.TalkBound <= 0 {
		cfg.TalkBound = 2 * time.Hour
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

// DefaultHeldBound is the longest undo window a reversible form may
// declare: held effects never hold an update longer than one of them
// could last (UX-76-2).
const DefaultHeldBound = reversible.MaxWindow

// talkUntil is when talk stops holding a pending release: a security fix
// TalkBound after it became due; an ordinary release never (zero).
func (a *Applier) talkUntil(p *pending) time.Time {
	if p == nil || !p.Security {
		return time.Time{}
	}
	return p.NotBefore.Add(a.cfg.TalkBound)
}

// heldUntil is when held effects stop holding a pending release:
// HeldBound after it became due.
func (a *Applier) heldUntil(p *pending) time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.NotBefore.Add(a.cfg.HeldBound)
}

// busy reports why the box is not free now, or "". Talk holds only until
// talkUntil, when that is set; held effects only until heldUntil.
func (a *Applier) busy(now, talkUntil, heldUntil time.Time) string {
	switch {
	case a.cfg.Stopped():
		return busyStop
	case a.cfg.InCall():
		return busyCall
	case a.cfg.Working():
		return busyWork
	case a.cfg.Excluded(now):
		return busyExcluded
	case now.Before(a.cfg.Held()) && now.Before(heldUntil):
		return busyHeld
	case now.Sub(a.cfg.LastTalk()) < a.cfg.Quiet && (talkUntil.IsZero() || now.Before(talkUntil)):
		return busyTalk
	}
	return ""
}

// Why the box is not free (UPD-6; UX-133-4).
const (
	busyStop     = "STOP is in force"
	busyCall     = "a call is in progress"
	busyWork     = "accepted work is in progress"
	busyExcluded = "the owner excluded these hours from updates"
	busyHeld     = "an approved action is in its undo window"
	busyTalk     = "the owner and the agent are talking"
)

// waitLines say why an update waits (UX-133-3).
var waitLines = map[string]string{
	busyStop:     "Update %d is on hold while actions are stopped; it installs after RESUME.",
	busyCall:     "Update %d will install after the current call.",
	busyWork:     "Update %d will install once the agent's current task is done.",
	busyExcluded: "Update %d will install after your update-free hours.",
	busyHeld:     "Update %d will install once the actions you can still undo have run.",
	busyTalk:     "Update %d will install once your conversation pauses.",
	"":           "Update %d will install soon. Nothing is needed from you.",
}

// Tick applies the pending release when it is due and the box is free,
// by journaling its activation, then restarts into it. The restart is
// its own step: it waits for the box to be free again after the slot
// write, which can take minutes (UPD-6), and it is retried on later ticks
// when the broker stopped before it (security F1 on #133). ok reports the
// restart.
func (a *Applier) Tick(ctx context.Context) (ok bool, err error) {
	if ok, err := a.restartIfHandedOver(ctx); ok || err != nil {
		return ok, err
	}
	now := a.cfg.Now()
	a.mu.Lock()
	p := a.st.Pending
	if p == nil || a.rel == nil || a.st.Applying != nil || now.Before(p.NotBefore) {
		a.mu.Unlock()
		return false, nil
	}
	until, held := a.talkUntil(p), a.heldUntil(p)
	a.mu.Unlock()
	if a.busy(now, until, held) != "" {
		return false, nil
	}
	id := a.nextID(p.Version)
	in, err := a.intent(ctx, id)
	if err != nil {
		return false, err
	}
	st, err := a.cfg.Journal.Submit(in)
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
	return a.restartIfHandedOver(ctx)
}

// restartIfHandedOver restarts into a release the activator took, in the
// boot it was handed over in, once the box is free.
func (a *Applier) restartIfHandedOver(ctx context.Context) (bool, error) {
	a.mu.Lock()
	pt := a.st.Applying
	if pt == nil || !pt.Installed || a.executing {
		a.mu.Unlock()
		return false, nil
	}
	a.mu.Unlock()
	b, err := a.cfg.Activator.Booted(ctx)
	if err != nil || b.ID != pt.BootID {
		return false, err // a new boot is Resume's to judge
	}
	if a.busy(a.cfg.Now(), pt.TalkUntil, pt.HeldUntil) != "" {
		return false, nil
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
func (a *Applier) intent(ctx context.Context, id string) (journal.Intent, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.st.Pending
	if p == nil || a.rel == nil {
		return journal.Intent{}, errors.New("apply: no release is waiting")
	}
	m, err := a.rel.Manifest()
	if err != nil {
		return journal.Intent{}, err
	}
	in, err := a.cfg.Store.Installed()
	if err != nil {
		return journal.Intent{}, err
	}
	b, err := a.cfg.Activator.Booted(ctx)
	if err != nil {
		return journal.Intent{}, err
	}
	return journal.Intent{ID: id, Origin: Origin, Account: journal.BrokerAccount, Action: Action, Executor: Executor,
		Params: map[string]any{"from": in.Version, "from_usr": b.UsrRootHash, "to": m.Version, "to_usr": m.UsrRootHash,
			"adoption": p.Adoption, "security": p.Security}}, nil
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
	until, heldUntil := a.talkUntil(p), a.heldUntil(p)
	a.mu.Unlock()
	if p == nil || !held || p.Version != v || applying {
		return errors.New("apply: no release is waiting for this activation")
	}
	if why := a.busy(a.cfg.Now(), until, heldUntil); why != "" {
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
		pt.TalkUntil = a.talkUntil(p)
		pt.HeldUntil = a.heldUntil(p)
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

// Status is the applier's STATUS line, or "": an update installing or
// waiting, with why, and a fallback until the next update installs
// (UX-133-1 to 3). A successful install is said once, in the digest.
func (a *Applier) Status() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.st.Applying != nil && a.st.Applying.Installed:
		return fmt.Sprintf("Update %d is installing; the box will restart and check it.", a.st.Applying.To)
	case a.st.Pending != nil && a.rel != nil:
		why := ""
		if now := a.cfg.Now(); !now.Before(a.st.Pending.NotBefore) {
			why = a.busy(now, a.talkUntil(a.st.Pending), a.heldUntil(a.st.Pending))
		}
		return fmt.Sprintf(waitLines[why], a.st.Pending.Version)
	case a.st.Last == nil || a.st.Last.Kind == doneInstalled:
		return ""
	case a.st.Last.Kind == doneFellBack:
		return fellBackLine(a.st.Last.Version)
	}
	return fmt.Sprintf("Update %d was not installed; the box will try again.", a.st.Last.Version)
}

// Digest returns the lines the next digest carries once: an update that
// installed, or one that fell back (UX-133-1, 133-2).
func (a *Applier) Digest() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	l := a.st.Last
	if l == nil || l.Told || (l.Kind != doneInstalled && l.Kind != doneFellBack) {
		return nil
	}
	l.Told = true
	_ = a.saveLocked()
	if l.Kind == doneInstalled {
		return []string{fmt.Sprintf("Update %d is installed.", l.Version)}
	}
	return []string{fellBackLine(l.Version)}
}

// fellBackLine: Loop 3 never proposes a release again once it was adopted
// (security C3 on #133), so it is not tried again.
func fellBackLine(v int64) string {
	return fmt.Sprintf("Update %d did not start cleanly, so the box went back to the version it had. "+
		"Nothing is needed from you. It won't be tried again; a later update will replace it.", v)
}

func (a *Applier) saveLocked() error {
	b, err := json.Marshal(a.st)
	if err != nil {
		return err
	}
	return a.cfg.State.Save(b)
}
