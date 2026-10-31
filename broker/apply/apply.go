// Package apply is the update clerk (UPD-1, UPD-6, KRN-4, KRN-8): it
// hands a verified release the change pipeline staged to the image's A/B
// activator as one kernel plan step, activate, under the image-pinned
// update key, only when the box is free (no call, no accepted work, not in
// hours the owner excluded), and after the restart commits it once the new
// slot passed its health check or drops it when boot counting fell back.
//
// A fallback rewinds only the boot slot. Everything the broker keeps lives
// outside the image (the kernel log, keys and their revocations, budgets,
// deletions, the update store's root metadata), so this package never
// snapshots or restores it.
package apply

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/check"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/update"
)

// Name is the update clerk's name in a plan step and its key's root.
const Name = "update"

// The activate verb: a release activation changes the box's own
// configuration and nobody can undo it for the owner once it booted, so it
// is change-account, irreversible at the high tier (VRB-2, KRN-4). Its
// object is the release's /usr verity root hash and its value the digest
// of the signed manifest that binds the boot entry with it (UPD-1a).
const (
	ArgRoot  = "target"
	ArgEntry = "value"
)

// Clerk refusal details beside check.Check's codes.
const (
	RKey      = "update-key" // the key is not the image-pinned update key for activate only
	RStep     = "step"       // not the one activate step of an applier plan
	RPaused   = "pinned"     // the pinned channel pauses automatic activation (UPD-4)
	RRelease  = "release"    // not the newer, threshold-verified release the applier holds
	RBusy     = "busy"       // the box is not free (UPD-6)
	RApplying = "applying"   // a release is being applied
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
	// makes the entry the next boot (security C2 on #133). The inactive
	// slot is the slot not booted, whatever the update store holds as
	// installed; never the running slot. A blessed entry on that slot
	// leaves the boot menu, and the running root's entry becomes the
	// default, durably (ESP written and synced), before any byte of the
	// slot is written (A12); activatortest.Check is its acceptance check.
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

// Stager is the change pipeline's hook for a staged image adoption. Each
// takes the adoption's exact ID and returns nil when the adoption already
// settled the same way, so Resume can call them again (SR3-4).
// StageDropped settles an adoption whose release left the applier before
// it was installed, so its image no longer counts as active and the
// release can be adopted again under a new ID (SR3-4f-2b; offering it
// again is the A1 wiring's, ASSUMPTIONS MIG-4-adapters-e-pin).
type Stager interface {
	ConfirmStaged(id string) error
	StageFailed(ctx context.Context, id string) error
	StageDropped(ctx context.Context, id string) error
}

// Kernel is the part of the kernel the applier submits its plans to: the
// kernel admits the plan, dispatches its step to this clerk (Do) and
// reconciles an unknown answer through it (Probe).
type Kernel interface {
	Submit(now int64, p kernel.Plan) error
}

// Store persists the applier's state (change.MemStore, change.FileStore).
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// Config configures New. Every function field but Excluded, Paused,
// LastTalk, Rand and Now is required.
type Config struct {
	Kernel Kernel
	// Key is the image-pinned update key (decision 2 of brief #3423, card
	// cmsg_01R91wiieBzMSvPKFsAJVvuKUCsPpUiKJNwvXkmXsdfr63): a standing root
	// whose owner is Pinned, for this clerk's activate verb only; Holder
	// signs each plan under it. Pinned is the clerk's own trust root: Do
	// takes no other key (CLK-2). The key's authority is the project's
	// signing threshold, not the owner's: Do activates only a release that
	// passed the TUF threshold and is newer than the installed one (UPD-2,
	// UPD-8), so the key adds no power beyond that check.
	Key    key.Key
	Holder ed25519.PrivateKey
	Pinned key.PublicKey
	// Paused reports the pinned channel (UPD-4): no plan is submitted, a
	// release handed over in this boot is withdrawn instead of restarted
	// into (Pin) and STATUS says why while it holds. Nil: never.
	Paused    func() bool
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
	// restart happens while it holds.
	Stopped func() bool
	// LastTalk is when the owner was last delivered a message or the
	// agent last replied. Within Quiet of it the box is not free, so a
	// restart never cuts a conversation off (UX-133-4). Nil: never.
	LastTalk func() time.Time
	// Quiet is how long after LastTalk the box waits. Default 10 minutes.
	Quiet time.Duration
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
	ID string `json:"id"`
	// From is the update store's installed release and FromUsr the root
	// that ran; after an other-root boot they differ (From = N, FromUsr =
	// N-1's root), so they are never one update.Ref, and a fallback is
	// judged by FromUsr (SR3-4f-r1).
	From    int64  `json:"from"`
	FromUsr string `json:"from_usr"`
	To      int64  `json:"to"`
	ToUsr   string `json:"to_usr"`
	// ToManifest: the digest of the handed-over release's signed
	// manifest; with To and ToUsr it names the release exactly (SR3-4).
	ToManifest string `json:"to_manifest,omitempty"`
	Adoption   string `json:"adoption"`
	BootID     string `json:"boot_id"`
	// TalkUntil: after it, talk no longer holds the restart (zero: no
	// bound).
	TalkUntil time.Time `json:"talk_until,omitzero"`
	// Installed: the activator took the release. Unset, a later boot is
	// not a fallback: nothing was handed over.
	Installed bool `json:"installed"`
	// Security: it was scheduled as a security fix, so its restart is
	// automatic only while the release still is one (SR3-4f-2c).
	Security bool `json:"security,omitempty"`
	// Withdrawing: after the handover, a security recheck failed the
	// adoption, the owner pinned the channel (Pinned) or moved the box
	// to stable (Stable). The release is never restarted into; the next Tick or
	// Withdraw finishes abandoning it, and a boot of the old root is not
	// a fallback (SR3-4f-3a).
	Withdrawing bool `json:"withdrawing,omitempty"`
	// Pinned: it is withdrawn because the owner pinned the update
	// channel (UPD-4, #3699), not for a failed security check.
	Pinned bool `json:"pinned,omitempty"`
	// Stable: it is withdrawn because the owner moved the box to the
	// stable channel after a fast adoption (UPD-4, UPD-5), not for a
	// failed security check.
	Stable bool `json:"stable,omitempty"`
	// Abandoned: the withdrawal's Abandon took. Unset on a withdrawal,
	// the counted entry may still boot (#3832, #3852).
	Abandoned bool `json:"abandoned,omitempty"`
}

// Outcome kinds for Status.
const (
	doneInstalled = "installed"
	doneFellBack  = "fell_back"
	doneNotHanded = "not_handed"
	// doneInstalledOtherRoot: the update store holds the release as
	// installed, but the box booted the previous root (SR3-4f-1a).
	doneInstalledOtherRoot = "installed_other_root"
	// doneUnrecorded: the release reached maxUnrecorded and is refused
	// until Retry (SR3-4f-1b).
	doneUnrecorded = "unrecorded"
	// donePinned: the owner pinned the update channel after the handover,
	// so the release was withdrawn before any boot took it (#3699).
	donePinned = "pinned"
	// doneStable: the owner moved the box to stable after the handover,
	// so the release was withdrawn before any boot took it; the release
	// check's own line says when it comes (UPD-4, UPD-5).
	doneStable = "stable"
)

// maxUnrecorded is how many times Install runs for one release with no
// recorded outcome; after that the release is refused until the owner
// retries it (SR3-4f-1b).
const maxUnrecorded = 2

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
	// FellBack: releases whose boot fell back, by decimal version.
	FellBack map[string]bool `json:"fell_back,omitempty"`
	// Unrecorded: Install attempts with no recorded outcome, by refKey.
	// At maxUnrecorded the release is refused until Retry (SR3-4f-1b).
	Unrecorded map[string]int `json:"unrecorded,omitempty"`
	// Retired: adoptions never scheduled again, because their release
	// left the applier before it was installed or was withdrawn
	// (SR3-4f-2).
	Retired []string `json:"retired,omitempty"`
	// Dropped: adoptions still to settle with Pipeline.StageDropped; each
	// is retired too (SR3-4f-2b).
	Dropped []string `json:"dropped,omitempty"`
}

// retire marks adoption id as never scheduled again and as still to
// settle with StageDropped. An adoption already retired is left as it is:
// it is settled once, saved with its retirement. The slices are copied,
// so a state copied from st is not changed.
func retire(st *state, id string) {
	if id == "" || slices.Contains(st.Retired, id) {
		return
	}
	st.Retired = append(slices.Clip(st.Retired), id)
	st.Dropped = append(slices.Clip(st.Dropped), id)
}

// refKey keys a release exactly in saved state.
func refKey(r update.Ref) string {
	return fmt.Sprintf("%d/%s/%s", r.Version, r.UsrRootHash, r.ManifestSHA256)
}

// counted is m with key set to n, or removed when n is 0 or less; m is
// not changed.
func counted(m map[string]int, key string, n int) map[string]int {
	m = maps.Clone(m)
	if n > 0 {
		if m == nil {
			m = map[string]int{}
		}
		m[key] = n
	} else {
		delete(m, key)
	}
	return m
}

// Applier applies staged releases.
type Applier struct {
	cfg Config
	mu  sync.Mutex
	st  state
	rel *update.Verified // the pending release, held in memory only
	// executing: execute is handing a release over, with the lock
	// released during the slot write.
	executing bool
	// handed: the release the activator took in this process, until it
	// settles; nil after a process restart (SR3-4f-2c).
	handed *update.Verified
	// restarting: the point restartIfHandedOver is restarting into; a
	// Withdraw of it is refused from then on (SR3-4f-3 B1).
	restarting string
	// refused: a security or stable Withdraw of the apply in flight was
	// refused for this adoption, in this process (SR3-4f-3 B2). Its
	// release is never restarted into, and a pending release of it never
	// installs.
	refused refusal
	// thisBoot: the boot this process runs in, once a boot read or a
	// handover in this process showed it; "" before. A process never
	// outlives a boot.
	thisBoot string
	// asked: the plan this process submitted and Do has not answered,
	// and when; no second plan is submitted for Quiet after it, so a
	// kernel that dispatches later does not get one plan per Tick.
	asked   string
	askedAt time.Time
}

// refusal: a Withdraw of adoption for why (WhySecurity or WhyStable)
// refused; starts says whether its image may start before it is undone.
type refusal struct {
	adoption string
	starts   bool
	why      string
}

// New loads the applier's state. A pending release is not kept across a
// restart (a *update.Verified is never persisted): its adoption is
// retired and settled with StageDropped by the next Tick, and the
// release can be scheduled again only under a new adoption ID, by the A1
// wiring (SR3-4f-2b; ASSUMPTIONS MIG-4-adapters-e-pin). A pending release
// whose handover is in flight is left to Resume.
func New(cfg Config) (*Applier, error) {
	if cfg.Kernel == nil || cfg.Activator == nil || cfg.Store == nil || cfg.Pipeline == nil || cfg.State == nil ||
		cfg.InCall == nil || cfg.Working == nil || cfg.Stopped == nil {
		return nil, errors.New("apply: Kernel, Activator, Store, Pipeline, State, InCall, Working and Stopped are required")
	}
	if !cfg.Pinned.Valid() || len(cfg.Holder) != ed25519.PrivateKeySize || !pinnedKey(cfg.Key, cfg.Pinned) {
		return nil, errors.New("apply: Key must be the image-pinned update key for activate, and Holder its holder")
	}
	if cfg.Excluded == nil {
		cfg.Excluded = func(time.Time) bool { return false }
	}
	if cfg.Paused == nil {
		cfg.Paused = func() bool { return false }
	}
	if cfg.LastTalk == nil {
		cfg.LastTalk = func() time.Time { return time.Time{} }
	}
	if cfg.Quiet <= 0 {
		cfg.Quiet = 10 * time.Minute
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
	if p := a.st.Pending; p != nil && (a.st.Applying == nil || a.st.Applying.Adoption != p.Adoption) {
		retire(&a.st, p.Adoption)
	}
	a.st.Pending = nil
	return a, nil
}

// Schedule queues a verified release the change pipeline adopted as
// staged. adoption is the adoption's exact ID (change.Report.ID, never
// its short ID), the only form that settles it (SR3-4). A security fix is due at
// once; an ordinary release after a random jitter (UPD-5). A newer
// schedule replaces an older one. An adoption the applier refuses, other
// than one it holds or retired, and one a newer schedule replaces, is
// retired and settled with StageDropped by the next Tick; a retired
// adoption is refused with ErrRetired (SR3-4f-2b), and a release that
// fell back on this box with ErrFellBack.
func (a *Applier) Schedule(v *update.Verified, adoption string) error {
	if adoption == "" {
		return errors.New("apply: no adoption")
	}
	return a.schedule(v, adoption, false)
}

// ErrApplying: a release is being applied now; schedule after it settles.
var ErrApplying = errors.New("apply: a release is being applied")

// ErrFellBack: the release already fell back on this box.
var ErrFellBack = errors.New("apply: this release fell back before")

// ErrRetired: the adoption was dropped or withdrawn; it is never
// scheduled again (SR3-4f-2); the release needs a new adoption ID.
var ErrRetired = errors.New("apply: this adoption was dropped or withdrawn")

// ErrRefused: Install ran maxUnrecorded times for this exact release
// with no recorded outcome; only Retry admits it again (SR3-4f-1b).
var ErrRefused = errors.New("apply: this release could not be recorded as installed; retry it first")

// ScheduleFirstBoot queues the newest stable release first boot found
// (UPD-3). It is due at once, with no jitter, and has no change-pipeline
// adoption: the box has no owner, tasks or held-out cases yet, so after
// the restart the release is committed or dropped in the update store
// only. The free-moment rules still hold. A release that fell back before
// is refused, so the box never boots into it again.
func (a *Applier) ScheduleFirstBoot(v *update.Verified) error {
	return a.schedule(v, "", true)
}

// FellBack reports whether release version fell back on this box.
func (a *Applier) FellBack(version int64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.st.FellBack[strconv.FormatInt(version, 10)]
}

func (a *Applier) schedule(v *update.Verified, adoption string, now bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if slices.Contains(a.st.Retired, adoption) {
		return fmt.Errorf("%w: %s", ErrRetired, adoption)
	}
	err := a.scheduleLocked(v, adoption, now)
	if err != nil && !a.holdsLocked(adoption) {
		retire(&a.st, adoption)
		_ = a.saveLocked() // else the next settle saves it
	}
	return err
}

// holdsLocked: adoption is pending or being applied.
func (a *Applier) holdsLocked(adoption string) bool {
	return (a.st.Pending != nil && a.st.Pending.Adoption == adoption) ||
		(a.st.Applying != nil && a.st.Applying.Adoption == adoption)
}

func (a *Applier) scheduleLocked(v *update.Verified, adoption string, now bool) error {
	if !v.OK() {
		return update.ErrNotChecked
	}
	m, err := v.Manifest()
	if err != nil {
		return err
	}
	// Never again, through either entry point: the box would boot into
	// the same bad release (UPD-1); a later release replaces it.
	if a.st.FellBack[strconv.FormatInt(m.Version, 10)] {
		return fmt.Errorf("%w: release %d", ErrFellBack, m.Version)
	}
	in, err := a.cfg.Store.Installed()
	if err != nil {
		return err
	}
	if m.Version <= in.Version {
		return fmt.Errorf("%w: release %d is not newer than installed %d", update.ErrRollback, m.Version, in.Version)
	}
	nb := a.cfg.Now()
	if !v.Security() && !now {
		nb = nb.Add(time.Duration(a.cfg.Rand(int64(a.cfg.Jitter))))
	}
	if a.st.Applying != nil || a.executing {
		return ErrApplying
	}
	if r := v.Ref(); a.st.Unrecorded[refKey(r)] >= maxUnrecorded {
		return fmt.Errorf("%w: release %d (%s)", ErrRefused, r.Version, r.ManifestSHA256)
	}
	if p := a.st.Pending; p != nil && p.Version == m.Version && p.Adoption == adoption {
		a.rel = v // the same release again: keep its moment
		return nil
	}
	if p := a.st.Pending; p != nil && p.Adoption != adoption {
		retire(&a.st, p.Adoption) // superseded
	}
	a.st.Pending = &pending{Version: m.Version, Adoption: adoption, Security: v.Security(), NotBefore: nb}
	a.rel = v
	return a.saveLocked()
}

// busy reports why the box is not free now, or "".
// talkUntil is when talk stops holding a pending release: a security fix
// TalkBound after it became due; an ordinary release never (zero).
func (a *Applier) talkUntil(p *pending) time.Time {
	if p == nil || !p.Security {
		return time.Time{}
	}
	return p.NotBefore.Add(a.cfg.TalkBound)
}

// busy reports why the box is not free now, or "". Talk holds only until
// talkUntil, when that is set.
func (a *Applier) busy(now, talkUntil time.Time) string {
	switch {
	case a.cfg.Paused():
		return busyPinned
	case a.cfg.Stopped():
		return busyStop
	case a.cfg.InCall():
		return busyCall
	case a.cfg.Working():
		return busyWork
	case a.cfg.Excluded(now):
		return busyExcluded
	case now.Sub(a.cfg.LastTalk()) < a.cfg.Quiet && (talkUntil.IsZero() || now.Before(talkUntil)):
		return busyTalk
	}
	return ""
}

// Why the box is not free (UPD-6; UX-133-4).
const (
	busyPinned   = "the update channel is pinned"
	busyStop     = "STOP is in force"
	busyCall     = "a call is in progress"
	busyWork     = "accepted work is in progress"
	busyExcluded = "the owner excluded these hours from updates"
	busyTalk     = "a conversation with the owner is in progress"
)

// waitLines say why an update waits (UX-133-3).
var waitLines = map[string]string{
	busyPinned:   "Update %d waits because you pinned your update channel. Nothing is needed from you.",
	busyStop:     "Update %d is on hold while actions are stopped; it installs after RESUME.",
	busyCall:     "Update %d will install after the current call. Nothing is needed from you.",
	busyWork:     "Update %d will install once my current task is done. Nothing is needed from you.",
	busyExcluded: "Update %d will install after your update-free hours. Nothing is needed from you.",
	busyTalk:     "Update %d will install once your conversation pauses. Nothing is needed from you.",
	"":           "Update %d will install soon. Nothing is needed from you.",
}

// Tick applies the pending release when it is due and the box is free,
// by submitting its activation as a kernel plan, then restarts into it
// once the kernel's dispatch to Do handed it over. The restart is
// its own step: it waits for the box to be free again after the slot
// write, which can take minutes (UPD-6), and it is retried on later ticks
// when the broker stopped before it (security F1 on #133). ok reports the
// restart.
// Adoptions dropped on the way are settled last, outside the kernel's
// dispatch (SR3-4f-2b).
func (a *Applier) Tick(ctx context.Context) (ok bool, err error) {
	defer a.settle(ctx)
	if ok, err := a.restartIfHandedOver(ctx); ok || err != nil {
		return ok, err
	}
	a.mu.Lock()
	unhanded := a.st.Applying != nil && !a.st.Applying.Installed && !a.executing
	a.mu.Unlock()
	if unhanded {
		// A handover execute could not undo; Resume abandons it.
		if err := a.Resume(ctx); err != nil {
			return false, err
		}
	}
	now := a.cfg.Now()
	a.mu.Lock()
	p := a.st.Pending
	if p == nil || a.rel == nil || a.st.Applying != nil || now.Before(p.NotBefore) {
		a.mu.Unlock()
		return false, nil
	}
	if p.Security && !a.rel.Security() || a.refused.adoption != "" && a.refused.adoption == p.Adoption {
		// The attestor policy narrowed since it was scheduled (SR3-6):
		// drop the automatic authorization and settle the adoption
		// (SR3-4f-2b). The release can be adopted again only under a
		// new ID, under the current policy, by the A1 wiring.
		a.st.Pending, a.rel = nil, nil
		retire(&a.st, p.Adoption)
		err := a.saveLocked()
		a.mu.Unlock()
		return false, err
	}
	if a.st.Unrecorded[refKey(a.rel.Ref())] >= maxUnrecorded {
		// Refused after its unrecorded installs (SR3-4f-1b).
		a.st.Pending, a.rel = nil, nil
		retire(&a.st, p.Adoption)
		err := a.saveLocked()
		a.mu.Unlock()
		return false, err
	}
	until := a.talkUntil(p)
	a.mu.Unlock()
	if a.busy(now, until) != "" {
		return false, nil
	}
	a.mu.Lock()
	if a.asked != "" && now.Before(a.askedAt.Add(a.cfg.Quiet)) {
		a.mu.Unlock()
		return false, nil // the kernel has not dispatched it yet
	}
	plan, err := a.planLocked()
	if err == nil {
		a.asked, a.askedAt = plan.ID, now
	}
	a.mu.Unlock()
	if err != nil {
		return false, err
	}
	if err := a.cfg.Kernel.Submit(now.UnixMilli(), plan); err != nil {
		a.answered(plan.ID)
		return false, err
	}
	return a.restartIfHandedOver(ctx)
}

// restartIfHandedOver restarts into a release the activator took, in the
// boot it was handed over in, once the box is free. A security fix whose
// release is no longer one under the current attestor policy is not
// restarted into: it is abandoned and its adoption dropped, as when the
// policy narrows before the handover (SR3-4f-2c, SR3-6). After a process
// restart the release is not held and cannot be judged again, so a
// security fix fails closed the same way (ASSUMPTIONS A13). A release
// being withdrawn (SR3-4f-3a), or whose security Withdraw was refused
// (SR3-4f-3 B2), is never restarted into either. The point is checked
// again under the lock just before the restart, and a Withdraw from then
// on is refused (B1); a failed restart lifts that.
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
	a.mu.Lock()
	if pt = a.applyingLocked(pt.ID); pt != nil && a.staleLocked(pt) {
		// A failed step leaves Applying set, and the next Tick tries
		// again (SR3-4f-2c).
		err := a.withdrawHandoverLocked(ctx, pt)
		a.mu.Unlock()
		return false, err
	}
	if pt != nil && a.cfg.Paused() {
		// Pinned after the handover: withdrawn before any boot takes it
		// (UPD-4, #3699).
		err := a.withdrawLocked(ctx, pt, whyPin)
		a.mu.Unlock()
		return false, err
	}
	a.mu.Unlock()
	if pt == nil || a.busy(a.cfg.Now(), pt.TalkUntil) != "" {
		return false, nil
	}
	a.mu.Lock()
	if pt = a.applyingLocked(pt.ID); pt == nil || a.staleLocked(pt) || a.cfg.Paused() {
		a.mu.Unlock()
		return false, nil // withdrawn or pinned meanwhile: the next Tick settles it
	}
	a.restarting = pt.ID
	a.mu.Unlock()
	if err := a.cfg.Activator.Restart(ctx); err != nil {
		a.mu.Lock()
		a.restarting = ""
		a.mu.Unlock()
		return true, err
	}
	return true, nil
}

// applyingLocked is the installed apply in flight if its ID is id.
func (a *Applier) applyingLocked(id string) *point {
	if pt := a.st.Applying; pt != nil && pt.ID == id && pt.Installed && !a.executing {
		return pt
	}
	return nil
}

// staleLocked: pt's release is never restarted into.
func (a *Applier) staleLocked(pt *point) bool {
	return pt.Withdrawing || a.refused.adoption != "" && a.refused.adoption == pt.Adoption ||
		pt.Security && (a.handed == nil || !a.handed.Security())
}

// withdrawHandoverLocked undoes the handover of pt in the boot it was
// handed over in, and drops its adoption (SR3-4f-2c).
func (a *Applier) withdrawHandoverLocked(ctx context.Context, pt *point) error {
	if err := a.cfg.Activator.Abandon(ctx); err != nil {
		return err
	}
	if abandonOwed(pt) {
		// Recorded, so STATUS, Pin and Withdraw say it will not start
		// (#3832, #3852).
		marked := *pt
		marked.Abandoned = true
		next := a.st
		next.Applying = &marked
		if err := a.save(next); err != nil {
			return err
		}
		a.st, pt = next, &marked
	}
	if err := a.cfg.Store.DropStaged(); err != nil {
		return err
	}
	next := a.st
	next.Applying = nil
	next.Last = &last{Version: pt.To, Kind: withdrawnKind(pt)}
	retire(&next, pt.Adoption)
	if err := a.save(next); err != nil {
		return err
	}
	a.st, a.handed = next, nil
	return nil
}

// abandonOwed: pt is a withdrawal (pin, security or stale) whose Abandon
// is not recorded as taken, so the counted entry may still boot, and
// Resume commits it once it does (#3832, #3852, the #3701 boundary).
func abandonOwed(pt *point) bool { return !pt.Abandoned }

// withdrawnKind is the outcome of a handover withdrawn before any boot
// took it.
func withdrawnKind(pt *point) string {
	switch {
	case pt.Pinned:
		return donePinned
	case pt.Stable:
		return doneStable
	}
	return doneNotHanded
}

// WhySecurity is the change pipeline's reason for a revert after a
// failed security check (change.WhySecurity). It and WhyStable are the
// reasons Withdraw undoes a handover (SR3-4f-3a).
const WhySecurity = "security"

// whyPin is withdrawLocked's reason for the owner's pin of the update
// channel (#3699).
const whyPin = "pin"

// Withdraw gives up adoption for the change pipeline's revert of a staged
// adoption for why (SR3-4f-2a). A pending release of it is dropped; the
// adoption is retired either way, saved before it takes effect, so it is
// never scheduled again. Withdraw never calls the pipeline: the caller
// reverts the adoption itself. It is also dropped, so if that revert
// fails or is cut short, the next Tick settles it with StageDropped, a
// no-op once the revert ran (SR3-4f-2 L3-1).
//
// From the save before the install until Resume settles the apply,
// Withdraw is refused with an error that is ErrApplying and has
// Handover() true, with one exception (SR3-4f-3a): for a failed security
// check, once the activator took the release and in the boot it was
// handed over in, the handover is undone (Abandon, DropStaged) and the
// adoption dropped, with no fallback recorded. A box moved to stable
// (WhyStable) is the same: a fast adoption it handed over never boots
// past the stable gate (UPD-4, UPD-5). That is marked durably
// first, so the release is never restarted into even when a step fails;
// a failure is the same refusal with the cause wrapped, and the next Tick
// or Withdraw finishes it. An owner's UNDO or a regression revert keeps
// the refusal: the image installs, and is reverted once it settles.
func (a *Applier) Withdraw(adoption, why string) error {
	if adoption == "" {
		return errors.New("apply: no adoption")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if pt := a.st.Applying; pt != nil && pt.Adoption == adoption {
		return a.withdrawInstalledLocked(pt, why)
	}
	next := a.st
	held := next.Pending != nil && next.Pending.Adoption == adoption
	if held {
		next.Pending = nil
	}
	retire(&next, adoption)
	if err := a.save(next); err != nil {
		return err
	}
	a.st = next
	if held {
		a.rel = nil
	}
	return nil
}

// withdrawInstalledLocked is Withdraw of the apply in flight (SR3-4f-3a).
// A refused security or stable Withdraw is recorded (SR3-4f-3 B2). Its
// reason is the one asked for; any other reason, which reaches here only
// for a point already withdrawing, keeps that point's own cause, and a
// security refusal of the same adoption keeps its reason.
func (a *Applier) withdrawInstalledLocked(pt *point, why string) error {
	if why != WhySecurity && why != WhyStable && !pt.Withdrawing {
		return handoverError{}
	}
	err := a.undoHandoverLocked(pt, why)
	var h handoverError
	if errors.As(err, &h) { // security, stable, or already withdrawing
		r := why
		if r != WhySecurity && r != WhyStable {
			switch {
			case pt.Stable:
				r = WhyStable
			case pt.Pinned:
				r = whyPin
			default:
				r = WhySecurity
			}
		}
		if a.refused.adoption == pt.Adoption && a.refused.why == WhySecurity {
			r = WhySecurity
		}
		a.refused = refusal{adoption: pt.Adoption, starts: h.starts, why: r}
	}
	return err
}

func (a *Applier) undoHandoverLocked(pt *point, why string) error {
	switch {
	case a.executing, !pt.Installed:
		// executing first: the activator may be mid-install, and Booted
		// would wait on it. execute marks it withdrawing, or Resume
		// abandons it: it never starts.
		return handoverError{}
	case a.restarting == pt.ID:
		return handoverError{starts: true}
	}
	ctx := context.Background()
	b, err := a.cfg.Activator.Booted(ctx)
	if err != nil {
		// Unread, the boot is still the handover's only when this process
		// saw it so; then it is marked durably, so a process restart
		// before the next Tick never restarts into it (#4112). Otherwise
		// a new boot may have fallen back, which Resume must judge as a
		// fallback (UPD-1).
		if a.thisBoot != "" && a.thisBoot == pt.BootID {
			if err := a.markLocked(pt, why); err != nil {
				return fmt.Errorf("%w: %w", handoverError{starts: true}, err)
			}
		}
		return handoverError{starts: true}
	}
	a.thisBoot = b.ID
	if b.ID != pt.BootID {
		return handoverError{starts: true} // a new boot is Resume's to settle
	}
	return a.withdrawLocked(ctx, pt, why)
}

// markLocked saves pt as withdrawing for why, unless it already is; a
// security withdraw of a point withdrawn for a move to stable saves its
// own cause over it.
func (a *Applier) markLocked(pt *point, why string) error {
	if pt.Withdrawing && !(why == WhySecurity && pt.Stable) {
		return nil
	}
	marked := *pt
	if !pt.Withdrawing {
		marked.Withdrawing, marked.Pinned = true, why == whyPin
	}
	marked.Stable = why == WhyStable
	next := a.st
	next.Applying = &marked
	if err := a.save(next); err != nil {
		return err
	}
	a.st = next
	return nil
}

// withdrawLocked undoes pt's handover in the boot it was handed over in,
// marked durably first, so it is never restarted into even when a step
// fails, and a reboot of the old root is not taken for a fallback
// (SR3-4f-3a). why: whyPin (the owner pinned the update channel, #3699),
// WhyStable or WhySecurity.
func (a *Applier) withdrawLocked(ctx context.Context, pt *point, why string) error {
	if err := a.markLocked(pt, why); err != nil {
		// Not durable, and nothing abandoned: a reboot boots the counted
		// entry (#3852).
		return fmt.Errorf("%w: %w", handoverError{starts: true}, err)
	}
	pt = a.st.Applying
	if err := a.withdrawHandoverLocked(ctx, pt); err != nil {
		return fmt.Errorf("%w: %w", handoverError{starts: abandonOwed(a.st.Applying)}, err)
	}
	return nil
}

// Pin withdraws a release handed over in this boot, for the owner's pin
// of the update channel (UPD-4, #3699): pinned means no automatic
// update, and a handed-over release would start at the next restart,
// planned or not. The caller pins the channel (Paused true) first and
// reports the pin as taken only once Pin returns nil, so the owner is
// never told "pinned" while the next boot would take the release.
//
// The boundary is the first boot of the new slot: once the box has booted
// it, going back is a downgrade, so the release stays and Resume settles
// it as usual (Security on #3701). An install still running, or a restart
// already under way, is refused with an error that is ErrApplying, and
// Pin is called again; a Tick while pinned withdraws it too. The
// withdrawal is marked durably before the slot is abandoned, the adoption
// is dropped, and STATUS and the digest say so.
func (a *Applier) Pin(ctx context.Context) error {
	a.mu.Lock()
	unhanded := a.st.Applying != nil && !a.st.Applying.Installed && !a.executing
	a.mu.Unlock()
	if unhanded {
		// A handover execute could not undo; Resume abandons it.
		if err := a.Resume(ctx); err != nil {
			return err
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	pt := a.st.Applying
	switch {
	case pt == nil:
		return nil
	case a.executing || !pt.Installed:
		return handoverError{}
	case a.restarting == pt.ID:
		return handoverError{starts: true}
	}
	b, err := a.cfg.Activator.Booted(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", handoverError{starts: true}, err)
	}
	if b.ID != pt.BootID {
		return nil // booted since the handover: Resume's to settle
	}
	err = a.withdrawLocked(ctx, pt, whyPin)
	a.settleLocked(ctx)
	return err
}

// handoverError: the adoption's release is being installed. It is
// ErrApplying, and its Handover method lets the change pipeline tell it
// apart without importing this package. Starts: the image may start
// before it is undone (SR3-4f-3 B5).
type handoverError struct{ starts bool }

func (handoverError) Error() string        { return ErrApplying.Error() }
func (handoverError) Is(target error) bool { return target == ErrApplying }
func (handoverError) Handover() bool       { return true }
func (h handoverError) Starts() bool       { return h.starts }

// settle calls StageDropped for each dropped adoption, after the state
// that records it is saved; a failed call stays for the next settle
// (SR3-4f-2b), unless the pipeline refused it for good: the adoption was
// confirmed meanwhile, or is unknown (SR3-4f-3c). It runs outside the kernel's dispatch: Tick defers it.
func (a *Applier) settle(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.settleLocked(ctx)
}

func (a *Applier) settleLocked(ctx context.Context) {
	if len(a.st.Dropped) == 0 || a.saveLocked() != nil {
		return
	}
	var left []string
	for _, id := range a.st.Dropped {
		if err := a.cfg.Pipeline.StageDropped(ctx, id); err != nil && !permanent(err) {
			left = append(left, id)
		}
	}
	a.st.Dropped = left
	_ = a.saveLocked() // else the calls are made again, as no-ops
}

// permanent: the pipeline refuses the call the same way every time.
func permanent(err error) bool {
	var p interface{ Permanent() bool }
	return errors.As(err, &p) && p.Permanent()
}

// pinnedKey: k is a key off the image-pinned update root, for this clerk's
// activate verb alone (decision 2 of brief #3423). A narrowing below the
// root keeps that; the owner's keys, and any root with another verb, are
// not it.
func pinnedKey(k key.Key, pinned key.PublicKey) bool {
	return pinned.Valid() && k.Root.Owner == pinned && k.Root.Clerk == Name &&
		slices.Equal(k.Root.Verbs, []key.Verb{key.ChangeAccount})
}

// Step is the activate step for rel: its /usr root hash and the digest of
// the signed manifest that binds its boot entry (UPD-1a).
func Step(rel *update.Verified) kernel.PlanStep {
	r := rel.Ref()
	return kernel.PlanStep{Verb: key.ChangeAccount, Clerk: Name,
		Args: map[string]string{ArgRoot: r.UsrRootHash, ArgEntry: r.ManifestSHA256}}
}

// planLocked is the signed plan activating the pending release, numbered
// upd:apply:<version>:n<seq>. The number is saved before the plan is
// submitted, so a restart never reuses a plan ID the kernel logged.
func (a *Applier) planLocked() (kernel.Plan, error) {
	p := a.st.Pending
	if p == nil || a.rel == nil {
		return kernel.Plan{}, errors.New("apply: no release is waiting")
	}
	next := a.st
	next.Seq++
	if err := a.save(next); err != nil {
		return kernel.Plan{}, err
	}
	a.st = next
	plan := kernel.Plan{ID: fmt.Sprintf("upd:apply:%d:n%d", p.Version, next.Seq), Key: a.cfg.Key,
		Steps: []kernel.PlanStep{Step(a.rel)}}
	return kernel.SignPlan(plan, a.cfg.Holder), nil
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

// Facts is the clerk's own reading of a step: an activation carries no
// content class or flow label, and moves no money (KEY-2).
func (a *Applier) Facts(key.Step) (string, []string, int64) { return "", nil, 0 }

// Do runs the activate step: once its own checks pass (CLK-2), it hands
// the release to the activator. A step already handed over is answered ok
// without a second Install (KRN-8).
func (a *Applier) Do(r kernel.Request, v kernel.View) kernel.Result {
	if res, ok := a.done(r.Plan.ID); ok {
		return res
	}
	if rf := a.authorize(r, v); rf != "" {
		a.answered(r.Plan.ID)
		return kernel.Result{Outcome: "failed", Detail: rf}
	}
	return a.execute(context.Background(), r.Plan.ID)
}

// done answers a step whose release was already handed over.
func (a *Applier) done(id string) (kernel.Result, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.st.Applied[id] {
		return kernel.Result{}, false
	}
	a.answeredLocked(id)
	return kernel.Result{Outcome: "ok", Detail: "already handed over"}, true
}

func (a *Applier) answered(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.answeredLocked(id)
}

func (a *Applier) answeredLocked(id string) {
	if a.asked == id {
		a.asked = ""
	}
}

// authorize is the clerk's own check of an activate request, just before
// it acts, on its own clock (CLK-2): the key is the image-pinned update
// key for activate, verified against the pinned root alone and live in the
// log, with the step in flight; the step is the one step of an applier
// plan; the channel is not pinned (UPD-4); the step names exactly the
// release the applier holds, which passed the TUF threshold (Store.Check)
// and is newer than the installed one (UPD-8); and the box is free
// (UPD-6). It returns the refusal's detail, or "".
func (a *Applier) authorize(r kernel.Request, v kernel.View) string {
	if rf := check.Check([]key.PublicKey{a.cfg.Pinned}, Name, a.Facts, a.cfg.Now().UnixMilli(), r, v); rf != nil {
		return rf.Code
	}
	if !pinnedKey(r.Plan.Key, a.cfg.Pinned) {
		return RKey
	}
	ver, ok := parseID(r.Plan.ID)
	st := step(r)
	if !ok || len(r.Plan.Steps) != 1 || r.Index != 0 || st.Verb != key.ChangeAccount {
		return RStep
	}
	if a.cfg.Paused() {
		return RPaused
	}
	a.mu.Lock()
	p, rel, applying := a.st.Pending, a.rel, a.st.Applying != nil || a.executing
	until := a.talkUntil(p)
	a.mu.Unlock()
	if applying {
		return RApplying
	}
	if p == nil || rel == nil || !rel.OK() || p.Version != ver {
		return RRelease
	}
	if a.cfg.Now().Before(p.NotBefore) {
		return RBusy + ": not due" // its jitter has not passed (UPD-5)
	}
	if ref := rel.Ref(); st.Args[ArgRoot].Value != ref.UsrRootHash || st.Args[ArgEntry].Value != ref.ManifestSHA256 {
		return RRelease
	}
	if in, err := a.cfg.Store.Installed(); err != nil || ver <= in.Version {
		return RRelease
	}
	if why := a.busy(a.cfg.Now(), until); why != "" {
		return RBusy + ": " + why
	}
	return ""
}

// step is the request's step as check.Check reads it, through the core's
// open kernel.Normalize.
func step(r kernel.Request) key.Step {
	if r.Index < 0 || r.Index >= len(r.Plan.Steps) {
		return key.Step{}
	}
	return kernel.Normalize(key.ChargeTask(r.Plan.Key, r.Plan.ID), r.Plan.Steps[r.Index])
}

// execute hands the release to the activator. The rollback point is saved
// first, then the release is staged in the update store and installed in
// the inactive slot, without holding the lock, so STATUS answers during
// the slot write. A failed install, or a handover whose record could not
// be saved, is abandoned and drops the stage, and the release stays
// pending: the step is ok only once the handover is durable (SR3-4), and
// its answer carries the rollback point, so the kernel logs it as the
// step's result (UPD-6). An abandon that fails leaves the point for Resume
// and answers unknown, so Probe settles it. The save before the install
// counts an unrecorded attempt for the exact release, and the save that
// records the handover clears it; a release that reached maxUnrecorded is
// not installed again (SR3-4f-1b).
func (a *Applier) execute(ctx context.Context, id string) kernel.Result {
	failed := func(detail string) kernel.Result { return kernel.Result{Outcome: "failed", Detail: detail} }
	v, _ := parseID(id)
	a.mu.Lock()
	a.answeredLocked(id)
	p, rel := a.st.Pending, a.rel
	if p == nil || rel == nil || p.Version != v || a.st.Applying != nil || a.executing {
		a.mu.Unlock()
		return failed(RRelease)
	}
	if a.cfg.Paused() {
		// Pinned since authorize: a Pin that found nothing applied was
		// reported taken, so nothing is handed over now (UPD-4, #3699).
		a.mu.Unlock()
		return failed(RPaused)
	}
	key := refKey(rel.Ref())
	if a.st.Unrecorded[key] >= maxUnrecorded {
		a.mu.Unlock()
		return failed(ErrRefused.Error())
	}
	pt, err := a.pointLocked(ctx, id, rel, p.Adoption)
	if err == nil {
		pt.TalkUntil, pt.Security = a.talkUntil(p), p.Security
		prev, prevLast := a.st.Unrecorded, a.st.Last
		a.st.Applying, a.st.Unrecorded = pt, counted(prev, key, prev[key]+1)
		if prevLast != nil && prevLast.Kind == doneInstalledOtherRoot {
			// Install writes the slot that holds that release (A12(3)), so
			// its restart promise ends before any byte is written, whatever
			// becomes of this attempt (SR3-4f-r1).
			a.st.Last = nil
		}
		if err = a.saveLocked(); err != nil {
			a.st.Applying, a.st.Unrecorded, a.st.Last = nil, prev, prevLast
		}
	}
	if err != nil {
		a.mu.Unlock()
		return failed("rollback point not saved: " + noted(err))
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
		if errors.Is(err, update.ErrPolicyMoved) && a.st.Pending == p {
			// As in Tick (SR3-6); Tick settles the adoption after the
			// dispatch (SR3-4f-2b).
			a.st.Pending, a.rel = nil, nil
			retire(&a.st, p.Adoption)
		}
		return a.abandonedLocked(ctx, key, false, noted(err))
	}
	next := a.st
	pt2 := *a.st.Applying
	pt2.Installed = true
	pt2.Withdrawing = a.refused.adoption != "" && a.refused.adoption == pt2.Adoption // B2
	pt2.Stable = pt2.Withdrawing && a.refused.why == WhyStable
	next.Applying = &pt2
	if next.Pending == p {
		next.Pending = nil
	}
	next.Applied = map[string]bool{id: true} // only the latest is ever probed
	next.Unrecorded = counted(a.st.Unrecorded, key, 0)
	if err := a.save(next); err != nil {
		// Unrecorded, the handover is undone, so the activation is never
		// called done while a restart in this boot would abandon it.
		return a.abandonedLocked(ctx, key, true, "handover not saved: "+noted(err))
	}
	a.st, a.handed = next, rel
	a.thisBoot = pt2.BootID // read for the rollback point, in this process
	if a.st.Pending == nil {
		a.rel = nil
	}
	return kernel.Result{Outcome: "ok", Detail: rollbackPoint(&pt2)}
}

// abandonedLocked is the answer to a handover that did not complete: failed
// once it is abandoned, unknown while its point stays for Resume.
func (a *Applier) abandonedLocked(ctx context.Context, key string, took bool, detail string) kernel.Result {
	a.abandonLocked(ctx, key, took)
	if a.st.Applying != nil {
		return kernel.Result{Outcome: "unknown", Detail: detail + "; not yet abandoned"}
	}
	return kernel.Result{Outcome: "failed", Detail: detail}
}

// rollbackPoint is the step's logged result: the release and root that
// ran, and the release handed over with its root (UPD-1a, UPD-6).
func rollbackPoint(pt *point) string {
	return fmt.Sprintf("rollback point: release %d on root %s; activating release %d on root %s",
		pt.From, pt.FromUsr, pt.To, pt.ToUsr)
}

// Probe settles an activate step whose answer was lost, from saved state
// and the boot counter, never by a second Install (KRN-8): done once the
// activator took the release, with what became of it (handed over and
// waiting for the restart, committed, health check pending, fell back,
// withdrawn); unknown while an install runs or an unrecorded handover
// waits for Resume to abandon it; notdone when nothing of it was handed
// over, so a retry is safe.
func (a *Applier) Probe(r kernel.Request, _ kernel.View) kernel.Result {
	id := r.Plan.ID
	a.mu.Lock()
	defer a.mu.Unlock()
	switch pt := a.st.Applying; {
	case pt != nil && pt.ID == id && a.executing:
		return kernel.Result{Outcome: "unknown", Detail: "installing"}
	case pt != nil && pt.ID == id && pt.Installed:
		return kernel.Result{Outcome: "done", Detail: a.bootLocked(pt)}
	case pt != nil && pt.ID == id:
		return kernel.Result{Outcome: "unknown", Detail: "handover not recorded; abandoning it"}
	case a.st.Applied[id]:
		v, _ := parseID(id)
		return kernel.Result{Outcome: "done", Detail: settled(a.st.Last, v)}
	}
	return kernel.Result{Outcome: "notdone"}
}

// bootLocked reads the boot counter for pt, handed over and not settled.
func (a *Applier) bootLocked(pt *point) string {
	b, err := a.cfg.Activator.Booted(context.Background())
	switch {
	case err != nil:
		return "handed over"
	case b.ID == pt.BootID:
		return "handed over; restart pending"
	case b.UsrRootHash == pt.ToUsr && b.Blessed:
		return "committed"
	case b.UsrRootHash == pt.ToUsr:
		return "booted; health check pending"
	}
	if _, ok, err := a.committedLocked(pt); err == nil && ok {
		return "committed; the previous root booted this time"
	}
	return "fell back"
}

// settled names a settled activation's outcome for Probe.
func settled(l *last, version int64) string {
	if l == nil || l.Version != version {
		return "handed over"
	}
	switch l.Kind {
	case doneInstalled:
		return "committed"
	case doneInstalledOtherRoot:
		return "committed; the previous root booted this time"
	case doneFellBack:
		return "fell back"
	}
	return "handed over, then withdrawn"
}

// abandonLocked undoes a handover that did not complete; the release
// stays pending unless the caller dropped it (ErrPolicyMoved, whose drop
// Tick saves and settles). If the activator or the update store fails, the rollback
// point stays, unrecorded as installed, for Resume to abandon (SR3-4).
// took: Install returned nil, so the attempt stays counted against key;
// otherwise the slot write failed and the count goes back (SR3-4f-1b).
func (a *Applier) abandonLocked(ctx context.Context, key string, took bool) {
	if a.cfg.Activator.Abandon(ctx) != nil || a.cfg.Store.DropStaged() != nil {
		return
	}
	if took {
		a.st.Last = unrecordedLast(a.st, a.st.Applying.To, key, a.st.Last)
	} else {
		a.st.Unrecorded = counted(a.st.Unrecorded, key, a.st.Unrecorded[key]-1)
	}
	a.st.Applying = nil
	_ = a.saveLocked()
}

// unrecordedLast is the outcome of an abandoned attempt with no recorded
// outcome: doneUnrecorded once the release reached maxUnrecorded, else l.
func unrecordedLast(st state, version int64, key string, l *last) *last {
	if st.Unrecorded[key] >= maxUnrecorded {
		return &last{Version: version, Kind: doneUnrecorded}
	}
	return l
}

// noted is err's text for the kernel log. A path stays in the log, not the
// evidence, because a later owner text can be built from the evidence.
func noted(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "/") || strings.Contains(msg, `\`) {
		log.Printf("apply: %v", err)
		return "not applied"
	}
	return msg
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
		ToUsr: m.UsrRootHash, ToManifest: rel.Ref().ManifestSHA256, Adoption: adoption, BootID: boot.ID}, nil
}

// Resume settles an apply in flight after a restart, and is safe to call
// again until it does. Once the box runs a new boot, a blessed boot of
// the new release commits it (the update store and the pipeline's staged
// adoption); any other release means boot counting fell back, so the
// stage is dropped and the adoption reverted with no owner action
// (UPD-1). A boot of the new release whose health check has not passed
// yet waits. An apply whose handover was never recorded (the broker
// stopped or a save failed mid-handover) is abandoned, in the same boot
// or after a reboot that kept the old root: with nothing recorded, the
// old root does not prove the release fell back, so it is not marked as
// one and can be tried again (SR3-4). Booting the new root, it is judged
// like any other apply.
//
// Settling spans three stores, written in this order (SR3-4):
//
//	outcome     update store                 pipeline          applier
//	installed   CommitRelease(exact release)  ConfirmStaged(id)  Applying cleared
//	fell back   DropStaged                    StageFailed(id)    FellBack set, Applying cleared
//	not handed  Abandon, DropStaged           StageDropped(id)*  Applying cleared
//	other root  CommitRelease(exact release)  ConfirmStaged(id)  Applying cleared
//
// Other root: the box booted the previous root after the handover, but
// the update store already holds the exact release as installed, so a
// blessed boot of it was being committed when the broker stopped. That
// is not a fallback: the commit is finished, never reverted (SR3-4f-1a).
// A not-handed release that reached maxUnrecorded is settled as
// unrecorded and refused until Retry (SR3-4f-1b).
//
// * Not handed: when no pending release of this process holds the
// adoption (after a process restart), it is retired and StageDropped is
// called after the save; in the same boot, while it is still pending,
// the next Tick installs it again (SR3-4f-2b).
//
// Each step is idempotent for the exact release and adoption, and the
// in-flight record goes last, from memory only once it is saved, so a cut
// or an error anywhere leaves Applying set and a later Resume redoes the
// steps already done as no-ops. Nothing is installed again.
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
	a.thisBoot = b.ID
	next := a.st
	next.Applying = nil
	switch {
	case b.ID == pt.BootID && pt.Installed:
		return nil // not restarted yet
	case !pt.Installed && (b.ID == pt.BootID || b.UsrRootHash != pt.ToUsr):
		if err := a.cfg.Activator.Abandon(ctx); err != nil {
			return err
		}
		if err := a.cfg.Store.DropStaged(); err != nil {
			return err
		}
		next.Last = unrecordedLast(a.st, pt.To, refKey(update.Ref{Version: pt.To, UsrRootHash: pt.ToUsr, ManifestSHA256: pt.ToManifest}),
			&last{Version: pt.To, Kind: doneNotHanded})
		if !a.holdsPendingLocked(pt.Adoption) {
			retire(&next, pt.Adoption)
		}
	case b.UsrRootHash == pt.ToUsr && !b.Blessed:
		return nil // the health check has not passed yet
	case b.UsrRootHash == pt.ToUsr:
		ref, err := a.refLocked(pt)
		if err != nil {
			return err
		}
		if err := a.cfg.Store.CommitRelease(ref); err != nil {
			return err
		}
		if pt.Adoption != "" {
			if err := a.cfg.Pipeline.ConfirmStaged(pt.Adoption); err != nil {
				return err
			}
		}
		next.Last = &last{Version: pt.To, Kind: doneInstalled}
	default:
		ref, committed, err := a.committedLocked(pt)
		if err != nil {
			return err // never taken for a fallback (SR3-4f-1a)
		}
		if committed {
			if err := a.cfg.Store.CommitRelease(ref); err != nil {
				return err // removes a staged record left behind
			}
			if pt.Adoption != "" {
				if err := a.cfg.Pipeline.ConfirmStaged(pt.Adoption); err != nil {
					return err
				}
			}
			next.Last = &last{Version: pt.To, Kind: doneInstalledOtherRoot}
			break
		}
		if err := a.cfg.Store.DropStaged(); err != nil {
			return err
		}
		if pt.Withdrawing || pt.Abandoned {
			// The withdraw's Abandon took before the reboot: not a
			// fallback (SR3-4f-3a, #3852).
			next.Last = &last{Version: pt.To, Kind: withdrawnKind(pt)}
			retire(&next, pt.Adoption)
			break
		}
		if pt.Adoption != "" {
			if err := a.cfg.Pipeline.StageFailed(ctx, pt.Adoption); err != nil {
				return err
			}
		}
		next.FellBack = maps.Clone(a.st.FellBack)
		if next.FellBack == nil {
			next.FellBack = map[string]bool{}
		}
		next.FellBack[strconv.FormatInt(pt.To, 10)] = true
		next.Last = &last{Version: pt.To, Kind: doneFellBack}
	}
	if err := a.save(next); err != nil {
		return err
	}
	a.st, a.handed = next, nil
	a.settleLocked(ctx)
	return nil
}

// holdsPendingLocked: adoption is pending, with its release held.
func (a *Applier) holdsPendingLocked(adoption string) bool {
	return a.st.Pending != nil && a.st.Pending.Adoption == adoption && a.rel != nil
}

// committedLocked: the handover was recorded and the update store holds
// its exact release as installed (SR3-4f-1a). A read error is returned,
// never taken for "not installed", so Resume retries it. Only a legacy
// point whose digest is gone with its staged record cannot be matched,
// and is judged as a fallback.
func (a *Applier) committedLocked(pt *point) (update.Ref, bool, error) {
	if !pt.Installed {
		return update.Ref{}, false, nil
	}
	ref, err := a.refLocked(pt)
	if err != nil || ref.ManifestSHA256 == "" {
		return ref, false, err
	}
	in, err := a.cfg.Store.Installed()
	if err != nil {
		return ref, false, err
	}
	return ref, in.Version == ref.Version && in.UsrRootHash == ref.UsrRootHash &&
		in.ManifestSHA256 == ref.ManifestSHA256, nil
}

// Retry admits again a release refused after maxUnrecorded unrecorded
// installs; it is the owner's path back (SR3-4f-1b). The cleared count is
// saved before it takes effect.
func (a *Applier) Retry(ref update.Ref) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.st.Applying != nil || a.executing {
		return ErrApplying
	}
	key := refKey(ref)
	next := a.st
	next.Unrecorded = counted(a.st.Unrecorded, key, 0)
	if l := a.st.Last; l != nil && l.Kind == doneUnrecorded && l.Version == ref.Version {
		next.Last = nil
	}
	if err := a.save(next); err != nil {
		return err
	}
	a.st = next
	return nil
}

// refLocked names the handed-over release exactly. A point saved before
// it carried the manifest digest takes it from the staged record of the
// same version and root.
func (a *Applier) refLocked(pt *point) (update.Ref, error) {
	ref := update.Ref{Version: pt.To, UsrRootHash: pt.ToUsr, ManifestSHA256: pt.ToManifest}
	if ref.ManifestSHA256 != "" {
		return ref, nil
	}
	st, ok, err := a.cfg.Store.Staged()
	if err != nil {
		return ref, err
	}
	if ok && st.Version == pt.To && st.UsrRootHash == pt.ToUsr {
		ref.ManifestSHA256 = st.ManifestSHA256
	}
	return ref, nil
}

// The STATUS lines for an apply whose security Withdraw was refused or
// is under way (SR3-4f-3 B6), and for one withdrawn because the owner
// moved the box to stable (UPD-4, UPD-5).
const (
	wontStartLine       = "Update %d failed a security check; I will not start it. Nothing is needed from you."
	mayStartLine        = "Update %d failed a security check while it was being installed; it may start before I can undo it. Nothing is needed from you."
	stableWontStartLine = "You moved to the stable channel, so I will not start update %d until it is ready for stable. Nothing is needed from you."
	stableMayStartLine  = "You moved to the stable channel while update %d was being installed; it may start before I can undo it. Nothing is needed from you."
)

// withdrawingLine is STATUS for update v being withdrawn: for a failed
// security check, or stable when the owner moved the box to stable;
// starts: it may start before it is undone.
func withdrawingLine(v int64, stable, starts bool) string {
	switch {
	case stable && starts:
		return fmt.Sprintf(stableMayStartLine, v)
	case stable:
		return fmt.Sprintf(stableWontStartLine, v)
	case starts:
		return fmt.Sprintf(mayStartLine, v)
	}
	return fmt.Sprintf(wontStartLine, v)
}

// The lines for a release the activator took (#3829), and for one
// withdrawn because the owner pinned the update channel after the
// handover (#3699).
const (
	installingLine     = "Update %d is installing; I will restart and check it."
	staleLine          = "Update %d is being withdrawn; I will not start it. Nothing is needed from you."
	staleMayStartLine  = "Update %d is being withdrawn; it may start before I can undo it. Nothing is needed from you."
	startedLine        = "Update %d has started; I am checking it. Nothing is needed from you."
	mayRunLine         = "Update %d may have started already. Nothing is needed from you."
	pinnedHeldLine     = "Update %d is held because you pinned your update channel; I will not start it. Nothing is needed from you."
	pinnedMayStartLine = "Update %d was ready to start before you pinned your update channel, and it may still start. Nothing is needed from you."
	pinnedStartedLine  = "Update %d was ready to start before you pinned your update channel and has started; I am checking it. Nothing is needed from you."
	pinnedMayRunLine   = "Update %d was ready to start before you pinned your update channel, so it may have started already. Nothing is needed from you."
	pinnedLine         = "Update %d was withdrawn because you pinned your update channel."
	pinnedDigestLine   = "Update %d was ready to start, but you pinned your update channel, so I withdrew it."
)

// installedLineLocked is STATUS for pt, a release the activator took.
// Only in the boot it was handed over in does the line say what comes
// next: a restart into it; none for a stale security fix (A13,
// SR3-4f-2c), which the next Tick withdraws (#3830), held only once its
// Abandon is recorded (#3852); and, while the
// channel is pinned or pt's pin withdrawal is under way (pinned or not
// since), held only once its Abandon is recorded. Before that, a mark
// save or an Abandon that failed, or a restart already under way, the
// counted entry may still boot (#3832). A later boot running its root with
// the health check pending has started it (#3830); any other later boot
// may already run it, and then it stays (Security release 2 on #3812);
// a boot that cannot be read may be either (#3829).
func (a *Applier) installedLineLocked(pt *point) string {
	pinned := pt.Pinned || a.cfg.Paused()
	b, err := a.cfg.Activator.Booted(context.Background())
	here := err == nil && b.ID == pt.BootID
	started := err == nil && !here && b.UsrRootHash == pt.ToUsr && !b.Blessed
	switch {
	case here && !pinned && a.staleLocked(pt) && pt.Abandoned:
		return fmt.Sprintf(staleLine, pt.To)
	case here && !pinned && a.staleLocked(pt):
		return fmt.Sprintf(staleMayStartLine, pt.To)
	case here && !pinned:
		return fmt.Sprintf(installingLine, pt.To)
	case here && a.restarting != pt.ID && pt.Abandoned:
		return fmt.Sprintf(pinnedHeldLine, pt.To)
	case here:
		return fmt.Sprintf(pinnedMayStartLine, pt.To)
	case started && pinned:
		return fmt.Sprintf(pinnedStartedLine, pt.To)
	case started:
		return fmt.Sprintf(startedLine, pt.To)
	case pinned:
		return fmt.Sprintf(pinnedMayRunLine, pt.To)
	}
	return fmt.Sprintf(mayRunLine, pt.To)
}

// Status is the applier's STATUS line, or "": an update installing or
// waiting, with why, and a fallback until the next update installs
// (UX-133-1 to 3). A successful install is said once, in the digest.
func (a *Applier) Status() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.st.Applying != nil && a.st.Applying.Withdrawing && !a.st.Applying.Pinned:
		// Its Abandon not recorded, a reboot boots it (#3852). A security
		// refusal since names the cause over a move to stable.
		sec := a.refused.adoption == a.st.Applying.Adoption && a.refused.why == WhySecurity
		return withdrawingLine(a.st.Applying.To, a.st.Applying.Stable && !sec, !a.st.Applying.Abandoned)
	case a.st.Applying != nil && a.refused.adoption != "" && a.refused.adoption == a.st.Applying.Adoption &&
		a.refused.why != whyPin: // a pinned point keeps its pinned lines
		return withdrawingLine(a.st.Applying.To, a.refused.why == WhyStable, a.refused.starts)
	case a.st.Applying != nil && a.st.Applying.Installed:
		return a.installedLineLocked(a.st.Applying)
	case a.st.Pending != nil && a.rel != nil:
		why := ""
		if now := a.cfg.Now(); a.cfg.Paused() || !now.Before(a.st.Pending.NotBefore) {
			why = a.busy(now, a.talkUntil(a.st.Pending))
		}
		return fmt.Sprintf(waitLines[why], a.st.Pending.Version)
	}
	n, prev := a.previousRootLocked()
	switch l := a.st.Last; {
	case l == nil || l.Kind == doneInstalled:
		if prev {
			return previousRootText(n)
		}
		return ""
	case l.Kind == doneInstalledOtherRoot:
		if prev {
			return otherRootText(l.Version)
		}
		return ""
	case l.Kind == doneFellBack:
		return fellBackText(l.Version, n, prev)
	case l.Kind == doneUnrecorded:
		return unrecordedText(l.Version, n, prev)
	case l.Kind == donePinned && a.cfg.Paused():
		return pinnedText(l.Version, n, prev)
	case l.Kind == donePinned, l.Kind == doneStable:
		if prev {
			return previousRootText(n)
		}
		return ""
	default:
		return withPreviousRoot(fmt.Sprintf("Update %d was not installed; I will try again.", l.Version), n, prev)
	}
}

// Digest returns the lines the next digest carries once: an update that
// installed, or one that fell back (UX-133-1, 133-2).
func (a *Applier) Digest() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	l := a.st.Last
	if l == nil || l.Told || l.Kind == doneNotHanded || l.Kind == doneStable {
		return nil
	}
	l.Told = true
	_ = a.saveLocked()
	n, prev := a.previousRootLocked()
	switch l.Kind {
	case doneInstalled:
		return []string{withPreviousRoot(fmt.Sprintf("Update %d is installed.", l.Version), n, prev)}
	case doneUnrecorded:
		return []string{unrecordedText(l.Version, n, prev)}
	case donePinned:
		return []string{withPreviousRoot(fmt.Sprintf(pinnedDigestLine, l.Version), n, prev)}
	case doneInstalledOtherRoot:
		if prev {
			return []string{otherRootText(l.Version)}
		}
		return []string{fmt.Sprintf("Update %d is installed.", l.Version)}
	}
	return []string{fellBackText(l.Version, n, prev)}
}

// previousRootLocked reports the update store's installed release when no
// apply is in flight and this boot runs another root than it (SR3-4f-r1,
// SR3-4f-r1-f2): an other-root boot, or a later release that fell back,
// was withdrawn or failed after execute's save before Stage, so the box
// runs N-1 while the store holds N. A boot or store that cannot be read,
// or a store that never recorded a root, is not taken for it, since the
// line says what the box started (CH-12).
func (a *Applier) previousRootLocked() (int64, bool) {
	if a.st.Applying != nil || a.executing {
		return 0, false
	}
	b, err := a.cfg.Activator.Booted(context.Background())
	if err != nil {
		return 0, false
	}
	in, err := a.cfg.Store.Installed()
	if err != nil || in.UsrRootHash == "" || b.UsrRootHash == in.UsrRootHash {
		return 0, false
	}
	return in.Version, true
}

// previousRootLine says the box runs the root before installed release n,
// with no restart promise: once a later Install may have written n's
// slot, n may not start (SR3-4f-r1-f2).
const previousRootLine = "I am running the previous version, not update %d."

func previousRootText(n int64) string {
	return fmt.Sprintf(previousRootLine, n) + " Nothing is needed from you; a later update will replace it."
}

// withPreviousRoot adds the previous-version line to an outcome line when
// prev holds.
func withPreviousRoot(line string, n int64, prev bool) string {
	if !prev {
		return line
	}
	return line + " " + fmt.Sprintf(previousRootLine, n)
}

// pinnedText: update v was withdrawn for the pin. The previous-version line
// comes before "Nothing is needed from you.", so the whole fits one
// segment (CH-12).
func pinnedText(v, n int64, prev bool) string {
	return withPreviousRoot(fmt.Sprintf(pinnedLine, v), n, prev) + " Nothing is needed from you."
}

// otherRootText: the release is installed, but this boot runs the
// previous root (SR3-4f-1a).
func otherRootText(v int64) string {
	return fmt.Sprintf("Update %d is installed, but I started the previous version this time. "+
		"I will start update %d at my next restart. Nothing is needed from you.", v, v)
}

// unrecordedText: the release reached maxUnrecorded and waits for the
// owner's retry (SR3-4f-1b). With prev, it names the root the box runs
// within the same segment (CH-12, #3830).
func unrecordedText(v, n int64, prev bool) string {
	runs := ""
	if prev {
		runs = fmt.Sprintf("; I run the version before update %d", n)
	}
	return fmt.Sprintf("I could not record update %d as installed, twice, so I stopped trying it%s. "+
		"You can retry it on my Wi-Fi page.", v, runs)
}

// fellBackText: Schedule refuses a release that fell back (ErrFellBack,
// #1924; security C3 on #133), so it is not tried again. With prev, it
// names the root the box runs within the same segment (CH-12, #3830).
func fellBackText(v, n int64, prev bool) string {
	had := "the version I had"
	if prev {
		had = fmt.Sprintf("the version before update %d", n)
	}
	return fmt.Sprintf("Update %d did not start cleanly, so I went back to %s. "+
		"It won't be tried again. Nothing is needed from you.", v, had)
}

func (a *Applier) saveLocked() error { return a.save(a.st) }

func (a *Applier) save(st state) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return a.cfg.State.Save(b)
}
